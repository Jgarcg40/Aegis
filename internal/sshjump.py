"""Salto SSH en auditoría: validación, probe, secreto y wrapper."""
from __future__ import annotations

import ipaddress
import json
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse

from internal.targets import Target, has_ip_target, ip_in_scope, parse_one, parse_targets

JUMP_NAME = ".ssh-jump.json"
SSH_PORT = 22
SOCKS_PORT = 18080


class SshJumpError(ValueError):
    """Error de lanzamiento (XOR, host, probe). Sin secretos en el texto."""


@dataclass(frozen=True)
class SshJump:
    host: str
    user: str
    password: str
    socks: bool = False


def ssh_dest(user: str, host: str) -> str:
    try:
        if ipaddress.ip_address(host).version == 6:
            return f"{user}@[{host}]"
    except ValueError:
        pass
    return f"{user}@{host}"


def parse_ssh_host(raw: str) -> str:
    text = (raw or "").strip()
    if not text:
        raise SshJumpError("SSH host vacío: pon la IP de la máquina")
    try:
        return str(ipaddress.ip_address(text))
    except ValueError as exc:
        raise SshJumpError("SSH host tiene que ser una IP (IPv4/IPv6)") from exc


def target_is_jump_only(targets: list[Target], host: str) -> bool:
    if not targets:
        return True
    for t in targets:
        if t.kind in {"ipv4", "ipv6"} and t.value == host:
            continue
        if t.kind == "hostport" and t.value == host:
            continue
        if t.kind == "url":
            h = urlparse(t.value).hostname
            if h == host:
                continue
        return False
    return True


def socks_needed(targets: list[Target], host: str) -> bool:
    return not target_is_jump_only(targets, host)


def ensure_host_in_scope(targets: list[Target], host: str) -> list[Target]:
    if not host:
        return list(targets)
    if ip_in_scope(host, targets):
        return list(targets)
    return [*targets, parse_one(host)]


def _user_pass_from_accounts(accounts: list[str] | None) -> tuple[str, str]:
    for raw in accounts or []:
        if ":" not in raw:
            continue
        user, secret = raw.split(":", 1)
        user, secret = user.strip(), secret.strip()
        if user and secret:
            return user, secret
    return "", ""


def resolve_ssh_launch(
    *,
    target_spec: str,
    ctf: bool,
    ssh_host: str = "",
    ssh_user: str = "",
    ssh_pass: str = "",
    accounts: list[str] | None = None,
    resume: bool = False,
) -> tuple[str, SshJump | None]:
    """Valida XOR/IP y rellena Target vacío con el host. Sin probe."""
    host_raw = (ssh_host or "").strip()
    user = (ssh_user or "").strip()
    password = ssh_pass or ""
    if not user or not password:
        acc_user, acc_pass = _user_pass_from_accounts(accounts)
        user = user or acc_user
        password = password or acc_pass
    want_ssh = bool(host_raw or user or password)
    if ctf and want_ssh:
        raise SshJumpError("SSH y CTF no se mezclan")
    if want_ssh:
        host = parse_ssh_host(host_raw)
        if not user or not password:
            raise SshJumpError("SSH necesita usuario y contraseña")
        spec = (target_spec or "").strip()
        if not spec:
            spec = host
        else:
            try:
                parse_targets(spec)
            except ValueError as exc:
                raise SshJumpError(str(exc)) from exc
        jump = SshJump(host=host, user=user, password=password, socks=False)
        return spec, jump
    spec = (target_spec or "").strip()
    if not spec:
        if resume:
            return "", None
        raise SshJumpError("target vacío: sin SSH hace falta una IP")
    targets = parse_targets(spec)
    if not has_ip_target(targets):
        raise SshJumpError("sin SSH el Target tiene que incluir una IP (IPv4/IPv6, IP:puerto o CIDR)")
    return spec, None


def probe_ssh(host: str, user: str, password: str, *, port: int = SSH_PORT, timeout: int = 12) -> None:
    if not shutil.which("ssh"):
        raise SshJumpError("no está ssh en el host; no se puede comprobar el salto")
    with tempfile.TemporaryDirectory(prefix="aegis-ssh-") as td:
        ask = Path(td) / "ask"
        ask.write_text('#!/bin/sh\nprintf \'%s\\n\' "$AEGIS_SSH_PASS"\n', encoding="utf-8")
        ask.chmod(0o700)
        env = os.environ.copy()
        env["AEGIS_SSH_PASS"] = password
        env["SSH_ASKPASS"] = str(ask)
        env["SSH_ASKPASS_REQUIRE"] = "force"
        env.setdefault("DISPLAY", ":0")
        try:
            proc = subprocess.run(
                [
                    "ssh",
                    "-o",
                    "BatchMode=no",
                    "-o",
                    "StrictHostKeyChecking=no",
                    "-o",
                    "UserKnownHostsFile=/dev/null",
                    "-o",
                    "GlobalKnownHostsFile=/dev/null",
                    "-o",
                    "PreferredAuthentications=password,keyboard-interactive",
                    "-o",
                    "PubkeyAuthentication=no",
                    "-o",
                    f"ConnectTimeout={max(3, timeout - 2)}",
                    "-p",
                    str(port),
                    ssh_dest(user, host),
                    "true",
                ],
                env=env,
                capture_output=True,
                text=True,
                timeout=timeout + 2,
            )
        except subprocess.TimeoutExpired as exc:
            raise SshJumpError("SSH no respondió a tiempo") from exc
        if proc.returncode != 0:
            raise SshJumpError("SSH rechazado o inalcanzable (host/usuario/contraseña)")


def jump_brief_note(host: str, user: str, *, socks: bool) -> str:
    extra = (
        "El Target no es esa caja: las herramientas salen por `proxychains` "
        "o `aegis-ssh`. El modelo no usa el proxy. No inventes túneles."
        if socks
        else "El Target es esa máquina: trabaja EN ella con `aegis-ssh`."
    )
    return (
        f"Tienes SSH a `{user}@{host}` (ya comprobado). "
        f"Para un comando en esa caja: `aegis-ssh '…'`. "
        f"No redescubras el login ni pongas la contraseña en comandos. {extra}"
    )


def write_jump_secret(
    out_dir: Path,
    *,
    host: str,
    user: str,
    password: str,
    socks: bool,
) -> Path:
    dest = Path(out_dir) / JUMP_NAME
    dest.write_text(
        json.dumps(
            {
                "host": host,
                "user": user,
                "port": SSH_PORT,
                "password": password,
                "socks": bool(socks),
                "socks_port": SOCKS_PORT if socks else 0,
            },
            indent=2,
        )
        + "\n",
        encoding="utf-8",
    )
    dest.chmod(0o600)
    return dest


AEGIS_SSH = r"""#!/usr/bin/env python3
import json
import os
import subprocess
import sys
from pathlib import Path

OUT = Path(os.environ.get("AEGIS_OUT", "/run/aegis/out"))
JUMP = OUT / ".ssh-jump.json"


def _die(msg: str, rc: int = 2) -> None:
    print(f"aegis-ssh: {msg}", file=sys.stderr)
    raise SystemExit(rc)


def main() -> int:
    if not JUMP.is_file():
        _die("no hay salto SSH en este run")
    try:
        data = json.loads(JUMP.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        _die("secreto SSH ilegible")
    host = str(data.get("host") or "")
    user = str(data.get("user") or "")
    password = str(data.get("password") or "")
    port = int(data.get("port") or 22)
    if not host or not user or not password:
        _die("secreto SSH incompleto")
    dest = f"{user}@[{host}]" if ":" in host else f"{user}@{host}"
    remote = " ".join(sys.argv[1:]).strip()
    if not remote:
        print("uso: aegis-ssh 'comando'", file=sys.stderr)
        return 2
    ask = Path("/tmp/aegis-ssh-ask")
    ask.write_text('#!/bin/sh\nprintf \'%s\\n\' "$AEGIS_SSH_PASS"\n', encoding="utf-8")
    ask.chmod(0o700)
    env = os.environ.copy()
    env["AEGIS_SSH_PASS"] = password
    env["SSH_ASKPASS"] = str(ask)
    env["SSH_ASKPASS_REQUIRE"] = "force"
    env.setdefault("DISPLAY", ":0")
    cmd = [
        "ssh",
        "-o",
        "BatchMode=no",
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "GlobalKnownHostsFile=/dev/null",
        "-o",
        "PreferredAuthentications=password,keyboard-interactive",
        "-o",
        "PubkeyAuthentication=no",
        "-o",
        "ControlMaster=auto",
        "-o",
        "ControlPath=/tmp/aegis-cm-%r@%h:%p",
        "-o",
        "ControlPersist=4h",
        "-o",
        "ConnectTimeout=12",
        "-p",
        str(port),
        dest,
        remote,
    ]
    return subprocess.call(cmd, env=env)


if __name__ == "__main__":
    raise SystemExit(main())
"""


def write_aegis_ssh(bin_dir: Path) -> Path:
    dest = Path(bin_dir) / "aegis-ssh"
    dest.write_text(AEGIS_SSH, encoding="utf-8")
    dest.chmod(0o755)
    return dest
