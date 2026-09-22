from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

PROVIDER_ALIASES = {
    "grok": "xai",
    "xai": "xai",
    "codex": "openai",
    "openai": "openai",
    "chatgpt": "openai",
}


def cwd_is_alive() -> bool:
    try:
        cur = Path.cwd()
        return cur.exists() and os.access(cur, os.X_OK)
    except OSError:
        return False


def ensure_alive_cwd(*preferred: Path | str) -> Path:
    if cwd_is_alive():
        cur = Path.cwd()
        os.environ["PWD"] = str(cur)
        return cur
    candidates: list[Path] = []
    for item in preferred:
        if item:
            candidates.append(Path(item))
    candidates.extend([Path.home(), Path("/tmp"), Path("/")])
    seen: set[Path] = set()
    for raw in candidates:
        try:
            c = raw.expanduser()
            if c in seen:
                continue
            seen.add(c)
            if not (c.is_dir() and os.access(c, os.X_OK)):
                continue
            os.chdir(c)
            resolved = c.resolve()
            os.environ["PWD"] = str(resolved)
            return resolved
        except OSError:
            continue
    return Path("/")


def host_cli_env(base: dict | None = None) -> dict[str, str]:
    env = dict(base or os.environ)
    home = str(Path.home())
    env["HOME"] = home
    extra = f"{home}/.opencode/bin:{home}/.local/bin:{home}/.npm-global/bin"
    path = env.get("PATH") or "/usr/bin:/bin"
    if f"{home}/.local/bin" not in path.split(":"):
        env["PATH"] = extra + ":" + path
    return env


def opencode_bin() -> Path | None:
    env = os.environ.get("OPENCODE_BIN", "").strip()
    if env:
        p = Path(env)
        if p.is_file() and os.access(p, os.X_OK):
            return p
    found = shutil.which("opencode")
    if found:
        return Path(found)
    home = Path.home()
    for cand in (
        home / ".opencode" / "bin" / "opencode",
        home / ".local" / "bin" / "opencode",
        home / "bin" / "opencode",
        Path("/usr/local/bin/opencode"),
    ):
        if cand.is_file() and os.access(cand, os.X_OK):
            return cand
    return None


def host_auth_path() -> Path:
    xdg = os.environ.get("XDG_DATA_HOME", "").strip()
    base = Path(xdg) if xdg else Path.home() / ".local" / "share"
    return base / "opencode" / "auth.json"


def load_auth(path: Path | None = None) -> dict:
    p = path or host_auth_path()
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def provider_entry(auth: dict, provider: str) -> dict | None:
    entry = auth.get(provider)
    return entry if isinstance(entry, dict) else None


def provider_kind(auth: dict, provider: str) -> str:
    entry = provider_entry(auth, provider)
    if not entry:
        return ""
    return str(entry.get("type") or "unknown")


def has_provider(auth: dict, provider: str) -> bool:
    entry = provider_entry(auth, provider)
    if not entry:
        return False
    typ = str(entry.get("type") or "")
    if typ == "oauth":
        return bool(entry.get("access") or entry.get("refresh"))
    if typ == "api":
        return bool(entry.get("key"))
    return bool(entry)


@dataclass
class StagedAuth:
    root: Path
    auth_file: Path

    @property
    def xdg_data_home(self) -> Path:
        return self.root


def stage_auth(run_id: str, src: Path | None = None) -> StagedAuth:
    src = src or host_auth_path()
    if not src.is_file():
        raise SystemExit(
            f"no hay {src}. En el host: aegis auth login grok  y  aegis auth login codex\n"
            "(OAuth de la suscripción SuperGrok / ChatGPT; no hace falta API key.)"
        )
    root = Path(f"/tmp/aegis-auth-{run_id}")
    if root.exists():
        shutil.rmtree(root)
    dest_dir = root / "opencode"
    dest_dir.mkdir(parents=True, mode=0o700)
    dest = dest_dir / "auth.json"
    shutil.copy2(src, dest)
    os.chmod(root, 0o700)
    os.chmod(dest_dir, 0o700)
    os.chmod(dest, 0o600)
    return StagedAuth(root=root, auth_file=dest)


def sync_back(staged: StagedAuth, dest: Path | None = None) -> None:
    dest = dest or host_auth_path()
    if not staged.auth_file.is_file():
        return
    try:
        staged_data = json.loads(staged.auth_file.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return
    if not isinstance(staged_data, dict) or not staged_data:
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    host = load_auth(dest)
    host.update(staged_data)
    tmp = dest.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(host, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(dest)
    os.chmod(dest, 0o600)


def cleanup_stage(staged: StagedAuth | None) -> None:
    if staged is None:
        return
    try:
        if staged.root.exists() and str(staged.root).startswith("/tmp/aegis-auth-"):
            shutil.rmtree(staged.root)
    except OSError as exc:
        print(f"aegis: no se pudo borrar staging de auth: {exc}", file=sys.stderr)


def summarize_providers(auth: dict) -> list[str]:
    rows = []
    for name in sorted(auth):
        kind = provider_kind(auth, name) or "?"
        rows.append(f"{name} ({kind})")
    return rows


def run_host_login(provider: str | None) -> int:
    if (provider or "").strip().lower() in {"claude", "anthropic", "claude-code"}:
        from internal.claude import wrapper_bin

        binary = wrapper_bin()
        if binary is None:
            raise SystemExit(
                "Claude Code no está en PATH. Esperado en ~/.local/bin/claude "
                "o exporta CLAUDE_BIN."
            )
        if not sys.stdin.isatty():
            raise SystemExit(
                "el login de Claude Code necesita un TTY. En una terminal: claude auth login"
            )
        print(
            "aegis: claude auth login — elige la suscripción Claude.ai, no una API key.",
            file=sys.stderr,
        )
        return subprocess.call([str(binary), "auth", "login"])
    binary = opencode_bin()
    if binary is None:
        raise SystemExit(
            "OpenCode no está en PATH. Está en ~/.opencode/bin/opencode; "
            "añádelo al PATH o exporta OPENCODE_BIN."
        )
    if not sys.stdin.isatty():
        raise SystemExit(
            "el login OAuth necesita un TTY. Ejecuta en una terminal: "
            "aegis auth login grok   o   aegis auth login codex"
        )
    cmd = [str(binary), "auth", "login"]
    if provider:
        pid = PROVIDER_ALIASES.get(provider, provider)
        cmd += ["--provider", pid]
    print(f"aegis: {cmd[0]} auth login — elige la suscripción (OAuth), no la API key.", file=sys.stderr)
    if provider in {"grok", "xai"}:
        print("aegis: en xAI elige SuperGrok Subscription.", file=sys.stderr)
    if provider in {"codex", "openai", "chatgpt"}:
        print("aegis: en OpenAI elige ChatGPT Plus/Pro.", file=sys.stderr)
    return subprocess.call(cmd)


def save_api_key(provider: str, key: str, dest: Path | None = None) -> None:
    """Escribe una API key en el auth.json de OpenCode (type=api)."""
    provider = PROVIDER_ALIASES.get(provider, provider)
    key = (key or "").strip()
    if not provider or not key:
        raise SystemExit("proveedor y api key son obligatorios")
    dest = dest or host_auth_path()
    dest.parent.mkdir(parents=True, exist_ok=True)
    data = load_auth(dest)
    data[provider] = {"type": "api", "key": key}
    tmp = dest.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(dest)
    os.chmod(dest, 0o600)


def drop_auth_provider(provider: str, dest: Path | None = None) -> None:
    """Quita la entrada del auth.json de OpenCode (el CLI a veces tarda o deja tokens)."""
    dest = dest or host_auth_path()
    pid = PROVIDER_ALIASES.get((provider or "").strip().lower(), (provider or "").strip())
    if not pid or not dest.is_file():
        return
    data = load_auth(dest)
    aliases = {pid, (provider or "").strip().lower()}
    if not any(a in data for a in aliases):
        return
    for a in aliases:
        data.pop(a, None)
    tmp = dest.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(dest)
    os.chmod(dest, 0o600)


def run_host_logout(provider: str) -> int:
    p = (provider or "").strip().lower()
    if p in {"claude", "claude-code"}:
        from internal.claude import wrapper_bin

        binary = wrapper_bin()
        if binary is None:
            raise SystemExit("Claude Code no está en PATH.")
        return subprocess.call([str(binary), "auth", "logout"])
    if p in {"cursor", "cursor-agent"}:
        from internal.cursorcli import agent_env, wrapper_bin

        binary = wrapper_bin()
        if binary is None:
            return 0
        return subprocess.call([str(binary), "logout"], env=agent_env())
    if p in {"codex", "codex-cli"}:
        from internal.codex import wrapper_bin

        binary = wrapper_bin()
        if binary is None:
            raise SystemExit("Codex CLI no está en PATH.")
        return subprocess.call([str(binary), "logout"])
    binary = opencode_bin()
    if binary is None:
        raise SystemExit("OpenCode no está en PATH.")
    pid = PROVIDER_ALIASES.get(provider, provider)
    rc = subprocess.call([str(binary), "auth", "logout", pid])
    drop_auth_provider(pid)
    return rc
