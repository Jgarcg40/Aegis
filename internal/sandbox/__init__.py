from __future__ import annotations

import os
import secrets
import shutil
import socket
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from internal.config import ROOT, Config
from internal.inbox import INBOX_MOUNT
from internal.models import ResolvedModel, rescue_env, rewrite_loopback_for_bridge

CONTAINER_PREFIX = "aegis-run-"


class DockerMissing(SystemExit):
    def __init__(self) -> None:
        super().__init__(
            "Docker no está disponible. Aegis no tiene fallback en el host: "
            "instala Docker y vuelve a intentar. Un run en el host contaminaría "
            "paquetes, iptables y credenciales entre engagements."
        )


@dataclass
class Sandbox:
    run_id: str
    name: str
    port: int
    password: str
    network_mode: str


def require_docker() -> None:
    if shutil.which("docker") is None:
        raise DockerMissing()
    try:
        subprocess.run(
            ["docker", "info"],
            check=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
    except (subprocess.CalledProcessError, FileNotFoundError) as exc:
        raise DockerMissing() from exc


def image_exists(image: str) -> bool:
    r = subprocess.run(
        ["docker", "image", "inspect", image],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return r.returncode == 0


def require_image(image: str) -> None:
    if not image_exists(image):
        raise SystemExit(
            f"imagen {image} no encontrada. Construye con: make image\n"
            "La primera build de Kali + herramientas tarda y pesa varios GB."
        )


def pick_port(lo: int, hi: int) -> int:
    for _ in range(64):
        port = secrets.randbelow(hi - lo + 1) + lo
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise SystemExit("no hay puertos libres en serve_port_range")


def container_name(run_id: str) -> str:
    return f"{CONTAINER_PREFIX}{run_id}"


def _cursor_cli_config_seed(host_out: Path) -> Path | None:
    """Copia cli-config.json al run. No monta el original."""
    candidates = [
        Path.home() / ".cache" / "aegis" / "cursor-home" / ".cursor" / "cli-config.json",
        Path.home() / ".cursor" / "cli-config.json",
    ]
    src = next((p for p in candidates if p.is_file() and os.access(p, os.R_OK)), None)
    if src is None:
        return None
    dest = host_out / ".cursor-cli-config.json"
    try:
        shutil.copy2(src, dest)
        os.chmod(dest, 0o600)
    except OSError:
        return None
    return dest


def start(
    *,
    cfg: Config,
    run_id: str,
    host_out: Path,
    host_brief: Path,
    host_inbox: Path | None = None,
    resolved: ResolvedModel,
    prompt: str,
    command_timeout_ms: int,
    smoke: bool = False,
    auth_xdg: Path | None = None,
    harness: str = "opencode",
    codex_bin: Path | None = None,
    codex_code_mode_host: Path | None = None,
    codex_home: Path | None = None,
    claude_bin: Path | None = None,
    claude_home: Path | None = None,
    cursor_dir: Path | None = None,
    persist: bool = True,
    continue_prompt: str = "",
    backup_harness: str = "",
    backup_resolved: ResolvedModel | None = None,
    rescue_model: str = "",
    rescue_harness: str = "",
    rescue_resolved: ResolvedModel | None = None,
    quiet: bool = False,
    host_tools: Path | None = None,
    timeout_s: float = 0,
) -> Sandbox:
    require_docker()
    require_image(cfg.image)
    name = container_name(run_id)
    if exists(name):
        raise SystemExit(f"el contenedor {name} ya existe; no se reutiliza. aborta o espera.")

    port = pick_port(*cfg.serve_port_range)
    password = secrets.token_urlsafe(24)
    network = cfg.network_mode
    endpoint = resolved.endpoint
    if network == "bridge" and endpoint:
        endpoint = rewrite_loopback_for_bridge(endpoint)

    env = {
        "AEGIS_RUN_ID": run_id,
        "AEGIS_SERVE_PORT": str(port),
        "AEGIS_PROMPT": prompt,
        "AEGIS_MODEL": resolved.opencode_id,
        "OPENCODE_SERVER_PASSWORD": password,
        "OPENCODE_SERVER_USERNAME": "aegis",
        "OPENCODE_EXPERIMENTAL_BASH_DEFAULT_TIMEOUT_MS": str(command_timeout_ms),
        "OPENCODE_DISABLE_AUTOUPDATE": "1",
        "HOME": "/root",
        "XDG_DATA_HOME": "/tmp/opencode-data",
        "XDG_CACHE_HOME": "/tmp/opencode-cache",
        "XDG_STATE_HOME": "/tmp/opencode-state",
        "BASH_ENV": "/etc/aegis/bash_audit.sh",
        "AEGIS_SMOKE": "1" if smoke else "0",
        "AEGIS_HARNESS": harness or "opencode",
        "CODEX_HOME": "/opt/aegis/codex-home",
        "CLAUDE_CONFIG_DIR": "/root/.claude",
        "AEGIS_PERSIST": "1" if persist else "0",
        "AEGIS_CONTINUE_PROMPT": continue_prompt or prompt,
        "AEGIS_QUIET": "1" if quiet else "0",
        "AEGIS_CONSCIENCE": os.environ.get("AEGIS_CONSCIENCE", "1"),
        "AEGIS_TIMEOUT_EPOCH": str(int(time.time() + timeout_s)) if timeout_s > 0 else "",
        # El entrypoint devuelve estos ficheros al uid del host.
        "AEGIS_HOST_UID": str(os.getuid()),
        "AEGIS_HOST_GID": str(os.getgid()),
    }
    if not smoke:
        env.update(rescue_env(harness, resolved, rescue_model, rescue_harness))
    if backup_resolved and backup_harness:
        env["AEGIS_BACKUP_MODEL"] = backup_resolved.opencode_id
        env["AEGIS_BACKUP_HARNESS"] = backup_harness
    extras = [resolved]
    if backup_resolved:
        extras.append(backup_resolved)
    if rescue_resolved:
        extras.append(rescue_resolved)
    for extra in extras:
        if extra.spec.provider == "xai":
            key = extra.env.get("XAI_API_KEY") or next(iter(extra.env.values()), "")
            if key:
                env["XAI_API_KEY"] = key
        if extra.spec.provider == "openai":
            key = extra.env.get("OPENAI_API_KEY") or next(iter(extra.env.values()), "")
            if key:
                env["OPENAI_API_KEY"] = key
        if extra.spec.provider == "anthropic":
            for key in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"):
                val = extra.env.get(key) or os.environ.get(key, "")
                if val:
                    env[key] = val
    if harness == "claude" or backup_harness == "claude" or rescue_harness == "claude":
        env["IS_SANDBOX"] = "1"
        env["CLAUDE_CODE_SANDBOXED"] = "1"
        for key in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"):
            val = os.environ.get(key, "")
            if val and key not in env:
                env[key] = val
    if endpoint:
        env["AEGIS_MODEL_ENDPOINT"] = endpoint

    args = [
        "docker",
        "run",
        "-d",
        # persist = bucle en el contenedor. on-success relanzaba el entrypoint.
        "--restart",
        "on-failure:3",
        "--name",
        name,
        "--hostname",
        name,
        "--network",
        network,
        "--memory",
        cfg.limits.memory,
        "--cpus",
        cfg.limits.cpus,
        "--pids-limit",
        str(cfg.limits.pids),
        "--tmpfs",
        f"/tmp:exec,mode=1777,size={cfg.limits.tmpfs_size}",
        "--tmpfs",
        "/tmp/opencode-cache:mode=0700,size=512m",
        "--tmpfs",
        "/tmp/opencode-state:mode=0700,size=128m",
        "--security-opt",
        "no-new-privileges:true",
        "--cap-drop",
        "ALL",
        # nmap/raw + apt como root
        "--cap-add",
        "NET_RAW",
        "--cap-add",
        "NET_BIND_SERVICE",
        "--cap-add",
        "CHOWN",
        "--cap-add",
        "SETUID",
        "--cap-add",
        "SETGID",
        "--cap-add",
        "DAC_OVERRIDE",
        "--cap-add",
        "FOWNER",
        "--cap-add",
        "MKNOD",
        "--cap-add",
        "AUDIT_WRITE",
        "--cap-add",
        "KILL",
        # sin --privileged, docker.sock, $HOME ni SSH keys.
        # auth.json: copia en /tmp/aegis-auth-<id>, no el del host.
        "-v",
        f"{host_brief.resolve()}:/run/aegis/brief:ro",
        "-v",
        f"{host_out.resolve()}:/run/aegis/out:rw",
        "-w",
        "/workspace",
        "-u",
        "0",
    ]
    host_entrypoint = ROOT / "images" / "runner" / "entrypoint.sh"
    if host_entrypoint.is_file():
        args += ["-v", f"{host_entrypoint.resolve()}:/usr/local/bin/aegis-entrypoint:ro"]
    # overlay del hook de auditoría (sin rebuild)
    host_audit = ROOT / "images" / "runner" / "bash_audit.sh"
    if host_audit.is_file():
        args += ["-v", f"{host_audit.resolve()}:/etc/aegis/bash_audit.sh:ro"]
    if host_tools is not None and host_tools.is_file():
        args += ["-v", f"{host_tools.resolve()}:/opt/aegis/TOOLS.md:ro"]
    if auth_xdg is not None:
        args += ["-v", f"{auth_xdg.resolve()}:/tmp/opencode-data:rw"]
    else:
        args += ["--tmpfs", "/tmp/opencode-data:mode=0700,size=512m"]
    if harness == "codex" or backup_harness == "codex" or rescue_harness == "codex":
        if codex_bin is not None and codex_bin.is_file():
            args += ["-v", f"{codex_bin.resolve()}:/opt/aegis/codex:ro"]
        if codex_code_mode_host is not None and codex_code_mode_host.is_file():
            args += [
                "-v",
                f"{codex_code_mode_host.resolve()}:/opt/aegis/codex-code-mode-host:ro",
            ]
        if codex_home is not None:
            args += ["-v", f"{codex_home.resolve()}:/opt/aegis/codex-home:rw"]
        else:
            args += ["--tmpfs", "/opt/aegis/codex-home:mode=0700,size=128m"]
    if harness == "claude" or backup_harness == "claude" or rescue_harness == "claude":
        if claude_bin is not None and claude_bin.is_file():
            args += ["-v", f"{claude_bin.resolve()}:/opt/aegis/claude:ro"]
        if claude_home is not None:
            cfg_json = claude_home / ".claude.json"
            cfg_dir = claude_home / ".claude"
            if cfg_json.is_file():
                args += ["-v", f"{cfg_json.resolve()}:/root/.claude.json:rw"]
            if cfg_dir.is_dir():
                # HOME=/root y CLAUDE_CONFIG_DIR deben ser el mismo árbol montado.
                # Si solo va a /tmp/claude-home, el refresh se escribe en
                # /root/.claude (overlay) y se pierde; el host se queda el refresh gastado.
                args += ["-v", f"{cfg_dir.resolve()}:/root/.claude:rw"]
                args += ["-v", f"{cfg_dir.resolve()}:/tmp/claude-home/.claude:rw"]
            else:
                args += ["--tmpfs", "/tmp/claude-home:mode=0700,size=256m"]
        else:
            args += ["--tmpfs", "/tmp/claude-home:mode=0700,size=256m"]
    if harness == "cursor" or backup_harness == "cursor" or rescue_harness == "cursor":
        if cursor_dir is not None and cursor_dir.is_dir():
            args += ["-v", f"{cursor_dir.resolve()}:/opt/aegis/cursor-cli:ro"]
        from internal.cursorcli import auth_dir as cursor_auth_dir

        session = cursor_auth_dir()
        if session.is_dir():
            args += ["-v", f"{session.resolve()}:/root/.config/cursor:rw"]
        # ~/.cursor no se monta. La config se copia dentro del contenedor.
        seed = _cursor_cli_config_seed(host_out)
        if seed is not None:
            args += ["-v", f"{seed.resolve()}:/opt/aegis/cursor-cli-config.json:ro"]
    if network == "bridge":
        args += ["--add-host", "host.docker.internal:host-gateway"]
    if host_inbox is not None:
        args += ["-v", f"{host_inbox.resolve()}:{INBOX_MOUNT}:ro"]
    for k, v in env.items():
        args += ["-e", f"{k}={v}"]
    args.append(cfg.image)

    print(f"aegis: docker run {name} ({network}, port {port})", file=sys.stderr)
    try:
        subprocess.run(args, check=True, capture_output=True, text=True)
    except subprocess.CalledProcessError as exc:
        err = (exc.stderr or exc.stdout or "").strip()
        raise SystemExit(f"docker run falló: {err}") from exc

    return Sandbox(
        run_id=run_id,
        name=name,
        port=port,
        password=password,
        network_mode=network,
    )


def exists(name: str) -> bool:
    r = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", name],
        capture_output=True,
        text=True,
    )
    return r.returncode == 0


def running(name: str) -> bool:
    r = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", name],
        capture_output=True,
        text=True,
    )
    return r.returncode == 0 and r.stdout.strip() == "true"


def wait(name: str, timeout_s: float) -> int:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if not exists(name):
            return 0
        if not running(name):
            r = subprocess.run(
                ["docker", "inspect", "-f", "{{.State.ExitCode}}", name],
                capture_output=True,
                text=True,
            )
            try:
                return int(r.stdout.strip() or "0")
            except ValueError:
                return 0
        time.sleep(1)
    return 124


def reclaim_out(name: str, host_out: Path | None = None) -> None:
    """El agente escribe como root en el volumen; el host tiene que poder borrar el run.

    `docker exec` falla si el contenedor ya hizo exit; en ese caso se hace chown
    con un contenedor efímero sobre el mismo volumen o el bind-mount del host.
    """
    uid = os.getuid()
    gid = os.getgid()
    dest_owner = f"{uid}:{gid}"
    r = subprocess.run(
        ["docker", "exec", "-u", "0", name, "chown", "-R", dest_owner, "/run/aegis/out"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    if r.returncode == 0:
        return
    image = ""
    insp = subprocess.run(
        ["docker", "inspect", "-f", "{{.Config.Image}}", name],
        capture_output=True,
        text=True,
    )
    if insp.returncode == 0:
        image = (insp.stdout or "").strip()
    if image:
        helper = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--user",
                "0",
                "--volumes-from",
                name,
                "--entrypoint",
                "chown",
                image,
                "-R",
                dest_owner,
                "/run/aegis/out",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        if helper.returncode == 0:
            return
    if host_out is None or not host_out.is_dir():
        return
    img = image or "aegis-runner:latest"
    subprocess.run(
        [
            "docker",
            "run",
            "--rm",
            "--user",
            "0",
            "-v",
            f"{host_out.resolve()}:/reclaim",
            "--entrypoint",
            "chown",
            img,
            "-R",
            dest_owner,
            "/reclaim",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def destroy(name: str) -> None:
    subprocess.run(
        ["docker", "rm", "-f", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def pause(name: str) -> bool:
    r = subprocess.run(
        ["docker", "pause", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return r.returncode == 0


def unpause(name: str) -> bool:
    r = subprocess.run(
        ["docker", "unpause", name],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return r.returncode == 0


def container_state(name: str) -> dict:
    """Estado runtime del contenedor: {exists, running, paused, status}."""
    r = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}} {{.State.Paused}} {{.State.Status}}", name],
        capture_output=True,
        text=True,
    )
    if r.returncode != 0:
        return {"exists": False, "running": False, "paused": False, "status": "absent"}
    parts = r.stdout.strip().split()
    running_v = parts[0] == "true" if parts else False
    paused_v = parts[1] == "true" if len(parts) > 1 else False
    status_v = parts[2] if len(parts) > 2 else ("running" if running_v else "exited")
    return {"exists": True, "running": running_v, "paused": paused_v, "status": status_v}


def exec_it(name: str, args: list[str]) -> int:
    cmd = ["docker", "exec", "-it", name, *args]
    return subprocess.call(cmd)


def exec_out(name: str, args: list[str], timeout: float = 30) -> str:
    r = subprocess.run(
        ["docker", "exec", name, *args],
        capture_output=True,
        text=True,
        timeout=timeout,
    )
    return r.stdout


def logs_follow(name: str, since: str | None = None):
    cmd = ["docker", "logs", "-f", "--timestamps", name]
    if since:
        cmd[3:3] = ["--since", since]
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )


def export_session(name: str, dest: Path) -> None:
    if not running(name):
        return
    try:
        r = subprocess.run(
            ["docker", "exec", name, "opencode", "export"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if r.returncode == 0 and r.stdout.strip():
            dest.write_text(r.stdout, encoding="utf-8")
            return
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    # último recurso: si el entrypoint ya escribió el export
    if not dest.exists():
        dest.write_text("{}\n", encoding="utf-8")


_ORPHAN_HINTS = ("feroxbuster", "gobuster", "wfuzz", "brutebg", "ffuf", "listener")


def docker_cpu_to_cores(perc: float) -> float:
    """`docker stats` CPU%: 100 = un núcleo del host, no el techo del contenedor."""
    try:
        return max(0.0, float(perc) / 100.0)
    except (TypeError, ValueError):
        return 0.0


def cpu_limit_cores(nano_cpus: int = 0, cpu_quota: int = 0, cpu_period: int = 0) -> float:
    """Techo de CPU del contenedor (`--cpus` o quota/period). 0 = sin límite."""
    try:
        nano = int(nano_cpus or 0)
    except (TypeError, ValueError):
        nano = 0
    if nano > 0:
        return nano / 1_000_000_000
    try:
        quota = int(cpu_quota or 0)
        period = int(cpu_period or 0)
    except (TypeError, ValueError):
        return 0.0
    if quota > 0 and period > 0:
        return quota / period
    return 0.0


def _container_cpu_limit(name: str) -> float:
    try:
        r = subprocess.run(
            [
                "docker",
                "inspect",
                "-f",
                "{{.HostConfig.NanoCpus}} {{.HostConfig.CpuQuota}} {{.HostConfig.CpuPeriod}}",
                name,
            ],
            capture_output=True,
            text=True,
            timeout=3,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return 0.0
    if r.returncode != 0 or not (r.stdout or "").strip():
        return 0.0
    bits = (r.stdout or "").split()
    nano = quota = period = 0
    try:
        if len(bits) > 0:
            nano = int(float(bits[0] or 0))
        if len(bits) > 1:
            quota = int(float(bits[1] or 0))
        if len(bits) > 2:
            period = int(float(bits[2] or 0))
    except ValueError:
        return 0.0
    return cpu_limit_cores(nano, quota, period)


def _docker_bytes(tok: str) -> int:
    raw = (tok or "").strip().replace("iB", "").replace("B", "")
    if not raw:
        return 0
    mult = 1
    if raw[-1:] in "Kk":
        mult = 1024
        raw = raw[:-1]
    elif raw[-1:] in "Mm":
        mult = 1024**2
        raw = raw[:-1]
    elif raw[-1:] in "Gg":
        mult = 1024**3
        raw = raw[:-1]
    try:
        return int(float(raw) * mult)
    except ValueError:
        return 0


def container_resources(name: str) -> dict:
    """RSS/CPU/PIDs y procesos huérfanos (ferox, brute, listeners)."""
    empty: dict = {
        "mem_bytes": 0,
        "mem_limit_bytes": 0,
        "cpu_pct": 0.0,
        "cpu_cores": 0.0,
        "cpu_limit": 0.0,
        "pids": 0,
        "orphans": [],
    }
    if not name or not running(name):
        return empty
    try:
        r = subprocess.run(
            [
                "docker",
                "stats",
                "--no-stream",
                "--format",
                "{{.MemUsage}}\t{{.CPUPerc}}\t{{.PIDs}}",
                name,
            ],
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        return empty
    if r.returncode != 0 or not r.stdout.strip():
        return empty
    parts = r.stdout.strip().split("\t")
    mem_used, mem_lim = 0, 0
    if parts:
        bits = [b.strip() for b in parts[0].split("/") if b.strip()]
        if bits:
            mem_used = _docker_bytes(bits[0])
        if len(bits) > 1:
            mem_lim = _docker_bytes(bits[1])
    docker_pct = 0.0
    if len(parts) > 1:
        try:
            docker_pct = float(parts[1].replace("%", "").strip() or 0)
        except ValueError:
            docker_pct = 0.0
    cores = docker_cpu_to_cores(docker_pct)
    limit = _container_cpu_limit(name)
    # cpu_pct = % del techo (4 CPU → 100%), no % de un núcleo. 0.96 cores / 4 = 24.
    if limit > 0:
        cpu = round(100.0 * cores / limit, 1)
    else:
        cpu = round(docker_pct, 1)
    pids = 0
    if len(parts) > 2:
        try:
            pids = int(float(parts[2].strip() or 0))
        except ValueError:
            pids = 0
    orphans: list[str] = []
    try:
        top = subprocess.run(
            ["docker", "top", name],
            capture_output=True,
            text=True,
            timeout=5,
        )
        if top.returncode == 0:
            for line in top.stdout.splitlines()[1:]:
                low = line.lower()
                if any(h in low for h in _ORPHAN_HINTS):
                    orphans.append(line.strip()[:160])
                    if len(orphans) >= 8:
                        break
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
        pass
    return {
        "mem_bytes": mem_used,
        "mem_limit_bytes": mem_lim,
        "cpu_pct": cpu,
        "cpu_cores": round(cores, 2),
        "cpu_limit": round(limit, 2),
        "pids": pids,
        "orphans": orphans,
    }
