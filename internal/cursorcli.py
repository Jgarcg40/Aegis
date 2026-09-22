"""Cursor Agent CLI en el host. El contenedor lo monta solo si el run lo usa."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path


def auth_dir() -> Path:
    """Sesión de `agent login` en Linux: ~/.config/cursor/auth.json."""
    base = os.environ.get("XDG_CONFIG_HOME", "").strip()
    root = Path(base).expanduser() if base else Path.home() / ".config"
    return root / "cursor"


def auth_path() -> Path:
    return auth_dir() / "auth.json"


def _cache_path() -> Path:
    return Path.home() / ".aegis" / "cursor-models.json"


def install_dir() -> Path | None:
    """Directorio del paquete (cursor-agent + node + index.js)."""
    exe = wrapper_bin()
    if exe is None:
        return None
    try:
        resolved = exe.resolve()
    except OSError:
        resolved = exe
    parent = resolved.parent
    if (parent / "index.js").is_file() and (parent / "node").is_file():
        return parent
    return None


def wrapper_bin() -> Path | None:
    env = os.environ.get("CURSOR_AGENT_BIN", "").strip()
    if env:
        p = Path(env)
        if p.is_file() and os.access(p, os.X_OK):
            return p
    found = shutil.which("agent")
    if found:
        return Path(found)
    home = Path.home()
    for cand in (
        home / ".local" / "bin" / "agent",
        home / ".local" / "bin" / "cursor-agent",
        Path("/usr/local/bin/agent"),
    ):
        if cand.is_file() and os.access(cand, os.X_OK):
            return cand
    return None


def _load_auth() -> dict:
    p = auth_path()
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def _session_logged_in() -> bool:
    data = _load_auth()
    return bool(data.get("accessToken") or data.get("refreshToken"))


def state_home() -> Path:
    """HOME de los `agent` que lanza Aegis. Los chats no van a ~/.cursor."""
    dest = Path.home() / ".cache" / "aegis" / "cursor-home"
    try:
        (dest / ".cursor").mkdir(parents=True, exist_ok=True)
        os.chmod(dest, 0o700)
    except OSError:
        return dest
    _reclaim_host_cursor_dir()
    return dest


_reclaim_done = False


def _reclaim_host_cursor_dir() -> None:
    """Devuelve ~/.cursor al usuario si un contenedor lo dejó de root."""
    global _reclaim_done
    if _reclaim_done:
        return
    _reclaim_done = True
    root = Path.home() / ".cursor"
    chats = root / "chats"
    if not chats.is_dir() or os.access(chats, os.W_OK):
        return
    if shutil.which("docker") is None:
        return
    try:
        from internal.config import Config

        image = Config().image
    except Exception:
        image = "aegis-runner:latest"
    try:
        subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "--network",
                "none",
                "--entrypoint",
                "chown",
                "-v",
                f"{root.resolve()}:/host-cursor",
                image,
                "-R",
                f"{os.getuid()}:{os.getgid()}",
                "/host-cursor",
            ],
            capture_output=True,
            text=True,
            timeout=90,
        )
    except (OSError, subprocess.TimeoutExpired):
        return


def agent_env() -> dict[str, str]:
    """Entorno de `agent` en el host: auth real, chats en un HOME propio."""
    env = os.environ.copy()
    env.pop("CURSOR_API_KEY", None)
    env.pop("AEGIS_CURSOR_API_KEY", None)
    env.pop("CURSOR_AUTH_TOKEN", None)
    env["HOME"] = str(state_home())
    # La sesión sigue en ~/.config/cursor.
    if not os.environ.get("XDG_CONFIG_HOME", "").strip():
        env["XDG_CONFIG_HOME"] = str(Path.home() / ".config")
    return env


def _run(args: list[str], timeout: int = 20) -> subprocess.CompletedProcess[str]:
    exe = wrapper_bin()
    if exe is None:
        raise OSError("agent ausente")
    return subprocess.run(
        [str(exe), *args],
        capture_output=True,
        text=True,
        timeout=timeout,
        env=agent_env(),
        cwd=str(Path.home()),
    )


def _status_logged_in() -> bool:
    try:
        r = _run(["status", "--format", "json"], timeout=12)
    except (OSError, subprocess.TimeoutExpired):
        return False
    blob = (r.stdout or "") + "\n" + (r.stderr or "")
    if r.returncode != 0 and "Authentication required" in blob:
        return False
    try:
        data = json.loads(r.stdout or "{}")
    except json.JSONDecodeError:
        data = {}
    if isinstance(data, dict):
        if data.get("loggedIn") or data.get("logged_in") or data.get("authenticated"):
            return True
        user = data.get("user") or data.get("email") or data.get("account")
        if user:
            return True
    low = blob.lower()
    if "not logged" in low or "authentication required" in low:
        return False
    return r.returncode == 0 and "logged" in low


def logged_in() -> bool:
    if _session_logged_in():
        return True
    return _status_logged_in()


def auth_status() -> dict:
    binary = wrapper_bin()
    ok = logged_in()
    return {
        "logged_in": ok,
        "auth_mode": "subscription" if ok else "",
        "binary": str(binary or ""),
        "install_dir": str(install_dir() or ""),
        "auth_file": str(auth_path()),
    }


def _parse_models(text: str) -> list[dict]:
    raw = (text or "").strip()
    if not raw:
        return []
    if raw[0] in "[{":
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            data = None
        else:
            rows = data.get("models") if isinstance(data, dict) else data
            out: list[dict] = []
            if isinstance(rows, list):
                for item in rows:
                    if isinstance(item, str) and item.strip():
                        out.append({"id": item.strip(), "label": item.strip()})
                    elif isinstance(item, dict):
                        mid = str(item.get("id") or item.get("name") or "").strip()
                        if not mid:
                            continue
                        label = str(item.get("label") or item.get("displayName") or item.get("display_name") or mid)
                        out.append({"id": mid, "label": label})
            if out:
                return out
    out = []
    seen: set[str] = set()
    for line in raw.splitlines():
        s = line.strip()
        if not s or s.startswith("#") or s.lower().startswith("available"):
            continue
        if s.lower().startswith("error"):
            continue
        chunk = s
        for sep in ("\t", " - ", " — ", " | "):
            if sep in chunk:
                chunk = chunk.split(sep, 1)[0].strip()
                label = s.split(sep, 1)[1].strip() or chunk
                break
        else:
            label = chunk
        if " " in chunk:
            continue
        if len(chunk) < 2 or chunk in seen:
            continue
        seen.add(chunk)
        out.append({"id": chunk, "label": label})
    return out


def list_models(*, refresh: bool = False) -> list[dict]:
    if not logged_in():
        return []
    cache = _cache_path()
    if not refresh and cache.is_file():
        try:
            age = cache.stat().st_mtime
            import time

            if time.time() - age < 600:
                data = json.loads(cache.read_text(encoding="utf-8"))
                if isinstance(data, list) and data:
                    return data
        except (OSError, json.JSONDecodeError):
            pass
    try:
        r = _run(["--list-models"], timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return []
    models = _parse_models(r.stdout or "")
    if not models:
        models = _parse_models(r.stderr or "")
    if models:
        try:
            cache.parent.mkdir(parents=True, exist_ok=True)
            cache.write_text(json.dumps(models), encoding="utf-8")
            os.chmod(cache, 0o600)
        except OSError:
            pass
    return models


def login_argv() -> list[str]:
    exe = str(wrapper_bin() or "agent")
    return [exe, "login"]
