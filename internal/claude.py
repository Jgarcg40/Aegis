from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import time
from dataclasses import dataclass
from pathlib import Path

# IDs que este Claude Code (2.1.x) acepta de verdad. Los alias sonnet/opus
# apuntan a la generación 5; 4.8 es Opus, no hay Sonnet 4.8.
FALLBACK_MODELS = [
    {"id": "claude-opus-4-8", "label": "Opus 4.8"},
    {"id": "claude-opus-4-7", "label": "Opus 4.7"},
    {"id": "claude-opus-5", "label": "Opus 5"},
    {"id": "claude-sonnet-5", "label": "Sonnet 5"},
    {"id": "claude-sonnet-4-6", "label": "Sonnet 4.6"},
    {"id": "claude-fable-5", "label": "Fable 5"},
    {"id": "claude-haiku-4-5", "label": "Haiku 4.5"},
]

_ALIAS_DEFAULTS = {"", "claude", "anthropic", "claude-code"}
_SKIP_DIR_NAMES = {
    "cache",
    "backups",
    "downloads",
    "debug",
    "telemetry",
    "statsig",
    ".oauth_refresh.lock",
}
_SKIP_FILE_NAMES = {".credentials.json.bak"}
# El access de la sub dura ~8 h. El refresh, semanas — pero es de un solo uso.
# Codex/Grok escriben el token nuevo en el bind-mount; Claude Code no, y el
# siguiente run hereda un refresh ya gastado.
_KEEP_OAUTH_GAP_S = 90.0
_last_keep: dict[str, float] = {}


def host_claude_home() -> Path:
    env = os.environ.get("CLAUDE_CONFIG_DIR", "").strip()
    if env:
        return Path(env)
    return Path.home() / ".claude"


def ensure_host_home() -> Path:
    home = host_claude_home()
    try:
        home.mkdir(parents=True, exist_ok=True)
        os.chmod(home, 0o700)
    except OSError:
        pass
    return home


def host_claude_json() -> Path:
    env = os.environ.get("CLAUDE_CONFIG_HOME", "").strip()
    if env:
        return Path(env) / ".claude.json"
    return Path.home() / ".claude.json"


def host_credentials_path() -> Path:
    return host_claude_home() / ".credentials.json"


def rust_bin() -> Path | None:
    env = os.environ.get("CLAUDE_BIN", "").strip()
    if env:
        p = Path(env)
        if p.is_file() and os.access(p, os.X_OK) and _is_elf(p):
            return p
    candidates: list[Path] = []
    found = shutil.which("claude")
    if found:
        candidates.append(Path(found))
    home = Path.home()
    versions = home / ".local" / "share" / "claude" / "versions"
    if versions.is_dir():
        numbered = []
        for child in versions.iterdir():
            if child.is_file() and os.access(child, os.X_OK):
                numbered.append(child)
        numbered.sort(key=lambda p: p.stat().st_mtime, reverse=True)
        candidates.extend(numbered)
    candidates += [
        home / ".local" / "bin" / "claude",
        Path("/usr/local/bin/claude"),
        home / ".npm-global" / "bin" / "claude",
    ]
    for c in candidates:
        resolved = c.resolve() if c.is_symlink() else c
        if resolved.is_file() and os.access(resolved, os.X_OK) and _is_elf(resolved):
            return resolved
    return None


def wrapper_bin() -> Path | None:
    env = os.environ.get("CLAUDE_BIN", "").strip()
    if env:
        p = Path(env)
        if p.is_file() and os.access(p, os.X_OK):
            return p
    found = shutil.which("claude")
    if found:
        return Path(found)
    home = Path.home()
    for cand in (
        home / ".local" / "bin" / "claude",
        Path("/usr/local/bin/claude"),
        home / ".npm-global" / "bin" / "claude",
    ):
        if cand.is_file() and os.access(cand, os.X_OK):
            return cand
    return rust_bin()


def _is_elf(path: Path) -> bool:
    try:
        return path.read_bytes()[:4] == b"\x7fELF"
    except OSError:
        return False


def load_auth(path: Path | None = None) -> dict:
    data: dict = {}
    cfg = path or host_claude_json()
    if cfg.is_file():
        parsed = _read_json(cfg)
        if isinstance(parsed, dict):
            data.update(parsed)
    creds = host_credentials_path()
    if creds.is_file():
        parsed = _read_json(creds)
        if isinstance(parsed, dict):
            data.setdefault("credentials", parsed)
    return data


def _read_json(path: Path) -> object:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def _env_logged_in() -> bool:
    for key in ("ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "CLAUDE_CODE_OAUTH_TOKEN"):
        if os.environ.get(key, "").strip():
            return True
    return False


def _dict_logged_in(data: dict) -> bool:
    if not isinstance(data, dict) or not data:
        return False
    if data.get("loggedIn") is True:
        return True
    for key in ("oauthAccount", "claudeAiOauth", "auth", "credentials"):
        blob = data.get(key)
        if isinstance(blob, dict) and _has_secret(blob):
            return True
    tokens = data.get("tokens") if isinstance(data.get("tokens"), dict) else {}
    if _has_secret(tokens):
        return True
    if data.get("ANTHROPIC_API_KEY") or data.get("apiKey"):
        return True
    return False


def _has_secret(blob: dict) -> bool:
    for key in (
        "accessToken",
        "refreshToken",
        "access_token",
        "refresh_token",
        "claudeAiOauth",
        "oauthToken",
        "apiKey",
        "key",
    ):
        val = blob.get(key)
        if isinstance(val, str) and val.strip():
            return True
        if isinstance(val, dict) and _has_secret(val):
            return True
    return False


def _oauth_blob(data: dict) -> dict:
    """Tokens viven en `.credentials.json` (`claudeAiOauth`), no en `oauthAccount` (perfil)."""
    if not isinstance(data, dict):
        return {}
    creds = data.get("credentials")
    if isinstance(creds, dict):
        inner = creds.get("claudeAiOauth")
        if isinstance(inner, dict) and _has_secret(inner):
            return inner
        if _has_secret(creds):
            return creds
    for key in ("claudeAiOauth", "auth"):
        blob = data.get(key)
        if isinstance(blob, dict):
            inner = blob.get("claudeAiOauth")
            if isinstance(inner, dict) and _has_secret(inner):
                return inner
            if _has_secret(blob):
                return blob
    acc = data.get("oauthAccount")
    if isinstance(acc, dict) and _has_secret(acc):
        return acc
    return {}


def _as_epoch(raw: object) -> float | None:
    if isinstance(raw, (int, float)):
        t = float(raw)
        if t > 1e12:
            t /= 1000.0
        return t
    if isinstance(raw, str) and raw.strip().isdigit():
        return _as_epoch(int(raw.strip()))
    return None


def oauth_expires_at(data: dict | None) -> float | None:
    blob = _oauth_blob(data or {})
    for key in ("expiresAt", "expires_at", "expiry", "expires"):
        t = _as_epoch(blob.get(key))
        if t:
            return t
    return None


def oauth_expired(data: dict | None) -> bool:
    exp = oauth_expires_at(data)
    if exp is None:
        return False
    return time.time() >= exp


def oauth_refresh_alive(data: dict | None) -> bool:
    """El access dura ~8 h; el refresh (si existe y no ha vencido) sigue valiendo."""
    blob = _oauth_blob(data or {})
    if not (blob.get("refreshToken") or blob.get("refresh_token")):
        return False
    for key in ("refreshTokenExpiresAt", "refresh_expires_at", "refreshExpiresAt"):
        t = _as_epoch(blob.get(key))
        if t:
            return time.time() < t
    return True


def _session_ok(data: dict | None) -> bool:
    if not _dict_logged_in(data or {}):
        return False
    if not oauth_expired(data):
        return True
    return oauth_refresh_alive(data)


def _token_pair(blob: dict) -> tuple[str, str]:
    acc = str(blob.get("accessToken") or blob.get("access_token") or "").strip()
    ref = str(blob.get("refreshToken") or blob.get("refresh_token") or "").strip()
    return acc, ref


def oauth_tokens_empty(data: dict | None) -> bool:
    """Claude Code, si el refresh falla, deja el JSON con tokens en blanco (no borra el fichero)."""
    acc, ref = _token_pair(_oauth_blob(data or {}))
    return not acc and not ref


def access_usable(data: dict | None = None) -> bool:
    """Access vigente. El CLI no entra con access muerto aunque el refresh siga en disco."""
    if data is None and _env_logged_in():
        return True
    blob = data if data is not None else load_auth()
    if not _dict_logged_in(blob) or oauth_expired(blob):
        return False
    acc, _ = _token_pair(_oauth_blob(blob))
    return bool(acc)


def _file_oauth_view(path: Path) -> dict:
    parsed = _read_json(path)
    if not isinstance(parsed, dict):
        return {}
    return {"credentials": parsed}


def backup_credentials() -> Path | None:
    src = host_credentials_path()
    if not src.is_file():
        return None
    dest = src.with_name(src.name + ".bak")
    view = _file_oauth_view(src)
    # Un access caducado no pisa un .bak que aún tenga tokens. Un stub vacío sí.
    if oauth_expired(view) and not oauth_tokens_empty(view):
        if dest.is_file() and not oauth_tokens_empty(_file_oauth_view(dest)):
            return dest
    if oauth_tokens_empty(view):
        return dest if dest.is_file() else None
    try:
        shutil.copy2(src, dest)
        os.chmod(dest, 0o600)
        return dest
    except OSError:
        return None


def restore_credentials_if_wiped() -> bool:
    src = host_credentials_path()
    bak = src.with_name(src.name + ".bak")
    if not bak.is_file() or oauth_tokens_empty(_file_oauth_view(bak)):
        return False
    try:
        missing = not src.is_file() or src.stat().st_size < 20
    except OSError:
        missing = True
    emptied = missing or oauth_tokens_empty(_file_oauth_view(src))
    if not emptied:
        return False
    try:
        shutil.copy2(bak, src)
        os.chmod(src, 0o600)
        return True
    except OSError:
        return False


def _cli_probe() -> bool:
    """`auth status` no renueva y declara loggedIn con access muerto.

    Un turno mínimo fuerza el refresh. Si falla, Claude Code deja tokens
    vacíos: restore_credentials_if_wiped recupera el .bak.
    """
    binary = wrapper_bin()
    if binary is None:
        return False
    backup_credentials()
    try:
        subprocess.run(
            [
                str(binary),
                "-p",
                "ok",
                "--model",
                "claude-haiku-4-5",
                "--output-format",
                "json",
                "--max-turns",
                "1",
            ],
            capture_output=True,
            text=True,
            timeout=45,
        )
    except (OSError, subprocess.TimeoutExpired):
        restore_credentials_if_wiped()
        return False
    restore_credentials_if_wiped()
    return access_usable()


def ensure_fresh_access() -> bool:
    """Renueva el access en el host antes de copiarlo al sandbox.

    Claude Code no escribe el token nuevo en `.credentials.json` al refrescar
    dentro del contenedor. El refresh es de un solo uso: el siguiente run
    hereda el viejo, falla y deja el fichero con tokens vacíos.
    """
    if access_usable():
        return True
    data = load_auth()
    if not oauth_refresh_alive(data) and not _dict_logged_in(data):
        return False
    _cli_probe()
    restore_credentials_if_wiped()
    return access_usable()


def logged_in(auth: dict | None = None) -> bool:
    if auth is not None:
        # Blob suelto: access caducado = no usable aquí (el CLI no entra).
        if oauth_expired(auth):
            return False
        return _dict_logged_in(auth)
    if _env_logged_in():
        return True
    data = load_auth()
    if _session_ok(data):
        return True
    # Access corto: el CLI puede renovarlo; si no toca el fichero, el refresh basta.
    cli = _cli_status()
    data = load_auth()
    if _session_ok(data):
        return True
    return bool(cli.get("loggedIn"))


def _cli_logged_in() -> bool:
    binary = wrapper_bin()
    if binary is None:
        return False
    try:
        r = subprocess.run(
            [str(binary), "auth", "status", "--json"],
            capture_output=True,
            text=True,
            timeout=8,
        )
    except (OSError, subprocess.TimeoutExpired):
        return False
    raw = (r.stdout or "").strip()
    if not raw:
        return False
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return False
    return bool(isinstance(data, dict) and data.get("loggedIn"))


def _cli_status(*, timeout: float = 8) -> dict:
    binary = wrapper_bin()
    if binary is None:
        return {}
    backup_credentials()
    try:
        r = subprocess.run(
            [str(binary), "auth", "status", "--json"],
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        restore_credentials_if_wiped()
        return {}
    restore_credentials_if_wiped()
    try:
        data = json.loads((r.stdout or "").strip() or "{}")
    except json.JSONDecodeError:
        return {}
    return data if isinstance(data, dict) else {}


def auth_status() -> dict:
    data = load_auth()
    env_ok = _env_logged_in()
    usable = access_usable(data)
    # El CLI tarda ~1s; si el access ya vale, hay env o el refresh sigue
    # vivo, no lo lanzamos. El access dura ~8 h; al lanzar, ensure_fresh_access
    # lo renueva. Caducado = hay que volver a loguear en el navegador.
    cli = {}
    if not usable and not env_ok and not oauth_refresh_alive(data):
        cli = _cli_status()
        data = load_auth()
        usable = access_usable(data)
    method = str(cli.get("authMethod") or "")
    cli_ok = bool(cli.get("loggedIn")) and access_usable(data)
    logged = bool(usable or env_ok or cli_ok or _session_ok(data))
    expired = bool((oauth_expired(data) or oauth_tokens_empty(data)) and not logged)
    if not method:
        if logged and env_ok and not usable:
            method = "api-key"
        elif logged:
            method = "subscription"
        elif expired:
            method = "expired"
        else:
            method = "none"
    return {
        "logged_in": logged,
        "expired": expired,
        "access_expired": bool(oauth_expired(data) and not env_ok),
        "auth_mode": method,
        "auth_method": method,
        "home": str(host_claude_home()),
        "config": str(host_claude_json()),
        "binary": str(rust_bin() or ""),
        "wrapper": str(wrapper_bin() or ""),
        "cli": {k: cli.get(k) for k in ("loggedIn", "authMethod", "apiProvider") if k in cli},
    }


_MODEL_ID_RX = re.compile(rb"claude-(?:opus|sonnet|haiku|fable)-\d+(?:-\d+)?")
_CANON_ID_RX = re.compile(r"^claude-(opus|sonnet|haiku|fable)-\d+(-\d+)?$")
_cli_models_memo: tuple[str, float, list[str]] | None = None


def _label_from_claude_id(mid: str) -> str:
    parts = mid.split("-")
    if len(parts) < 3:
        return mid
    family = parts[1].title()
    nums = [p for p in parts[2:] if p.isdigit()]
    if not nums:
        return family
    ver = nums[0] if len(nums) == 1 else nums[0] + "." + ".".join(nums[1:])
    return f"{family} {ver}"


def _keep_discovered_id(mid: str) -> bool:
    if not _CANON_ID_RX.match(mid):
        return False
    parts = mid.split("-")
    family = parts[1]
    try:
        major = int(parts[2])
    except (IndexError, ValueError):
        return False
    if family == "fable":
        return True
    return major >= 5


def _ids_from_claude_bin(path: Path) -> list[str]:
    global _cli_models_memo
    try:
        mtime = path.stat().st_mtime
    except OSError:
        return []
    key = str(path)
    if _cli_models_memo and _cli_models_memo[0] == key and _cli_models_memo[1] == mtime:
        return list(_cli_models_memo[2])
    try:
        data = path.read_bytes()
    except OSError:
        return []
    found = sorted({m.decode("ascii") for m in _MODEL_ID_RX.findall(data) if _keep_discovered_id(m.decode("ascii"))})
    _cli_models_memo = (key, mtime, found)
    return list(found)


def list_models(*, refresh: bool = False) -> list[dict]:
    """Lista fija + ids que el Claude Code instalado ya conoce."""
    if refresh:
        global _cli_models_memo
        _cli_models_memo = None
    out = [dict(m) for m in FALLBACK_MODELS]
    seen = {m["id"] for m in out}
    bin_p = rust_bin()
    extra = _ids_from_claude_bin(bin_p) if bin_p else []
    for mid in extra:
        if mid in seen:
            continue
        out.append({"id": mid, "label": _label_from_claude_id(mid)})
        seen.add(mid)
    return out


def normalize_model(value: str) -> str:
    raw = (value or "").strip()
    if "/" in raw:
        raw = raw.split("/", 1)[1]
    if raw.lower() in _ALIAS_DEFAULTS:
        return FALLBACK_MODELS[0]["id"]
    return raw or FALLBACK_MODELS[0]["id"]


@dataclass
class StagedClaude:
    root: Path
    home: Path
    config_json: Path
    config_dir: Path


def stage_claude(run_id: str) -> StagedClaude:
    backup_credentials()
    if not ensure_fresh_access():
        if oauth_expired(load_auth()) or oauth_refresh_alive(load_auth()):
            raise SystemExit(
                "OAuth de Claude caducado y el CLI no pudo renovarlo. "
                "En una terminal: claude auth login "
                "(un refresh fallido puede vaciar .credentials.json; hay copia .bak)"
            )
        raise SystemExit(
            "no hay sesión Claude Code en el host. "
            "En una terminal: claude auth login   (suscripción Claude.ai)"
        )
    root = Path(f"/tmp/aegis-claude-{run_id}")
    if root.exists():
        shutil.rmtree(root)
    home = root / "home"
    home.mkdir(parents=True, mode=0o700)
    config_dir = home / ".claude"
    config_dir.mkdir(parents=True, mode=0o700)

    _copy_host_session(home)
    return StagedClaude(root=root, home=home, config_json=home / ".claude.json", config_dir=config_dir)


def _access_only_blob(raw: dict) -> dict:
    """Copia de credenciales sin refresh: el contenedor no puede gastarlo."""
    out = dict(raw)
    inner = out.get("claudeAiOauth")
    if isinstance(inner, dict):
        inner = dict(inner)
        inner.pop("refreshToken", None)
        inner.pop("refresh_token", None)
        out["claudeAiOauth"] = inner
        return out
    out.pop("refreshToken", None)
    out.pop("refresh_token", None)
    return out


def _pin_access_only(config_dir: Path) -> None:
    dest = config_dir / ".credentials.json"
    raw = _read_json(dest) if dest.is_file() else {}
    if not isinstance(raw, dict) or oauth_tokens_empty(_file_oauth_view(dest) if dest.is_file() else {}):
        host_raw = _read_json(host_credentials_path())
        raw = host_raw if isinstance(host_raw, dict) else {}
    if not isinstance(raw, dict) or not raw:
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(json.dumps(_access_only_blob(raw), indent=2) + "\n", encoding="utf-8")
    os.chmod(dest, 0o600)


def _copy_host_session(home: Path) -> None:
    """Copia la sesión del host al home de stage (login inicial o re-login)."""
    home.mkdir(parents=True, exist_ok=True)
    config_dir = home / ".claude"
    config_dir.mkdir(parents=True, exist_ok=True)
    src_json = host_claude_json()
    dest_json = home / ".claude.json"
    if src_json.is_file():
        shutil.copy2(src_json, dest_json)
        os.chmod(dest_json, 0o600)
    elif not dest_json.is_file():
        dest_json.write_text("{}\n", encoding="utf-8")
        os.chmod(dest_json, 0o600)

    src_home = host_claude_home()
    if src_home.is_dir():
        for child in src_home.iterdir():
            if child.name in _SKIP_DIR_NAMES or child.name in _SKIP_FILE_NAMES:
                continue
            dest = config_dir / child.name
            try:
                if child.is_dir():
                    shutil.copytree(child, dest, dirs_exist_ok=True)
                elif child.is_file():
                    shutil.copy2(child, dest)
                    if child.name.startswith(".") or "cred" in child.name.lower():
                        os.chmod(dest, 0o600)
            except OSError:
                continue
    _pin_access_only(config_dir)


def refresh_staged_claude(run_id: str, *, root: Path | None = None) -> bool:
    """Reinyecta el login del host en un stage vivo. False si no hay sesión o stage."""
    dest_root = root if root is not None else Path(f"/tmp/aegis-claude-{run_id}")
    home = dest_root / "home"
    if not home.is_dir():
        return False
    if not ensure_fresh_access():
        return False
    _copy_host_session(home)
    return True


def write_claude_config(home: Path, model: str) -> None:
    config_dir = home / ".claude"
    config_dir.mkdir(parents=True, exist_ok=True)
    settings = config_dir / "settings.json"
    current: dict = {}
    if settings.is_file():
        parsed = _read_json(settings)
        if isinstance(parsed, dict):
            current = parsed
    current.setdefault("theme", "dark")
    current["skipDangerousModePermissionPrompt"] = True
    current.setdefault("permissions", {})
    allow = current["permissions"].setdefault("allow", [])
    if isinstance(allow, list):
        for rule in (
            "Bash(*)",
            "Read(*)",
            "Edit(*)",
            "Write(*)",
            "Glob(*)",
            "Grep(*)",
            "WebFetch(*)",
            "WebSearch(*)",
        ):
            if rule not in allow:
                allow.append(rule)
    settings.write_text(json.dumps(current, indent=2) + "\n", encoding="utf-8")
    os.chmod(settings, 0o600)

    cfg_path = home / ".claude.json"
    cfg: dict = {}
    if cfg_path.is_file():
        parsed = _read_json(cfg_path)
        if isinstance(parsed, dict):
            cfg = parsed
    projects = cfg.setdefault("projects", {})
    if not isinstance(projects, dict):
        projects = {}
        cfg["projects"] = projects
    for path in ("/workspace", "/root"):
        entry = projects.get(path)
        if not isinstance(entry, dict):
            entry = {}
        entry["hasTrustDialogAccepted"] = True
        entry.setdefault("allowedTools", [])
        if model:
            entry.setdefault("lastModel", model)
        projects[path] = entry
    if model:
        cfg.setdefault("model", model)
    cfg_path.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
    os.chmod(cfg_path, 0o600)


def keep_claude_oauth(run_id: str) -> bool:
    """Durante el run: si el access del stage murió, renueva en el host y reinyecta.

    No llama al CLI si el access del host sigue vivo y el stage lo tiene.
    """
    rid = (run_id or "").strip()
    if not rid:
        return False
    dest_root = Path(f"/tmp/aegis-claude-{rid}")
    home = dest_root / "home"
    if not home.is_dir():
        return False
    staged = home / ".claude" / ".credentials.json"
    host_ok = access_usable()
    staged_bad = True
    if staged.is_file():
        view = _file_oauth_view(staged)
        staged_bad = oauth_tokens_empty(view) or oauth_expired(view)
    if host_ok and not staged_bad:
        return False
    now = time.time()
    if now - _last_keep.get(rid, 0.0) < _KEEP_OAUTH_GAP_S:
        return False
    _last_keep[rid] = now
    if not ensure_fresh_access():
        return False
    return refresh_staged_claude(rid, root=dest_root)


def sync_back(staged: StagedClaude) -> None:
    """El refresh vive solo en el host. El stage no lo lleva (se lo quitamos
    para que Claude Code no lo gaste en el contenedor). No copiar credentials."""
    _sync_file(staged.config_json, host_claude_json())


def _sync_file(src: Path, dest: Path) -> None:
    if not src.is_file():
        return
    try:
        data = json.loads(src.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(data, dict) or not data:
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(dest.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(dest)
    os.chmod(dest, 0o600)


def cleanup_stage(staged: StagedClaude | None) -> None:
    if staged is None:
        return
    try:
        if staged.root.exists() and str(staged.root).startswith("/tmp/aegis-claude-"):
            shutil.rmtree(staged.root)
    except OSError:
        pass
