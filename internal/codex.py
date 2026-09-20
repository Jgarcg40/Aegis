from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path

FALLBACK_MODELS = [
    {"id": "gpt-5.6-sol", "label": "GPT-5.6 Sol (frontera)"},
    {"id": "gpt-5.6-terra", "label": "GPT-5.6 Terra"},
    {"id": "gpt-5.6-luna", "label": "GPT-5.6 Luna"},
    {"id": "gpt-5.5", "label": "GPT-5.5"},
    {"id": "gpt-5.4", "label": "GPT-5.4"},
    {"id": "gpt-5.4-mini", "label": "GPT-5.4 mini"},
]


def host_codex_home() -> Path:
    env = os.environ.get("CODEX_HOME", "").strip()
    if env:
        p = Path(env).expanduser()
        try:
            if p.is_dir() and os.access(p, os.W_OK):
                return p
        except OSError:
            pass
    return Path.home() / ".codex"


def ensure_host_home(root: Path | None = None) -> Path:
    home = Path(root) if root is not None else host_codex_home()
    try:
        home.mkdir(parents=True, exist_ok=True)
        os.chmod(home, 0o700)
        cfg = home / "config.toml"
        if not cfg.is_file():
            cfg.write_text("", encoding="utf-8")
            os.chmod(cfg, 0o600)
    except OSError:
        pass
    return home


def host_auth_path() -> Path:
    return host_codex_home() / "auth.json"


def rust_bin() -> Path | None:
    env = os.environ.get("CODEX_BIN", "").strip()
    if env:
        p = Path(env)
        if p.is_file() and os.access(p, os.X_OK):
            return p
    found = shutil.which("codex")
    # el wrapper npm es JS; preferimos el binario musl estático para el contenedor
    candidates = []
    if found:
        candidates.append(Path(found))
    home = Path.home()
    candidates += [
        home / ".npm-global" / "lib" / "node_modules" / "@openai" / "codex"
        / "node_modules" / "@openai" / "codex-linux-x64" / "vendor"
        / "x86_64-unknown-linux-musl" / "bin" / "codex",
        home / ".local" / "bin" / "codex",
        Path("/usr/local/bin/codex"),
    ]
    for c in candidates:
        if not c.is_file() or not os.access(c, os.X_OK):
            continue
        try:
            head = c.read_bytes()[:4]
        except OSError:
            continue
        if head == b"\x7fELF":
            return c
    return None


def wrapper_bin() -> Path | None:
    env = os.environ.get("CODEX_BIN", "").strip()
    if env:
        p = Path(env)
        if p.is_file() and os.access(p, os.X_OK):
            return p
    found = shutil.which("codex")
    if found:
        return Path(found)
    home = Path.home()
    for cand in (home / ".local" / "bin" / "codex", Path("/usr/local/bin/codex")):
        if cand.is_file() and os.access(cand, os.X_OK):
            return cand
    return rust_bin()


def login_argv(binary: Path | None = None) -> list[str]:
    exe = str(binary or wrapper_bin() or rust_bin() or "codex")
    work = str(Path.home())
    help_txt = ""
    try:
        r = subprocess.run(
            [exe, "login", "--help"],
            capture_output=True,
            text=True,
            timeout=8,
            cwd=work,
        )
        help_txt = (r.stdout or "") + (r.stderr or "")
    except (OSError, subprocess.TimeoutExpired):
        pass
    if "device-auth" in help_txt:
        return [exe, "-C", work, "login", "--device-auth"]
    return [exe, "-C", work, "login"]


def code_mode_host_bin() -> Path | None:
    """Binario acompañante `codex-code-mode-host` (junto al binario musl).

    El CLI de Codex lo lanza para ejecutar comandos (feature `code_mode_host`,
    estable). Vive en el mismo directorio que el binario nativo; si no se monta
    en el sandbox, todo `exec` falla con "code-mode host was not found".
    """
    env = os.environ.get("CODEX_CODE_MODE_HOST_BIN", "").strip()
    if env:
        p = Path(env)
        if p.is_file() and os.access(p, os.X_OK):
            return p
    cands: list[Path] = []
    base = rust_bin()
    if base is not None:
        cands.append(base.parent / "codex-code-mode-host")
        try:
            cands.append(base.resolve().parent / "codex-code-mode-host")
        except OSError:
            pass
    else:
        home = Path.home()
        cands += [
            home / ".local" / "bin" / "codex-code-mode-host",
            home / ".codex" / "packages" / "standalone" / "current" / "bin" / "codex-code-mode-host",
        ]
    seen: set[Path] = set()
    for cand in cands:
        try:
            key = cand.resolve() if cand.exists() else cand
        except OSError:
            key = cand
        if key in seen:
            continue
        seen.add(key)
        if cand.is_file() and os.access(cand, os.X_OK):
            return cand
    return None


def load_auth(path: Path | None = None) -> dict:
    p = path or host_auth_path()
    if not p.is_file():
        return {}
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def logged_in(auth: dict | None = None) -> bool:
    data = auth if auth is not None else load_auth()
    tokens = data.get("tokens") if isinstance(data.get("tokens"), dict) else {}
    if tokens.get("access_token") or tokens.get("refresh_token"):
        return True
    return bool(data.get("OPENAI_API_KEY"))


def is_chatgpt_oauth(auth: dict | None = None) -> bool:
    """True si la sesión es una suscripción ChatGPT (OAuth), sin API key.

    Con cuenta ChatGPT los modelos "*-codex" (gpt-5.1-codex) no están
    permitidos; solo con API key de pago (OPENAI_API_KEY).
    """
    data = auth if auth is not None else load_auth()
    tokens = data.get("tokens") if isinstance(data.get("tokens"), dict) else {}
    has_oauth = bool(tokens.get("access_token") or tokens.get("refresh_token"))
    has_key = bool(
        data.get("OPENAI_API_KEY")
        or os.environ.get("OPENAI_API_KEY")
        or os.environ.get("AEGIS_OPENAI_API_KEY")
    )
    return has_oauth and not has_key


def is_codex_only_model(model: str) -> bool:
    slug = (model or "").rsplit("/", 1)[-1].lower().replace("_", "-")
    return "-codex" in slug


def auth_status() -> dict:
    data = load_auth()
    tokens = data.get("tokens") if isinstance(data.get("tokens"), dict) else {}
    return {
        "logged_in": logged_in(data),
        "auth_mode": str(data.get("auth_mode") or ""),
        "has_access": bool(tokens.get("access_token")),
        "has_refresh": bool(tokens.get("refresh_token")),
        "home": str(host_codex_home()),
        "binary": str(rust_bin() or ""),
        "wrapper": str(wrapper_bin() or ""),
    }


def _cache_path() -> Path:
    return host_codex_home() / "models_cache.json"


def _format_codex_models(items: list) -> list[dict]:
    out: list[dict] = []
    seen: set[str] = set()
    for m in items:
        if not isinstance(m, dict):
            continue
        vis = str(m.get("visibility") or "list").lower()
        if vis in {"hide", "hidden"}:
            continue
        slug = str(m.get("slug") or m.get("id") or "").strip()
        if not slug or slug in seen:
            continue
        seen.add(slug)
        out.append(
            {
                "id": slug,
                "label": str(m.get("display_name") or slug),
                "description": str(m.get("description") or ""),
            }
        )
    return out


def _read_models_cache(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    items = raw.get("models") if isinstance(raw, dict) else None
    return _format_codex_models(items) if isinstance(items, list) else []


def _fetch_cli_models() -> list | None:
    """Catálogo vivo del CLI (`codex debug models`). None si no se pudo."""
    bin_p = wrapper_bin() or rust_bin()
    if bin_p is None:
        return None
    try:
        r = subprocess.run(
            [str(bin_p), "debug", "models"],
            capture_output=True,
            text=True,
            timeout=20,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    blob = (r.stdout or "").strip()
    if r.returncode != 0 or not blob:
        return None
    try:
        data = json.loads(blob)
    except json.JSONDecodeError:
        return None
    items = data.get("models") if isinstance(data, dict) else data
    if not isinstance(items, list) or not items:
        return None
    return items


def _write_models_cache(path: Path, items: list) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "fetched_at": datetime.now(timezone.utc).isoformat(),
        "models": items,
    }
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_text(json.dumps(payload) + "\n", encoding="utf-8")
    tmp.replace(path)


_LIVE: dict = {"ts": 0.0, "models": None}
_LIVE_TTL = 60.0


def list_models(*, refresh: bool = False) -> list[dict]:
    """Catálogo del CLI. Lanzar no depende de pulsar Refrescar en Modelos."""
    now = time.time()
    hit = _LIVE.get("models")
    if not refresh and hit and now - float(_LIVE.get("ts") or 0) < _LIVE_TTL:
        return [dict(m) for m in hit]
    cache = _cache_path()
    live = _fetch_cli_models()
    if live:
        try:
            _write_models_cache(cache, live)
        except OSError:
            pass
        out = _format_codex_models(live)
        if out:
            _LIVE["models"] = out
            _LIVE["ts"] = now
            return out
    cached = _read_models_cache(cache)
    if cached:
        _LIVE["models"] = cached
        _LIVE["ts"] = now
        return cached
    return [dict(m) for m in FALLBACK_MODELS]


def normalize_model(value: str) -> str:
    raw = (value or "").strip()
    if not raw:
        return FALLBACK_MODELS[0]["id"]
    if "/" in raw:
        raw = raw.split("/", 1)[1]
    return raw


@dataclass
class StagedCodex:
    root: Path
    home: Path
    auth_file: Path


def _stage_root(run_id: str) -> Path:
    # Codex se niega a crear helpers si CODEX_HOME vive bajo /tmp.
    safe = "".join(c if c.isalnum() or c in "._-" else "-" for c in (run_id or "run"))[:64] or "run"
    return Path.home() / ".cache" / "aegis" / "codex-stage" / safe


def _is_stage_root(path: Path) -> bool:
    raw = str(path)
    if raw.startswith("/tmp/aegis-codex-"):
        return True
    try:
        parent = path.resolve().parent
        return parent == (Path.home() / ".cache" / "aegis" / "codex-stage").resolve()
    except OSError:
        return False


def stage_codex(run_id: str) -> StagedCodex:
    src = host_auth_path()
    if not src.is_file() or not logged_in():
        raise SystemExit(
            "no hay sesión Codex CLI en el host (~/.codex/auth.json). "
            "En una terminal: codex login   (Sign in with ChatGPT)"
        )
    root = _stage_root(run_id)
    if root.exists():
        shutil.rmtree(root)
    home = root / "home"
    home.mkdir(parents=True, mode=0o700)
    dest = home / "auth.json"
    shutil.copy2(src, dest)
    os.chmod(dest, 0o600)
    cache = host_codex_home() / "models_cache.json"
    if cache.is_file():
        shutil.copy2(cache, home / "models_cache.json")
    return StagedCodex(root=root, home=home, auth_file=dest)


def write_codex_config(home: Path, model: str) -> None:
    (home / "config.toml").write_text(
        (
            f'model = "{model}"\n'
            'approval_policy = "never"\n'
            'sandbox_mode = "danger-full-access"\n'
        ),
        encoding="utf-8",
    )


def sync_back(staged: StagedCodex) -> None:
    dest = host_auth_path()
    if not staged.auth_file.is_file():
        return
    try:
        data = json.loads(staged.auth_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return
    if not isinstance(data, dict) or not data:
        return
    dest.parent.mkdir(parents=True, exist_ok=True)
    tmp = dest.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(dest)
    os.chmod(dest, 0o600)


def cleanup_stage(staged: StagedCodex | None) -> None:
    if staged is None:
        return
    try:
        if staged.root.exists() and _is_stage_root(staged.root):
            shutil.rmtree(staged.root)
    except OSError:
        pass
