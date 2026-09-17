from __future__ import annotations

import json
import re
import subprocess
import time
import urllib.request
from pathlib import Path
from typing import Any

from internal.auth import host_auth_path, host_cli_env, load_auth, opencode_bin
from internal.claude import auth_status as claude_auth_status
from internal.claude import list_models as claude_models
from internal.claude import rust_bin as claude_bin
from internal.claude import wrapper_bin as claude_wrapper_bin
from internal.codex import auth_status as codex_auth_status
from internal.codex import list_models as codex_models
from internal.codex import rust_bin as codex_bin
from internal.codex import wrapper_bin as codex_wrapper_bin
from internal.config import Config
from internal.models import _display_endpoint, _normalize_endpoint

_MODEL_LINE = re.compile(r"^([a-z0-9_.-]+)/([A-Za-z0-9_.:-]+)")
_CACHE: dict[str, Any] = {"models": None, "ts": 0.0}
_TTL = 90.0
_CATALOG: dict[str, Any] = {"payload": None, "ts": 0.0}
_CATALOG_TTL = 30.0

PROVIDER_LABELS = {
    "xai": "xAI (Grok)",
    "openai": "OpenAI (ChatGPT / Codex)",
    "anthropic": "Anthropic (Claude)",
    "google": "Google (Gemini)",
    "groq": "Groq",
    "openrouter": "OpenRouter",
    "opencode": "OpenCode Zen",
    "opencode-go": "OpenCode Go",
    "ollama": "Ollama (local)",
    "vllm": "vLLM (local)",
}

# «Añadir cuenta»: no aparecen en la parrilla hasta activarlos.
POPULAR_CONNECT = [
    {"id": "opencode", "label": "OpenCode Zen", "hint": "gateway / modelos free"},
    {"id": "opencode-go", "label": "OpenCode Go", "hint": "suscripción low-cost"},
    {"id": "xai", "label": "xAI / Grok", "hint": "OAuth SuperGrok o API key"},
    {"id": "openai", "label": "OpenAI / ChatGPT", "hint": "OAuth Plus/Pro o API key"},
    {"id": "anthropic", "label": "Anthropic / Claude", "hint": "API key (OpenCode)"},
    {"id": "google", "label": "Google / Gemini", "hint": "OAuth o API key"},
    {"id": "groq", "label": "Groq", "hint": "API key"},
    {"id": "openrouter", "label": "OpenRouter", "hint": "API key"},
]

ACCOUNT_PROVIDERS = {
    "xai", "openai", "anthropic", "google", "groq", "openrouter",
    "mistral", "deepseek", "cohere", "opencode-go",
}
# sin login (gateway / modelos free)
GATEWAY_PROVIDERS = {"opencode"}

LOGIN_METHOD = {
    "xai": "web",
    "openai": "headless",
}


def classify_access(provider: str, auth: dict, has_models: bool) -> str:
    """subscription | api | gateway | logged_out | none."""
    typ = str(auth.get("type") or "")
    if auth.get("logged_in"):
        return "api" if typ == "api" else "subscription"
    if provider in GATEWAY_PROVIDERS:
        return "gateway"
    if provider in ACCOUNT_PROVIDERS:
        return "logged_out"
    if has_models:
        return "gateway"
    return "none"


def _opencode_env() -> dict[str, str]:
    return host_cli_env()


def opencode_models(refresh: bool = False) -> list[dict]:
    now = time.time()
    if not refresh and _CACHE["models"] is not None and now - _CACHE["ts"] < _TTL:
        return _CACHE["models"]
    binary = opencode_bin()
    models: list[dict] = []
    if binary is not None:
        args = [str(binary), "models"]
        if refresh:
            args.append("--refresh")
        try:
            r = subprocess.run(
                args, capture_output=True, text=True, timeout=40, env=_opencode_env()
            )
            for line in (r.stdout or "").splitlines():
                line = line.strip()
                m = _MODEL_LINE.match(line)
                if not m:
                    continue
                provider, model = m.group(1), m.group(2)
                models.append(
                    {"id": f"{provider}/{model}", "provider": provider, "model": model}
                )
        except (subprocess.TimeoutExpired, OSError):
            pass
    _CACHE["models"] = models
    _CACHE["ts"] = now
    return models


def auth_status() -> dict[str, dict]:
    auth = load_auth()
    out: dict[str, dict] = {}
    for provider, entry in auth.items():
        if not isinstance(entry, dict):
            continue
        typ = str(entry.get("type") or "unknown")
        logged = False
        if typ == "oauth":
            logged = bool(entry.get("access") or entry.get("refresh"))
        elif typ == "api":
            logged = bool(entry.get("key"))
        out[provider] = {"provider": provider, "type": typ, "logged_in": logged}
    return out


def _names_from_probe_payload(data: Any) -> list[str]:
    names: list[str] = []
    if not isinstance(data, dict):
        return names
    if isinstance(data.get("data"), list):
        names = [str(m.get("id") or "") for m in data["data"] if isinstance(m, dict)]
    elif isinstance(data.get("models"), list):
        names = [
            str(m.get("name") or m.get("model") or "")
            for m in data["models"]
            if isinstance(m, dict)
        ]
    return [n for n in names if n]


def _probe_openai_compatible(base_url: str, provider: str = "") -> list[str]:
    raw = (base_url or "").rstrip("/")
    prov = provider or "ollama"
    url = _normalize_endpoint(raw, prov).rstrip("/")
    origin = _display_endpoint(raw, prov).rstrip("/")
    if origin and "://" not in origin:
        origin = "http://" + origin
    candidates: list[str] = []
    # Ollama nativo primero: /api/tags. /v1 a secas es 404.
    if prov == "ollama" and origin:
        candidates.append(origin + "/api/tags")
    if raw.endswith("/api/tags") or raw.endswith("/v1/models") or raw.endswith("/models"):
        candidates.append(raw)
    if url:
        candidates.append(url + "/models")
        if url.endswith("/v1"):
            candidates.append(url[: -len("/v1")] + "/api/tags")
        else:
            candidates.append(url + "/api/tags")
    seen: set[str] = set()
    for u in candidates:
        if not u or u in seen:
            continue
        seen.add(u)
        try:
            with urllib.request.urlopen(u, timeout=3) as resp:
                data = json.loads(resp.read().decode("utf-8", "replace"))
        except Exception:
            continue
        names = _names_from_probe_payload(data)
        if names:
            return names
    return []


def _reload_local_specs(cfg: Config) -> None:
    """El yaml puede haber cambiado sin reiniciar aegis-web."""
    try:
        from internal.config import load_config

        fresh = load_config()
    except Exception:
        return
    for alias in ("ollama", "vllm"):
        spec = fresh.models.get(alias)
        if spec is not None:
            cfg.models[alias] = spec


def local_providers(cfg: Config, *, probe: bool = False) -> list[dict]:
    _reload_local_specs(cfg)
    out: list[dict] = []
    for alias in ("ollama", "vllm"):
        spec = cfg.models.get(alias)
        raw = spec.endpoint if spec else ""
        endpoint = _display_endpoint(raw, alias) if raw else ""
        entry = {
            "provider": alias,
            "label": PROVIDER_LABELS.get(alias, alias),
            "endpoint": endpoint or raw,
            "models": [],
            "reachable": False,
        }
        # Con URL se prueba siempre: si solo al refrescar, Guardar deja la lista
        # vacía y parece que no hay modelos. Connection refused cae al instante.
        if endpoint:
            names = _probe_openai_compatible(raw or endpoint, alias)
            entry["models"] = names
            entry["reachable"] = bool(names)
        out.append(entry)
    return out


def activated_path(cfg: Config) -> Path:
    return Path(cfg.data_dir) / "activated_providers.json"


def load_activated(cfg: Config) -> list[str]:
    path = activated_path(cfg)
    if not path.is_file():
        return []
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    if isinstance(data, dict):
        data = data.get("providers")
    if not isinstance(data, list):
        return []
    out: list[str] = []
    for x in data:
        name = str(x or "").strip()
        if name and name not in out:
            out.append(name)
    return out


def save_activated(cfg: Config, names: list[str]) -> None:
    path = activated_path(cfg)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"providers": names}, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")


def note_activated(cfg: Config, provider: str) -> None:
    name = str(provider or "").strip()
    if not name or name in {"ollama", "vllm"}:
        return
    cur = load_activated(cfg)
    if name in cur:
        return
    cur.append(name)
    save_activated(cfg, cur)
    invalidate_catalog()


def invalidate_catalog() -> None:
    _CATALOG["payload"] = None
    _CATALOG["ts"] = 0.0
    _CACHE["models"] = None
    _CACHE["ts"] = 0.0


def provider_is_visible(provider: str, group: dict, activated: set[str]) -> bool:
    access = str(group.get("access") or "")
    if access in {"subscription", "api", "gateway"}:
        return True
    return provider in activated


def _default_opencode_id(cfg: Config) -> str:
    """Id concreto que debe preseleccionar el lanzador (alias yaml → provider/model)."""
    alias = str(getattr(cfg, "default_model", "") or "grok").strip()
    spec = (cfg.models or {}).get(alias)
    if spec is not None:
        return spec.opencode_id
    if "/" in alias:
        return alias
    return ""


def catalog(cfg: Config, refresh: bool = False) -> dict:
    now = time.time()
    cached = _CATALOG.get("payload")
    if not refresh and cached is not None and now - float(_CATALOG.get("ts") or 0) < _CATALOG_TTL:
        return cached
    payload = _build_catalog(cfg, refresh=refresh)
    _CATALOG["payload"] = payload
    _CATALOG["ts"] = now
    return payload


def _build_catalog(cfg: Config, refresh: bool = False) -> dict:
    models = opencode_models(refresh=refresh)
    auth = auth_status()
    groups: dict[str, dict] = {}
    for m in models:
        p = m["provider"]
        g = groups.setdefault(
            p,
            {
                "provider": p,
                "label": PROVIDER_LABELS.get(p, p),
                "models": [],
                "auth": auth.get(p, {"provider": p, "type": "none", "logged_in": False}),
                "login_method": LOGIN_METHOD.get(p, "web"),
            },
        )
        g["models"].append(m["id"])
    for p, st in auth.items():
        if p not in groups:
            groups[p] = {
                "provider": p,
                "label": PROVIDER_LABELS.get(p, p),
                "models": [],
                "auth": st,
                "login_method": LOGIN_METHOD.get(p, "web"),
            }
    activated = load_activated(cfg)
    for p in activated:
        if p in groups or p in {"ollama", "vllm"}:
            continue
        groups[p] = {
            "provider": p,
            "label": PROVIDER_LABELS.get(p, p),
            "models": [],
            "auth": auth.get(p, {"provider": p, "type": "none", "logged_in": False}),
            "login_method": LOGIN_METHOD.get(p, "web"),
        }
    seen = set(activated)
    dirty = False
    for p, g in groups.items():
        g["access"] = classify_access(p, g.get("auth") or {}, bool(g.get("models")))
        logged = bool((g.get("auth") or {}).get("logged_in"))
        g["requires_login"] = p in ACCOUNT_PROVIDERS or logged or p == "opencode-go"
        # opencode models sigue listando openai/* sin sesión; no los enseñamos.
        if g["access"] == "logged_out" and p in ACCOUNT_PROVIDERS:
            g["models"] = []
        if g["access"] in {"subscription", "api", "gateway"} and p not in seen:
            seen.add(p)
            activated.append(p)
            dirty = True
        g["activated"] = p in seen
    if dirty:
        save_activated(cfg, activated)
    visible = [g for p, g in groups.items() if provider_is_visible(p, g, seen)]
    oc_models = [{"id": m["id"], "label": m["id"], "provider": m["provider"]} for m in models]
    cx = codex_auth_status()
    cl = claude_auth_status()
    local = local_providers(cfg, probe=refresh)
    return {
        "providers": sorted(visible, key=lambda g: g["label"].lower()),
        "connect_popular": POPULAR_CONNECT,
        "local": local,
        "auth_file": str(host_auth_path()),
        "opencode": str(opencode_bin() or ""),
        "defaults": {
            "model": cfg.default_model,
            "opencode_id": _default_opencode_id(cfg),
            "harness": "opencode",
            "aliases": {a: s.opencode_id for a, s in cfg.models.items()},
        },
        "harnesses": {
            "opencode": {
                "id": "opencode",
                "label": "OpenCode",
                "available": bool(opencode_bin()),
                "binary": str(opencode_bin() or ""),
                "models": oc_models,
                "local": local,
            },
            "codex": {
                "id": "codex",
                "label": "Codex CLI (ChatGPT)",
                "available": bool(codex_wrapper_bin() or codex_bin()),
                "binary": str(codex_bin() or codex_wrapper_bin() or ""),
                "logged_in": bool(cx.get("logged_in")),
                "auth_mode": cx.get("auth_mode") or "",
                "models": codex_models(refresh=refresh),
            },
            "claude": {
                "id": "claude",
                "label": "Claude Code (Anthropic)",
                "available": bool(claude_wrapper_bin() or claude_bin()),
                "binary": str(claude_bin() or claude_wrapper_bin() or ""),
                "logged_in": bool(cl.get("logged_in")),
                "expired": bool(cl.get("expired")),
                "auth_mode": cl.get("auth_mode") or "",
                "models": claude_models(refresh=refresh),
            },
        },
    }
