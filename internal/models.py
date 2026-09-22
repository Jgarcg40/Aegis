from __future__ import annotations

import json
import os
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlparse, urlunparse

from internal.auth import has_provider, host_auth_path, load_auth
from internal.config import Config, ModelSpec


@dataclass
class ResolvedModel:
    spec: ModelSpec
    opencode_id: str
    endpoint: str
    env: dict[str, str]
    missing_keys: list[str]
    auth_provider: str = ""
    auth_via: str = ""  # oauth | api-key | local | missing


def resolve_model(
    cfg: Config,
    alias: str,
    *,
    model_id: str = "",
    endpoint: str = "",
) -> ResolvedModel:
    spec = cfg.model(alias)
    provider = spec.provider
    model = model_id or spec.model
    if not model:
        raise SystemExit(
            f"el alias {alias} no tiene model id; pasa --model-id o configúralo en aegis.yaml"
        )
    ep = _normalize_endpoint(endpoint or spec.endpoint, provider)
    env: dict[str, str] = {}
    missing: list[str] = []
    auth_via = "missing"
    auth = load_auth()

    if provider in {"ollama", "vllm"}:
        if not ep:
            raise SystemExit(
                f"{alias} requiere --endpoint (ej. 192.168.1.10:11434) o endpoint en aegis.yaml"
            )
        auth_via = "local"
    elif has_provider(auth, provider):
        auth_via = "oauth" if (auth.get(provider) or {}).get("type") == "oauth" else "api-key"
    else:
        for key in spec.env_keys:
            val = os.environ.get(key, "")
            if val:
                canon = "XAI_API_KEY" if provider == "xai" else "OPENAI_API_KEY"
                env[canon] = val
                env[key] = val
                auth_via = "api-key"
                break
        if auth_via == "missing" and spec.env_keys:
            missing = list(spec.env_keys)

    return ResolvedModel(
        spec=ModelSpec(
            alias=spec.alias,
            provider=provider,
            model=model,
            endpoint=ep,
            env_keys=spec.env_keys,
        ),
        opencode_id=f"{provider}/{model}",
        endpoint=ep,
        env=env,
        missing_keys=missing,
        auth_provider=provider,
        auth_via=auth_via,
    )


GROK_WARMUP_ID = "xai/grok-4.3"
GROK_WARMUP_S = 120
# 4.3 acepta none|low|medium|high. Off: en 120 s deja estado y 4.6 no ve el brief crudo.
GROK_WARMUP_REASONING = "none"
HARNESS_IDS = frozenset({"opencode", "codex", "claude", "cursor"})
CLAUDE_RESCUE_DEFAULT = "claude-sonnet-4-6"
CODEX_RESCUE_DEFAULT = "gpt-5.4"
CODEX_RESCUE_SOFT = "gpt-5.4-mini"


def _model_slug(model_id: str) -> str:
    return (model_id or "").rsplit("/", 1)[-1].lower().replace("_", "-")


def same_model(a: str, b: str) -> bool:
    if not (a or "").strip() or not (b or "").strip():
        return False
    if a.strip() == b.strip():
        return True
    return _model_slug(a) == _model_slug(b)


def _is_xai_grok_id(model_id: str) -> bool:
    raw = (model_id or "").strip().lower()
    if raw.startswith("xai/"):
        return True
    if "/" in raw:
        return False
    return raw.startswith("grok")


def grok_opencode_warmup(
    harness: str,
    resolved: ResolvedModel,
    warmup_id: str = "",
) -> str:
    """OpenCode + sub xAI: 4.3 durante 60 s al arranque o al relevo. Vacío si no aplica."""
    if (harness or "").strip().lower() != "opencode":
        return ""
    if resolved.spec.provider != "xai":
        return ""
    chosen = (warmup_id or "").strip() or GROK_WARMUP_ID
    if not _is_xai_grok_id(chosen):
        return ""
    warm = _normalize_rescue_id(harness, chosen)
    if not warm or same_model(warm, resolved.opencode_id):
        return ""
    return warm


def _openai_family_rescue(model_id: str) -> str:
    """Hermano menos frontera (estilo Sonnet). Mini si el principal ya es 5.4."""
    slug = _model_slug(model_id)
    if not slug:
        return ""
    if slug in {CODEX_RESCUE_SOFT, "gpt-5.4-nano"}:
        return ""
    if slug.startswith("gpt-5.4"):
        return CODEX_RESCUE_SOFT
    return CODEX_RESCUE_DEFAULT


def default_rescue_model(harness: str, resolved: ResolvedModel) -> str:
    """Relevo de salvaguarda si el operador no elige. Vacío = este harness no de-escala."""
    h = (harness or "").strip().lower()
    if h == "claude":
        if same_model(resolved.opencode_id, CLAUDE_RESCUE_DEFAULT):
            return ""
        return CLAUDE_RESCUE_DEFAULT
    if h == "codex":
        return _openai_family_rescue(resolved.opencode_id)
    if h == "cursor":
        return ""
    if h == "opencode":
        provider = (resolved.spec.provider or "").strip().lower()
        if provider == "xai":
            if same_model(resolved.opencode_id, GROK_WARMUP_ID):
                return ""
            return GROK_WARMUP_ID
        if provider == "openai":
            soft = _openai_family_rescue(resolved.opencode_id)
            return f"openai/{soft}" if soft else ""
        if provider == "anthropic":
            if same_model(resolved.opencode_id, CLAUDE_RESCUE_DEFAULT):
                return ""
            return f"anthropic/{CLAUDE_RESCUE_DEFAULT}"
        return ""
    return ""


def _normalize_rescue_id(harness: str, raw: str) -> str:
    """Claude/Codex: slug. OpenCode: provider/slug."""
    h = (harness or "").strip().lower()
    raw = (raw or "").strip()
    if not raw:
        return ""
    if h == "codex":
        return raw.rsplit("/", 1)[-1]
    if h == "cursor":
        return raw.rsplit("/", 1)[-1]
    if h == "claude":
        return raw.rsplit("/", 1)[-1]
    if h == "opencode" and "/" not in raw:
        low = raw.lower()
        if low.startswith("grok"):
            return f"xai/{raw}"
        if low.startswith("claude"):
            return f"anthropic/{raw}"
        if low.startswith("gpt") or "codex" in low:
            return f"openai/{raw}"
    return raw


def split_rescue_ref(raw: str) -> tuple[str, str]:
    """'claude::sonnet' o 'xai/grok-4.3' → (harness, modelo). harness vacío = inferir."""
    s = (raw or "").strip()
    if "::" in s:
        h, m = s.split("::", 1)
        h = h.strip().lower()
        m = m.strip()
        if h in HARNESS_IDS and m:
            return h, m
    return "", s


def infer_rescue_harness(primary: str, model: str, explicit: str = "") -> str:
    h = (explicit or "").strip().lower()
    if h in HARNESS_IDS:
        return h
    m = (model or "").strip()
    if not m:
        return ""
    if "/" in m:
        return "opencode"
    return (primary or "opencode").strip().lower()


def resolve_rescue(
    harness: str,
    resolved: ResolvedModel,
    rescue_model: str = "",
    rescue_harness: str = "",
) -> tuple[str, str]:
    """→ (harness, modelo) del relevo. Vacío = sin relevo."""
    raw = (rescue_model or "").strip()
    rh_from_ref, rm = split_rescue_ref(raw)
    if rh_from_ref:
        raw = rm
    explicit_h = (rescue_harness or rh_from_ref or "").strip().lower()
    if explicit_h not in HARNESS_IDS:
        explicit_h = ""
    if raw.lower() in {"", "auto", "default"}:
        raw = default_rescue_model(harness, resolved)
        if not explicit_h and raw:
            explicit_h = (harness or "").strip().lower()
    dest_h = infer_rescue_harness(harness, raw, explicit_h)
    raw = _normalize_rescue_id(dest_h or harness, raw)
    if not raw:
        return "", ""
    primary_h = (harness or "opencode").strip().lower()
    if _same_rescue_identity(dest_h, raw, primary_h, resolved.opencode_id):
        return "", ""
    return dest_h, raw


def _same_rescue_identity(dest_h: str, dest_id: str, primary_h: str, primary_id: str) -> bool:
    """Mismo relevo que el principal. xai/grok-4.6 ≠ opencode-go/grok-4.6."""
    if (dest_h or "").strip().lower() != (primary_h or "").strip().lower():
        return False
    a, b = (dest_id or "").strip(), (primary_id or "").strip()
    if not a or not b:
        return False
    if a == b:
        return True
    if "/" in a and "/" in b:
        pa, sa = a.split("/", 1)
        pb, sb = b.split("/", 1)
        if pa.lower() != pb.lower():
            return False
        return _model_slug(sa) == _model_slug(sb)
    return _model_slug(a) == _model_slug(b)


def pick_rescue_model(
    harness: str,
    resolved: ResolvedModel,
    rescue_model: str = "",
    rescue_harness: str = "",
) -> str:
    """Vacío/auto = default del harness. Mismo id que el principal = sin relevo."""
    _, model = resolve_rescue(harness, resolved, rescue_model, rescue_harness)
    return model


def grok_warmup_env(
    harness: str,
    resolved: ResolvedModel,
    *,
    seconds: int = GROK_WARMUP_S,
    warmup_id: str = "",
) -> dict[str, str]:
    """Arranque 120s en el modelo de salvaguarda. No es el backup."""
    warm = grok_opencode_warmup(harness, resolved, warmup_id)
    if not warm or same_model(warm, resolved.opencode_id):
        return {}
    return {
        "AEGIS_MODEL": warm,
        "AEGIS_PRIMARY_MODEL": resolved.opencode_id,
        "AEGIS_WARMUP_MODEL": warm,
        "AEGIS_WARMUP_S": str(int(seconds) if seconds > 0 else GROK_WARMUP_S),
    }


def rescue_env(
    harness: str,
    resolved: ResolvedModel,
    rescue_model: str = "",
    rescue_harness: str = "",
) -> dict[str, str]:
    """Relevo (cualquier harness hasta ficha; Grok xAI→xAI 120s) + warmup."""
    dest_h, chosen = resolve_rescue(harness, resolved, rescue_model, rescue_harness)
    env: dict[str, str] = {}
    if dest_h == "opencode":
        warm = grok_warmup_env(harness, resolved, warmup_id=chosen)
        if warm:
            env.update(warm)
    if not dest_h or not chosen:
        return env
    env["AEGIS_RESCUE_MODEL"] = chosen
    env["AEGIS_RESCUE_HARNESS"] = dest_h
    env["AEGIS_PRIMARY_MODEL"] = resolved.opencode_id
    env["AEGIS_PRIMARY_HARNESS"] = (harness or "opencode").strip().lower()
    if dest_h == "claude":
        env["AEGIS_CLAUDE_RESCUE_MODEL"] = chosen
    return env


def require_credentials(resolved: ResolvedModel) -> None:
    if resolved.spec.provider in {"ollama", "vllm"}:
        return
    if resolved.auth_via in {"oauth", "api-key"}:
        return
    path = host_auth_path()
    raise SystemExit(
        f"no hay sesión OpenCode para {resolved.spec.alias} ({resolved.spec.provider}).\n"
        f"En el host (TTY, un vez):\n"
        f"  aegis auth login {resolved.spec.alias}\n"
        f"Elige la suscripción OAuth (SuperGrok / ChatGPT Plus), no una API key.\n"
        f"Credenciales: {path}\n"
        f"Fallback opcional: variables {', '.join(resolved.missing_keys) or '(ninguna)'}."
    )


# Si pegan la URL que abre el navegador (/api/tags, /v1/models), la bajamos a
# la base OpenAI-compatible que usa OpenCode.
_ENDPOINT_LIST_SUFFIXES = ("/api/tags", "/v1/models", "/api/models")


def _normalize_endpoint(endpoint: str, provider: str) -> str:
    if not endpoint:
        return ""
    ep = endpoint.strip()
    if not ep.startswith(("http://", "https://")):
        default_port = "11434" if provider == "ollama" else "8000"
        if ":" not in ep:
            ep = f"{ep}:{default_port}"
        ep = f"http://{ep}"
    parsed = urlparse(ep)
    path = (parsed.path or "").rstrip("/")
    for suffix in _ENDPOINT_LIST_SUFFIXES:
        if path.endswith(suffix):
            path = path[: -len(suffix)]
            break
    else:
        if path.endswith("/models"):
            path = path[: -len("/models")]
    if not path or path == "/":
        path = "/v1"
    return urlunparse((parsed.scheme, parsed.netloc, path, "", parsed.query, ""))


def _display_endpoint(endpoint: str, provider: str) -> str:
    """Lo que se muestra y se guarda: solo host:puerto.

    Ollama 127.0.0.1:11434, vLLM 127.0.0.1:8000. /api/tags y /v1 se recortan.
    OpenCode sigue usando /v1 por dentro vía _normalize_endpoint.
    """
    ep = _normalize_endpoint(endpoint, provider)
    if not ep:
        return ""
    if provider in {"ollama", "vllm"}:
        return urlparse(ep).netloc
    return ep


def rewrite_loopback_for_bridge(endpoint: str) -> str:
    if not endpoint:
        return endpoint
    return (
        endpoint.replace("://127.0.0.1", "://host.docker.internal")
        .replace("://localhost", "://host.docker.internal")
        .replace("://[::1]", "://host.docker.internal")
    )


def _pin_grok43_no_reasoning(cfg: dict) -> None:
    """Solo 4.3 (warmup/relevo xAI). Sin thinking para que el corte de 60 s deje estado. 4.6 no se toca."""
    xai = cfg.setdefault("provider", {}).setdefault("xai", {})
    grok43 = xai.setdefault("models", {}).setdefault("grok-4.3", {})
    grok43.setdefault("options", {})["reasoningEffort"] = GROK_WARMUP_REASONING
    variants = grok43.setdefault("variants", {})
    for name in ("none", "low", "medium", "high"):
        variants.setdefault(name, {})["reasoningEffort"] = GROK_WARMUP_REASONING


def opencode_config(resolved: ResolvedModel, command_timeout_ms: int) -> dict:
    provider = resolved.spec.provider
    model = resolved.spec.model
    tools = {
        "bash": "allow",
        "read": "allow",
        "edit": "allow",
        "glob": "allow",
        "grep": "allow",
        "webfetch": "allow",
        "websearch": "allow",
        "question": "deny",
    }
    specialist = {**tools, "task": "deny"}
    # Grok (xAI) se niega si ve identity/spray/subagentes. El 19 funcionó
    # con un solo agente y task: deny — mismo perfil.
    grok_safe = provider == "xai"
    lead = {**tools, "task": "deny" if grok_safe else "allow"}
    agents: dict = {
        "aegis": {
            "description": (
                "Único agente del engagement Aegis. Sin subagentes."
                if grok_safe
                else "Lead del engagement: coordina identity/web/critic."
            ),
            "mode": "primary",
            "model": resolved.opencode_id,
            "prompt": "{file:./AGENTS.md}",
            "permission": lead,
        },
        "build": {"disable": True},
        "plan": {"disable": True},
        "general": {"disable": True},
        "explore": {"disable": True},
        "scout": {"disable": True},
    }
    if not grok_safe:
        agents["identity"] = {
            "description": "AD/Kerberos/creds. Foothold, no inventario.",
            "mode": "subagent",
            "model": resolved.opencode_id,
            "prompt": "{file:./.opencode/agent/identity.md}",
            "permission": specialist,
        }
        agents["web"] = {
            "description": "Foothold HTTP: RCE/SSRF/auth, no crawler eterno.",
            "mode": "subagent",
            "model": resolved.opencode_id,
            "prompt": "{file:./.opencode/agent/web.md}",
            "permission": specialist,
        }
        agents["critic"] = {
            "description": "Mata findings basura y fija el siguiente paso.",
            "mode": "subagent",
            "model": resolved.opencode_id,
            "prompt": "{file:./.opencode/agent/critic.md}",
            "permission": specialist,
        }
    cfg: dict = {
        "$schema": "https://opencode.ai/config.json",
        "model": resolved.opencode_id,
        "default_agent": "aegis",
        "permission": lead,
        "agent": agents,
        "server": {"hostname": "127.0.0.1"},
    }
    if grok_safe:
        _pin_grok43_no_reasoning(cfg)
    if provider in {"ollama", "vllm"}:
        cfg["provider"] = {
            provider: {
                "npm": "@ai-sdk/openai-compatible",
                "name": f"{provider} (Aegis)",
                "options": {"baseURL": resolved.endpoint},
                "models": {model: {"name": model}},
            }
        }
    elif resolved.auth_via == "api-key" and provider == "xai" and resolved.env:
        xai = cfg.setdefault("provider", {}).setdefault("xai", {})
        xai.setdefault("options", {})["apiKey"] = "{env:XAI_API_KEY}"
    elif resolved.auth_via == "api-key" and provider == "openai" and resolved.env:
        cfg.setdefault("provider", {})
        cfg["provider"]["openai"] = {"options": {"apiKey": "{env:OPENAI_API_KEY}"}}
    # timeout de bash lo consume OpenCode por env, no por json; se documenta aquí
    cfg["_aegis"] = {"command_timeout_ms": command_timeout_ms}
    return cfg


def write_opencode_config(path: Path, cfg: dict) -> None:
    path.write_text(json.dumps(cfg, indent=2) + "\n", encoding="utf-8")
