from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_CONFIG = ROOT / "aegis.yaml"


@dataclass
class ModelSpec:
    alias: str
    provider: str
    model: str
    endpoint: str = ""
    env_keys: list[str] = field(default_factory=list)

    @property
    def opencode_id(self) -> str:
        return f"{self.provider}/{self.model}"


@dataclass
class Limits:
    cpus: str = "4"
    memory: str = "8g"
    pids: int = 2048
    tmpfs_size: str = "4g"


@dataclass
class Config:
    image: str = "aegis-runner:latest"
    network_mode: str = "host"
    timeout: str = "6h"
    command_timeout: str = "10m"
    data_dir: Path = field(default_factory=lambda: ROOT / "data")
    serve_port_range: tuple[int, int] = (41000, 41999)
    limits: Limits = field(default_factory=Limits)
    models: dict[str, ModelSpec] = field(default_factory=dict)
    default_model: str = "grok"
    raw: dict[str, Any] = field(default_factory=dict)

    def model(self, alias: str) -> ModelSpec:
        if alias in self.models:
            return self.models[alias]
        if "/" in alias:
            provider, model = alias.split("/", 1)
            provider = provider.strip()
            model = model.strip()
            if provider and model:
                return ModelSpec(
                    alias=alias,
                    provider=provider,
                    model=model,
                    endpoint="",
                    env_keys=default_env_keys(provider),
                )
        known = ", ".join(sorted(self.models)) or "(ninguno)"
        raise SystemExit(
            f"modelo desconocido: {alias}. Configurados: {known}. "
            "También puedes pasar un id concreto provider/model (ej. xai/grok-4)."
        )

    def runs_dir(self) -> Path:
        return self.data_dir / "runs"

    def live_path(self) -> Path:
        return self.data_dir / ".live"


def default_env_keys(provider: str) -> list[str]:
    return {
        "xai": ["XAI_API_KEY", "AEGIS_XAI_API_KEY"],
        "openai": ["OPENAI_API_KEY", "AEGIS_OPENAI_API_KEY"],
        "anthropic": ["ANTHROPIC_API_KEY"],
        "groq": ["GROQ_API_KEY"],
        "google": ["GEMINI_API_KEY", "GOOGLE_GENERATIVE_AI_API_KEY"],
        "openrouter": ["OPENROUTER_API_KEY"],
    }.get(provider, [])


def _as_path(value: str | Path) -> Path:
    p = Path(value)
    if not p.is_absolute():
        p = ROOT / p
    return p


def load_config(path: Path | None = None) -> Config:
    cfg_path = path or Path(os.environ.get("AEGIS_CONFIG", DEFAULT_CONFIG))
    raw: dict[str, Any] = {}
    if cfg_path.exists():
        raw = yaml.safe_load(cfg_path.read_text()) or {}

    limits_raw = raw.get("limits") or {}
    models_raw = raw.get("models") or {}
    default_model = models_raw.pop("default", "grok") if isinstance(models_raw, dict) else "grok"

    models: dict[str, ModelSpec] = {}
    if isinstance(models_raw, dict):
        for alias, spec in models_raw.items():
            if not isinstance(spec, dict):
                continue
            models[alias] = ModelSpec(
                alias=alias,
                provider=str(spec.get("provider", alias)),
                model=str(spec.get("model", "")),
                endpoint=str(spec.get("endpoint", "")),
                env_keys=list(spec.get("env_keys") or []),
            )

    port_range = raw.get("serve_port_range") or [41000, 41999]
    return Config(
        image=str(raw.get("image", "aegis-runner:latest")),
        network_mode=str(raw.get("network_mode", "host")),
        timeout=str(raw.get("timeout", "6h")),
        command_timeout=str(raw.get("command_timeout", "10m")),
        data_dir=_as_path(raw.get("data_dir", "data")),
        serve_port_range=(int(port_range[0]), int(port_range[1])),
        limits=Limits(
            cpus=str(limits_raw.get("cpus", "4")),
            memory=str(limits_raw.get("memory", "8g")),
            pids=int(limits_raw.get("pids", 2048)),
            tmpfs_size=str(limits_raw.get("tmpfs_size", "4g")),
        ),
        models=models,
        default_model=str(default_model),
        raw=raw,
    )


def parse_duration(text: str) -> float:
    """Devuelve segundos. Acepta 90, 90s, 10m, 6h, 2h30m, 1d."""
    raw = text.strip().lower()
    if not raw:
        raise ValueError("duración vacía")
    if raw.isdigit():
        return float(raw)
    total = 0.0
    num = ""
    units = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    for ch in raw:
        if ch.isdigit() or ch == ".":
            num += ch
            continue
        if ch not in units or not num:
            raise ValueError(f"duración inválida: {text}")
        total += float(num) * units[ch]
        num = ""
    if num:
        total += float(num)
    if total <= 0:
        raise ValueError(f"duración inválida: {text}")
    return total
