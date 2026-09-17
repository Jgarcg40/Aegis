from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from internal.auth import StagedAuth, cleanup_stage, stage_auth, sync_back
from internal.claude import (
    StagedClaude,
    cleanup_stage as cleanup_claude,
    logged_in as claude_logged_in,
    normalize_model as normalize_claude_model,
    rust_bin as claude_rust_bin,
    stage_claude,
    sync_back as sync_claude,
    write_claude_config,
)
from internal.codex import (
    StagedCodex,
    cleanup_stage as cleanup_codex,
    code_mode_host_bin as codex_code_mode_host_bin,
    is_chatgpt_oauth as codex_is_chatgpt_oauth,
    is_codex_only_model as codex_is_codex_only_model,
    logged_in as codex_logged_in,
    normalize_model as normalize_codex_model,
    rust_bin as codex_rust_bin,
    stage_codex,
    sync_back as sync_codex,
    write_codex_config,
)
from internal.agentpack import write_agent_pack
from internal.engage import add_access, add_cred, add_users, fact_sink, load, locked_state, reset_tried_idle, save
from internal.brief import (
    agents_md,
    build_brief,
    continuation_prompt,
    initial_prompt,
    resume_prompt,
    validate_mode_launch,
    write_brief,
)
from internal.flagspec import is_complete, load_contract, write_contract
from internal.inbox import InboxError, materialize
from internal.conscience import _logc, write_backend
from internal.jobs import detach_resume_links, seed_resume, write_steer
from internal.config import Config, ModelSpec, parse_duration
from internal.models import (
    GROK_WARMUP_S,
    ResolvedModel,
    grok_opencode_warmup,
    opencode_config,
    resolve_rescue,
    require_credentials,
    resolve_model,
    write_opencode_config,
)
from internal.report import ensure_reports
from internal.report.harvest import close_and_report
from internal.sandbox import (
    Sandbox,
    container_state,
    destroy,
    exec_it,
    exists,
    pause as docker_pause,
    reclaim_out,
    unpause as docker_unpause,
    running,
    start,
)
from internal.cmdhold import write_aegis_cmd
from internal.sshjump import (
    SshJumpError,
    ensure_host_in_scope,
    probe_ssh,
    resolve_ssh_launch,
    socks_needed,
    write_aegis_ssh,
    write_jump_secret,
)
from internal.targets import Target, parse_targets
from internal.telemetry import EventLog, Sidecar, Stats, parse_run_ts, print_live_stats


@dataclass
class Meta:
    run_id: str
    status: str
    mode: str
    model: str
    model_alias: str
    targets: list[dict]
    container: str
    serve_port: int
    network_mode: str
    out_dir: str
    started_at: str
    ended_at: str = ""
    reason: str = ""
    authorized: bool = True
    harness: str = "opencode"
    backup_harness: str = ""
    backup_model: str = ""
    rescue_model: str = ""
    rescue_harness: str = ""
    resumed_from: str = ""
    title: str = ""
    ctf: bool = False
    ctf_flags: list[str] = field(default_factory=list)
    ssh_host: str = ""
    ssh_user: str = ""
    exploit_mgmt: bool = False
    timeout_s: int = 0


TITLE_MAX = 80
WATCH_PID = ".aegis-run.pid"


def write_watch_pid(root: Path, pid: int | None = None) -> None:
    (root / WATCH_PID).write_text(str(pid if pid is not None else os.getpid()) + "\n", encoding="utf-8")


def read_watch_pid(root: Path) -> int | None:
    path = root / WATCH_PID
    if not path.is_file():
        return None
    try:
        return int(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def watch_pid_alive(root: Path) -> bool:
    pid = read_watch_pid(root)
    if pid is None or pid <= 0:
        return False
    try:
        os.kill(pid, 0)
    except OSError:
        return False
    return True


def clear_watch_pid(root: Path) -> None:
    try:
        (root / WATCH_PID).unlink()
    except OSError:
        pass


def normalize_title(raw: str) -> str:
    text = re.sub(r"\s+", " ", str(raw or "").strip())
    if not text:
        return ""
    if any(ch in text for ch in "/\\\x00") or any(ord(ch) < 32 for ch in text):
        raise ValueError("título inválido")
    if len(text) > TITLE_MAX:
        text = text[:TITLE_MAX].rstrip()
    return text


def write_meta_dict(root: Path, meta: dict) -> None:
    """Escribe meta.json atómicamente (tmp+replace). El BFF lo lee sin parar; una
    escritura directa puede pillarse a medias y romper el parseo JSON."""
    path = root / "meta.json"
    tmp = path.with_name("meta.json.tmp")
    tmp.write_text(json.dumps(meta, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    tmp.chmod(0o600)
    tmp.replace(path)


def set_run_title(root: Path, title: str) -> str:
    meta = read_meta(root)
    clean = normalize_title(title)
    meta["title"] = clean
    write_meta_dict(root, meta)
    return clean


def new_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    return f"{stamp}-{secrets.token_hex(3)}"


def run_paths(cfg: Config, run_id: str) -> dict[str, Path]:
    root = cfg.runs_dir() / run_id
    brief = root / "brief_mount"
    return {
        "root": root,
        "brief_mount": brief,
        "workspace": brief / "workspace",
        "out": root,
        "findings": root / "findings",
        "audit": root / ".audit",
    }


def prepare_dirs(paths: dict[str, Path]) -> None:
    for key in ("root", "brief_mount", "workspace", "findings", "audit"):
        paths[key].mkdir(parents=True, exist_ok=True)
    (paths["workspace"] / ".opencode" / "agent").mkdir(parents=True, exist_ok=True)


_RUN_DIR_RE = re.compile(r"^[0-9]{8}-[0-9]{6}-[a-f0-9]{6}$")


def remove_run_dir(root: Path, *, runs_dir: Path, image: str = "aegis-runner:latest") -> None:
    """Borra un run. El loot del contenedor suele ser uid 0; si rmtree falla, rm como root vía Docker."""
    root = root.resolve()
    runs_dir = runs_dir.resolve()
    if root.parent != runs_dir or not _RUN_DIR_RE.match(root.name):
        raise ValueError("path fuera de data/runs o id inválido")
    if not detach_resume_links(root, runs_dir):
        raise PermissionError(
            "no se pudo copiar loot/scans/vmbackups de un run que aún enlaza este; no borro el origen"
        )
    try:
        shutil.rmtree(root)
        return
    except FileNotFoundError:
        return
    except OSError:
        pass
    cmd = [
        "docker",
        "run",
        "--rm",
        "--network",
        "none",
        "--entrypoint",
        "rm",
        "-v",
        f"{runs_dir}:/aegis-runs",
        image,
        "-rf",
        f"/aegis-runs/{root.name}",
    ]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0 or root.exists():
        err = (r.stderr or r.stdout or "permission denied").strip()
        raise PermissionError(
            f"no se pudo borrar el run (ficheros del contenedor como root): {err}"
        )


def write_meta(root: Path, meta: Meta) -> None:
    write_meta_dict(root, asdict(meta))


def read_meta(root: Path) -> dict:
    p = root / "meta.json"
    if not p.is_file():
        raise SystemExit(f"no hay meta.json en {root}")
    return json.loads(p.read_text(encoding="utf-8"))


def set_live(cfg: Config, run_id: str | None) -> None:
    live = cfg.live_path()
    live.parent.mkdir(parents=True, exist_ok=True)
    if run_id is None:
        if live.exists():
            live.unlink()
        return
    live.write_text(run_id + "\n", encoding="utf-8")


def adopt_live(cfg: Config) -> str | None:
    """Si `.live` falta, reatacha el run cuyo contenedor sigue up.

    Evita que Operar quede vacío cuando un reap/abort viejo borra `.live`
    después de que el run nuevo ya está en marcha.
    """
    rid = live_id(cfg)
    if rid:
        return rid
    runs_dir = cfg.runs_dir()
    if not runs_dir.is_dir():
        return None
    found: list[tuple[str, str]] = []
    for meta_path in runs_dir.glob("*/meta.json"):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            cand = meta_path.parent.name
            if _RUN_DIR_RE.match(cand):
                st = container_state(f"aegis-run-{cand}")
                if st.get("running") or st.get("paused"):
                    found.append(("", cand))
            continue
        if not isinstance(meta, dict) or str(meta.get("status") or "") == "ended":
            continue
        cand = str(meta.get("run_id") or meta_path.parent.name)
        name = str(meta.get("container") or f"aegis-run-{cand}")
        st = container_state(name)
        if not (st.get("running") or st.get("paused")):
            continue
        found.append((str(meta.get("started_at") or ""), cand))
    if not found:
        return None
    found.sort(reverse=True)
    pick = found[0][1]
    set_live(cfg, pick)
    return pick


def live_id(cfg: Config) -> str | None:
    p = cfg.live_path()
    if not p.is_file():
        return None
    rid = p.read_text(encoding="utf-8").strip()
    return rid or None


def run_deadline_ts(root: Path, default_timeout: str = "6h") -> float | None:
    """Epoch UTC del fin de presupuesto. None si no hay started_at usable."""
    started = ""
    budget = default_timeout
    meta: dict[str, Any] = {}
    meta_p = root / "meta.json"
    if meta_p.is_file():
        try:
            loaded = json.loads(meta_p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            loaded = {}
        if isinstance(loaded, dict):
            meta = loaded
            started = str(meta.get("started_at") or "")
    brief_p = root / "brief.json"
    if brief_p.is_file():
        try:
            brief = json.loads(brief_p.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            brief = {}
        if isinstance(brief, dict) and brief.get("time_budget"):
            budget = str(brief["time_budget"])
    if not started:
        return None
    try:
        dt = datetime.fromisoformat(started.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp() + parse_duration(budget) + _pause_credit_s(root, meta)


PAUSE_REASON = ".pause-reason"
SESSION_RESUME_AT = ".session-resume-at"
SESSION_BACKOFF_N = ".session-backoff-n"


def _pause_credit_s(root: Path, meta: dict[str, Any]) -> int:
    """Pausa acumulada + tramo abierto. El presupuesto de pared no la cuenta."""
    held = 0
    try:
        held = max(0, int(meta.get("paused_s") or 0))
    except (TypeError, ValueError):
        held = 0
    since = str(meta.get("paused_since") or "").strip()
    start: datetime | None = None
    if since:
        try:
            start = datetime.fromisoformat(since.replace("Z", "+00:00"))
        except ValueError:
            start = None
    flag = root / PAUSE_REASON
    if start is None and flag.is_file():
        try:
            start = datetime.fromtimestamp(flag.stat().st_mtime, tz=timezone.utc)
        except OSError:
            start = None
    if start is None:
        return held
    if start.tzinfo is None:
        start = start.replace(tzinfo=timezone.utc)
    return held + max(0, int((datetime.now(timezone.utc) - start).total_seconds()))


def run_held(root: Path) -> bool:
    return (root / PAUSE_REASON).is_file()


def pause_reason_of(root: Path) -> str:
    try:
        return (root / PAUSE_REASON).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def session_resume_at(root: Path) -> int | None:
    try:
        raw = (root / SESSION_RESUME_AT).read_text(encoding="utf-8").strip()
    except OSError:
        return None
    try:
        n = int(raw)
    except ValueError:
        return None
    return n if n > 0 else None


def _clear_session_pause_flags(root: Path) -> None:
    for name in (PAUSE_REASON, SESSION_RESUME_AT, SESSION_BACKOFF_N):
        try:
            (root / name).unlink()
        except OSError:
            pass


def maybe_release_session_pause(
    root: Path, container: str, *, now: float | None = None
) -> bool:
    """Suelta tope de sesión con hora ya vencida. No toca quota/user/auth."""
    if pause_reason_of(root) != "session":
        return False
    until = session_resume_at(root)
    if until is None:
        return False
    if (time.time() if now is None else now) < until:
        return False
    from internal.sessioncap import fold_open_pause

    when = datetime.fromtimestamp(until, tz=timezone.utc) if until else None
    fold_open_pause(root, now=when)
    _clear_session_pause_flags(root)
    docker_unpause(container)
    return True


def write_end_reason(root: Path, reason: str) -> None:
    """Escribe .end-reason solo si aún no hay uno. El wait y el reap deben coincidir."""
    text = str(reason or "").strip()
    if not text:
        return
    path = root / ".end-reason"
    if path.is_file():
        return
    path.write_text(text + "\n", encoding="utf-8")


def release_live_slot(cfg: Config, root: Path, *, reason: str, run_id: str) -> None:
    """Marca ended y borra .live. El informe puede escribirse después."""
    rid = str(run_id or "").strip()
    if not rid:
        return
    write_end_reason(root, reason)
    try:
        meta = read_meta(root)
    except SystemExit:
        meta = {"run_id": rid}
    if not isinstance(meta, dict):
        meta = {"run_id": rid}
    if str(meta.get("status") or "") != "ended":
        meta["status"] = "ended"
        meta["ended_at"] = datetime.now(timezone.utc).isoformat()
        meta["reason"] = str(reason or "").strip() or str(meta.get("reason") or "") or "ended"
        write_meta_dict(root, meta)
    if live_id(cfg) == rid:
        set_live(cfg, None)


def linger_enabled(user: str | None = None) -> bool:
    import getpass

    who = user or getpass.getuser()
    r = subprocess.run(
        ["loginctl", "show-user", who, "-p", "Linger", "--value"],
        capture_output=True,
        text=True,
    )
    return r.returncode == 0 and r.stdout.strip().lower() == "yes"


def reap_live(cfg: Config) -> str | None:
    """Cierra un .live huérfano: contenedor muerto o timeout ya vencido."""
    rid = live_id(cfg)
    if not rid:
        return None
    root = cfg.runs_dir() / rid
    if not root.is_dir():
        set_live(cfg, None)
        return rid
    try:
        meta = read_meta(root)
    except SystemExit:
        set_live(cfg, None)
        return rid
    if meta.get("status") == "ended":
        set_live(cfg, None)
        return rid
    name = str(meta.get("container") or f"aegis-run-{rid}")
    st = container_state(name)
    alive = bool(st.get("running") or st.get("paused"))
    dead = not alive
    held = run_held(root)
    deadline = run_deadline_ts(root, cfg.timeout)
    overdue = deadline is not None and time.time() >= deadline
    why = end_reason_of(root)
    contract = load_contract(root)
    ctf_done = bool(contract.get("enabled") and is_complete(root, contract))
    force = force_end_requested(root)
    if ctf_done:
        mark_ctf_complete_at(root)
    if overdue and alive and not held and not force and not doc_grace_started(root):
        begin_doc_grace(root, "timeout", cut=True)
    grace_open = bool(doc_grace_started(root) and not doc_grace_elapsed(root))
    ctf_ready = bool(ctf_done and (dead or doc_grace_elapsed(root)))
    terminal = why in TERMINAL_END_REASONS or ctf_ready
    # Pausa y prórroga: no siegues. El contenedor puede caer un instante
    # (SIGINT al cortar el turno, on-failure) y volver para documentar.
    if (held or grace_open) and not force:
        return None
    if (
        not force
        and not dead
        and not overdue
        and not terminal
        and not (doc_grace_started(root) and doc_grace_elapsed(root))
    ):
        return None
    if force:
        reason = "abort"
    elif ctf_ready:
        reason = "completed"
    elif doc_grace_started(root) and doc_grace_elapsed(root):
        mapped = {"ctf": "completed"}.get(doc_grace_why(root), doc_grace_why(root))
        reason = mapped or ("timeout" if overdue else "ended")
    elif overdue and not held:
        reason = "timeout"
    else:
        reason = why or str(meta.get("reason") or "") or "ended"
    write_end_reason(root, reason)
    release_live_slot(cfg, root, reason=reason, run_id=rid)
    try:
        reclaim_out(name, root)
    except Exception:
        pass
    destroy(name)
    try:
        close_and_report(
            root,
            mode=str(meta.get("mode") or "full"),
            model=str(meta.get("model") or ""),
            run_id=rid,
            quick=(reason == "abort"),
        )
    except Exception as exc:
        print(f"aegis: reap informe: {exc}", file=sys.stderr)
    if live_id(cfg) == rid:
        set_live(cfg, None)
    return rid


def resolve_run_id(cfg: Config, run_id: str | None) -> str:
    if run_id:
        return run_id
    rid = live_id(cfg)
    if rid:
        return rid
    runs = sorted(cfg.runs_dir().glob("*/meta.json"), reverse=True)
    if not runs:
        raise SystemExit("no hay runs")
    return runs[0].parent.name


def _resolve_for_harness(
    cfg: Config,
    harness: str,
    model_alias: str,
    *,
    model_id: str = "",
    endpoint: str = "",
    smoke: bool = False,
    role: str = "principal",
) -> ResolvedModel:
    harness = (harness or "opencode").strip().lower()
    if harness not in {"opencode", "codex", "claude"}:
        raise SystemExit(f"harness desconocido: {harness}. Usa opencode, codex o claude")
    where = {"backup": "de respaldo", "rescue": "de salvaguarda"}.get(role, "principal")
    if harness == "claude":
        # alias "claude" o vacío → modelo por defecto del yaml, no el literal
        requested = (model_id or model_alias or "").strip()
        if requested.lower() in ("", "claude"):
            try:
                requested = cfg.model("claude").model
            except SystemExit:
                requested = ""
        slug = normalize_claude_model(requested)
        try:
            resolved = resolve_model(cfg, "claude", model_id=slug, endpoint=endpoint)
        except SystemExit:
            from internal.config import ModelSpec

            resolved = ResolvedModel(
                spec=ModelSpec(alias="claude", provider="anthropic", model=slug),
                opencode_id=slug,
                endpoint="",
                env={},
                missing_keys=[],
                auth_provider="anthropic",
                auth_via="claude-cli",
            )
        resolved.spec.model = slug
        resolved.opencode_id = slug
        if not smoke and not claude_logged_in():
            raise SystemExit(
                f"Claude Code no está logueado en el host (modelo {where}). "
                "En una terminal: claude auth login"
            )
        if not smoke and claude_rust_bin() is None:
            raise SystemExit(
                "no encuentro el binario nativo de Claude Code. "
                "Instálalo o exporta CLAUDE_BIN (esperado en ~/.local/bin/claude)"
            )
        return resolved
    if harness == "codex":
        # alias "codex" o vacío → modelo por defecto del yaml, no el literal
        requested = (model_id or model_alias or "").strip()
        if requested.lower() in ("", "codex"):
            try:
                requested = cfg.model("codex").model
            except SystemExit:
                requested = ""
        slug = normalize_codex_model(requested)
        try:
            resolved = resolve_model(cfg, "codex", model_id=slug, endpoint=endpoint)
        except SystemExit:
            from internal.config import ModelSpec

            resolved = ResolvedModel(
                spec=ModelSpec(alias="codex", provider="openai", model=slug),
                opencode_id=slug,
                endpoint="",
                env={},
                missing_keys=[],
                auth_provider="openai",
                auth_via="codex-cli",
            )
        resolved.spec.model = slug
        resolved.opencode_id = slug
        if not smoke and not codex_logged_in():
            raise SystemExit(
                f"Codex CLI no está logueado en el host (modelo {where}). "
                "En una terminal: codex login"
            )
        if not smoke and codex_is_chatgpt_oauth() and codex_is_codex_only_model(slug):
            raise SystemExit(
                f"El modelo {slug!r} no está disponible con cuenta ChatGPT (codex login).\n"
                "Con suscripción ChatGPT usa un modelo de chat, p. ej.:\n"
                "  --harness codex --model-id gpt-5.6-sol\n"
                "Los modelos '*-codex' (gpt-5.1-codex) requieren una API key de pago "
                "(exporta OPENAI_API_KEY)."
            )
        if not smoke and codex_rust_bin() is None:
            raise SystemExit(
                "no encuentro el binario nativo de Codex. "
                "Instala con: npm i -g @openai/codex   o exporta CODEX_BIN"
            )
        return resolved
    resolved = resolve_model(cfg, model_alias, model_id=model_id, endpoint=endpoint)
    if not smoke:
        require_credentials(resolved)
    return resolved


def execute(
    *,
    cfg: Config,
    target_spec: str,
    mode: str,
    model_alias: str,
    note: str,
    timeout: str,
    authorized: bool,
    model_id: str = "",
    endpoint: str = "",
    image: str = "",
    smoke: bool = False,
    harness: str = "opencode",
    persist: bool = True,
    backup_harness: str = "",
    backup_model: str = "",
    rescue_model: str = "",
    rescue_harness: str = "",
    resume: str = "",
    accounts: list[str] | None = None,
    title: str = "",
    ctf_contract: dict | None = None,
    ssh_host: str = "",
    ssh_user: str = "",
    ssh_pass: str = "",
    exploit_mgmt: bool = False,
    inbox: str = "",
    anexo: list[str] | None = None,
) -> int:
    if not authorized:
        raise SystemExit(
            "Aegis no arranca sin autorización explícita. "
            "Pasa --i-am-authorized o authorized:true en un brief."
        )
    if image:
        cfg.image = image
    harness = (harness or "opencode").strip().lower()
    if harness not in {"opencode", "codex", "claude"}:
        raise SystemExit(f"harness desconocido: {harness}. Usa opencode, codex o claude")
    resume_id = (resume or "").strip()
    resume_src: Path | None = None
    if resume_id:
        resume_src = cfg.runs_dir() / resume_id
        if not (resume_src / "meta.json").is_file():
            raise SystemExit(f"no existe el run {resume_id}")
        if live_id(cfg) == resume_id:
            raise SystemExit(f"run {resume_id} sigue vivo; aborta o espera")
        old_meta = read_meta(resume_src)
        if not (title or "").strip():
            title = str(old_meta.get("title") or "")
        if not (target_spec or "").strip():
            inherited = [
                (t.get("raw") or t.get("value") or "")
                for t in (old_meta.get("targets") or [])
                if isinstance(t, dict)
            ]
            target_spec = ",".join(x for x in inherited if x)
    try:
        title = normalize_title(title)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    ctf = bool(ctf_contract and ctf_contract.get("enabled"))
    if resume_src is not None and not ctf:
        inherited_ctf = load_contract(resume_src)
        if inherited_ctf.get("enabled"):
            ctf = True
            ctf_contract = inherited_ctf
    try:
        target_spec, jump = resolve_ssh_launch(
            target_spec=target_spec,
            ctf=ctf,
            ssh_host=ssh_host,
            ssh_user=ssh_user,
            ssh_pass=ssh_pass or os.environ.get("AEGIS_SSH_PASS", ""),
            accounts=accounts,
            resume=bool(resume_id),
        )
    except SshJumpError as exc:
        raise SystemExit(str(exc)) from exc
    if not (target_spec or "").strip():
        raise SystemExit(f"--resume {resume_id} no tiene targets en meta.json; pasa --target")
    if jump is not None and not smoke:
        try:
            probe_ssh(jump.host, jump.user, jump.password)
        except SshJumpError as exc:
            raise SystemExit(str(exc)) from exc
    targets = parse_targets(target_spec)
    try:
        validate_mode_launch(
            mode=mode, targets=targets, ctf=ctf, exploit_mgmt=exploit_mgmt
        )
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    exploit_mgmt = bool(exploit_mgmt) and mode == "net"
    jump_socks = bool(jump is not None and socks_needed(targets, jump.host))
    scope = ensure_host_in_scope(targets, jump.host) if jump is not None else targets
    resolved = _resolve_for_harness(
        cfg, harness, model_alias, model_id=model_id, endpoint=endpoint, smoke=smoke
    )
    backup_harness = (backup_harness or "").strip().lower()
    backup_model = (backup_model or "").strip()
    backup_resolved: ResolvedModel | None = None
    if backup_model:
        if not backup_harness:
            backup_harness = "opencode"
        if backup_harness not in {"opencode", "codex", "claude"}:
            raise SystemExit(
                f"harness de respaldo desconocido: {backup_harness}. Usa opencode, codex o claude"
            )
        if backup_harness == harness and backup_model in {model_alias, resolved.opencode_id}:
            backup_harness = ""
            backup_model = ""
        else:
            backup_resolved = _resolve_for_harness(
                cfg, backup_harness, backup_model, smoke=smoke, role="backup"
            )
            backup_model = backup_resolved.opencode_id
    else:
        backup_harness = ""
    dest_h, dest_m = resolve_rescue(harness, resolved, rescue_model, rescue_harness)
    rescue_harness, rescue_model = dest_h, dest_m
    rescue_resolved: ResolvedModel | None = None
    if dest_h and dest_m and dest_h != harness:
        rescue_resolved = _resolve_for_harness(
            cfg, dest_h, dest_m, smoke=smoke, role="rescue"
        )
        if dest_h == "opencode":
            rescue_model = rescue_resolved.opencode_id
    timeout_s = parse_duration(timeout)
    cmd_ms = int(parse_duration(cfg.command_timeout) * 1000)

    run_id = new_run_id()
    paths = run_paths(cfg, run_id)
    prepare_dirs(paths)
    if resume_src is not None:
        seed_resume(resume_src, paths["root"])

    try:
        inbox_files = materialize(
            paths["root"] / "inbox", inbox_dir=inbox, attach=anexo
        )
    except InboxError as exc:
        raise SystemExit(str(exc)) from exc
    has_inbox = bool(inbox_files)

    grok_safe = harness == "opencode" and resolved.spec.provider == "xai"
    quiet = grok_safe or harness == "codex" or resolved.spec.provider == "openai"
    ctf = bool(ctf_contract and ctf_contract.get("enabled"))
    if not ctf:
        inherited = load_contract(paths["root"])
        if inherited.get("enabled"):
            ctf = True
            ctf_contract = inherited
    if ctf and jump is not None:
        raise SystemExit("SSH y CTF no se mezclan")
    if ctf and mode == "net":
        raise SystemExit("Red y CTF no se mezclan")
    brief = build_brief(
        run_id=run_id,
        mode=mode,
        targets=targets,
        operator_note=note,
        time_budget=timeout,
        model=resolved.opencode_id,
        ctf=ctf,
        ssh_host=jump.host if jump is not None else "",
        ssh_user=jump.user if jump is not None else "",
        ssh_socks=jump_socks,
        exploit_mgmt=exploit_mgmt,
        inbox_files=inbox_files,
    )
    write_brief(brief, paths["brief_mount"])
    shutil.copy2(paths["brief_mount"] / "BRIEF.md", paths["root"] / "brief.md")
    shutil.copy2(paths["brief_mount"] / "brief.json", paths["root"] / "brief.json")
    if ctf:
        write_contract(paths["root"] / "ctf.json", ctf_contract)
    else:
        write_contract(paths["root"] / "ctf.json", {"enabled": False, "slots": []})
    host_tools = None

    (paths["workspace"] / "AGENTS.md").write_text(
        agents_md(mode, ctf=ctf, exploit_mgmt=exploit_mgmt, inbox=has_inbox),
        encoding="utf-8",
    )
    write_agent_pack(
        paths["workspace"],
        out_dir=paths["root"],
        targets=[t.asset() for t in scope],
        specialists=not quiet and mode != "net",
        quiet=quiet,
        ctf=ctf,
        mode=mode,
        exploit_mgmt=exploit_mgmt,
    )
    write_aegis_cmd(paths["workspace"] / "bin")
    if accounts or jump is not None:
        st = load(paths["root"] / "engagement.json")
        with fact_sink(paths["root"]):
            if jump is not None:
                write_jump_secret(
                    paths["root"],
                    host=jump.host,
                    user=jump.user,
                    password=jump.password,
                    socks=jump_socks,
                )
                write_aegis_ssh(paths["workspace"] / "bin")
                add_users(st, [jump.user])
                add_cred(st, jump.user, jump.password, "ssh", jump.host)
                add_access(st, jump.host, jump.user, via="ssh")
            for raw in accounts or []:
                if ":" not in raw:
                    continue
                user, secret = raw.split(":", 1)
                user, secret = user.strip(), secret.strip()
                if not user or not secret:
                    continue
                if jump is not None and user == jump.user and secret == jump.password:
                    continue
                add_users(st, [user])
                add_cred(st, user, secret, "password", "operator")
        save(st, paths["root"] / "engagement.json", sidecars=not quiet)
    oc_for_cfg = resolved if harness == "opencode" else backup_resolved
    if oc_for_cfg is not None and (
        harness == "opencode" or backup_harness == "opencode"
    ):
        write_opencode_config(
            paths["workspace"] / "opencode.json",
            opencode_config(oc_for_cfg, cmd_ms),
        )
    task_perm = "deny" if grok_safe else "allow"
    agent_desc = (
        "Único agente del engagement Aegis. Sin subagentes."
        if grok_safe
        else "Lead Aegis. Coordina identity, web y critic."
    )
    (paths["workspace"] / ".opencode" / "agent" / "aegis.md").write_text(
        "---\n"
        f"description: {agent_desc}\n"
        "mode: primary\n"
        "permission:\n"
        "  bash: allow\n"
        "  read: allow\n"
        "  edit: allow\n"
        "  glob: allow\n"
        "  grep: allow\n"
        "  webfetch: allow\n"
        "  websearch: allow\n"
        f"  task: {task_perm}\n"
        "  question: deny\n"
        "---\n\n" + agents_md(mode, grok_safe=grok_safe, ctf=ctf, inbox=has_inbox),
        encoding="utf-8",
    )

    if resume_id:
        prompt = resume_prompt(mode, resume_id, note, grok_safe=grok_safe)
        steer_p = paths["root"] / "STEER.md"
        if steer_p.is_file() and not grok_safe:
            prompt = (
                f"Instrucción del operador (obligatoria): {steer_p.read_text(encoding='utf-8').strip()}\n\n"
                + prompt
            )
    else:
        prompt = initial_prompt(mode, note, grok_safe=grok_safe, inbox=has_inbox)
    events = EventLog(paths["root"] / "events.jsonl")
    target_label = ",".join(t.asset() for t in targets)
    started = time.time()
    if resume_src is not None:
        old_start = parse_run_ts(old_meta.get("started_at"))
        if old_start is not None:
            started = old_start.timestamp()
    stats = Stats(mode=mode, model=resolved.opencode_id, target=target_label, started=started)

    print(f"run-id:  {run_id}")
    if title:
        print(f"title:   {title}")
    print(f"harness: {harness}")
    print(f"mode:    {mode}{' +mgmt' if exploit_mgmt else ''}")
    print(f"model:   {resolved.opencode_id} ({model_alias})")
    warm = (
        grok_opencode_warmup(harness, resolved, warmup_id=rescue_model)
        if rescue_harness == "opencode"
        else ""
    )
    if warm and not smoke:
        print(f"warmup:  {warm} → {resolved.opencode_id} @{GROK_WARMUP_S}s")
    if rescue_model and not smoke:
        label = f"{rescue_harness}/{rescue_model}" if rescue_harness else rescue_model
        if warm:
            print(f"rescue:  {label} (salvaguarda → {GROK_WARMUP_S}s → {resolved.opencode_id})")
        else:
            print(f"rescue:  {label} (salvaguarda → ficha → {resolved.opencode_id})")
    if backup_resolved:
        print(f"backup:  {backup_harness}/{backup_resolved.opencode_id}")
    auth_label = {
        "opencode": resolved.auth_via,
        "codex": "codex-cli",
        "claude": "claude-cli",
    }.get(harness, harness)
    print(f"auth:    {auth_label}")
    print(f"out:     {paths['root']}")
    print(f"targets: {target_label}")
    if jump is not None:
        print(f"ssh:     {jump.user}@{jump.host}")
    if resume_id:
        print(f"resume:  {resume_id}")
    if persist and not smoke:
        persist_lbl = (
            "sí (hasta timeout o parada; cobertura de red, no foothold)"
            if mode == "net"
            else "sí (hasta timeout o parada; foothold manda, no inflar findings)"
        )
    else:
        persist_lbl = "no"
    print(f"persist: {persist_lbl}")
    sys.stdout.flush()

    sandbox: Sandbox | None = None
    sidecar: Sidecar | None = None
    staged: StagedAuth | None = None
    staged_cx: StagedCodex | None = None
    staged_cl: StagedClaude | None = None
    reason = "completed"
    try:
        need_oc_auth = False
        if not smoke:
            if harness == "opencode" and resolved.auth_via in {"oauth", "api-key"} and not resolved.env:
                need_oc_auth = True
            if (
                backup_resolved
                and backup_harness == "opencode"
                and backup_resolved.auth_via in {"oauth", "api-key"}
                and not backup_resolved.env
            ):
                need_oc_auth = True
            if (
                rescue_resolved
                and rescue_harness == "opencode"
                and rescue_resolved.auth_via in {"oauth", "api-key"}
                and not rescue_resolved.env
            ):
                need_oc_auth = True
        if need_oc_auth:
            staged = stage_auth(run_id)
        need_codex = harness == "codex" or backup_harness == "codex" or rescue_harness == "codex"
        if need_codex and not smoke:
            staged_cx = stage_codex(run_id)
            if harness == "codex":
                cx_model = resolved.opencode_id
            elif rescue_harness == "codex":
                cx_model = rescue_model
            else:
                cx_model = backup_resolved.opencode_id
            write_codex_config(staged_cx.home, cx_model)
        need_claude = harness == "claude" or backup_harness == "claude" or rescue_harness == "claude"
        if need_claude and not smoke:
            staged_cl = stage_claude(run_id)
            if harness == "claude":
                cl_model = resolved.opencode_id
            elif rescue_harness == "claude":
                cl_model = rescue_model
            else:
                cl_model = backup_resolved.opencode_id
            write_claude_config(staged_cl.home, cl_model)
            (paths["workspace"] / "CLAUDE.md").write_text(
                agents_md(mode, ctf=ctf, exploit_mgmt=exploit_mgmt, inbox=has_inbox),
                encoding="utf-8",
            )
        sandbox = start(
            cfg=cfg,
            run_id=run_id,
            host_out=paths["root"],
            host_brief=paths["brief_mount"],
            host_inbox=(paths["root"] / "inbox") if has_inbox else None,
            resolved=resolved,
            prompt=prompt,
            command_timeout_ms=cmd_ms,
            smoke=smoke,
            auth_xdg=staged.xdg_data_home if staged else None,
            harness=harness,
            codex_bin=codex_rust_bin() if need_codex else None,
            codex_code_mode_host=codex_code_mode_host_bin() if need_codex else None,
            codex_home=staged_cx.home if staged_cx else None,
            claude_bin=claude_rust_bin() if need_claude else None,
            claude_home=staged_cl.home if staged_cl else None,
            persist=persist and not smoke,
            continue_prompt=continuation_prompt(mode, grok_safe=grok_safe, ctf=ctf),
            backup_harness=backup_harness,
            backup_resolved=backup_resolved,
            rescue_model=rescue_model,
            rescue_harness=rescue_harness,
            rescue_resolved=rescue_resolved,
            quiet=quiet,
            host_tools=host_tools,
            timeout_s=timeout_s,
        )
        meta = Meta(
            run_id=run_id,
            status="running",
            mode=mode,
            model=resolved.opencode_id,
            model_alias=model_alias,
            targets=[t.__dict__ for t in scope],
            container=sandbox.name,
            serve_port=sandbox.port,
            network_mode=sandbox.network_mode,
            out_dir=str(paths["root"]),
            started_at=datetime.now(timezone.utc).isoformat(),
            harness=harness,
            backup_harness=backup_harness,
            backup_model=backup_resolved.opencode_id if backup_resolved else "",
            rescue_model=rescue_model,
            rescue_harness=rescue_harness,
            resumed_from=resume_id,
            title=title,
            ctf=ctf,
            ctf_flags=[str(s.get("match") or "") for s in (ctf_contract or {}).get("slots") or [] if s.get("match")] if ctf else [],
            ssh_host=jump.host if jump is not None else "",
            ssh_user=jump.user if jump is not None else "",
            exploit_mgmt=exploit_mgmt,
            timeout_s=int(timeout_s),
        )
        write_meta(paths["root"], meta)
        write_backend(
            paths["root"],
            harness=harness,
            model=resolved.opencode_id,
            claude_bin=claude_rust_bin() if need_claude else None,
            claude_home=staged_cl.home if staged_cl else None,
            codex_bin=codex_rust_bin() if need_codex else None,
            codex_home=staged_cx.home if staged_cx else None,
            xdg_data_home=staged.xdg_data_home if staged else None,
        )
        (paths["root"] / ".serve").write_text(
            json.dumps({"port": sandbox.port, "user": "aegis", "password": sandbox.password}) + "\n",
            encoding="utf-8",
        )
        (paths["root"] / ".serve").chmod(0o600)
        set_live(cfg, run_id)
        events.emit(
            run_id,
            "run.start",
            {
                "mode": mode,
                "model": resolved.opencode_id,
                "targets": [t.asset() for t in targets],
                "container": sandbox.name,
                "network_mode": sandbox.network_mode,
                "harness": harness,
                "backup_harness": backup_harness,
                "backup_model": backup_resolved.opencode_id if backup_resolved else "",
                "rescue_model": rescue_model,
                "rescue_harness": rescue_harness,
            },
        )
        sidecar = Sidecar(
            run_id=run_id,
            sandbox=sandbox,
            out_dir=paths["root"],
            events=events,
            stats=stats,
            targets=scope,
            mode=mode,
            quiet=quiet,
        )
        sidecar.start()
        write_watch_pid(paths["root"])
        reason = _wait_loop(cfg, sandbox, paths["root"], timeout_s)
    except KeyboardInterrupt:
        reason = "abort"
        print("aegis: abort (SIGINT)", file=sys.stderr)
    except SystemExit:
        cleanup_stage(staged)
        cleanup_codex(staged_cx)
        cleanup_claude(staged_cl)
        raise
    except Exception as exc:  # noqa: BLE001
        reason = "error"
        events.emit(run_id, "error", {"error": str(exc)})
        print(f"aegis: error: {exc}", file=sys.stderr)
    finally:
        if sandbox:
            _finalize(
                cfg, sandbox, paths, events, sidecar, stats, reason, mode, resolved, staged,
                staged_cx,
                staged_cl,
            )
        else:
            cleanup_stage(staged)
            cleanup_codex(staged_cx)
            cleanup_claude(staged_cl)
    return 0 if reason == "completed" else 1


TERMINAL_END_REASONS = frozenset(
    {"completed", "timeout", "stalled", "quota", "abort", "refused", "harness", "failed", "error", "ended"}
)

# Al cierre (timeout, flags CTF o primer cancelar): un comprobador
# (cualquier harness/modelo: consola + disco → corrige fichas/cuentas/informe).
# Cierra al escribir `.doc-done` o al tope. El segundo cancelar corta ya.
# close_and_report después aplica el veredicto; no relanza la IA si .doc-done.
DOC_GRACE_S = 480
CTF_DOC_GRACE_S = DOC_GRACE_S
CTF_COMPLETE_AT = ".ctf-complete-at"
CTF_DOC_NOTED = ".ctf-doc-noted"
CTF_DOC_MSG = "conciencia: Máquina terminada. Revisa, informa y cierra..."
DOC_GRACE_AT = ".doc-grace-at"
DOC_GRACE_WHY = ".doc-grace-why"
DOC_GRACE_STEER = ".doc-grace-steer"
DOC_GRACE_NOTED = ".doc-grace-noted"
DOC_DONE = ".doc-done"
FORCE_END = ".force-end"
CLOSE_DOC_STEER = """\
Comprobador de cierre. No abras otro vector. No lances scans ni exploits.
El ataque YA acabó. NO resuelvas la máquina otra vez: ni curl, ssh, nmap, redis-cli ni PoC contra el host. Ni login ni RCE. No re-demuestres nada.

Lee SOLO findings/, engagement.json y loot/. No leas console.log ni busques uid/payloads en el log.

Revisa y completa, con prueba YA en disco:
- Findings: reescribe las malas, crea las que falten, borra ruido. título, explain, proof. evidence = archivos reales en findings/F-xxx/. Sin archivo no es proven (suspected o bórrala).
- Usuarios: escribe accounts.json (lista). Comprometida = login/SSH/RCE/password de verdad; el censo AD (nxc --users, RID) va con status=enumerated y via=enum, no como comprometida. Cada ítem: principal, host, via, priv, status; finding si hay ficha; secret solo si hay contraseña. Quita IPs, nombres o vías erróneos. Si falta, añade. Si es un error, no la pongas. Eso actualiza la pestaña Cuentas y el §5. Alinea engagement.json (users/creds/access).
- Informe: report.agent.md en español.
## Ejecutivo
2–4 frases de lo demostrado.
## Narrativa
Cadena en orden, IDs F-xxx.

Luego .doc-done (una línea: ok) y para.
"""
DOC_GRACE_MSG = {
    "ctf": CTF_DOC_MSG,
    "timeout": "conciencia: Tiempo agotado. Revisa, informa y cierra (tope 8 min)...",
    "abort": "conciencia: Cierre pedido. Revisa, informa y cierra (tope 8 min)...",
}


def _read_stamp(path: Path) -> float | None:
    if not path.is_file():
        return None
    try:
        return float(path.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return None


def _write_stamp(path: Path, ts: float) -> bool:
    try:
        path.write_text(f"{ts:.3f}\n", encoding="utf-8")
        return True
    except OSError:
        return False


def doc_grace_stamps(root: Path) -> list[float]:
    # Solo el sello de cierre. Un .ctf-complete-at viejo no debe
    # hacer que un timeout fresco parezca ya agotado.
    ts = _read_stamp(root / DOC_GRACE_AT)
    if ts is not None:
        return [ts]
    ts = _read_stamp(root / CTF_COMPLETE_AT)
    return [ts] if ts is not None else []


def doc_grace_started(root: Path) -> bool:
    return bool(doc_grace_stamps(root))


def doc_done(root: Path) -> bool:
    return (root / DOC_DONE).is_file()


def doc_grace_elapsed(root: Path, now: float | None = None) -> bool:
    if doc_done(root):
        return True
    stamps = doc_grace_stamps(root)
    if not stamps:
        return False
    t = float(now if now is not None else time.time())
    return (t - min(stamps)) >= DOC_GRACE_S


def doc_grace_why(root: Path) -> str:
    path = root / DOC_GRACE_WHY
    if path.is_file():
        try:
            why = path.read_text(encoding="utf-8", errors="replace").strip()
            if why:
                return why
        except OSError:
            pass
    if (root / CTF_COMPLETE_AT).is_file():
        return "ctf"
    return ""


def doc_grace_left_s(root: Path, now: float | None = None) -> int:
    if doc_done(root):
        return 0
    stamps = doc_grace_stamps(root)
    if not stamps:
        return 0
    t = float(now if now is not None else time.time())
    left = DOC_GRACE_S - (t - min(stamps))
    return max(0, int(left))


def doc_grace_info(root: Path, now: float | None = None) -> dict[str, Any]:
    if not doc_grace_started(root):
        return {"active": False, "why": "", "left_s": 0}
    elapsed = doc_grace_elapsed(root, now=now)
    return {
        "active": not elapsed,
        "why": doc_grace_why(root),
        "left_s": 0 if elapsed else doc_grace_left_s(root, now=now),
    }


def announce_doc_grace(root: Path, why: str) -> bool:
    flag = root / DOC_GRACE_NOTED
    if why == "ctf":
        return announce_ctf_doc(root)
    if flag.is_file():
        return False
    try:
        flag.write_text("1\n", encoding="utf-8")
    except OSError:
        return False
    _logc(root, DOC_GRACE_MSG.get(why) or DOC_GRACE_MSG["timeout"])
    return True


def announce_ctf_doc(root: Path) -> bool:
    """Una sola línea de conciencia: el reloj de máquina ya paró."""
    flag = root / CTF_DOC_NOTED
    if flag.is_file():
        return False
    try:
        flag.write_text("1\n", encoding="utf-8")
    except OSError:
        return False
    _logc(root, CTF_DOC_MSG)
    return True


def write_close_doc_steer(root: Path, *, cut: bool = False) -> bool:
    """STEER de cierre. cut=True corta el turno en curso (timeout/cancelar)."""
    marker = root / DOC_GRACE_STEER
    first = not marker.is_file()
    try:
        (root / "STEER.md").write_text(CLOSE_DOC_STEER.strip() + "\n", encoding="utf-8")
        if first:
            marker.write_text("1\n", encoding="utf-8")
    except OSError:
        return False
    if cut and first:
        try:
            (root / ".conscience-cut").write_text("steer\n", encoding="utf-8")
        except OSError:
            pass
    return first


def mark_doc_grace_at(root: Path, why: str, now: float | None = None) -> tuple[float, bool]:
    """Sella la prórroga de cierre. (stamp, created)."""
    why_p = root / DOC_GRACE_WHY
    if not why_p.is_file():
        try:
            why_p.write_text((why or "timeout") + "\n", encoding="utf-8")
        except OSError:
            pass
    existing = _read_stamp(root / DOC_GRACE_AT)
    if existing is not None:
        return existing, False
    # Timeout/cancelar: reloj ahora. El sello CTF no se hereda (si no, un
    # .ctf-complete-at de hace >8 min hace parecer la prórroga ya vencida).
    if why == "ctf":
        ctf_ts = _read_stamp(root / CTF_COMPLETE_AT)
        ts = float(ctf_ts if ctf_ts is not None else (now if now is not None else time.time()))
    else:
        ts = float(now if now is not None else time.time())
    if not _write_stamp(root / DOC_GRACE_AT, ts):
        return ts, False
    return ts, True


def mark_ctf_complete_at(root: Path, now: float | None = None) -> tuple[float, bool]:
    """Primera vez que hay flags: sella el reloj. (stamp, created)."""
    path = root / CTF_COMPLETE_AT
    existing = _read_stamp(path)
    if existing is not None:
        mark_doc_grace_at(root, "ctf", now=existing)
        write_close_doc_steer(root, cut=False)
        return existing, False
    ts = float(now if now is not None else time.time())
    if not _write_stamp(path, ts):
        return ts, False
    mark_doc_grace_at(root, "ctf", now=ts)
    write_close_doc_steer(root, cut=False)
    announce_ctf_doc(root)
    return ts, True


def begin_doc_grace(root: Path, why: str, *, cut: bool = False, now: float | None = None) -> bool:
    """Arranca la prórroga de cierre (stamp + STEER + anuncio). True si es nueva."""
    created = False
    if why == "ctf":
        _, created = mark_ctf_complete_at(root, now=now)
    else:
        _, created = mark_doc_grace_at(root, why, now=now)
        if created:
            announce_doc_grace(root, why)
    wrote = write_close_doc_steer(root, cut=cut and why != "ctf")
    return created or wrote


def ctf_grace_elapsed(root: Path, now: float | None = None) -> bool:
    return doc_grace_elapsed(root, now=now) if (root / CTF_COMPLETE_AT).is_file() else False


def force_end_requested(root: Path) -> bool:
    return (root / "ABORT").is_file() or (root / FORCE_END).is_file()


def end_reason_of(root: Path) -> str:
    end = root / ".end-reason"
    if not end.is_file():
        return ""
    try:
        return end.read_text(encoding="utf-8", errors="replace").strip()
    except OSError:
        return ""


def wait_should_stop(
    *,
    abort: bool,
    end_reason: str,
    container_running: bool,
    ctf_done: bool = False,
    ctf_grace_done: bool = False,
    grace_open: bool = False,
) -> str | None:
    """El run cierra si el entrypoint ya escribió un motivo terminal.

    En CTF, flags en disco cierran: al instante si el contenedor ya murió;
    si sigue up, tras `DOC_GRACE_S` para que el agente escriba fichas.
    Timeout/cancelar: misma prórroga. `.end-reason timeout` o un
    contenedor caído un instante no cortan mientras la gracia esté abierta.
    ABORT / .force-end cortan ya. Contenedor muerto sin flags ni
    .end-reason es `ended`, no `completed`.
    """
    if abort:
        return "abort"
    if grace_open:
        return None
    # El entrypoint viejo escribe `completed` al 2/2. No cortar la gracia.
    if (
        ctf_done
        and container_running
        and not ctf_grace_done
        and end_reason == "completed"
    ):
        return None
    if end_reason in TERMINAL_END_REASONS:
        return end_reason
    if ctf_done and (not container_running or ctf_grace_done):
        return "completed"
    if not container_running:
        return end_reason or "ended"
    return None


def _wait_loop(cfg: Config, sandbox: Sandbox, root: Path, timeout_s: float) -> str:
    work_deadline = time.time() + timeout_s
    abort_flag = root / "ABORT"
    force_flag = root / FORCE_END
    pause_flag = root / PAUSE_REASON
    tty = sys.stderr.isatty()
    last_print = 0.0
    from internal.sessioncap import fold_open_pause, mark_open_pause

    while True:
        maybe_release_session_pause(root, sandbox.name)
        reason = pause_reason_of(root)
        if reason or pause_flag.is_file():
            mark_open_pause(root)
        else:
            fold_open_pause(root)
        if reason == "session":
            held_now = container_state(sandbox.name)
            if held_now.get("paused"):
                docker_unpause(sandbox.name)
        elif pause_flag.is_file():
            docker_pause(sandbox.name)
        else:
            held_now = container_state(sandbox.name)
            if held_now.get("paused"):
                docker_unpause(sandbox.name)
        st = container_state(sandbox.name)
        held = bool(st.get("paused") or pause_flag.is_file())
        contract = load_contract(root)
        ctf_done = bool(contract.get("enabled") and is_complete(root, contract))
        now = time.time()
        if ctf_done:
            _, created = mark_ctf_complete_at(root)
            if created:
                print(
                    f"aegis: CTF completo; {DOC_GRACE_S}s de prórroga (no cuenta)",
                    file=sys.stderr,
                )
        overdue = now >= work_deadline
        if overdue and not held:
            if begin_doc_grace(root, "timeout", cut=True):
                print(
                    f"aegis: timeout; {DOC_GRACE_S}s de prórroga (no cuenta)",
                    file=sys.stderr,
                )
        grace_open = doc_grace_started(root) and not doc_grace_elapsed(root)
        why = wait_should_stop(
            abort=abort_flag.exists() or force_flag.exists(),
            end_reason=end_reason_of(root),
            container_running=bool(st.get("running") or st.get("paused")),
            ctf_done=ctf_done,
            ctf_grace_done=not grace_open if ctf_done else False,
            grace_open=grace_open,
        )
        if why:
            write_end_reason(root, why)
            return why
        if doc_grace_started(root) and not grace_open and not held:
            reason = doc_grace_why(root) or ("completed" if ctf_done else "timeout")
            if reason == "ctf":
                reason = "completed"
            write_end_reason(root, reason)
            return reason
        if tty and now - last_print >= 15:
            print_live_stats(root / "stats.json")
            last_print = now
        time.sleep(1)
        if held:
            work_deadline += 1


def _finalize(
    cfg: Config,
    sandbox: Sandbox,
    paths: dict[str, Path],
    events: EventLog,
    sidecar: Sidecar | None,
    stats: Stats,
    reason: str,
    mode: str,
    resolved: ResolvedModel,
    staged: StagedAuth | None = None,
    staged_cx: StagedCodex | None = None,
    staged_cl: StagedClaude | None = None,
) -> None:
    root = paths["root"]
    release_live_slot(cfg, root, reason=reason, run_id=sandbox.run_id)
    try:
        from internal.sandbox import export_session

        export_session(sandbox.name, root / "session.opencode.json")
    except Exception as exc:  # noqa: BLE001
        print(f"aegis: export incompleto: {exc}", file=sys.stderr)
        if not (root / "session.opencode.json").exists():
            (root / "session.opencode.json").write_text("{}\n", encoding="utf-8")

    if sidecar:
        sidecar.stop()
    else:
        stats_path = root / "stats.json"
        if not stats_path.exists():
            stats_path.write_text(json.dumps(stats.snapshot(), indent=2) + "\n", encoding="utf-8")

    events.emit(sandbox.run_id, "run.end", {"reason": reason})
    print(f"aegis: destruyendo {sandbox.name}", file=sys.stderr)
    try:
        reclaim_out(sandbox.name, root)
    except Exception as exc:  # noqa: BLE001
        print(f"aegis: no se pudo devolver el dueño de out/: {exc}", file=sys.stderr)
    try:
        close_and_report(root, mode=mode, model=resolved.opencode_id, run_id=sandbox.run_id)
    except Exception as exc:  # noqa: BLE001
        print(f"aegis: no se pudo regenerar el informe: {exc}", file=sys.stderr)
    if staged:
        try:
            sync_back(staged)
        except Exception as exc:  # noqa: BLE001
            print(f"aegis: no se pudo devolver el refresh OAuth al host: {exc}", file=sys.stderr)
    if staged_cx:
        try:
            sync_codex(staged_cx)
        except Exception as exc:  # noqa: BLE001
            print(f"aegis: no se pudo devolver el refresh Codex al host: {exc}", file=sys.stderr)
    if staged_cl:
        try:
            sync_claude(staged_cl)
        except Exception as exc:  # noqa: BLE001
            print(f"aegis: no se pudo devolver el refresh Claude al host: {exc}", file=sys.stderr)
    destroy(sandbox.name)
    cleanup_stage(staged)
    cleanup_codex(staged_cx)
    cleanup_claude(staged_cl)
    if exists(sandbox.name):
        print(f"aegis: aviso: {sandbox.name} aún existe tras rm -f", file=sys.stderr)
    else:
        print(f"aegis: contenedor {sandbox.name} no existe", file=sys.stderr)

    if live_id(cfg) == sandbox.run_id:
        set_live(cfg, None)
    clear_watch_pid(root)
    print(f"reason:  {reason}")
    print(f"out:     {root}")


def cmd_watch(cfg: Config, run_id: str | None, *, supervise: bool = False) -> int:
    """Sidecar + wait sobre un contenedor que ya corre. No lanza otro Docker."""
    rid = resolve_run_id(cfg, run_id)
    root = cfg.runs_dir() / rid
    if supervise:
        return _watch_supervise(cfg, rid, root)
    return _watch_once(cfg, rid, root)


def _watch_supervise(cfg: Config, rid: str, root: Path) -> int:
    """Reintenta el sidecar si muere y el contenedor sigue up. No relanza un run cerrado."""
    while True:
        try:
            return _watch_once(cfg, rid, root)
        except SystemExit as exc:
            msg = str(exc)
            if any(x in msg for x in ("ya terminó", "presupuesto", "no tiene targets")):
                raise
            meta = read_meta(root)
            name = str(meta.get("container") or f"aegis-run-{rid}")
            if str(meta.get("status") or "") == "ended" or not running(name):
                raise
            print(f"aegis: watch reintenta en 8s ({exc})", file=sys.stderr)
            time.sleep(8)


def _watch_once(cfg: Config, rid: str, root: Path) -> int:
    """Un ciclo de sidecar. Si arranca, al salir finaliza el run."""
    meta = read_meta(root)
    if str(meta.get("status") or "") == "ended":
        raise SystemExit(f"run {rid} ya terminó")
    name = str(meta.get("container") or f"aegis-run-{rid}")
    if not running(name):
        raise SystemExit(f"run {rid} no está vivo (contenedor {name} ausente)")
    if watch_pid_alive(root) and read_watch_pid(root) != os.getpid():
        print(f"aegis: ya hay watcher pid={read_watch_pid(root)}", file=sys.stderr)
        return 0
    deadline = run_deadline_ts(root, cfg.timeout)
    if deadline is not None and time.time() >= deadline and not run_held(root):
        raise SystemExit(f"run {rid}: presupuesto agotado")
    write_watch_pid(root)
    serve = _serve_info(root)
    sandbox = Sandbox(
        run_id=rid,
        name=name,
        port=int(serve.get("port") or meta.get("serve_port") or 0),
        password=str(serve.get("password") or ""),
        network_mode=str(meta.get("network_mode") or "host"),
    )
    targets: list[Target] = []
    for row in meta.get("targets") or []:
        if not isinstance(row, dict):
            continue
        raw = str(row.get("raw") or row.get("value") or "").strip()
        if raw:
            targets.extend(parse_targets(raw))
    if not targets:
        raise SystemExit(f"run {rid} no tiene targets en meta.json")
    events = EventLog(root / "events.jsonl")
    started = parse_run_ts(meta.get("started_at"))
    started_f = started.timestamp() if started else time.time()
    mode = str(meta.get("mode") or "full")
    model = str(meta.get("model") or "")
    stats = Stats(
        mode=mode,
        model=model,
        target=targets[0].asset() if targets else "",
        started=started_f,
    )
    stats.hydrate(root / "stats.json")
    harness = str(meta.get("harness") or "opencode")
    quiet = harness == "codex" or model.lower().startswith(("xai/", "openai/"))
    sidecar = Sidecar(
        run_id=rid,
        sandbox=sandbox,
        out_dir=root,
        events=events,
        stats=stats,
        targets=targets,
        mode=mode,
        quiet=quiet,
    )
    remain = (deadline - time.time()) if deadline else parse_duration(cfg.timeout)
    remain = max(60.0, remain)
    resolved = ResolvedModel(
        spec=ModelSpec(alias="", provider="", model=model, endpoint=""),
        opencode_id=model,
        endpoint="",
        env={},
        missing_keys=[],
    )
    reason = "completed"
    ready = False
    try:
        sidecar.start()
        events.emit(rid, "sidecar.watch", {"pid": os.getpid()})
        try:
            with locked_state(root / "engagement.json", sidecars=False) as st:
                reset_tried_idle(st)
        except Exception:
            pass
        _logc(root, "conciencia: reloj del host reenganchado")
        ready = True
        reason = _wait_loop(cfg, sandbox, root, remain)
    except KeyboardInterrupt:
        reason = "abort"
        print("aegis: abort (SIGINT)", file=sys.stderr)
    except Exception as exc:
        print(f"aegis: watch error: {exc}", file=sys.stderr)
        if not ready:
            try:
                sidecar.stop()
            except Exception:
                pass
            clear_watch_pid(root)
            raise SystemExit(f"watch falló al arrancar (contenedor intacto): {exc}") from exc
        reason = "error"
    finally:
        if ready:
            _finalize(
                cfg,
                sandbox,
                {"root": root},
                events,
                sidecar,
                stats,
                reason,
                mode,
                resolved,
            )
        else:
            clear_watch_pid(root)
    return 0 if reason == "completed" else 1


def cmd_attach(cfg: Config, run_id: str | None) -> int:
    rid = resolve_run_id(cfg, run_id)
    meta = read_meta(cfg.runs_dir() / rid)
    name = meta.get("container") or f"aegis-run-{rid}"
    if not running(name):
        raise SystemExit(f"run {rid} no está vivo (contenedor {name} ausente)")
    serve = _serve_info(cfg.runs_dir() / rid)
    url = f"http://127.0.0.1:{serve['port']}"
    print(f"aegis: attach TUI OpenCode {url} @ {name}", file=sys.stderr)
    return exec_it(
        name,
        [
            "opencode",
            "attach",
            url,
            "--username",
            serve.get("user", "aegis"),
            "--password",
            serve.get("password", ""),
            "--dir",
            "/workspace",
        ],
    )


def cmd_status(cfg: Config, run_id: str | None) -> int:
    rid = resolve_run_id(cfg, run_id)
    root = cfg.runs_dir() / rid
    meta = read_meta(root)
    print(f"run-id: {rid}")
    if meta.get("title"):
        print(f"title:  {meta.get('title')}")
    print(f"status: {meta.get('status')} reason={meta.get('reason') or '-'}")
    print(f"mode:   {meta.get('mode')}  model={meta.get('model')}")
    ssh_host = str(meta.get("ssh_host") or "").strip()
    if ssh_host:
        ssh_user = str(meta.get("ssh_user") or "").strip()
        print(f"ssh:    {ssh_user + '@' if ssh_user else ''}{ssh_host}")
    print(f"out:    {root}")
    print_live_stats(root / "stats.json")
    return 0


def _force_abort_teardown(name: str, root: Path) -> None:
    """chown + docker rm fuera del request HTTP («cortar ya»)."""
    try:
        reclaim_out(name, root)
    except Exception:
        pass
    destroy(name)


def cmd_abort(cfg: Config, run_id: str | None) -> int:
    rid = resolve_run_id(cfg, run_id)
    root = cfg.runs_dir() / rid
    meta = read_meta(root)
    name = str(meta.get("container") or f"aegis-run-{rid}")
    st = container_state(name)
    alive = bool(st.get("running") or st.get("paused"))
    paused = bool(st.get("paused") or (root / PAUSE_REASON).is_file())
    already = doc_grace_started(root)
    ended = str(meta.get("status") or "") == "ended" or bool(end_reason_of(root))
    if alive and not paused and not already and not force_end_requested(root) and not ended:
        begin_doc_grace(root, "abort", cut=True)
        print(
            f"aegis: cierre {rid}; documenta y escribe .doc-done (tope {DOC_GRACE_S}s; cancelar otra vez corta)",
            file=sys.stderr,
        )
        return 0
    (root / FORCE_END).write_text("1\n", encoding="utf-8")
    (root / "ABORT").write_text("abort\n", encoding="utf-8")
    print(f"aegis: abort {rid} ({name})", file=sys.stderr)
    # Hueco libre YA. chown + docker rm -f son ~15s y no pueden tapar la UI.
    release_live_slot(cfg, root, reason="abort", run_id=rid)
    threading.Thread(
        target=_force_abort_teardown,
        args=(name, root),
        daemon=True,
        name=f"aegis-abort-{rid}",
    ).start()
    try:
        close_and_report(
            root,
            mode=str(meta.get("mode") or "full"),
            model=str(meta.get("model") or ""),
            run_id=rid,
            quick=True,
        )
    except Exception as exc:
        print(f"aegis: abort informe: {exc}", file=sys.stderr)
        try:
            ensure_reports(
                root,
                mode=str(meta.get("mode") or "full"),
                model=str(meta.get("model") or ""),
                run_id=rid,
                polish=False,
            )
        except Exception:
            pass
    return 0


def cmd_report(cfg: Config, run_id: str | None) -> int:
    rid = resolve_run_id(cfg, run_id)
    root = cfg.runs_dir() / rid
    meta = read_meta(root)
    ensure_reports(root, mode=meta.get("mode", "full"), model=meta.get("model", ""), run_id=rid)
    md = root / "report.md"
    print(md.read_text(encoding="utf-8"))
    print(f"\n---\njson: {root / 'report.json'}", file=sys.stderr)
    return 0


def cmd_steer(cfg: Config, run_id: str | None, text: str) -> int:
    rid = resolve_run_id(cfg, run_id)
    dest = write_steer(cfg.runs_dir() / rid, text)
    print(f"steer: {dest}")
    return 0


def cmd_list(cfg: Config) -> int:
    runs_dir = cfg.runs_dir()
    if not runs_dir.is_dir():
        print("sin runs")
        return 0
    rows = []
    for meta_path in sorted(runs_dir.glob("*/meta.json")):
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        targets = ",".join(
            (t.get("value") or "") for t in (meta.get("targets") or [])
        )
        label = (meta.get("title") or meta.get("run_id") or "")[:28]
        rows.append(
            f"{label:<28} {meta.get('run_id'):<24} {meta.get('mode', ''):<7} "
            f"{meta.get('status', ''):<10} {meta.get('model_alias', ''):<8} "
            f"{targets[:40]}"
        )
    print("TITLE                        RUN_ID                   MODE    STATUS     MODEL    TARGETS")
    print("\n".join(rows) if rows else "(vacío)")
    return 0


def cmd_rename(cfg: Config, run_id: str | None, title: str) -> int:
    rid = resolve_run_id(cfg, run_id)
    try:
        clean = set_run_title(cfg.runs_dir() / rid, title)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc
    print(f"run-id: {rid}")
    print(f"title:  {clean or '(sin título)'}")
    return 0


def _serve_info(root: Path) -> dict:
    p = root / ".serve"
    if p.is_file():
        return json.loads(p.read_text(encoding="utf-8"))
    meta = read_meta(root)
    return {"port": meta.get("serve_port"), "user": "aegis", "password": ""}
