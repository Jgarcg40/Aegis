from __future__ import annotations

import ipaddress
import json
import os
import re
import socket
import subprocess
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from internal.config import Config
from internal.inbox import (
    InboxError,
    INBOX_ID_RE,
    list_files,
    remove_staging,
    staging_dir,
    sweep_stale,
)
from internal.jobs import write_steer
from internal.report import _is_noise_argv, load_findings
from internal.conscience import public_status
from internal.flagspec import build_contract, finding_is_draft, load_contract
from internal.run import (
    _RUN_DIR_RE,
    adopt_live,
    cmd_abort,
    doc_grace_info,
    live_id,
    normalize_title,
    read_meta,
    reap_live,
    remove_run_dir,
    set_live,
    set_run_title,
    watch_pid_alive,
    write_meta_dict,
)
from internal.sandbox import container_state, pause as docker_pause, running, unpause as docker_unpause
from internal.telemetry import usage_from_console

ROOT = Path(__file__).resolve().parents[1]
AEGIS_BIN = ROOT / "aegis"

SCRIPT_SUFFIXES = {
    ".py", ".sh", ".bash", ".zsh", ".rb", ".ps1", ".go", ".c", ".cpp", ".h",
    ".pl", ".php", ".js", ".ts", ".rs", ".java", ".lua", ".sql", ".yaml", ".yml",
}
TEXT_SUFFIXES = SCRIPT_SUFFIXES | {
    ".txt", ".md", ".json", ".log", ".csv", ".xml", ".html", ".htm", ".ini",
    ".conf", ".cfg", ".toml", ".env", ".list", ".nmap", ".gnmap", ".diff", ".patch",
    ".hdr", ".iv", ".key", ".ct", ".out", ".err",
}
# internos: ocultos por defecto en Archivos
SYSTEM_NAMES = {
    "meta.json", "events.jsonl", "console.log", "stats.json", "report.md",
    "report.json", "brief.md", "brief.json", "session.opencode.json",
    "opencode-stats.txt", "last-message.txt", "ABORT",
    ".agent-pid", ".end-reason", ".conscience-backend.json",
    ".conscience-pause", ".pause-reason", ".ctf-complete-at",
    ".ctf-doc-noted", ".backup-used",
    ".doc-grace-at", ".doc-grace-why", ".doc-grace-steer", ".doc-grace-noted",
    ".doc-grace-cut", ".doc-done", ".force-end", ".ctf-doc-steer",
}
# password del server OpenCode: no servir ni listar
SECRET_NAMES = {".serve"}

_PTR_CACHE: dict[str, str] = {}

# -oN de nmap no cuenta. Cada orden va en su línea.
_DOWNLOAD_TOOL_RE = re.compile(
    r"(?i)\b(?P<tool>wget|curl|aria2c)\b(?P<body>[^\n;|&]*)"
)
_DOWNLOAD_OUT_RE = re.compile(
    r"(?i)(?:^|\s)(?:-O\b|--remote-name\b|--output(?:=|\s)|-o(?![A-Za-z])(?:=|\s))"
)
_DNS_LINE_RE = re.compile(
    r"(?:^|[;&|\n])\s*(?:sudo\s+)?(?P<tool>dig|nslookup|host|getent\s+hosts|resolvectl|drill)\b(?P<body>[^\n;&|]*)",
    re.I,
)
_URL_RE = re.compile(r"https?://([A-Za-z0-9._-]+)(?::(\d+))?", re.I)
_FULL_URL_RE = re.compile(r"https?://[^\s'\"<>]+", re.I)
_HTTP_CLIENT_RE = re.compile(r"urllib|requests\.|http\.client|urlopen|aiohttp|httpx\.", re.I)
# URL armada: http://{host} o "http://" + host.
_BUILT_HTTP_RE = re.compile(r"""(?i)https?://(?:\{|['\"]\s*\+|%[\(\{])""")
_QUOTED_HOST_RE = re.compile(
    r"""['\"]((?:\d{1,3}(?:\.\d{1,3}){3})|[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,62}[A-Za-z0-9])?)+)['\"]"""
)
_ANNOUNCED_URL_RE = re.compile(
    r"(?i)^(?:\s*(?:GET|POST|HEAD|PUT|DELETE|URL|FETCH|REQUEST)\b\s*[:=]?\s*)?(https?://\S+)\s*$"
)
_DOMAIN_RE = re.compile(r"\b([a-z][a-z0-9-]*\.(?:[a-z0-9-]+\.)*[a-z]{2,})\b", re.I)
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?\b")
_NET_CALL_RE = re.compile(
    r"(?P<tool>curl|wget|aria2c|nmap|masscan|rustscan|ffuf|gobuster|feroxbuster|wfuzz|dirb|hydra|httpx|nikto|sqlmap|nuclei|whatweb|smbclient|showmount|ncat|nc)\b(?P<body>[^\n;&|]*)",
    re.I,
)
_CURL_PAYLOAD_RE = re.compile(
    r"(?:^|\s)(?:-[dHebuAToFwF]|--(?:data(?:-raw|-binary|-ascii|-urlencode)?|json|header|cookie|user-agent|referer|user|upload-file|output|write-out|resolve|cert|form))\s+(?:\"[^\"]*\"|'[^']*'|\S+)",
    re.I,
)
_HOST_HDR_RE = re.compile(r"(?i)(?:-H|--header)\s+[\"']?Host:\s*([A-Za-z0-9._-]+)")
_SCOPE_RANK = {"internal": 0, "external": 1, "local": 2}
_NOISE_ARGV = {"", "{}", "[]", "None", "null", "()", "none"}
def _normalize_ts(ts: Any) -> str:
    """OpenCode manda epoch ms (int); events.jsonl usa ISO. La UI espera ISO o ms."""
    if ts is None or ts == "":
        return ""
    if isinstance(ts, (int, float)):
        n = float(ts)
        if n > 1e12:
            n /= 1000.0
        try:
            return datetime.fromtimestamp(n, timezone.utc).isoformat()
        except (OSError, OverflowError, ValueError):
            return ""
    s = str(ts).strip()
    if re.fullmatch(r"\d{10,13}(?:\.\d+)?", s):
        return _normalize_ts(float(s))
    return s


_LOOPBACKISH = re.compile(
    r"^(127\.|0\.0\.0\.0$|localhost|::1$|0x7f|0177|2130706433$|\d+$)",
    re.I,
)


@dataclass
class QueueItem:
    qid: str
    target: str
    mode: str
    model: str
    model_id: str
    endpoint: str
    note: str
    timeout: str
    authorized: bool
    enqueued_at: float
    harness: str = "opencode"
    backup_harness: str = ""
    backup_model: str = ""
    rescue_model: str = ""
    rescue_harness: str = ""
    persist: bool = True
    resume: str = ""
    title: str = ""
    ctf: bool = False
    flags: list = field(default_factory=list)
    flag_count: int = 0
    ssh_host: str = ""
    ssh_user: str = ""
    ssh_pass: str = ""
    exploit_mgmt: bool = False
    inbox: str = ""
    state: str = "queued"  # queued | launching | running | done
    run_id: str = ""
    error: str = ""


def _public_queue_item(item: QueueItem) -> dict:
    row = asdict(item)
    if row.get("ssh_pass"):
        row["ssh_pass"] = "****"
    return row


def _queue_disk_row(item: QueueItem) -> dict:
    """Cola en disco: nunca la contraseña SSH."""
    row = asdict(item)
    row.pop("ssh_pass", None)
    return row


class RunManager:
    """Cola persistente + un run vivo a la vez + supervisor."""

    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        self.lock = threading.RLock()
        self.web_dir = cfg.data_dir / "web"
        self.web_dir.mkdir(parents=True, exist_ok=True)
        self.queue_path = cfg.data_dir / "queue.json"
        self.queue: list[QueueItem] = self._load_queue()
        self._proc: subprocess.Popen | None = None
        self._current: QueueItem | None = None
        self._stop = threading.Event()
        self._sup = threading.Thread(target=self._supervise, name="aegis-web-sup", daemon=True)
        # stats de históricos: el polling reescanea todos los runs
        self._stats_cache: dict[str, tuple] = {}
        self._stats_lock = threading.Lock()
        self._findings_stats_cache: dict[str, tuple] = {}
        self._ctf_got_cache: dict[str, tuple] = {}
        self._mission_cache: dict[str, tuple] = {}
        self._mission_lock = threading.Lock()
        self._detail_cache: dict[str, tuple] = {}
        self._detail_locks: dict[str, threading.Lock] = {}
        self._list_cache: tuple | None = None
        self._list_lock = threading.Lock()

    def start(self) -> None:
        # listen() va en el proceso; reap e informe, en el supervisor.
        self._save_queue()
        self._sweep_inboxes()
        if not self._sup.is_alive():
            self._sup.start()

    def stop(self) -> None:
        self._stop.set()

    def _load_queue(self) -> list[QueueItem]:
        if not self.queue_path.is_file():
            return []
        try:
            raw = json.loads(self.queue_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return []
        items = []
        for r in raw if isinstance(raw, list) else []:
            try:
                rec = dict(r)
                rec.setdefault("harness", "opencode")
                rec.setdefault("backup_harness", "")
                rec.setdefault("backup_model", "")
                rec.setdefault("rescue_model", "")
                rec.setdefault("rescue_harness", "")
                rec.setdefault("resume", "")
                rec.setdefault("title", "")
                rec.setdefault("ctf", False)
                rec.setdefault("flags", [])
                rec.setdefault("flag_count", 0)
                rec.setdefault("ssh_host", "")
                rec.setdefault("ssh_user", "")
                rec.pop("ssh_pass", None)
                rec["ssh_pass"] = ""
                rec.setdefault("exploit_mgmt", False)
                rec.setdefault("inbox", "")
                rec.pop("lab", None)
                rec.pop("token_budget", None)
                rec.pop("turn_budget", None)
                items.append(QueueItem(**rec))
            except TypeError:
                continue
        # sin Popen al arrancar: el qid del run vivo no vuelve a la cola
        live = live_id(self.cfg)
        kept: list[QueueItem] = []
        for it in items:
            if live and it.run_id == live:
                continue
            if it.run_id and self._run_already_ended(it.run_id):
                continue
            if it.state in {"launching", "running"}:
                it.state = "queued"
            if it.state == "queued":
                kept.append(it)
        return kept

    def _run_already_ended(self, run_id: str) -> bool:
        root = self.cfg.runs_dir() / run_id
        if not root.is_dir() or not (root / "meta.json").is_file():
            return True
        if (root / ".end-reason").is_file() or (root / "ABORT").is_file():
            return True
        try:
            meta = read_meta(root)
        except (SystemExit, json.JSONDecodeError, OSError, TypeError):
            return True
        return str(meta.get("status") or "") == "ended"

    def _save_queue(self) -> None:
        data = [_queue_disk_row(it) for it in self.queue]
        tmp = self.queue_path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(self.queue_path)

    def _invalidate_run_views(self, run_id: str = "") -> None:
        with self._stats_lock:
            self._list_cache = None
            if run_id:
                self._detail_cache.pop(run_id, None)
            else:
                self._detail_cache.clear()

    def enqueue(self, params: dict[str, Any]) -> QueueItem:
        if not params.get("authorized"):
            raise ValueError("authorized:true es obligatorio (--i-am-authorized)")
        from internal.brief import validate_mode_launch
        from internal.sshjump import SshJumpError, resolve_ssh_launch
        from internal.targets import parse_targets

        ctf = bool(params.get("ctf"))
        mode = str(params.get("mode") or "full")
        exploit_mgmt = bool(params.get("exploit_mgmt"))
        ssh_host = str(params.get("ssh_host") or "").strip()
        ssh_user = str(params.get("ssh_user") or "").strip()
        ssh_pass = str(params.get("ssh_pass") or "")
        try:
            title = normalize_title(str(params.get("title") or ""))
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        try:
            target, _jump = resolve_ssh_launch(
                target_spec=str(params.get("target") or ""),
                ctf=ctf,
                ssh_host=ssh_host,
                ssh_user=ssh_user,
                ssh_pass=ssh_pass,
                resume=bool(params.get("resume")),
            )
        except SshJumpError as exc:
            raise ValueError(str(exc)) from exc
        try:
            validate_mode_launch(
                mode=mode,
                targets=parse_targets(target) if (target or "").strip() else [],
                ctf=ctf,
                exploit_mgmt=exploit_mgmt,
            )
        except ValueError as exc:
            raise ValueError(str(exc)) from exc
        raw_flags = params.get("flags") or []
        if isinstance(raw_flags, str):
            raw_flags = [x.strip() for x in raw_flags.split(",") if x.strip()]
        flags = [str(x).strip() for x in raw_flags if str(x).strip()]
        flag_count = int(params.get("flag_count") or 0)
        if ctf:
            n = flag_count or (len(flags) if flags else 2)
            build_contract(enabled=True, flags=flags, count=n)
            flag_count = n
        inbox_id = str(params.get("inbox") or "").strip()
        if inbox_id:
            if not INBOX_ID_RE.match(inbox_id):
                raise ValueError("inbox inválido")
            staged = staging_dir(self.cfg, inbox_id)
            if not list_files(staged):
                raise ValueError("el inbox no tiene anexos")
        item = QueueItem(
            qid=f"q-{int(time.time()*1000)}-{len(self.queue)}",
            target=target,
            mode=mode,
            model=str(params.get("model") or self.cfg.default_model),
            model_id=str(params.get("model_id") or ""),
            endpoint=str(params.get("endpoint") or ""),
            note=str(params.get("note") or ""),
            timeout=str(params.get("timeout") or self.cfg.timeout),
            authorized=True,
            enqueued_at=time.time(),
            harness=str(params.get("harness") or "opencode"),
            backup_harness=str(params.get("backup_harness") or ""),
            backup_model=str(params.get("backup_model") or ""),
            rescue_model=str(params.get("rescue_model") or ""),
            rescue_harness=str(params.get("rescue_harness") or ""),
            persist=bool(params.get("persist", True)),
            resume=str(params.get("resume") or ""),
            title=title,
            ctf=ctf,
            flags=flags,
            flag_count=flag_count,
            ssh_host=ssh_host,
            ssh_user=ssh_user,
            ssh_pass=ssh_pass,
            exploit_mgmt=exploit_mgmt and mode == "net",
            inbox=inbox_id,
        )
        with self.lock:
            if self._target_already_pending(item.target):
                raise ValueError(
                    f"ya hay un run o un puesto en cola para {item.target}; "
                    "cancela ese o espera, no se encola un clon"
                )
            self.queue.append(item)
            self._save_queue()
        self._try_advance()
        self._invalidate_run_views()
        return item

    def _target_already_pending(self, target: str) -> bool:
        want = (target or "").strip()
        if not want:
            return False
        for it in self.queue:
            if it.state in {"queued", "launching", "running"} and it.target.strip() == want:
                return True
        rid = live_id(self.cfg)
        if not rid:
            return False
        root = self.cfg.runs_dir() / rid
        # Cortar ya deja ABORT/.end-reason al instante; no bloquear el target
        # mientras se escribe el informe.
        if (root / "ABORT").is_file() or (root / ".end-reason").is_file():
            return False
        try:
            meta = read_meta(root)
        except SystemExit:
            return False
        for t in meta.get("targets") or []:
            if isinstance(t, dict) and str(t.get("value") or "").strip() == want:
                return True
        return False

    def dequeue(self, qid: str) -> bool:
        with self.lock:
            if self._current and self._current.qid == qid:
                return False
            before = len(self.queue)
            dropped = [it for it in self.queue if it.qid == qid]
            self.queue = [it for it in self.queue if it.qid != qid]
            changed = len(self.queue) != before
            if changed:
                self._save_queue()
            for it in dropped:
                self._discard_inbox(it.inbox)
            return changed

    def queue_view(self) -> list[dict]:
        self._sweep_dead_queue()
        with self.lock:
            rows = [_public_queue_item(it) for it in self.queue]
            cur = self._current
            if cur is not None and not any(it.qid == cur.qid for it in self.queue):
                rows.append(_public_queue_item(cur))
            return rows

    def current_view(self) -> dict | None:
        with self.lock:
            if self._current:
                return _public_queue_item(self._current)
        rid = adopt_live(self.cfg) or live_id(self.cfg)
        if rid:
            return {"run_id": rid, "state": "running", "qid": "", "external": True}
        return None

    def _busy(self) -> bool:
        # Sidecar de un run ya cerrado no ocupa el hueco.
        proc_up = self._proc is not None and self._proc.poll() is None
        if proc_up:
            cur = self._current
            if cur is not None and not str(cur.run_id or "").strip():
                return True
            owned = str((cur.run_id if cur else "") or "").strip() or (live_id(self.cfg) or "")
            if owned and not self._run_already_ended(owned):
                return True
        rid = live_id(self.cfg)
        if not rid:
            return False
        root = self.cfg.runs_dir() / rid
        if not root.is_dir() or not (root / "meta.json").is_file():
            set_live(self.cfg, None)
            return False
        if self._run_already_ended(rid):
            set_live(self.cfg, None)
            return False
        try:
            meta = read_meta(root)
        except (SystemExit, json.JSONDecodeError, OSError, TypeError):
            set_live(self.cfg, None)
            return False
        if not isinstance(meta, dict):
            set_live(self.cfg, None)
            return False
        return str(meta.get("status") or "") != "ended"

    def _detach_closed_sidecar(self) -> None:
        """Quita de la cola un run ya cerrado. El host puede seguir escribiendo."""
        cur = self._current
        if cur is None or not str(cur.run_id or "").strip():
            return
        if not self._run_already_ended(cur.run_id):
            return
        self.queue = [it for it in self.queue if it.qid != cur.qid]
        self._save_queue()
        self._current = None
        self._proc = None

    def _try_advance(self) -> None:
        with self.lock:
            if self._stop.is_set() or self._busy():
                return
            self._detach_closed_sidecar()
            nxt = next((it for it in self.queue if it.state == "queued"), None)
            if nxt is None:
                return
            self._launch(nxt)

    def _launch(self, item: QueueItem) -> None:
        item.state = "launching"
        self._save_queue()
        log = self.web_dir / f"launch-{item.qid}.log"
        argv = [
            sys.executable,
            str(AEGIS_BIN),
            "run",
            "--target",
            item.target,
            "--mode",
            item.mode,
            "--model",
            item.model,
            "--timeout",
            item.timeout,
            "--i-am-authorized",
            "--harness",
            item.harness or "opencode",
        ]
        if item.model_id:
            argv += ["--model-id", item.model_id]
        if item.endpoint:
            argv += ["--endpoint", item.endpoint]
        if item.note:
            argv += ["--note", item.note]
        if item.inbox:
            argv += ["--inbox", str(staging_dir(self.cfg, item.inbox))]
        if not item.persist:
            argv += ["--no-persist"]
        if item.backup_model:
            argv += ["--backup-model", item.backup_model]
            if item.backup_harness:
                argv += ["--backup-harness", item.backup_harness]
        if item.rescue_model:
            argv += ["--rescue-model", item.rescue_model]
            if item.rescue_harness:
                argv += ["--rescue-harness", item.rescue_harness]
        if item.resume:
            argv += ["--resume", item.resume]
        if item.title:
            argv += ["--title", item.title]
        if item.ctf:
            argv += ["--ctf"]
            n = item.flag_count or (len(item.flags) if item.flags else 2)
            argv += ["--flag-count", str(n)]
            for fl in item.flags:
                argv += ["--flag", fl]
        env = os.environ.copy()
        if item.exploit_mgmt:
            argv += ["--exploit-mgmt"]
        if item.ssh_host:
            argv += ["--ssh-host", item.ssh_host]
            if item.ssh_user:
                argv += ["--ssh-user", item.ssh_user]
            if item.ssh_pass:
                env["AEGIS_SSH_PASS"] = item.ssh_pass
        fh = log.open("w", encoding="utf-8")
        try:
            self._proc = subprocess.Popen(
                argv,
                cwd=str(ROOT),
                stdout=fh,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
                env=env,
            )
        except OSError as exc:
            item.state = "queued"
            item.error = str(exc)
            self._save_queue()
            fh.close()
            return
        self._current = item
        threading.Thread(
            target=self._resolve_run_id, args=(item, log), name="aegis-web-rid", daemon=True
        ).start()

    def _resolve_run_id(self, item: QueueItem, log: Path) -> None:
        deadline = time.time() + 180
        while time.time() < deadline:
            try:
                for line in log.read_text(encoding="utf-8").splitlines():
                    if line.startswith("run-id:"):
                        rid = line.split(":", 1)[1].strip()
                        with self.lock:
                            item.run_id = rid
                            item.state = "running"
                            self._save_queue()
                        self._invalidate_run_views(rid)
                        return
            except OSError:
                pass
            if self._proc and self._proc.poll() is not None:
                return
            time.sleep(0.5)

    def _supervise(self) -> None:
        while not self._stop.is_set():
            try:
                reaped = reap_live(self.cfg)
            except Exception:
                reaped = None
            try:
                adopt_live(self.cfg)
            except Exception:
                pass
            if reaped:
                # no arrancar el clon encolado al cerrar (doble envío)
                self._drop_queued_for_targets(self._targets_of_run(reaped))
            self._sweep_dead_queue()
            finished_rid = ""
            died = False
            with self.lock:
                if self._proc is not None and self._proc.poll() is not None:
                    died = True
                    finished = self._current
                    self._proc = None
                    self._current = None
                else:
                    finished = None
            if died:
                if self._reattach_live():
                    time.sleep(1.5)
                    continue
            if not self._proc_alive():
                if self._reattach_live():
                    time.sleep(1.5)
                    continue
                if finished is not None:
                    finished_rid = self._forget_queue_item(finished)
            if finished_rid:
                self._drop_queued_for_targets(self._targets_of_run(finished_rid))
            self._try_advance()
            time.sleep(1.5)

    def _proc_alive(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def _reattach_live(self) -> bool:
        """Si el contenedor sigue up y el sidecar del host murió, lanza `aegis watch`."""
        if self._proc_alive():
            return True
        rid = live_id(self.cfg)
        if not rid:
            return False
        root = self.cfg.runs_dir() / rid
        try:
            meta = read_meta(root)
        except SystemExit:
            return False
        if str(meta.get("status") or "") == "ended":
            return False
        name = str(meta.get("container") or f"aegis-run-{rid}")
        if not running(name):
            return False
        if watch_pid_alive(root):
            return True
        return self._spawn_watch(rid, meta)

    def _spawn_watch(self, rid: str, meta: dict) -> bool:
        log = self.web_dir / f"watch-{rid}.log"
        argv = [sys.executable, str(AEGIS_BIN), "watch", "--supervise", rid]
        try:
            fh = log.open("a", encoding="utf-8")
        except OSError:
            return False
        try:
            self._proc = subprocess.Popen(
                argv,
                cwd=str(ROOT),
                stdout=fh,
                stderr=subprocess.STDOUT,
                text=True,
                start_new_session=True,
            )
        except OSError:
            fh.close()
            return False
        target = ""
        for row in meta.get("targets") or []:
            if isinstance(row, dict):
                target = str(row.get("value") or row.get("raw") or "")
                if target:
                    break
        self._current = QueueItem(
            qid=f"watch-{rid}",
            target=target,
            mode=str(meta.get("mode") or "full"),
            model=str(meta.get("model") or ""),
            model_id="",
            endpoint="",
            note="",
            timeout=str(self.cfg.timeout),
            authorized=True,
            enqueued_at=time.time(),
            harness=str(meta.get("harness") or "opencode"),
            state="running",
            run_id=rid,
            title=str(meta.get("title") or ""),
        )
        return True

    def _targets_of_run(self, run_id: str) -> set[str]:
        targets: set[str] = set()
        if not run_id:
            return targets
        try:
            meta = read_meta(self.cfg.runs_dir() / run_id)
        except SystemExit:
            return targets
        for t in meta.get("targets") or []:
            if isinstance(t, dict) and t.get("value"):
                targets.add(str(t["value"]).strip())
        return targets

    def _drop_queued_for_targets(self, targets: set[str]) -> None:
        if not targets:
            return
        dropped: list[QueueItem] = []
        with self.lock:
            keep = []
            for it in self.queue:
                if it.state == "queued" and it.target.strip() in targets:
                    dropped.append(it)
                else:
                    keep.append(it)
            if dropped:
                self.queue = keep
                self._save_queue()
        for it in dropped:
            self._discard_inbox(it.inbox)

    def _discard_inbox(self, inbox_id: str) -> None:
        if inbox_id:
            remove_staging(self.cfg, inbox_id)

    def _inbox_keep(self) -> set[str]:
        ids = {it.inbox for it in self.queue if it.inbox}
        if self._current and self._current.inbox:
            ids.add(self._current.inbox)
        return ids

    def _sweep_inboxes(self) -> None:
        sweep_stale(self.cfg, keep=self._inbox_keep())

    def create_inbox(self) -> dict:
        from internal.inbox import create_staging

        self._sweep_inboxes()
        iid = create_staging(self.cfg)
        return {"id": iid, "files": []}

    def inbox_files(self, inbox_id: str) -> list[dict]:
        folder = staging_dir(self.cfg, inbox_id)
        if not folder.is_dir():
            raise InboxError("inbox no encontrado")
        return list_files(folder)

    def add_inbox_file(self, inbox_id: str, name: str, reader, length: int) -> dict:
        from internal.inbox import add_file

        try:
            return add_file(self.cfg, inbox_id, name, reader, length)
        except InboxError as exc:
            raise ValueError(str(exc)) from exc

    def drop_inbox(self, inbox_id: str) -> None:
        if inbox_id in self._inbox_keep():
            raise ValueError("ese inbox ya está en cola")
        self._discard_inbox(inbox_id)

    def _forget_queue_run(self, run_id: str) -> None:
        if not run_id:
            return
        with self.lock:
            keep = [it for it in self.queue if it.run_id != run_id]
            if self._current is not None and self._current.run_id == run_id:
                self._current = None
            if len(keep) != len(self.queue):
                self.queue = keep
                self._save_queue()

    def _forget_queue_item(self, item: QueueItem | None) -> str:
        """Quita el ítem de cola. Devuelve run_id si lo había (para dropear clones)."""
        if item is None:
            return ""
        rid = item.run_id or ""
        item.state = "done"
        with self.lock:
            self.queue = [it for it in self.queue if it.qid != item.qid]
            self._save_queue()
        self._discard_inbox(item.inbox)
        return rid

    def _sweep_dead_queue(self) -> None:
        live = live_id(self.cfg)
        with self.lock:
            keep = []
            changed = False
            for it in self.queue:
                if it.run_id and it.run_id != live and self._run_already_ended(it.run_id):
                    changed = True
                    self._discard_inbox(it.inbox)
                    continue
                # launch fallido (sin run_id, ya no current): no bloquear el target
                if (
                    it.state == "launching"
                    and not it.run_id
                    and (self._current is None or self._current.qid != it.qid)
                ):
                    changed = True
                    self._discard_inbox(it.inbox)
                    continue
                keep.append(it)
            if changed:
                self.queue = keep
                self._save_queue()

    def abort(self, run_id: str) -> dict:
        targets = self._targets_of_run(run_id)
        cmd_abort(self.cfg, run_id)
        closing = not self._run_already_ended(run_id)
        if not closing:
            self._forget_queue_run(run_id)
            # no arrancar el clon encolado (doble envío)
            self._drop_queued_for_targets(targets)
        return {"ok": True, "closing": closing}

    def _container_name(self, run_id: str) -> str:
        root = self.cfg.runs_dir() / run_id
        try:
            meta = read_meta(root)
            return meta.get("container") or f"aegis-run-{run_id}"
        except SystemExit:
            return f"aegis-run-{run_id}"

    def _mark_paused_since(self, run_id: str) -> None:
        from internal.sessioncap import mark_open_pause

        mark_open_pause(self.cfg.runs_dir() / run_id)

    def _clear_paused_since(self, run_id: str) -> None:
        from internal.sessioncap import fold_open_pause, mark_open_pause

        root = self.cfg.runs_dir() / run_id
        # Sin paused_since (tope de sesión armado solo con el flag): ábrelo
        # desde el mtime del flag para no perder el tramo al reanudar.
        try:
            meta = read_meta(root)
        except SystemExit:
            meta = {}
        if not str(meta.get("paused_since") or "").strip():
            flag = root / ".pause-reason"
            if flag.is_file():
                try:
                    stamp = datetime.fromtimestamp(flag.stat().st_mtime, tz=timezone.utc)
                    mark_open_pause(root, now=stamp)
                except OSError:
                    pass
        fold_open_pause(root)

    def pause(self, run_id: str) -> bool:
        st = container_state(self._container_name(run_id))
        if not st.get("running"):
            raise ValueError("el run no está vivo")
        root = self.cfg.runs_dir() / run_id
        flag = root / ".pause-reason"
        # El wait loop del host despausa si no hay este flag. Sin él,
        # el botón Pausar congela el contenedor un segundo y lo suelta.
        if not flag.is_file():
            flag.write_text("user\n", encoding="utf-8")
        if st.get("paused"):
            self._mark_paused_since(run_id)
            self._invalidate_run_views(run_id)
            return True
        if not docker_pause(self._container_name(run_id)):
            raise ValueError("docker pause falló")
        self._mark_paused_since(run_id)
        self._invalidate_run_views(run_id)
        return True

    def unpause(self, run_id: str) -> bool:
        name = self._container_name(run_id)
        root = self.cfg.runs_dir() / run_id
        self._clear_paused_since(run_id)
        pause_flag = root / ".pause-reason"
        if pause_flag.is_file():
            reason = ""
            try:
                reason = pause_flag.read_text(encoding="utf-8").strip()
            except OSError:
                reason = ""
            if reason == "auth":
                try:
                    from internal.claude import ensure_fresh_access, refresh_staged_claude

                    if ensure_fresh_access():
                        refresh_staged_claude(run_id)
                except Exception:
                    pass
            pause_flag.unlink(missing_ok=True)
        (root / ".session-resume-at").unlink(missing_ok=True)
        st = container_state(name)
        if not st.get("exists"):
            raise ValueError("el contenedor ya no existe")
        if not st.get("paused"):
            self._invalidate_run_views(run_id)
            return True
        if not docker_unpause(name):
            raise ValueError("docker unpause falló")
        self._invalidate_run_views(run_id)
        return True

    def steer(self, run_id: str, text: str, model_role: str = "") -> Path:
        root = self.cfg.runs_dir() / run_id
        if not root.is_dir():
            raise FileNotFoundError(run_id)
        if not str(text or "").strip():
            raise ValueError("steer vacío")
        role = str(model_role or "").strip().lower()
        if role and role not in {"primary", "rescue"}:
            raise ValueError("modelo de steer inválido")
        if role == "rescue" and not str(read_meta(root).get("rescue_model") or "").strip():
            raise ValueError("este run no tiene modelo de salvaguarda")
        dest = write_steer(root, text)
        # El entrypoint lee .steer-model en el próximo tick: fuerza principal o
        # relevo y sigue con la lógica normal de salvaguardas desde ahí.
        if role:
            (root / ".steer-model").write_text(role + "\n", encoding="utf-8")
        return dest

    def resume_run(self, run_id: str, extra: dict[str, Any] | None = None) -> QueueItem:
        root = self.cfg.runs_dir() / run_id
        if not root.is_dir():
            raise FileNotFoundError(run_id)
        if live_id(self.cfg) == run_id:
            raise ValueError("ese run sigue vivo; usa pausa/steer, no resume")
        meta = read_meta(root)
        targets = []
        for t in meta.get("targets") or []:
            if isinstance(t, dict):
                targets.append(t.get("raw") or t.get("value") or "")
        target = ",".join(x for x in targets if x)
        extra = extra or {}
        if not target:
            raise ValueError("el run no tiene targets en meta.json")
        contract = load_contract(root)
        if "ctf" in extra:
            ctf = bool(extra.get("ctf"))
        elif contract.get("enabled"):
            ctf = True
        else:
            ctf = bool(meta.get("ctf"))
        flags = extra.get("flags") or []
        if isinstance(flags, str):
            flags = [x.strip() for x in flags.split(",") if x.strip()]
        flags = [str(x).strip() for x in flags if str(x).strip()]
        if ctf and not flags:
            flags = [
                str(s.get("match") or "").strip()
                for s in (contract.get("slots") or [])
                if isinstance(s, dict) and str(s.get("match") or "").strip()
            ]
            if not flags:
                flags = [str(x).strip() for x in (meta.get("ctf_flags") or []) if str(x).strip()]
        try:
            flag_count = int(extra.get("flag_count") or 0)
        except (TypeError, ValueError):
            flag_count = 0
        if ctf and not flag_count:
            flag_count = len(flags) or int(meta.get("ctf_total") or 0) or 2
        if "exploit_mgmt" in extra:
            exploit_mgmt = bool(extra.get("exploit_mgmt"))
        else:
            exploit_mgmt = bool(meta.get("exploit_mgmt"))
        return self.enqueue(
            {
                "target": target,
                "mode": extra.get("mode") or meta.get("mode") or "full",
                "model": extra.get("model") or meta.get("model_alias") or meta.get("model") or "",
                "model_id": extra.get("model_id") or "",
                "endpoint": extra.get("endpoint") or "",
                "note": extra.get("note") or "",
                "timeout": extra.get("timeout") or self.cfg.timeout,
                "authorized": True,
                "harness": extra.get("harness") or meta.get("harness") or "opencode",
                "backup_harness": extra.get("backup_harness") or meta.get("backup_harness") or "",
                "backup_model": extra.get("backup_model") or meta.get("backup_model") or "",
                "rescue_model": extra.get("rescue_model") or meta.get("rescue_model") or "",
                "rescue_harness": extra.get("rescue_harness") or meta.get("rescue_harness") or "",
                "persist": bool(extra.get("persist", True)),
                "resume": run_id,
                "title": extra.get("title") if extra.get("title") is not None else (meta.get("title") or ""),
                "ctf": ctf,
                "flags": flags,
                "flag_count": flag_count,
                "ssh_host": extra.get("ssh_host") if extra.get("ssh_host") is not None else (meta.get("ssh_host") or ""),
                "ssh_user": extra.get("ssh_user") if extra.get("ssh_user") is not None else (meta.get("ssh_user") or ""),
                "ssh_pass": extra.get("ssh_pass") or "",
                "exploit_mgmt": exploit_mgmt,
                "inbox": extra.get("inbox") or "",
            }
        )

    def rename_run(self, run_id: str, title: str) -> dict:
        root = self.cfg.runs_dir() / run_id
        if not root.is_dir():
            raise FileNotFoundError(run_id)
        clean = set_run_title(root, title)
        meta = read_meta(root)
        meta["title"] = clean
        self._invalidate_run_views(run_id)
        return meta

    def delete_run(self, run_id: str) -> None:
        cur = self.current_view()
        if cur and cur.get("run_id") == run_id:
            raise ValueError("no puedes borrar el run vivo; aborta primero")
        root = self.cfg.runs_dir() / run_id
        if not root.is_dir():
            raise FileNotFoundError(run_id)
        try:
            meta = read_meta(root)
            if meta.get("status") == "running" and live_id(self.cfg) == run_id:
                raise ValueError("run en curso")
        except SystemExit:
            pass
        remove_run_dir(root, runs_dir=self.cfg.runs_dir(), image=self.cfg.image)
        self._invalidate_run_views(run_id)

    def delete_runs(self, run_ids: list[str]) -> dict[str, Any]:
        """Borra varios runs. El vivo se omite; el resto sigue aunque uno falle."""
        deleted: list[str] = []
        skipped: list[dict[str, str]] = []
        missing: list[str] = []
        errors: list[dict[str, str]] = []
        seen: set[str] = set()
        for raw in run_ids:
            rid = str(raw or "").strip()
            if not rid or rid in seen:
                continue
            seen.add(rid)
            try:
                self.delete_run(rid)
                deleted.append(rid)
            except FileNotFoundError:
                missing.append(rid)
            except ValueError as exc:
                skipped.append({"run_id": rid, "reason": str(exc)})
            except OSError as exc:
                errors.append({"run_id": rid, "reason": str(exc)})
        return {
            "ok": not errors,
            "deleted": deleted,
            "skipped": skipped,
            "missing": missing,
            "errors": errors,
        }

    def list_runs(self) -> list[dict]:
        now = time.monotonic()
        with self._stats_lock:
            hit = self._list_cache
            if hit and now - hit[0] < 2.0:
                return [dict(r) for r in hit[1]]
        with self._list_lock:
            now = time.monotonic()
            with self._stats_lock:
                hit = self._list_cache
                if hit and now - hit[0] < 2.0:
                    return [dict(r) for r in hit[1]]
            runs_dir = self.cfg.runs_dir()
            out: list[dict] = []
            if not runs_dir.is_dir():
                return out
            adopt_live(self.cfg)
            live = live_id(self.cfg)
            for meta_path in sorted(runs_dir.glob("*/meta.json"), reverse=True):
                try:
                    meta = json.loads(meta_path.read_text(encoding="utf-8"))
                except (OSError, json.JSONDecodeError):
                    cand = meta_path.parent.name
                    if not _RUN_DIR_RE.match(cand):
                        continue
                    st = container_state(f"aegis-run-{cand}")
                    if not (st.get("running") or st.get("paused")):
                        continue
                    meta = {
                        "run_id": cand,
                        "status": "running",
                        "title": cand,
                        "container": f"aegis-run-{cand}",
                    }
                is_live = meta.get("run_id") == live and str(meta.get("status") or "") != "ended"
                meta["live"] = is_live
                meta["paused"] = False
                meta["pause_reason"] = self._pause_reason(meta_path.parent)
                meta["pause_until"] = self._pause_until(meta_path.parent)
                if is_live:
                    st = container_state(meta.get("container") or f"aegis-run-{meta.get('run_id')}")
                    meta["paused"] = bool(st.get("paused") or meta["pause_reason"])
                    meta["doc_grace"] = doc_grace_info(meta_path.parent)
                    meta["conscience"] = public_status(
                        meta_path.parent, watcher=watch_pid_alive(meta_path.parent)
                    )
                meta["operator_note"] = self._operator_note(meta_path.parent)
                self._enrich_ctf(meta_path.parent, meta)
                meta["_stats"] = self._read_stats(meta_path.parent, light=True)
                out.append(meta)
            with self._stats_lock:
                self._list_cache = (time.monotonic(), out)
            return [dict(r) for r in out]

    def run_detail(self, run_id: str) -> dict:
        if live_id(self.cfg) == run_id:
            return self._run_detail_uncached(run_id)
        now = time.monotonic()
        with self._stats_lock:
            hit = self._detail_cache.get(run_id)
            if hit and now - hit[0] < 3.0:
                return hit[1]
            lock = self._detail_locks.get(run_id)
            if lock is None:
                lock = threading.Lock()
                self._detail_locks[run_id] = lock
        with lock:
            now = time.monotonic()
            with self._stats_lock:
                hit = self._detail_cache.get(run_id)
                if hit and now - hit[0] < 3.0:
                    return hit[1]
            meta = self._run_detail_uncached(run_id)
            with self._stats_lock:
                self._detail_cache[run_id] = (time.monotonic(), meta)
            return meta

    def _run_detail_uncached(self, run_id: str) -> dict:
        root = self.cfg.runs_dir() / run_id
        if not root.is_dir():
            raise FileNotFoundError(run_id)
        meta = self._read_json(root / "meta.json") or {"run_id": run_id}
        is_live = live_id(self.cfg) == run_id and str(meta.get("status") or "") != "ended"
        meta["live"] = is_live
        meta["paused"] = False
        meta["pause_reason"] = self._pause_reason(root)
        meta["pause_until"] = self._pause_until(root)
        if is_live:
            st = container_state(meta.get("container") or f"aegis-run-{run_id}")
            meta["paused"] = bool(st.get("paused") or meta["pause_reason"])
            meta["container_status"] = st.get("status")
            meta["doc_grace"] = doc_grace_info(root)
        meta["stats"] = self._read_stats(root)
        used = root / ".backup-used"
        if used.is_file():
            try:
                meta["backup_used"] = used.read_text(encoding="utf-8").strip()
            except OSError:
                pass
        meta["operator_note"] = self._operator_note(root)
        inbox_dir = root / "inbox"
        if inbox_dir.is_dir():
            n = 0
            nbytes = 0
            for p in inbox_dir.rglob("*"):
                if p.is_file() and not p.is_symlink():
                    n += 1
                    try:
                        nbytes += p.stat().st_size
                    except OSError:
                        pass
            meta["inbox_count"] = n
            meta["inbox_bytes"] = nbytes
        # run cerrado: sin watcher (evita «reloj muerto» / «atrasada»)
        watcher = watch_pid_alive(root) if is_live else None
        ended = str(meta.get("status") or "") == "ended"
        meta["conscience"] = public_status(root, watcher=watcher, ended=ended)
        md = root / "CONSCIENCE.md"
        if md.is_file():
            try:
                meta["conscience_md"] = md.read_text(encoding="utf-8", errors="replace")[:8000]
            except OSError:
                meta["conscience_md"] = ""
        self._enrich_ctf(root, meta)
        try:
            meta["mission"] = self._mission_view(root, ctf=bool(meta.get("ctf")))
        except Exception:
            meta["mission"] = {"timeline": [], "ctf": None, "notebook": {}, "graph": {}}
        # stats.json lo escribe el sidecar; no llamar docker stats en el request
        eng = self._read_json(root / "engagement.json")
        if isinstance(eng, dict):
            jobs = eng.get("_jobs")
            meta["jobs"] = jobs if isinstance(jobs, dict) else {}
        return meta

    def _enrich_ctf(self, root: Path, meta: dict) -> None:
        flags = [str(x) for x in (meta.get("ctf_flags") or []) if str(x).strip()]
        data = self._read_json(root / "ctf.json")
        brief = self._read_json(root / "brief.json")
        if isinstance(data, dict) and data.get("enabled"):
            enabled = True
            if not flags:
                flags = [
                    str(s.get("match") or "").strip()
                    for s in (data.get("slots") or [])
                    if isinstance(s, dict) and str(s.get("match") or "").strip()
                ]
        elif isinstance(brief, dict) and "ctf" in brief:
            enabled = bool(brief.get("ctf"))
        elif "ctf" in meta:
            enabled = bool(meta.get("ctf"))
        else:
            enabled = False
        if enabled and not flags:
            flags = ["user.txt", "root.txt"]
        meta["ctf"] = enabled
        meta["ctf_flags"] = flags
        if enabled:
            meta["ctf_got"] = self._ctf_got(root, data if isinstance(data, dict) else {}, flags)
            meta["ctf_total"] = len(flags)
        else:
            meta.pop("ctf_got", None)
            meta.pop("ctf_total", None)

    def _ctf_got(self, root: Path, contract: dict, flags: list[str]) -> int:
        """Slots cubiertos, no filas sueltas de engagement.flags (un hash extra no es 3/2)."""
        sig = (
            tuple(self._file_sig(root, ("engagement.json", "ctf.json"))),
            self._findings_signature(root),
            tuple(flags),
        )
        key = str(root)
        now = time.monotonic()
        with self._stats_lock:
            hit = self._ctf_got_cache.get(key)
            if hit and hit[0] == sig:
                return hit[1]
        got = self._ctf_got_uncached(root, contract, flags)
        with self._stats_lock:
            self._ctf_got_cache[key] = (sig, got, time.monotonic())
            if len(self._ctf_got_cache) > 256:
                self._ctf_got_cache.pop(next(iter(self._ctf_got_cache)))
        return got

    def _ctf_got_uncached(self, root: Path, contract: dict, flags: list[str]) -> int:
        slots = [s for s in (contract.get("slots") or []) if isinstance(s, dict)]
        if not slots:
            slots = [{"match": x} for x in flags]
        total = len(slots) or len(flags)
        if total <= 0:
            return 0
        pool: dict[str, int] = {}
        eng = self._read_json(root / "engagement.json")
        if isinstance(eng, dict):
            for row in eng.get("flags") or []:
                if not isinstance(row, dict) or not str(row.get("value") or "").strip():
                    continue
                k = str(row.get("kind") or "user").lower()
                if "root" in k or k in {"admin", "system", "proof"}:
                    bucket = "root"
                else:
                    bucket = "user"
                pool[bucket] = pool.get(bucket, 0) + 1
        got = 0
        for slot in slots:
            match = str(slot.get("match") or "").lower()
            bucket = "root" if any(x in match for x in ("root", "proof", "admin")) else "user"
            if pool.get(bucket, 0) > 0:
                pool[bucket] -= 1
                got += 1
        try:
            from internal.flagspec import found_count

            disk = found_count(root, contract if contract.get("enabled") else None)
        except Exception:
            disk = 0
        return min(max(got, disk), total)

    def _operator_note(self, root: Path) -> str:
        data = self._read_json(root / "brief.json")
        if not isinstance(data, dict):
            return ""
        return str(data.get("operator_note") or "").strip()

    @staticmethod
    def _pause_reason(root: Path) -> str:
        flag = root / ".pause-reason"
        if not flag.is_file():
            return ""
        try:
            return flag.read_text(encoding="utf-8", errors="replace").strip()
        except OSError:
            return ""

    @staticmethod
    def _pause_until(root: Path) -> int:
        flag = root / ".session-resume-at"
        if not flag.is_file():
            return 0
        try:
            raw = flag.read_text(encoding="utf-8", errors="replace").strip()
            ts = int(raw or 0)
        except (OSError, ValueError):
            return 0
        return ts if ts > 0 else 0

    def stats(self, run_id: str) -> dict:
        return self._read_stats(self.cfg.runs_dir() / run_id)

    @staticmethod
    def _file_sig(root: Path, rels: tuple[str, ...]) -> list:
        sig: list = []
        for rel in rels:
            try:
                st = (root / rel).stat()
                sig.append((rel, int(st.st_mtime_ns), st.st_size))
            except OSError:
                sig.append((rel, 0, 0))
        return sig

    @staticmethod
    def _findings_signature(root: Path) -> tuple:
        d = root / "findings"
        if not d.is_dir():
            return ()
        out: list = []
        try:
            for p in d.glob("F-*.json"):
                try:
                    st = p.stat()
                    out.append((p.name, int(st.st_mtime_ns), st.st_size))
                except OSError:
                    continue
        except OSError:
            return ()
        out.sort()
        return tuple(out)

    @staticmethod
    def _stats_signature(root: Path, *, light: bool = False) -> tuple:
        """Firma barata de las entradas de _read_stats: si no cambian, cache válida.

        En light no entra console.log: el run vivo lo reescribe cada poco y
        invalidaba findings/elapsed en cada poll de Historial.
        """
        rels = ("stats.json", "meta.json") if light else ("stats.json", "console.log", "meta.json")
        sig = RunManager._file_sig(root, rels)
        sig.append(("findings", RunManager._findings_signature(root)))
        return tuple(sig)

    def _mission_signature(self, root: Path) -> tuple:
        sig = self._file_sig(root, ("engagement.json", "events.jsonl", "ctf.json", "brief.json", "meta.json"))
        sig.append(("findings", self._findings_signature(root)))
        return tuple(sig)

    def _mission_view(self, root: Path, *, ctf: bool) -> dict:
        """mission_view lee findings varias veces; en un run vivo eso tumba la UI."""
        key = f"{root}|{int(ctf)}"
        sig = self._mission_signature(root)
        now = time.monotonic()
        with self._stats_lock:
            hit = self._mission_cache.get(key)
            if hit and hit[0] == sig:
                return hit[1]
        with self._mission_lock:
            now = time.monotonic()
            with self._stats_lock:
                hit = self._mission_cache.get(key)
                if hit and hit[0] == sig:
                    return hit[1]
            from internal.mission import mission_view

            view = mission_view(root, ctf=ctf)
            with self._stats_lock:
                self._mission_cache[key] = (sig, view, time.monotonic())
                if len(self._mission_cache) > 128:
                    self._mission_cache.pop(next(iter(self._mission_cache)))
            return view

    def _read_stats(self, root: Path, *, light: bool = False) -> dict:
        key = f"{root}|{light}"
        sig = self._stats_signature(root, light=light)
        with self._stats_lock:
            hit = self._stats_cache.get(key)
            if hit and hit[0] == sig:
                stats = dict(hit[1])
            else:
                stats = None
        if stats is None:
            stats = self._compute_stats(root, light=light)
            with self._stats_lock:
                self._stats_cache[key] = (sig, dict(stats))
                if len(self._stats_cache) > 512:  # cota dura por si hay muchísimos runs
                    self._stats_cache.pop(next(iter(self._stats_cache)))
            stats = dict(stats)
        from internal.telemetry import run_elapsed_seconds

        wall = run_elapsed_seconds(root)
        if wall is not None:
            stats["elapsed"] = wall
        return stats

    def _compute_stats(self, root: Path, *, light: bool = False) -> dict:
        stats = self._read_json(root / "stats.json") or {}
        if not isinstance(stats, dict):
            stats = {}
        else:
            stats = dict(stats)
        try:
            lim = float(self.cfg.limits.cpus or 0)
        except (TypeError, ValueError):
            lim = 0.0
        if lim > 0 and not float(stats.get("cpu_limit") or 0):
            stats["cpu_limit"] = lim
        from internal.telemetry import run_elapsed_seconds

        wall = run_elapsed_seconds(root)
        if wall is not None:
            stats["elapsed"] = wall
        if not light:
            extra = self._usage_from_console(root)
            if extra:
                if not float(stats.get("cost") or 0) and extra.get("cost"):
                    stats["cost"] = extra["cost"]
                toks = dict(stats.get("tokens") or {})
                changed = False
                if not int(toks.get("cache") or 0) and extra.get("cache"):
                    toks["cache"] = extra["cache"]
                    changed = True
                if not int(toks.get("in") or 0) and extra.get("in"):
                    toks["in"] = extra["in"]
                    changed = True
                if not int(toks.get("out") or 0) and extra.get("out"):
                    toks["out"] = extra["out"]
                    changed = True
                if changed:
                    stats["tokens"] = toks
            if not int(stats.get("commands_count") or 0):
                n = len(self._commands_from_console(root))
                if n:
                    stats["commands_count"] = n
            if not int(stats.get("tools_count") or 0):
                n = len(self._tools_from_console(root))
                if n:
                    stats["tools_count"] = n
        self._enrich_findings_stats(root, stats)
        return stats

    def _enrich_findings_stats(self, root: Path, stats: dict) -> None:
        sig = self._findings_signature(root)
        key = str(root)
        with self._stats_lock:
            hit = self._findings_stats_cache.get(key)
            if hit and hit[0] == sig:
                stats.update(hit[1])
                return
        proven = suspected = 0
        sev = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        last = ""
        from internal.report import _reportable

        for data in _reportable(load_findings(root)):
            # Flags van al contrato CTF, no al recuento ni a la pestaña Findings.
            if str(data.get("kind") or "").lower() == "flag":
                continue
            st = str(data.get("status") or "")
            if st == "proven":
                proven += 1
            else:
                suspected += 1
            s = str(data.get("severity") or "info")
            if s in sev:
                sev[s] += 1
            last = str(data.get("title") or last)
        extra = {
            "findings_proven": proven,
            "findings_suspected": suspected,
            "findings_by_severity": sev,
        }
        if last:
            extra["last_finding"] = last
        with self._stats_lock:
            self._findings_stats_cache[key] = (sig, extra)
            if len(self._findings_stats_cache) > 256:
                self._findings_stats_cache.pop(next(iter(self._findings_stats_cache)))
        stats.update(extra)

    def _usage_from_console(self, root: Path) -> dict:
        """OpenCode pone cost/cache en step_finish; Claude en message.usage."""
        path = root / "console.log"
        if not path.is_file():
            return {}
        try:
            st = path.stat()
            key = (str(path), st.st_mtime_ns, st.st_size)
            cache = getattr(self, "_usage_cache", None)
            if not isinstance(cache, dict):
                cache = {}
                self._usage_cache = cache
            hit = cache.get(str(path))
            if hit and hit[0] == key:
                return hit[1]
            out = usage_from_console(root)
            cache[str(path)] = (key, out)
            return out
        except OSError:
            return {}

    def findings(self, run_id: str) -> list[dict]:
        root = self.cfg.runs_dir() / run_id
        items = load_findings(root)
        try:
            from internal.report import _remap_finding_evidence

            items = _remap_finding_evidence(root, items)
        except Exception:
            pass
        try:
            from internal.pocsrc import enrich_findings

            items = enrich_findings(root, items)
        except Exception:
            pass
        try:
            from internal.report import _reportable

            items = _reportable(items)
        except Exception:
            items = [
                it
                for it in items
                if str(it.get("status") or "").lower() not in {"discarded", "void"}
            ]
        out: list[dict] = []
        for raw in items:
            it = dict(raw)
            if finding_is_draft(it):
                it["title"] = "Redactando…"
                it["explain"] = ""
                it["summary"] = ""
                it["draft"] = True
            out.append(it)
        try:
            from internal.mission import attach_finding_commands

            out = attach_finding_commands(root, out)
        except Exception:
            pass
        try:
            from internal.claimcheck import mark_reviewed_findings

            out = mark_reviewed_findings(root, out)
        except Exception:
            pass
        try:
            from internal.report import _redact_text, _secret_values

            secrets = _secret_values(root, out)
            for it in out:
                if it.get("draft"):
                    continue
                for k in ("title", "summary", "explain", "proof", "reproduction", "impact"):
                    if it.get(k):
                        it[k] = _redact_text(str(it[k]), secrets)
        except Exception:
            pass
        return out

    def watch_run(self, run_id: str) -> dict:
        root = self.cfg.runs_dir() / run_id
        if not root.is_dir():
            raise FileNotFoundError(run_id)
        try:
            meta = read_meta(root)
        except SystemExit as exc:
            raise FileNotFoundError(run_id) from exc
        if str(meta.get("status") or "") == "ended":
            raise ValueError("el run ya terminó")
        name = str(meta.get("container") or f"aegis-run-{run_id}")
        if not running(name):
            raise ValueError("el contenedor no está vivo")
        if watch_pid_alive(root):
            return {"ok": True, "already": True}
        if self._proc_alive() and self._current and self._current.run_id == run_id:
            return {"ok": True, "already": True}
        if not self._spawn_watch(run_id, meta):
            raise ValueError("no se pudo reenganchar el reloj")
        return {"ok": True, "already": False}

    def eval_runs(self, ids: list[str] | None = None) -> dict:
        from internal.eval import score_runs, summarize

        rows = score_runs(self.cfg.runs_dir(), ids)
        return {"runs": rows, "summary": summarize(rows)}

    def preset_for(self, run_id: str) -> dict:
        from internal.mission import launch_preset

        root = self.cfg.runs_dir() / run_id
        if not (root / "meta.json").is_file():
            raise FileNotFoundError(run_id)
        try:
            meta = json.loads((root / "meta.json").read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            meta = {}
        out = launch_preset(root, meta if isinstance(meta, dict) else {})
        out["run_id"] = run_id
        return out

    def last_preset(self) -> dict | None:
        runs_dir = self.cfg.runs_dir()
        if not runs_dir.is_dir():
            return None
        metas = sorted(runs_dir.glob("*/meta.json"), reverse=True)
        if not metas:
            return None
        return self.preset_for(metas[0].parent.name)

    def report(self, run_id: str) -> dict:
        root = self.cfg.runs_dir() / run_id
        if not root.is_dir():
            raise FileNotFoundError(run_id)
        meta = self._read_json(root / "meta.json") or {}
        try:
            from internal.report import refresh_report_if_stale

            refresh_report_if_stale(
                root,
                mode=str(meta.get("mode") or "full"),
                model=str(meta.get("model") or ""),
                run_id=run_id,
            )
        except Exception:
            pass
        md = root / "report.md"
        js = root / "report.json"
        return {
            "markdown": md.read_text(encoding="utf-8") if md.is_file() else "",
            "json": self._read_json(js) or {},
        }

    def run_root(self, run_id: str) -> Path:
        return self.cfg.runs_dir() / run_id

    def state_md(self, run_id: str) -> str:
        from web.safeio import read_contained_text

        return read_contained_text(self.cfg.runs_dir() / run_id, "STATE.md")

    def activity(self, run_id: str, *, part: str = "all") -> dict:
        root = self.cfg.runs_dir() / run_id
        if not root.is_dir():
            raise FileNotFoundError(run_id)
        if part == "commands":
            commands = self._collapse_commands(self._commands_from_console(root) or [])
            slim = [self._slim_command_io(c) for c in commands[-400:]]
            return {
                "commands": slim,
                "tools": {"summary": [], "recent": []},
                "network": [],
                "dns": [],
                "downloads": [],
                "counts": {"commands": len(commands), "tools": 0, "net": 0, "dns": 0, "downloads": 0},
            }
        targets = self._targets_of(root)
        commands: list[dict] = []
        tool_counts: dict[str, int] = {}
        tools_recent: list[dict] = []
        net: dict[str, dict] = {}
        downloads: list[dict] = []
        dns_names: dict[str, str] = {}

        extra_argv: list[tuple[str, str]] = []
        events_path = root / "events.jsonl"
        if events_path.is_file():
            try:
                lines = events_path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                lines = []
            for raw in lines:
                raw = raw.strip()
                if not raw:
                    continue
                try:
                    ev = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                typ = ev.get("type")
                ts = ev.get("ts", "")
                p = ev.get("payload") or {}
                if typ == "command":
                    argv = self._useful_argv(p.get("argv"))
                    if not argv:
                        continue
                    commands.append({
                        "ts": ts, "argv": argv, "cwd": p.get("cwd") or "",
                        "exit": p.get("exit"),
                        "stdout": p.get("stdout") or "", "stderr": p.get("stderr") or "",
                    })
                elif typ == "tool.use":
                    name = str(p.get("name") or "tool")
                    args = p.get("args")
                    exit_s = str(p.get("exit") or "")
                    if self._empty_args(args) and exit_s in {"", "pending", "running"}:
                        continue
                    tool_counts[name] = tool_counts.get(name, 0) + 1
                    tools_recent.append({
                        "ts": ts, "name": name, "args": args,
                        "exit": p.get("exit"), "call_id": p.get("call_id") or "",
                    })
                elif typ in ("net.conn", "net.out_of_scope"):
                    self._accumulate_net(net, p, ts, typ, targets)

        audit = root / ".audit" / "commands.jsonl"
        if audit.is_file():
            try:
                alines = audit.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                alines = []
            for raw in alines:
                try:
                    rec = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                argv = self._useful_argv(rec.get("argv") or rec.get("cmd"))
                if argv and _NET_CALL_RE.search(argv):
                    extra_argv.append((argv, str(rec.get("ts") or "")))

        from_console = self._commands_from_console(root)
        if from_console:
            commands = from_console
        from_console_tools = self._tools_from_console(root)
        if from_console_tools:
            tools_recent = from_console_tools
        commands = self._collapse_commands(commands)
        tools_recent = self._collapse_tools(tools_recent)
        self._attach_console_io(root, commands, tools_recent)
        seen_argv = {(c.get("argv") or "")[:240] for c in commands}
        for c in commands:
            argv = c.get("argv") or ""
            ts = c.get("ts") or ""
            self._scan_argv(argv, ts, downloads, dns_names, net, targets)
            self._scan_built_http(argv, c.get("stdout") or "", ts, dns_names, net, targets)
        for argv, ts in extra_argv:
            if argv[:240] in seen_argv:
                continue
            seen_argv.add(argv[:240])
            self._scan_argv(argv, ts, downloads, dns_names, net, targets)
        for t in tools_recent:
            self._scan_tool(
                t.get("name") or "",
                t.get("args"),
                t.get("ts") or "",
                downloads,
                dns_names,
                net,
                targets,
            )
        downloads = self._collapse_downloads(downloads)
        tool_counts = {}
        for t in tools_recent:
            n = t["name"]
            tool_counts[n] = tool_counts.get(n, 0) + 1

        # PTR best-effort (solo pestaña Red; Comandos no espera DNS inverso).
        net_list = list(net.values())
        if part in {"all", "network"}:
            looked = 0
            for row in net_list:
                if looked >= 8:
                    break
                if row["scope"] == "external" and row["dst_ip"] and self._looks_ip(row["dst_ip"]):
                    host = self._ptr(row["dst_ip"])
                    looked += 1
                    if host:
                        row["host"] = host
                        dns_names.setdefault(host, "ptr")
        net_list.sort(key=lambda r: (_SCOPE_RANK.get(r["scope"], 9), -r["count"]))

        tools_summary = sorted(
            ({"name": k, "count": v} for k, v in tool_counts.items()),
            key=lambda x: -x["count"],
        )
        empty_tools = {"summary": [], "recent": []}
        counts = {
            "commands": len(commands),
            "tools": sum(tool_counts.values()),
            "net": len(net_list),
            "dns": len(dns_names),
            "downloads": len(downloads),
        }
        if part == "commands":
            slim = [self._slim_command_io(c) for c in commands[-400:]]
            return {
                "commands": slim,
                "tools": empty_tools,
                "network": [],
                "dns": [],
                "downloads": [],
                "counts": counts,
            }
        if part == "network":
            return {
                "commands": [],
                "tools": empty_tools,
                "network": net_list[:800],
                "dns": sorted(({"name": k, "source": v} for k, v in dns_names.items()), key=lambda x: x["name"])[:400],
                "downloads": downloads[-400:],
                "counts": counts,
            }
        return {
            "commands": commands[-1500:],
            "tools": {"summary": tools_summary, "recent": tools_recent[-400:]},
            "network": net_list[:800],
            "dns": sorted(({"name": k, "source": v} for k, v in dns_names.items()), key=lambda x: x["name"])[:400],
            "downloads": downloads[-400:],
            "counts": counts,
        }

    @staticmethod
    def _useful_argv(argv: Any) -> str:
        if isinstance(argv, (list, dict)) and not argv:
            return ""
        s = str(argv or "").strip()
        if not s or s in _NOISE_ARGV or _is_noise_argv(s):
            return ""
        return s

    @staticmethod
    def _claude_tool_result_text(ev: dict, block: dict) -> tuple[str, bool]:
        is_err = bool(block.get("is_error"))
        tur = ev.get("tool_use_result")
        if isinstance(tur, dict):
            if tur.get("is_error") or tur.get("interrupted"):
                is_err = True
            out = tur.get("stdout")
            if isinstance(out, str) and out:
                return out, is_err
            err = tur.get("stderr")
            if isinstance(err, str) and err.strip():
                return err, True
        c = block.get("content")
        if isinstance(c, str):
            return c, is_err
        if isinstance(c, list):
            parts: list[str] = []
            for x in c:
                if isinstance(x, str):
                    parts.append(x)
                elif isinstance(x, dict) and x.get("text"):
                    parts.append(str(x["text"]))
            return "\n".join(parts), is_err
        return "", is_err

    def _iter_console_events(self, root: Path, *, tail_bytes: int | None = None) -> list[dict]:
        path = root / "console.log"
        if not path.is_file():
            return []
        try:
            st = path.stat()
            key = (str(path), st.st_mtime_ns, st.st_size, tail_bytes)
            hit = getattr(self, "_console_events_cache", None)
            if hit and hit[0] == key:
                return hit[1]
            if tail_bytes and st.st_size > tail_bytes:
                with path.open("rb") as fh:
                    fh.seek(-int(tail_bytes), 2)
                    blob = fh.read().decode("utf-8", errors="replace")
                blob = blob.split("\n", 1)[-1]
                lines = blob.splitlines()
            else:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            events: list[dict] = []
            for raw in lines:
                i = raw.find("{")
                if i < 0:
                    continue
                try:
                    ev = json.loads(raw[i:])
                except json.JSONDecodeError:
                    continue
                if isinstance(ev, dict):
                    events.append(ev)
            self._console_events_cache = (key, events)
            return events
        except OSError:
            return []

    def _iter_console_tools(self, root: Path, *, tail_bytes: int | None = None):
        events = self._iter_console_events(root, tail_bytes=tail_bytes)
        results: dict[str, tuple[str, bool]] = {}
        for ev in events:
            if ev.get("type") != "user":
                continue
            msg = ev.get("message") if isinstance(ev.get("message"), dict) else {}
            for block in msg.get("content") or []:
                if not isinstance(block, dict) or block.get("type") != "tool_result":
                    continue
                tid = str(block.get("tool_use_id") or "")
                if tid:
                    results[tid] = self._claude_tool_result_text(ev, block)
        for ev in events:
            part = ev.get("part") if isinstance(ev.get("part"), dict) else {}
            if ev.get("type") in {"tool_use", "tool"} or part.get("type") in {"tool", "tool-invocation"}:
                st = part.get("state") if isinstance(part.get("state"), dict) else {}
                inp = st.get("input") if isinstance(st.get("input"), dict) else {}
                yield ev, part, st, inp
                continue
            if ev.get("type") == "tool_call" and ev.get("subtype") == "completed":
                tool = ev.get("tool_call") if isinstance(ev.get("tool_call"), dict) else {}
                fetch = tool.get("webFetchToolCall") if isinstance(tool.get("webFetchToolCall"), dict) else {}
                fargs = fetch.get("args") if isinstance(fetch.get("args"), dict) else {}
                furl = str(fargs.get("url") or "").strip()
                if furl:
                    # Fetch del modelo. La lista deduplica por URL.
                    st = {
                        "status": "completed",
                        "exit": "completed",
                        "input": {"url": furl},
                        "output": "",
                        "error": "",
                    }
                    part = {
                        "type": "tool",
                        "tool": "webfetch",
                        "id": str(ev.get("call_id") or fargs.get("toolCallId") or ""),
                        "state": st,
                    }
                    yield ev, part, st, st["input"]
                    continue
                call = tool.get("shellToolCall") if isinstance(tool.get("shellToolCall"), dict) else {}
                args = call.get("args") if isinstance(call.get("args"), dict) else {}
                cmd = str(args.get("command") or "").strip()
                if not cmd:
                    continue
                result = call.get("result") if isinstance(call.get("result"), dict) else {}
                ok = result.get("success") if isinstance(result.get("success"), dict) else {}
                err = result.get("failure") if isinstance(result.get("failure"), dict) else {}
                if not err and isinstance(result.get("error"), dict):
                    err = result["error"]
                body = ok or err
                code = body.get("exitCode")
                stdout = str(body.get("stdout") or body.get("interleavedOutput") or "")
                stderr = str(body.get("stderr") or "")
                failed = bool(err) or (isinstance(code, int) and code != 0)
                st = {
                    "status": "error" if failed else "completed",
                    "exit": code if isinstance(code, int) else ("error" if failed else "completed"),
                    "input": {"command": cmd, "cwd": str(args.get("workingDirectory") or "")},
                    "output": stdout[:12000],
                    "error": stderr[:2000] if failed else "",
                }
                part = {
                    "type": "tool",
                    "tool": "bash",
                    "id": str(ev.get("call_id") or tool.get("toolCallId") or ""),
                    "state": st,
                }
                yield ev, part, st, st["input"]
                continue
            if ev.get("type") == "item.completed":
                item = ev.get("item") if isinstance(ev.get("item"), dict) else {}
                if item.get("type") != "command_execution":
                    continue
                cmd = str(item.get("command") or "")
                status = str(item.get("status") or "completed")
                out = str(item.get("aggregated_output") or "")
                code = item.get("exit_code")
                failed = status in {"failed", "error"} or (isinstance(code, int) and code != 0)
                if failed and status not in {"failed", "error"}:
                    status = "error"
                st = {
                    "status": status,
                    "exit": code if isinstance(code, int) else status,
                    "input": {"command": cmd},
                    "output": out[:12000],
                    "error": out[:2000] if failed else "",
                }
                part = {"type": "tool", "tool": "bash", "id": str(item.get("id") or ""), "state": st}
                yield ev, part, st, st["input"]
                continue
            if ev.get("type") != "assistant":
                continue
            msg = ev.get("message") if isinstance(ev.get("message"), dict) else {}
            for block in msg.get("content") or []:
                if not isinstance(block, dict) or block.get("type") != "tool_use":
                    continue
                name = str(block.get("name") or "tool")
                inp = block.get("input") if isinstance(block.get("input"), dict) else {}
                tid = str(block.get("id") or "")
                out, is_err = results.get(tid, ("", False))
                st = {
                    "status": "error" if is_err else ("completed" if tid in results else "running"),
                    "input": inp,
                    "output": out[:12000],
                    "error": out[:2000] if is_err else "",
                }
                part = {"type": "tool", "tool": name, "id": tid, "state": st}
                yield ev, part, st, inp

    def _commands_from_console(self, root: Path) -> list[dict]:
        out: list[dict] = []
        seen: set[str] = set()
        for ev, part, st, inp in self._iter_console_tools(root) or []:
            cmd = str(inp.get("command") or inp.get("cmd") or "")
            if not cmd or cmd in _NOISE_ARGV or _is_noise_argv(cmd):
                continue
            key = cmd[:240]
            status = str(st.get("status") or "")
            if key in seen and status in {"pending", "running", "in_progress"}:
                continue
            seen.add(key)
            ts = _normalize_ts(ev.get("timestamp") or ev.get("time") or ev.get("ts"))
            exit_val = st.get("exit")
            if exit_val in (None, ""):
                exit_val = status
            out.append({
                "ts": ts,
                "argv": cmd,
                "cwd": str(inp.get("cwd") or ""),
                "exit": exit_val,
                "stdout": str(st.get("output") or "")[:12000],
                "stderr": str(st.get("error") or ""),
            })
        return out

    def _tools_from_console(self, root: Path) -> list[dict]:
        """El sidecar del run vivo a veces guarda tool.use sin args; console.log sí los tiene."""
        out: list[dict] = []
        for ev, part, st, inp in self._iter_console_tools(root) or []:
            name = str(part.get("tool") or part.get("name") or "tool")
            status = str(st.get("status") or "")
            if status in {"pending", "running"} and self._empty_args(inp):
                continue
            out.append({
                "ts": _normalize_ts(ev.get("timestamp") or ev.get("time") or ev.get("ts")),
                "name": name,
                "args": inp or {},
                "exit": status,
                "call_id": str(part.get("callID") or part.get("id") or ""),
            })
        return out

    def _attach_console_io(self, root: Path, commands: list[dict], tools: list[dict]) -> None:
        """OpenCode deja stdout en console.log (JSON); el audit solo guarda argv."""
        path = root / "console.log"
        if not path.is_file():
            return
        by_cmd: dict[str, dict] = {}
        try:
            for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
                i = raw.find("{")
                if i < 0:
                    continue
                try:
                    ev = json.loads(raw[i:])
                except json.JSONDecodeError:
                    continue
                part = ev.get("part") if isinstance(ev, dict) else None
                if not isinstance(part, dict):
                    continue
                if ev.get("type") not in {"tool_use", "tool"} and part.get("type") not in {"tool", "tool-invocation"}:
                    continue
                st = part.get("state") if isinstance(part.get("state"), dict) else {}
                inp = st.get("input") if isinstance(st.get("input"), dict) else {}
                cmd = str(inp.get("command") or inp.get("cmd") or "")
                output = st.get("output") or ""
                err = st.get("error") or ""
                if not cmd:
                    continue
                by_cmd[cmd[:240]] = {
                    "stdout": str(output)[:12000],
                    "stderr": str(err)[:2000],
                    "exit": st.get("status") or "",
                    "args": inp,
                }
        except OSError:
            return
        if not by_cmd:
            return
        for c in commands:
            key = (c.get("argv") or "")[:240]
            hit = by_cmd.get(key)
            if not hit:
                continue
            if not (c.get("stdout") or "").strip() and hit["stdout"]:
                c["stdout"] = hit["stdout"]
            if not (c.get("stderr") or "").strip() and hit["stderr"]:
                c["stderr"] = hit["stderr"]
            if str(c.get("exit") or "") in {"", "pending", "running", "None"} and hit["exit"]:
                c["exit"] = hit["exit"]
        for t in tools:
            if t.get("name") not in {"bash", "shell"}:
                continue
            if not self._empty_args(t.get("args")):
                continue
            # no argv on tool row; leave as-is
            pass

    @staticmethod
    def _empty_args(args: Any) -> bool:
        if args is None or args == "" or args == {} or args == []:
            return True
        if isinstance(args, str) and args.strip() in _NOISE_ARGV:
            return True
        return False

    CMD_STDOUT_SLIM = 6000
    CMD_STDERR_SLIM = 1500

    @classmethod
    def _slim_command_io(cls, row: dict) -> dict:
        """Recorte para la pestaña Comandos: bastante para un curl/nmap, no el dump entero."""
        out = dict(row)
        stdout = str(out.get("stdout") or "")
        stderr = str(out.get("stderr") or "")
        cut = False
        if len(stdout) > cls.CMD_STDOUT_SLIM:
            out["stdout"] = stdout[: cls.CMD_STDOUT_SLIM]
            cut = True
        if len(stderr) > cls.CMD_STDERR_SLIM:
            out["stderr"] = stderr[: cls.CMD_STDERR_SLIM]
            cut = True
        out["truncated"] = cut
        return out

    @staticmethod
    def _exit_label(val: object) -> str:
        if val is None or isinstance(val, bool):
            return ""
        if isinstance(val, (int, float)):
            return str(int(val))
        return str(val)

    @staticmethod
    def _collapse_commands(rows: list[dict]) -> list[dict]:
        """Una fila por comando real: ignora pending/running vacíos y duplicados."""
        best: dict[str, dict] = {}
        order: list[str] = []
        pending = {"pending", "running", "in_progress", ""}
        for r in rows:
            argv = r.get("argv") or ""
            key = argv[:240]
            if key not in best:
                rr = dict(r)
                rr["count"] = int(r.get("count") or 1)
                best[key] = rr
                order.append(key)
                continue
            prev = best[key]
            prev["count"] = int(prev.get("count") or 1) + 1
            prev_ex = RunManager._exit_label(prev.get("exit"))
            new_ex = RunManager._exit_label(r.get("exit"))
            if prev_ex in pending or new_ex not in pending:
                r = dict(r)
                r["count"] = prev["count"]
                if not r.get("ts") and prev.get("ts"):
                    r["ts"] = prev["ts"]
                best[key] = r
        return [best[k] for k in order]

    @staticmethod
    def _collapse_tools(rows: list[dict]) -> list[dict]:
        best: dict[str, dict] = {}
        order: list[str] = []
        for r in rows:
            key = str(r.get("call_id") or "") or f"{r.get('name')}|{r.get('ts','')[:19]}"
            if key not in best:
                best[key] = r
                order.append(key)
                continue
            prev = best[key]
            if str(prev.get("exit") or "") in {"pending", "running"}:
                best[key] = r
        return [best[k] for k in order]

    @staticmethod
    def _collapse_downloads(rows: list[dict]) -> list[dict]:
        best: dict[str, dict] = {}
        order: list[str] = []
        for r in rows:
            key = str(r.get("target") or r.get("argv") or "")[:240]
            if not key:
                continue
            if key not in best:
                rr = dict(r)
                rr["count"] = 1
                best[key] = rr
                order.append(key)
                continue
            best[key]["count"] = int(best[key].get("count") or 1) + 1
            if r.get("ts"):
                best[key]["ts"] = r["ts"]
        return [best[k] for k in order]

    def _targets_of(self, root: Path) -> list[str]:
        meta = self._read_json(root / "meta.json") or {}
        out: list[str] = []
        for t in meta.get("targets") or []:
            if isinstance(t, dict) and t.get("value"):
                out.append(str(t["value"]))
        return out

    @staticmethod
    def _looks_ip(s: str) -> bool:
        try:
            ipaddress.ip_address(s)
            return True
        except ValueError:
            return False

    @staticmethod
    def _ok_dns(name: str) -> bool:
        n = (name or "").strip().lower()
        if not n or "." not in n or not any(c.isalpha() for c in n):
            return False
        tld = n.rsplit(".", 1)[-1]
        if tld not in {
            "lab", "test", "example", "com", "net", "org", "io", "dev", "local", "internal", "lan",
            "corp", "edu", "gov", "info", "xyz", "app", "cloud", "localdomain",
            "ai", "co", "me", "to", "sh", "so", "cc", "gg",
        }:
            return False
        return not RunManager._skip_net_host(n)

    @staticmethod
    def _skip_net_host(host: str) -> bool:
        h = (host or "").strip().lower()
        if not h or h in {"0", "1", "*", "-", "foo", "bar", "unix", "test"}:
            return True
        if "nip.io" in h or h.endswith(".localhost") or "localtest.me" in h:
            return True
        # encodings SSRF tipo 2130706433 sí; puertos sueltos tipo 1248 no
        if h.isdigit() and len(h) < 8:
            return True
        if h.isdigit() and len(h) >= 8:
            return False
        if h.startswith("0x") or h.startswith("127.") or h in {"localhost", "::1"}:
            return False
        if not RunManager._looks_ip(h) and "." not in h:
            return True
        if h.replace(".", "").isdigit() and not RunManager._looks_ip(h) and not h.startswith("127"):
            return True
        return False

    @staticmethod
    def _scope_of(ip: str, targets: list[str]) -> str:
        s = str(ip or "")
        if _LOOPBACKISH.search(s) or s.startswith("127.") or s in {"localhost", "::1"}:
            return "local"
        if s in targets:
            return "internal"
        try:
            addr = ipaddress.ip_address(s)
        except ValueError:
            if any(s.endswith(t) or t.endswith(s) for t in targets):
                return "internal"
            return "internal" if "." in s else "external"
        if addr.is_loopback or s in {"0.0.0.0", "::"}:
            return "local"
        if s in targets:
            return "internal"
        if addr.is_private or addr.is_link_local or addr.is_reserved:
            return "internal"
        return "external"

    def _accumulate_net(self, net: dict, p: dict, ts: str, typ: str, targets: list[str]) -> None:
        dst_ip = str(p.get("dst_ip") or "")
        if self._skip_net_host(dst_ip):
            return
        dst_port = p.get("dst_port") or 0
        proto = str(p.get("proto") or "tcp")
        key = f"{dst_ip}:{dst_port}:{proto}"
        row = net.get(key)
        if row is None:
            row = {
                "dst_ip": dst_ip, "dst_port": dst_port, "proto": proto,
                "count": 0, "first_ts": ts, "last_ts": ts, "host": "",
                "scope": self._scope_of(dst_ip, targets),
                "out_of_scope": typ == "net.out_of_scope",
                "result": p.get("result") or "",
                "via": "",
            }
            net[key] = row
        row["count"] += 1
        row["last_ts"] = ts
        if p.get("host") and not row.get("host"):
            row["host"] = str(p["host"])
        if not row.get("host") and dst_ip and not self._looks_ip(dst_ip):
            row["host"] = dst_ip
        via = str(p.get("via") or "")
        if not via:
            res = str(p.get("result") or "")
            via = "ss" if res in {"estab", "syn"} else res
        if via and not row.get("via"):
            row["via"] = via
        if typ == "net.out_of_scope":
            row["out_of_scope"] = True

    _FETCH_TOOLS = frozenset({"webfetch", "web_fetch", "web-fetch", "fetch"})
    _SHELL_TOOLS = frozenset({"bash", "shell", "bash_tool", "terminal"})

    @staticmethod
    def _tool_url(args: Any) -> str:
        if isinstance(args, dict):
            for k in ("url", "uri", "href"):
                v = args.get(k)
                if isinstance(v, str) and v.strip():
                    return v.strip()
            return ""
        if isinstance(args, str) and "://" in args:
            return args.strip()
        return ""

    def _scan_tool(
        self,
        name: str,
        args: Any,
        ts: str,
        downloads: list,
        dns_names: dict,
        net: dict,
        targets: list[str],
    ) -> None:
        n = str(name or "").strip().lower().replace("-", "_")
        if n in self._SHELL_TOOLS:
            return
        url = self._tool_url(args)
        if not url:
            return
        if n in self._FETCH_TOOLS or n.endswith("fetch"):
            downloads.append({"ts": ts, "argv": f"{name} {url}"[:400], "target": url[:300]})
        self._add_url_dest(url, ts, dns_names, net, targets, via="webfetch")

    def _add_url_dest(
        self,
        raw: str,
        ts: str,
        dns_names: dict,
        net: dict,
        targets: list[str],
        *,
        via: str,
    ) -> None:
        if not raw:
            return
        m = _URL_RE.search(raw)
        host = ""
        port = 0
        if m:
            host = m.group(1).lower()
            port = int(m.group(2) or (443 if m.group(0).lower().startswith("https") else 80))
        else:
            hm = re.match(r"^([A-Za-z0-9._-]+)(?::(\d+))?$", raw.strip())
            if hm:
                host = hm.group(1).lower()
                port = int(hm.group(2) or 0)
        if not host:
            return
        if self._ok_dns(host):
            dns_names.setdefault(host, via if via in {"webfetch", "vhost"} else "url")
        dest = host if (self._looks_ip(host) or self._ok_dns(host) or host.startswith("127.") or host.isdigit()) else ""
        if not dest:
            return
        self._accumulate_net(
            net,
            {"dst_ip": dest, "dst_port": port, "proto": "tcp", "result": via, "via": via, "host": host if not self._looks_ip(host) else ""},
            ts, "net.conn", targets,
        )

    def _scan_argv(self, argv: str, ts: str, downloads: list, dns_names: dict, net: dict, targets: list[str]) -> None:
        if not argv:
            return
        for m in _DOWNLOAD_TOOL_RE.finditer(argv):
            body = m.group("body") or ""
            if not _DOWNLOAD_OUT_RE.search(body):
                continue
            um = _FULL_URL_RE.search(_CURL_PAYLOAD_RE.sub(" ", body))
            if not um:
                continue
            downloads.append({
                "ts": ts,
                "argv": argv[:400],
                "target": um.group(0).rstrip(").,;\"'"),
            })
        try:
            from internal.pocsrc import iter_fetch_urls

            for url in iter_fetch_urls(argv):
                downloads.append({"ts": ts, "argv": argv[:400], "target": url[:300]})
                self._add_url_dest(url, ts, dns_names, net, targets, via="download")
        except Exception:
            pass
        for m in _DNS_LINE_RE.finditer("\n" + argv):
            for d in _DOMAIN_RE.finditer(m.group("body") or ""):
                name = d.group(1).lower()
                if self._ok_dns(name):
                    dns_names.setdefault(name, "query")
        for m in _HOST_HDR_RE.finditer(argv):
            name = m.group(1).lower()
            if self._ok_dns(name):
                dns_names.setdefault(name, "vhost")
        for m in _NET_CALL_RE.finditer(argv):
            tool = (m.group("tool") or "").lower()
            body = m.group("body") or ""
            self._scan_net_call(tool, body, ts, dns_names, net, targets)
        # URL suelta en el script, sin curl/wget.
        if not re.search(r"\b(curl|wget|aria2c)\b", argv, re.I):
            for u in _URL_RE.finditer(argv):
                self._add_url_dest(u.group(0), ts, dns_names, net, targets, via="url")

    def _scan_built_http(
        self,
        argv: str,
        stdout: str,
        ts: str,
        dns_names: dict,
        net: dict,
        targets: list[str],
    ) -> None:
        """Host o URL anunciada cuando el script no deja la dirección entera."""
        if not argv or not _HTTP_CLIENT_RE.search(argv):
            return
        if _BUILT_HTTP_RE.search(argv):
            for m in _QUOTED_HOST_RE.finditer(argv):
                host = m.group(1)
                if self._skip_net_host(host):
                    continue
                self._add_url_dest(host, ts, dns_names, net, targets, via="url")
        for i, line in enumerate((stdout or "").splitlines()):
            if i >= 40 or len(line) > 240:
                continue
            um = _ANNOUNCED_URL_RE.match(line.strip())
            if not um:
                continue
            self._add_url_dest(um.group(1).rstrip(").,;\"'"), ts, dns_names, net, targets, via="url")

    def _scan_net_call(
        self,
        tool: str,
        body: str,
        ts: str,
        dns_names: dict,
        net: dict,
        targets: list[str],
    ) -> None:
        if tool in {"curl", "wget", "aria2c"}:
            cleaned = _CURL_PAYLOAD_RE.sub(" ", body)
            found = False
            for u in _URL_RE.finditer(cleaned):
                found = True
                self._add_url_dest(u.group(0), ts, dns_names, net, targets, via=tool)
            if found:
                return
        if tool == "hydra":
            port = 0
            pm = re.search(r"(?i)(?:^|\s)-s\s+(\d+)", body)
            if pm:
                port = int(pm.group(1))
            elif re.search(r"(?i)(?:\s-S\b|https)", body):
                port = 443
            elif re.search(r"(?i)\bssh\b", body):
                port = 22
            for tok in body.split():
                tok = tok.strip("'\"`")
                if tok.startswith("-"):
                    continue
                if tok.lower() in {"https-post-form", "http-post-form", "http-get", "https-get", "ssh", "ftp", "smb"}:
                    continue
                if self._ok_dns(tok.lower()) or self._looks_ip(tok):
                    self._accumulate_net(
                        net,
                        {"dst_ip": tok.lower(), "dst_port": port or 0, "proto": "tcp", "via": "hydra", "host": tok if not self._looks_ip(tok) else ""},
                        ts, "net.conn", targets,
                    )
                    return
            return
        if tool in {"nmap", "masscan", "rustscan", "ffuf", "gobuster", "feroxbuster", "wfuzz", "dirb", "httpx", "nikto", "sqlmap", "nuclei", "whatweb", "smbclient", "showmount", "nc", "ncat"}:
            blob = _CURL_PAYLOAD_RE.sub(" ", body)
            for u in _URL_RE.finditer(blob):
                self._add_url_dest(u.group(0), ts, dns_names, net, targets, via=tool)
            for tok in blob.split():
                tok = tok.strip("'\"`")
                if tok.startswith("-") or not tok:
                    continue
                host = tok.split("/")[0].strip("'\"`")
                if host.startswith("//"):
                    host = host[2:]
                host, port_s = (host.rsplit(":", 1) + [""])[:2] if host.count(":") == 1 and not host.startswith("[") else (host, "")
                port = int(port_s) if port_s.isdigit() else 0
                if self._ok_dns(host.lower()) or self._looks_ip(host):
                    self._accumulate_net(
                        net,
                        {"dst_ip": host.lower(), "dst_port": port, "proto": "tcp", "via": tool, "host": host if not self._looks_ip(host) else ""},
                        ts, "net.conn", targets,
                    )

    @staticmethod
    def _ptr(ip: str) -> str:
        if ip in _PTR_CACHE:
            return _PTR_CACHE[ip]
        name = ""
        old = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(0.4)
            name = socket.gethostbyaddr(ip)[0]
        except (OSError, socket.herror, socket.gaierror):
            name = ""
        finally:
            socket.setdefaulttimeout(old)
        _PTR_CACHE[ip] = name
        return name

    def tree(self, run_id: str) -> list[dict]:
        root = self.cfg.runs_dir() / run_id
        if not root.is_dir():
            raise FileNotFoundError(run_id)
        out: list[dict] = []
        for p in sorted(root.rglob("*")):
            if not p.is_file():
                continue
            rel = p.relative_to(root)
            parts = rel.parts
            if parts and parts[0] == "brief_mount":
                continue
            if p.name in SECRET_NAMES:
                continue
            try:
                stat = p.stat()
            except OSError:
                continue
            suffix = p.suffix.lower()
            category = self._categorize(rel, p.name, suffix)
            if category == "inbox":
                origin = "operador"
            elif category in {"system", "brief"}:
                origin = "orquestador"
            else:
                origin = "agente"
            out.append({
                "rel": rel.as_posix(),
                "name": p.name,
                "size": stat.st_size,
                "mtime": stat.st_mtime,
                "suffix": suffix,
                "category": category,
                "origin": origin,
                "previewable": (suffix in TEXT_SUFFIXES or suffix == "") and stat.st_size <= 512 * 1024,
            })
        out.sort(key=lambda f: (f["category"] == "system", f["rel"]))
        return out

    @staticmethod
    def _categorize(rel: Path, name: str, suffix: str) -> str:
        parts = rel.parts
        top = parts[0] if parts else ""
        if top == "inbox":
            return "inbox"
        if top == "findings":
            if suffix in SCRIPT_SUFFIXES:
                return "script"
            if name.endswith(".json") and len(parts) == 2:
                return "finding"
            return "evidence"
        if top == ".audit":
            return "system"
        if name in {
            "STATE.md",
            "engagement.json",
            "RECAP.md",
            "STEER.md",
            "STEER.last.md",
            "NEXT.md",
            "CONSCIENCE.md",
            "CONSCIENCE.json",
        }:
            return "state"
        if name in {"report.md", "report.json"}:
            return "report"
        if name in {"brief.md", "brief.json"}:
            return "brief"
        if suffix in SCRIPT_SUFFIXES:
            return "script"
        if name in SYSTEM_NAMES:
            return "system"
        if name.endswith(".lock"):
            return "system"
        if name.startswith(".") and len(parts) == 1:
            return "system"
        return "evidence"

    def set_local_endpoint(self, provider: str, endpoint: str) -> dict:
        provider = (provider or "").strip().lower()
        if provider not in {"ollama", "vllm"}:
            raise ValueError("proveedor local no soportado (usa ollama o vllm)")
        endpoint = (endpoint or "").strip()
        cfg_path = Path(__import__("os").environ.get("AEGIS_CONFIG", ROOT / "aegis.yaml"))
        import yaml
        from internal.config import ModelSpec
        from internal.models import _display_endpoint
        from web.catalog import local_providers

        raw: dict = {}
        if cfg_path.is_file():
            raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
        models = raw.setdefault("models", {})
        spec = models.get(provider) if isinstance(models.get(provider), dict) else {}
        spec = dict(spec or {})
        spec.setdefault("provider", provider)
        spec.setdefault("model", "llama3.1" if provider == "ollama" else "local")
        endpoint = _display_endpoint(endpoint, provider) or endpoint
        spec["endpoint"] = endpoint
        self.cfg.models[provider] = ModelSpec(
            alias=provider, provider=provider,
            model=spec["model"], endpoint=endpoint,
        )
        self.cfg.raw.setdefault("models", {})[provider] = spec
        entry = next((x for x in local_providers(self.cfg) if x.get("provider") == provider), {})
        names = list(entry.get("models") or [])
        if provider == "ollama" and names and spec.get("model") in {"", "llama3.1", "local"}:
            spec["model"] = names[0]
            self.cfg.models[provider] = ModelSpec(
                alias=provider, provider=provider,
                model=spec["model"], endpoint=endpoint,
            )
        models[provider] = spec
        tmp = cfg_path.with_suffix(".yaml.tmp")
        tmp.write_text(yaml.safe_dump(raw, sort_keys=False, allow_unicode=True), encoding="utf-8")
        tmp.replace(cfg_path)
        return {
            "provider": provider,
            "endpoint": entry.get("endpoint") or endpoint,
            "models": names,
            "reachable": bool(entry.get("reachable")),
        }

    @staticmethod
    def _read_json(path: Path) -> Any:
        if not path.is_file():
            return None
        try:
            return json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
