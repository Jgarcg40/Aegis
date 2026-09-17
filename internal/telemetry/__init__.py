from __future__ import annotations

import json
import re
import select
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from internal.hostloop import tick
from internal.sandbox import Sandbox, container_resources, exec_out, logs_follow, running
from internal.targets import Target, ip_in_scope

SEVERITIES = ("critical", "high", "medium", "low", "info")
_CONSOLE_TS_RE = re.compile(
    r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)"
)
# Frontera de palabra: «terceros» no es RCE (F-TEL-1).
_NET_EXPLOIT_RX = re.compile(
    r"(?<![a-z0-9áéíóúñ])(rce|ssti|lfi|webshell|reverse\s+shell|login\s+web)(?![a-z0-9áéíóúñ])",
    re.I,
)
_FID_STEM = re.compile(r"^F-\d+$", re.I)
# Cuaderno del run: citarlos no demuestra el hallazgo.
_NOTEBOOK_EVIDENCE = frozenset(
    {
        "state.md",
        "pivot.md",
        "conscience.md",
        "resume.md",
        "recap.md",
        "next.md",
        "steer.md",
        "steer.last.md",
    }
)
_SEV_CRITICAL_RX = re.compile(
    r"(?<![a-z0-9áéíóúñ])(rce|ssti|inyecci[oó]n de comandos|command injection|"
    r"ejecuci[oó]n remota)(?![a-z0-9áéíóúñ])",
    re.I,
)
_SEV_HIGH_RX = re.compile(
    r"(?<![a-z0-9áéíóúñ])(traversal|lfi|sin autentic|unauth|requirepass|"
    r"credenciales por defecto|default cred|secret_key)(?![a-z0-9áéíóúñ])",
    re.I,
)


def last_console_since(path: Path) -> str | None:
    """Último timestamp de console.log + 1s, para `docker logs --since` al reenganchar."""
    if not path.is_file():
        return None
    try:
        size = path.stat().st_size
        if size <= 0:
            return None
        with path.open("rb") as fh:
            fh.seek(max(0, size - 16384))
            chunk = fh.read().decode("utf-8", errors="replace")
    except OSError:
        return None
    last = None
    for line in chunk.splitlines():
        m = _CONSOLE_TS_RE.match(line)
        if m:
            last = m.group(1)
    if not last:
        return None
    dt = parse_run_ts(last)
    if dt is None:
        return last
    nxt = dt.timestamp() + 1
    return datetime.fromtimestamp(nxt, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def now_ts() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_run_ts(raw: Any) -> datetime | None:
    s = str(raw or "").strip()
    if not s:
        return None
    try:
        if s.endswith("Z"):
            s = s[:-1] + "+00:00"
        dt = datetime.fromisoformat(s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc)
    except ValueError:
        return None


def _paused_hold_seconds(root: Path, data: dict[str, Any], end: datetime) -> int:
    """Tiempo en pausa (acumulado + tramo abierto). No cuenta para el reloj ni el tope."""
    held = 0
    try:
        held = max(0, int(data.get("paused_s") or 0))
    except (TypeError, ValueError):
        held = 0
    since = parse_run_ts(data.get("paused_since"))
    if since is None:
        flag = root / ".pause-reason"
        if flag.is_file():
            try:
                since = datetime.fromtimestamp(flag.stat().st_mtime, tz=timezone.utc)
            except OSError:
                since = None
    if since is not None:
        if since.tzinfo is None:
            since = since.replace(tzinfo=timezone.utc)
        held += max(0, int((end - since).total_seconds()))
    return held


def _ctf_doc_hold_seconds(root: Path, end: datetime) -> int:
    """Prórroga de cierre (timeout, flags o cancelar). No cuenta como tiempo de máquina."""
    stamps: list[float] = []
    for name in (".doc-grace-at", ".ctf-complete-at"):
        path = root / name
        if not path.is_file():
            continue
        try:
            stamps.append(float(path.read_text(encoding="utf-8").strip()))
        except (OSError, ValueError):
            continue
    if not stamps:
        return 0
    return max(0, int(end.timestamp() - min(stamps)))


def run_elapsed_seconds(root: Path, meta: dict[str, Any] | None = None) -> int | None:
    """Tiempo activo del run. Pausa y prórroga de cierre no suman (KPI ni timeout)."""
    data = meta
    if data is None:
        path = root / "meta.json"
        if not path.is_file():
            return None
        try:
            loaded = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return None
        if isinstance(loaded, dict):
            data = loaded
    if not isinstance(data, dict):
        return None
    start = parse_run_ts(data.get("started_at"))
    if start is None:
        return None
    end = parse_run_ts(data.get("ended_at")) or datetime.now(timezone.utc)
    wall = max(0, int((end - start).total_seconds()))
    held = _paused_hold_seconds(root, data, end) + _ctf_doc_hold_seconds(root, end)
    return max(0, wall - held)


def _int_field(data: dict[str, Any], *names: str) -> int:
    for name in names:
        raw = data.get(name)
        if isinstance(raw, bool):
            continue
        if isinstance(raw, (int, float)):
            return int(raw)
        if isinstance(raw, str) and raw.strip().lstrip("-").isdigit():
            return int(raw)
    return 0


def _codex_usage_fields(usage: dict[str, Any]) -> tuple[int, int, int]:
    inn = _int_field(usage, "input_tokens", "input", "in")
    out = _int_field(usage, "output_tokens", "output", "out")
    cache = _int_field(
        usage,
        "cached_input_tokens",
        "cache_read_input_tokens",
        "cache_tokens",
        "cache",
    ) + _int_field(usage, "cache_write_input_tokens", "cache_creation_input_tokens")
    return inn, out, cache


def usage_from_console(root: Path) -> dict[str, Any]:
    """OpenCode pone cost/cache en step_finish; Claude en message.usage / result."""
    path = root / "console.log"
    if not path.is_file():
        return {}
    try:
        cost = 0.0
        cache = 0
        tok_in = 0
        tok_out = 0
        by_req: dict[str, tuple[int, int, int]] = {}
        result_cost = 0.0
        result_in = result_out = result_cache = 0
        have_result = False
        cx_in = cx_out = cx_cache = 0
        for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
            i = raw.find("{")
            if i < 0:
                continue
            try:
                ev = json.loads(raw[i:])
            except json.JSONDecodeError:
                continue
            if not isinstance(ev, dict):
                continue
            if ev.get("type") in {"turn.completed", "turn.failed"}:
                usage = ev.get("usage") if isinstance(ev.get("usage"), dict) else {}
                turn = ev.get("turn") if isinstance(ev.get("turn"), dict) else {}
                if not usage and isinstance(turn.get("usage"), dict):
                    usage = turn["usage"]
                inn, outv, ch = _codex_usage_fields(usage)
                if inn or outv or ch:
                    cx_in += inn
                    cx_out += outv
                    cx_cache += ch
            part = ev.get("part") if isinstance(ev.get("part"), dict) else None
            if part:
                c = part.get("cost")
                toks = part.get("tokens")
                if isinstance(c, (int, float)) and isinstance(toks, dict):
                    cost += float(c)
                    ch = toks.get("cache")
                    if isinstance(ch, dict):
                        cache += int(ch.get("read") or 0) + int(ch.get("write") or 0)
                    elif isinstance(ch, (int, float)):
                        cache += int(ch)
                    tok_in += int(toks.get("input") or toks.get("in") or 0)
                    tok_out += int(toks.get("output") or toks.get("out") or 0)
            if ev.get("type") == "assistant":
                msg = ev.get("message") if isinstance(ev.get("message"), dict) else {}
                usage = msg.get("usage") if isinstance(msg.get("usage"), dict) else {}
                rid = str(ev.get("request_id") or msg.get("id") or "")
                if usage and rid:
                    created = int(usage.get("cache_creation_input_tokens") or 0)
                    read = int(usage.get("cache_read_input_tokens") or 0)
                    inp = int(usage.get("input_tokens") or 0) + created + read
                    out = int(usage.get("output_tokens") or 0)
                    prev = by_req.get(rid)
                    if prev is None or out >= prev[1]:
                        by_req[rid] = (inp, out, created + read)
            if ev.get("type") == "result":
                tc = ev.get("total_cost_usd")
                if isinstance(tc, (int, float)):
                    result_cost += float(tc)
                usage = ev.get("usage") if isinstance(ev.get("usage"), dict) else {}
                if usage:
                    have_result = True
                    created = int(usage.get("cache_creation_input_tokens") or 0)
                    read = int(usage.get("cache_read_input_tokens") or 0)
                    result_in += int(usage.get("input_tokens") or 0) + created + read
                    result_out += int(usage.get("output_tokens") or 0)
                    result_cache += created + read
        if have_result:
            return {
                "cost": round(result_cost or cost, 6),
                "cache": result_cache + cx_cache,
                "in": result_in + cx_in,
                "out": result_out + cx_out,
            }
        tok_in += cx_in
        tok_out += cx_out
        cache += cx_cache
        for inp, out, ch in by_req.values():
            tok_in += inp
            tok_out += out
            cache += ch
        return {"cost": round(result_cost or cost, 6), "cache": cache, "in": tok_in, "out": tok_out}
    except OSError:
        return {}


class EventLog:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._lock = threading.Lock()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.touch(exist_ok=True)

    def emit(self, run_id: str, typ: str, payload: dict[str, Any]) -> None:
        rec = {"ts": now_ts(), "run_id": run_id, "type": typ, "payload": payload}
        line = json.dumps(rec, ensure_ascii=False) + "\n"
        with self._lock:
            with self.path.open("a", encoding="utf-8") as fh:
                fh.write(line)
                fh.flush()


class Stats:
    def __init__(self, *, mode: str, model: str, target: str, started: float | None = None) -> None:
        self.started = started if started is not None else time.time()
        self.mode = mode
        self.model = model
        self.target = target
        self.tokens_in = 0
        self.tokens_out = 0
        self.tokens_cache = 0
        self.cost = 0.0
        self.commands_count = 0
        self.tools_count = 0
        self.scripts_created = 0
        self.net_destinations: set[str] = set()
        self.ports: dict[int, int] = {}
        self.findings_by_severity = {k: 0 for k in SEVERITIES}
        self.findings_proven = 0
        self.findings_suspected = 0
        self.last_command = ""
        self.last_finding = ""

    def hydrate(self, path: Path) -> None:
        """Recupera contadores de un stats.json previo (sidecar reenganchado)."""
        if not path.is_file():
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            return
        if not isinstance(data, dict):
            return
        toks = data.get("tokens") if isinstance(data.get("tokens"), dict) else {}
        self.tokens_in = max(self.tokens_in, int(toks.get("in") or 0))
        self.tokens_out = max(self.tokens_out, int(toks.get("out") or 0))
        self.tokens_cache = max(self.tokens_cache, int(toks.get("cache") or 0))
        self.cost = max(self.cost, float(data.get("cost") or 0))
        self.commands_count = max(self.commands_count, int(data.get("commands_count") or 0))
        self.tools_count = max(self.tools_count, int(data.get("tools_count") or 0))
        self.scripts_created = max(self.scripts_created, int(data.get("scripts_created") or 0))
        self.last_command = str(data.get("last_command") or self.last_command)
        self.last_finding = str(data.get("last_finding") or self.last_finding)
        n_dest = int(data.get("net_destinations_unique") or 0)
        while len(self.net_destinations) < n_dest:
            self.net_destinations.add(f"_kept:{len(self.net_destinations)}")

    def snapshot(self) -> dict[str, Any]:
        top_ports = sorted(self.ports.items(), key=lambda kv: kv[1], reverse=True)[:12]
        return {
            "elapsed": int(time.time() - self.started),
            "tokens": {
                "in": self.tokens_in,
                "out": self.tokens_out,
                "cache": self.tokens_cache,
            },
            "cost": self.cost,
            "commands_count": self.commands_count,
            "tools_count": self.tools_count,
            "scripts_created": self.scripts_created,
            "net_destinations_unique": len(
                {d for d in self.net_destinations if not str(d).startswith(("0:", "0.0.0.0:"))}
            ),
            "top_ports": [{"port": p, "count": c} for p, c in top_ports],
            "findings_by_severity": dict(self.findings_by_severity),
            "findings_proven": self.findings_proven,
            "findings_suspected": self.findings_suspected,
            "mode": self.mode,
            "model": self.model,
            "target": self.target,
            "last_command": self.last_command,
            "last_finding": self.last_finding,
        }


class Sidecar:
    def __init__(
        self,
        *,
        run_id: str,
        sandbox: Sandbox,
        out_dir: Path,
        events: EventLog,
        stats: Stats,
        targets: list[Target],
        mode: str,
        quiet: bool = False,
    ) -> None:
        self.run_id = run_id
        self.sandbox = sandbox
        self.out_dir = out_dir
        self.events = events
        self.stats = stats
        self.targets = targets
        self.mode = mode
        self.quiet = quiet
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []
        self._seen_findings: set[str] = set()
        self._seen_conns: set[str] = set()
        self._seen_audit: int = 0
        self.console = out_dir / "console.log"
        self.stats_path = out_dir / "stats.json"
        self._resources: dict[str, Any] = {}
        self._usage: dict[str, Any] = {}
        self._usage_ts: float = 0.0

    def start(self) -> None:
        try:
            self.console.touch(exist_ok=True)
        except OSError:
            pass
        self._spawn(self._follow_logs, "logs")
        self._spawn(self._sse_loop, "sse")
        self._spawn(self._watch_out, "fs")
        self._spawn(self._poll_net, "net")
        self._spawn(self._poll_audit, "audit")
        self._spawn(self._write_stats_loop, "stats")
        self._spawn(self._conscience_loop, "conscience")

    def stop(self) -> None:
        self._stop.set()
        for t in self._threads:
            t.join(timeout=3)
        self.index_findings()
        self.write_stats()

    def _spawn(self, fn: Callable[[], None], name: str) -> None:
        t = threading.Thread(target=self._guard(fn, name), name=f"aegis-{name}", daemon=True)
        self._threads.append(t)
        t.start()

    def _guard(self, fn: Callable[[], None], name: str) -> Callable[[], None]:
        def wrap() -> None:
            try:
                fn()
            except Exception as exc:  # noqa: BLE001
                self.events.emit(self.run_id, "error", {"source": name, "error": str(exc)})

        return wrap

    def _follow_logs(self) -> None:
        proc = logs_follow(self.sandbox.name, since=last_console_since(self.console))
        assert proc.stdout is not None
        try:
            while not self._stop.is_set():
                if proc.poll() is not None:
                    rest = proc.stdout.read()
                    if rest:
                        with self.console.open("a", encoding="utf-8") as fh:
                            fh.write(rest)
                    break
                ready, _, _ = select.select([proc.stdout], [], [], 0.5)
                if not ready:
                    continue
                line = proc.stdout.readline()
                if not line:
                    continue
                with self.console.open("a", encoding="utf-8") as fh:
                    fh.write(line)
        finally:
            if proc.poll() is None:
                proc.terminate()

    def _sse_loop(self) -> None:
        url = f"http://127.0.0.1:{self.sandbox.port}/event"
        pwd = self.sandbox.password
        auth = ("aegis", pwd)
        while not self._stop.is_set():
            if not running(self.sandbox.name):
                time.sleep(0.5)
                continue
            try:
                self._consume_sse(url, auth)
            except Exception:
                time.sleep(1)

    def _consume_sse(self, url: str, auth: tuple[str, str]) -> None:
        req = urllib.request.Request(url, headers={"Accept": "text/event-stream"})
        mgr = urllib.request.HTTPPasswordMgrWithDefaultRealm()
        mgr.add_password(None, url, auth[0], auth[1])
        opener = urllib.request.build_opener(urllib.request.HTTPBasicAuthHandler(mgr))
        with opener.open(req, timeout=30) as resp:
            buf = ""
            while not self._stop.is_set():
                chunk = resp.read(4096)
                if not chunk:
                    break
                buf += chunk.decode("utf-8", errors="replace")
                while "\n\n" in buf:
                    block, buf = buf.split("\n\n", 1)
                    data_lines = [
                        ln[5:].strip()
                        for ln in block.splitlines()
                        if ln.startswith("data:")
                    ]
                    if not data_lines:
                        continue
                    raw = "\n".join(data_lines)
                    try:
                        evt = json.loads(raw)
                    except json.JSONDecodeError:
                        continue
                    self._on_opencode(evt)

    def _on_opencode(self, evt: Any) -> None:
        if not isinstance(evt, dict):
            return
        typ = evt.get("type") or evt.get("event") or ""
        props = evt.get("properties") or evt.get("payload") or evt
        if typ in {"server.connected", "server.heartbeat"}:
            return
        if "part" in typ or typ == "message.part.updated":
            part = props.get("part") if isinstance(props, dict) else None
            if isinstance(part, dict):
                self._on_part(part)
        if "token" in typ or "session.idle" in typ:
            self._ingest_usage(props if isinstance(props, dict) else {})
        if typ in {"session.error"}:
            self.events.emit(self.run_id, "error", {"opencode": props})
        if typ == "file.edited":
            path = ""
            if isinstance(props, dict):
                path = str(props.get("file") or props.get("path") or "")
            self.stats.scripts_created += 1
            self.events.emit(self.run_id, "file.write", {"path": path})
        # contrato UI: también el crudo, por si la UI quiere pintar la TUI
        if typ:
            self.events.emit(self.run_id, "opencode.event", {"type": typ})

    def _on_part(self, part: dict[str, Any]) -> None:
        ptype = str(part.get("type") or "")
        if ptype in {"tool", "tool-invocation", "tool_call"}:
            name = str(part.get("tool") or part.get("name") or "tool")
            state = part.get("state") if isinstance(part.get("state"), dict) else {}
            args = (
                part.get("input")
                or part.get("arguments")
                or part.get("args")
                or state.get("input")
                or {}
            )
            exit_code = state.get("status") or part.get("exit")
            call_id = str(part.get("callID") or part.get("id") or "")
            if not args and str(exit_code or "") in {"", "pending", "running"}:
                return
            if call_id:
                seen = getattr(self, "_seen_calls", None)
                if seen is None:
                    self._seen_calls = seen = set()
                key = f"{call_id}:{exit_code}"
                if key in seen:
                    return
                seen.add(key)
            self.stats.tools_count += 1
            if name in {"bash", "shell"}:
                argv = ""
                if isinstance(args, dict):
                    argv = str(args.get("command") or args.get("cmd") or "")
                else:
                    argv = str(args)
                if argv and argv not in {"{}", "[]", "None"}:
                    self.stats.commands_count += 1
                    self.stats.last_command = argv[:240]
                    self.events.emit(
                        self.run_id,
                        "command",
                        {
                            "argv": argv[:2000],
                            "cwd": str(args.get("cwd") if isinstance(args, dict) else ""),
                            "exit": exit_code,
                            "stdout": _trunc(state.get("output"), 1200),
                        },
                    )
            self.events.emit(
                self.run_id,
                "tool.use",
                {
                    "name": name,
                    "args": _summarize(args),
                    "exit": exit_code,
                    "call_id": call_id,
                },
            )
        tokens = part.get("tokens") or part.get("usage")
        if isinstance(tokens, dict) or part.get("cost") is not None:
            data = dict(tokens) if isinstance(tokens, dict) else {}
            if "cost" not in data and part.get("cost") is not None:
                data["cost"] = part.get("cost")
            cache = data.get("cache")
            if isinstance(cache, dict):
                data["cache"] = int(cache.get("read") or 0) + int(cache.get("write") or 0)
            self._ingest_usage(data)

    def _ingest_usage(self, data: dict[str, Any]) -> None:
        inn = _first_int(data, "input", "input_tokens", "in")
        out = _first_int(data, "output", "output_tokens", "out")
        cache = _first_int(data, "cache", "cache_tokens", "cached")
        cost = data.get("cost") or data.get("costUSD")
        if inn:
            self.stats.tokens_in += inn
        if out:
            self.stats.tokens_out += out
        if cache:
            self.stats.tokens_cache += cache
        if isinstance(cost, (int, float)):
            self.stats.cost += float(cost)
        if inn or out or cache or cost:
            self.events.emit(
                self.run_id,
                "model.usage",
                {
                    "provider": self.stats.model.split("/")[0] if "/" in self.stats.model else "",
                    "model": self.stats.model,
                    "in": inn,
                    "out": out,
                    "cache": cache,
                    "cost": cost,
                },
            )

    def _watch_out(self) -> None:
        while not self._stop.is_set():
            try:
                tick(self.out_dir, sidecars=not self.quiet)
            except Exception:
                pass
            try:
                self.index_findings()
                self._index_scripts()
            except Exception:
                pass
            try:
                from internal.claimcheck import poll

                poll(self.out_dir)
            except Exception:
                pass
            time.sleep(2)

    def _conscience_loop(self) -> None:
        import importlib
        import internal.conscience as cons

        last_mtime = 0.0
        path = Path(cons.__file__)
        while not self._stop.is_set():
            try:
                try:
                    mtime = path.stat().st_mtime
                except OSError:
                    mtime = last_mtime
                if mtime != last_mtime:
                    cons = importlib.reload(cons)
                    last_mtime = mtime
                cons.tick_conscience(self.out_dir)
            except Exception as exc:
                self.events.emit(self.run_id, "error", {"source": "conscience", "error": str(exc)})
            self._stop.wait(5)

    def index_findings(self) -> None:
        findings_dir = self.out_dir / "findings"
        if not findings_dir.is_dir():
            return
        self.stats.findings_by_severity = {k: 0 for k in SEVERITIES}
        self.stats.findings_proven = 0
        self.stats.findings_suspected = 0
        seen: set[str] = set()
        paths = sorted(findings_dir.rglob("F-*.json"), key=lambda p: (len(p.relative_to(findings_dir).parts), str(p)))
        for path in paths:
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if not isinstance(data, dict):
                continue
            data = fill_finding_identity(data, path)
            if not data.get("id"):
                continue
            fid = str(data.get("id") or path.stem)
            if fid in seen:
                continue
            seen.add(fid)
            normalized = normalize_finding(data, findings_dir, self.mode, self.out_dir)
            if normalized != data:
                try:
                    path.write_text(json.dumps(normalized, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
                except OSError:
                    pass
            if normalized.get("duplicate_of"):
                continue
            normalized = coerce_flag_finding(normalized)
            if str(normalized.get("status") or "").lower() in {"discarded", "void"}:
                continue
            is_flag = str(normalized.get("kind") or "").lower() == "flag"
            if not is_flag:
                sev = normalized.get("severity", "info")
                if sev in self.stats.findings_by_severity:
                    self.stats.findings_by_severity[sev] += 1
                if normalized.get("status") == "proven":
                    self.stats.findings_proven += 1
                else:
                    self.stats.findings_suspected += 1
                self.stats.last_finding = str(normalized.get("title") or fid)
            if fid not in self._seen_findings:
                self._seen_findings.add(fid)
                self.events.emit(self.run_id, "finding", normalized)

    def _index_scripts(self) -> None:
        findings = self.out_dir / "findings"
        if not findings.exists():
            return
        n = 0
        for p in findings.rglob("*"):
            if p.is_file() and p.suffix in {".py", ".sh", ".rb", ".ps1", ".go", ".c"}:
                n += 1
        if n > self.stats.scripts_created:
            self.stats.scripts_created = n

    def _poll_audit(self) -> None:
        audit = self.out_dir / ".audit" / "commands.jsonl"
        while not self._stop.is_set():
            if audit.is_file():
                try:
                    lines = audit.read_text(encoding="utf-8").splitlines()
                except OSError:
                    lines = []
                for line in lines[self._seen_audit :]:
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    argv = str(rec.get("argv") or rec.get("cmd") or "")
                    if argv:
                        self.stats.last_command = argv[:240]
                self._seen_audit = len(lines)
            time.sleep(2)

    def _poll_net(self) -> None:
        # Best-effort: host-net ve las conns del host; filtramos por PID del cgroup.
        while not self._stop.is_set():
            if running(self.sandbox.name):
                try:
                    self._sample_ss()
                except Exception:
                    pass
            time.sleep(5)

    def _sample_ss(self) -> None:
        # ss dentro del contenedor: los PID coinciden y se ven los curl cortos
        # mejor que en el host (namespace distinto / conexiones ya cerradas).
        if not running(self.sandbox.name):
            return
        out = exec_out(self.sandbox.name, ["ss", "-tnp"])
        if not out:
            return
        for row in _parse_ss(out):
            if not _usable_ss_row(row):
                continue
            key = f"{row['dst_ip']}:{row['dst_port']}:{row['proto']}:{row['pid']}"
            if key in self._seen_conns:
                continue
            self._seen_conns.add(key)
            self.stats.net_destinations.add(f"{row['dst_ip']}:{row['dst_port']}")
            if row["dst_port"]:
                self.stats.ports[row["dst_port"]] = self.stats.ports.get(row["dst_port"], 0) + 1
            typ = "net.conn"
            if row["dst_ip"] and not ip_in_scope(row["dst_ip"], self.targets):
                if not _is_local(row["dst_ip"]):
                    typ = "net.out_of_scope"
            self.events.emit(self.run_id, typ, row)

    def _write_stats_loop(self) -> None:
        # `docker stats --no-stream` bloquea ~1-2 s y pesa; no cada 3 s. Cada ~15 s
        # basta para RAM/CPU/PIDs/huérfanos. write_stats reusa self._resources.
        tick = 0
        while not self._stop.is_set():
            if tick % 5 == 0:
                try:
                    self._resources = container_resources(self.sandbox.name)
                except Exception:
                    self._resources = {}
            self.write_stats()
            tick += 1
            self._stop.wait(3)

    def write_stats(self) -> None:
        snap = self.stats.snapshot()
        try:
            old = json.loads(self.stats_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            old = {}
        if isinstance(old, dict):
            ot = old.get("tokens") if isinstance(old.get("tokens"), dict) else {}
            nt = snap.get("tokens") if isinstance(snap.get("tokens"), dict) else {}
            snap["tokens"] = {
                "in": max(int(ot.get("in") or 0), int(nt.get("in") or 0)),
                "out": max(int(ot.get("out") or 0), int(nt.get("out") or 0)),
                "cache": max(int(ot.get("cache") or 0), int(nt.get("cache") or 0)),
            }
            snap["cost"] = max(float(old.get("cost") or 0), float(snap.get("cost") or 0))
            for key in ("commands_count", "tools_count", "scripts_created", "net_destinations_unique"):
                snap[key] = max(int(old.get(key) or 0), int(snap.get(key) or 0))
        extra = self._resources or {}
        snap["mem_bytes"] = int(extra.get("mem_bytes") or 0)
        snap["mem_limit_bytes"] = int(extra.get("mem_limit_bytes") or 0)
        snap["cpu_pct"] = float(extra.get("cpu_pct") or 0)
        snap["cpu_cores"] = float(extra.get("cpu_cores") or 0)
        snap["cpu_limit"] = float(extra.get("cpu_limit") or 0)
        snap["pids"] = int(extra.get("pids") or 0)
        snap["orphans"] = list(extra.get("orphans") or [])
        # Parsear el console.log entero es caro; el harness (Claude) no rellena
        # tokens por otra vía, así que lo hacemos como mucho cada 15 s (como docker
        # stats), no en cada tick de 3 s.
        now = time.time()
        if not self._usage or now - self._usage_ts >= 15:
            self._usage = usage_from_console(self.out_dir) or {}
            self._usage_ts = now
        console_u = self._usage
        if console_u:
            nt = snap.get("tokens") if isinstance(snap.get("tokens"), dict) else {}
            snap["tokens"] = {
                "in": max(int(nt.get("in") or 0), int(console_u.get("in") or 0)),
                "out": max(int(nt.get("out") or 0), int(console_u.get("out") or 0)),
                "cache": max(int(nt.get("cache") or 0), int(console_u.get("cache") or 0)),
            }
            snap["cost"] = max(float(snap.get("cost") or 0), float(console_u.get("cost") or 0))
        try:
            eng = json.loads((self.out_dir / "engagement.json").read_text(encoding="utf-8"))
            if isinstance(eng, dict) and isinstance(eng.get("_jobs"), dict):
                snap["jobs"] = eng["_jobs"]
            if isinstance(eng, dict):
                n = max(len(eng.get("cmd_log") or []), len(eng.get("tried") or []))
                snap["commands_count"] = max(int(snap.get("commands_count") or 0), n)
        except (OSError, json.JSONDecodeError):
            pass
        self.stats_path.write_text(
            json.dumps(snap, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )


def _stringify_evidence_blob(ev: Any) -> str:
    """Dict/lista del modelo → texto. No tirar la prueba que no es una ruta."""
    if ev is None:
        return ""
    if isinstance(ev, str):
        return ev.strip()
    if isinstance(ev, list):
        return "\n".join(p for p in (_stringify_evidence_blob(x) for x in ev) if p)
    if isinstance(ev, dict):
        lines: list[str] = []
        for key, val in ev.items():
            inner = _stringify_evidence_blob(val)
            if not inner:
                continue
            label = str(key).replace("_", " ")
            lines.append(f"{label}:\n{inner}" if "\n" in inner else f"{label}: {inner}")
        return "\n".join(lines)
    return str(ev).strip()


_INLINE_DEMO_RX = re.compile(
    r"https?://|\b\d{1,3}(?:\.\d{1,3}){3}\b|CVE-\d{4}-\d+|AES|base64|"
    r"[A-Za-z0-9+/]{20,}={0,2}|jato\.|openam|/openam|sso\.|"
    r"curl |nmap |ldapsearch ",
    re.I,
)


def _inline_demo(out: dict[str, Any]) -> bool:
    """Prueba escrita en la ficha (dict evidence, explain largo), no solo un título."""
    blob = " ".join(
        str(out.get(k) or "") for k in ("explain", "proof", "summary", "reproduction")
    ).strip()
    if len(blob) < 60:
        return False
    return bool(_INLINE_DEMO_RX.search(blob))


_SKIP_SIDECAR = frozenset({".ds_store", "thumbs.db"})


def sidecar_evidence_rels(findings_dir: Path, fid: str) -> list[str]:
    """Archivos reales en findings/F-xxx/. El modelo a menudo no los lista."""
    fid = (fid or "").strip()
    if not fid or "/" in fid or fid in {".", ".."}:
        return []
    folder = findings_dir / fid
    if not folder.is_dir():
        return []
    rels: list[str] = []
    try:
        for p in sorted(folder.iterdir()):
            if not p.is_file() or p.name.startswith("."):
                continue
            if p.name.lower() in _SKIP_SIDECAR:
                continue
            rels.append(f"findings/{fid}/{p.name}")
    except OSError:
        return []
    return rels


def _rels_from_evidence_dict(ev: dict, fid: str) -> list[str]:
    """dir + files: ['app.enc (nota)'] → findings/F-xxx/app.enc."""
    directory = str(ev.get("dir") or ev.get("directory") or "").strip().rstrip("/")
    raw_files = ev.get("files") or ev.get("paths") or []
    if isinstance(raw_files, str):
        raw_files = [raw_files]
    if not isinstance(raw_files, list):
        return []
    rels: list[str] = []
    for item in raw_files:
        token = str(item or "").strip().split()[0].strip(" ,;")
        if not token:
            continue
        name = Path(token).name
        if directory:
            base = directory if directory.startswith("findings/") else (
                f"findings/{fid}" if fid else directory
            )
            rels.append(f"{base.rstrip('/')}/{name}")
        elif fid:
            rels.append(f"findings/{fid}/{name}")
        else:
            rels.append(token)
    return rels


def _coerce_evidence_list(raw_ev: Any, fid: str = "") -> tuple[list[str], str]:
    """Lista de rutas + prosa si el modelo metió un dict o notas sueltas."""
    prose = ""
    paths: list[str] = []
    if isinstance(raw_ev, dict):
        prose = _stringify_evidence_blob(raw_ev)
        paths = _rels_from_evidence_dict(raw_ev, fid)
        return paths, prose
    if isinstance(raw_ev, str):
        return [part.strip() for part in raw_ev.split(",") if part.strip()], ""
    if not isinstance(raw_ev, list):
        return [], ""
    blobs: list[str] = []
    for item in raw_ev:
        if isinstance(item, dict):
            paths.extend(_rels_from_evidence_dict(item, fid))
            inner = _stringify_evidence_blob(item)
            if inner:
                blobs.append(inner)
        elif isinstance(item, str) and item.strip():
            paths.append(item.strip())
        elif item is not None:
            s = str(item).strip()
            if s:
                paths.append(s)
    return paths, "\n".join(blobs)


def _product_line(out: dict[str, Any]) -> str:
    product = str(out.get("product") or "").strip()
    version = str(out.get("version") or "").strip()
    ident = " ".join(p for p in (product, version) if p)
    where = str(out.get("asset") or out.get("vhost") or out.get("host") or "").strip()
    if ident and where:
        return f"{ident} en {where}"
    return ident or where


def fill_finding_identity(data: dict, path: Path | None = None) -> dict:
    """Completa id, asset y evidence si el modelo escribió una ficha a medias.

    Claude/Opus meten la prueba en `evidence: {…}` (objeto) o dejan los
    archivos en findings/F-xxx/ sin listarlos. Tirar el dict dejaba la
    tarjeta vacía y suspected para siempre.
    """
    out = dict(data)
    if not out.get("id") and path is not None and _FID_STEM.match(path.stem):
        out["id"] = path.stem
    fid = str(out.get("id") or (path.stem if path is not None else "") or "")
    raw_ev = data.get("evidence")
    paths, prose = _coerce_evidence_list(raw_ev, fid)
    seen: set[str] = set()
    evidence: list[str] = []
    for rel in paths:
        if rel in seen:
            continue
        seen.add(rel)
        evidence.append(rel)
    if path is not None:
        for rel in sidecar_evidence_rels(path.parent, fid):
            if rel not in seen:
                seen.add(rel)
                evidence.append(rel)
    out["evidence"] = evidence
    if not str(out.get("asset") or "").strip():
        host = str(out.get("vhost") or out.get("host") or "").strip()
        if host:
            out["asset"] = host
    notes = _stringify_evidence_blob(data.get("cve_notes")) if data.get("cve_notes") else ""
    leaks = _stringify_evidence_blob(data.get("leaks")) if data.get("leaks") else ""
    ident = _product_line(out)
    if not str(out.get("explain") or "").strip():
        if prose:
            out["explain"] = prose[:2000]
        elif ident:
            out["explain"] = (ident + ((". " + notes) if notes else ""))[:2000]
        elif notes:
            out["explain"] = notes[:2000]
        elif leaks:
            out["explain"] = leaks[:800]
        else:
            for alt in ("finding", "description", "vector"):
                v = str(out.get(alt) or "").strip()
                if v:
                    out["explain"] = v[:800]
                    break
    if not str(out.get("proof") or "").strip():
        if isinstance(raw_ev, dict):
            for key in ("decrypt", "proof", "poc", "command", "cmd", "xui_index", "serverinfo"):
                if raw_ev.get(key):
                    out["proof"] = _stringify_evidence_blob(raw_ev[key])[:800]
                    break
        if not str(out.get("proof") or "").strip() and notes:
            out["proof"] = notes[:800]
        if not str(out.get("proof") or "").strip() and prose and prose != str(out.get("explain") or ""):
            out["proof"] = prose[:800]
    has_sidecar = bool(path is not None and sidecar_evidence_rels(path.parent, fid))
    if _inline_demo(out) or has_sidecar:
        st = str(out.get("status") or "").strip().lower()
        if st in {"", "suspected", "confirmed", "obtained", "proven"}:
            out["status"] = "proven"
    return out


def infer_severity(out: dict) -> str:
    blob = " ".join(
        str(out.get(k) or "") for k in ("title", "summary", "explain", "impact", "kind", "proof")
    )
    if _SEV_CRITICAL_RX.search(blob):
        return "critical"
    if _SEV_HIGH_RX.search(blob):
        return "high"
    kind = str(out.get("kind") or "").lower()
    if kind in {"vuln", "cve"}:
        return "high"
    if kind == "misconfig":
        return "medium"
    return "info"


# El agente declara la evidencia con rutas del CONTENEDOR (p. ej.
# /run/aegis/out/evidence/x.html). El sidecar del host verifica esos paths con
# out_dir del host (data/runs/<id>): con una ruta absoluta, `out_dir / p` se
# ignora (pathlib) y la evidencia real no se encuentra → todo a "suspected"
# (carta 0/7 pese a pruebas en disco). Remapear el prefijo del contenedor al
# out_dir del host lo resuelve.
_CONTAINER_OUT_MARKER = "run/aegis/out/"


def _evidence_paths(rel: str, out_dir: Path, findings_dir: Path, fid: str = "") -> list[Path]:
    """Candidatas donde puede vivir un archivo de evidencia, host y contenedor."""
    s = str(rel)
    p = Path(s)
    cands: list[Path] = [p]
    if not p.is_absolute():
        cands += [out_dir / p, findings_dir / p]
    idx = s.find(_CONTAINER_OUT_MARKER)
    if idx != -1:
        tail = s[idx + len(_CONTAINER_OUT_MARKER):].lstrip("/")
        if tail:
            cands += [out_dir / tail, findings_dir / tail]
    if p.name:
        cands.append(out_dir / "evidence" / p.name)
        cands.append(out_dir / "loot" / p.name)
        stem = (fid or "").strip()
        if stem:
            cands.append(findings_dir / stem / p.name)
    return cands


def resolve_evidence_rel(out_dir: Path, rel: str, fid: str = "") -> str | None:
    """Ruta relativa al run que existe en disco. None si no hay archivo usable."""
    root = out_dir.resolve()
    findings_dir = root / "findings"
    seen: set[Path] = set()
    for cand in _evidence_paths(str(rel or ""), root, findings_dir, fid):
        try:
            target = cand.resolve()
        except OSError:
            continue
        if target in seen:
            continue
        seen.add(target)
        try:
            if target.is_file() and target.is_relative_to(root):
                return target.relative_to(root).as_posix()
        except (OSError, ValueError):
            continue
    return None


def normalize_finding(data: dict, findings_dir: Path, mode: str, out_dir: Path) -> dict:
    out = fill_finding_identity(data)
    out.setdefault("id", "F-UNK")
    out.setdefault("title", "")
    out.setdefault("asset", "")
    # Los modelos (sobre todo grok) escriben fichas con un esquema propio: el texto
    # va en `finding`/`vector`/`description`, la prueba en `poc`/`command`, y a
    # veces vuelcan su scratchpad de recon (campo `next_action`, resultados
    # negativos) como si fuera un hallazgo. Sin normalizar, la tarjeta sale vacía y
    # etiquetada «vuln». Mapeamos alias a los campos canónicos y degradamos las
    # notas de scratchpad a kind=info (no son vulnerabilidades demostradas).
    if not str(out.get("title") or "").strip():
        for alt in ("finding", "vector", "summary", "explain", "description"):
            v = str(out.get(alt) or "").strip()
            if v:
                out["title"] = v[:200]
                break
    if not str(out.get("explain") or "").strip():
        for alt in ("finding", "description", "vector"):
            v = str(out.get(alt) or "").strip()
            if v:
                out["explain"] = v[:800]
                break
    if not str(out.get("proof") or "").strip():
        poc = out.get("poc")
        if isinstance(poc, dict):
            poc = poc.get("proof") or poc.get("command") or poc.get("cmd") or poc.get("url") or ""
        cand = str(poc or out.get("command") or out.get("cmd") or "").strip()
        if cand:
            out["proof"] = cand[:800]
    _scratch = str(out.get("next_action") or "").strip()
    _kind_blob = " ".join(
        str(out.get(k) or "") for k in ("title", "explain", "summary", "impact", "kind")
    )
    _is_note = bool(_scratch) and not _CVE_RE.search(_kind_blob) and not _FLAG_RE.search(_kind_blob)
    if _is_note:
        out["kind"] = "info"
    inferred = infer_severity(out)
    explicit_sev = str(data.get("severity") or "").strip().lower() in SEVERITIES
    if explicit_sev:
        sev = str(data.get("severity") or "").lower()
        if inferred in SEVERITIES and SEVERITIES.index(inferred) < SEVERITIES.index(sev):
            sev = inferred
    else:
        sev = inferred
    if sev not in SEVERITIES:
        sev = "info"
    status = str(out.get("status") or "suspected")
    if status not in {"suspected", "proven"}:
        status = "suspected"
    evidence = out.get("evidence") or []
    if not isinstance(evidence, list):
        evidence = []
    fid = str(out.get("id") or "")
    for rel in sidecar_evidence_rels(findings_dir, fid):
        if rel not in evidence:
            evidence.append(rel)
    on_disk = []
    for rel in evidence:
        if Path(str(rel)).name.lower() in _NOTEBOOK_EVIDENCE:
            continue
        if any(c.is_file() for c in _evidence_paths(str(rel), out_dir, findings_dir, fid)):
            on_disk.append(str(rel))
    if on_disk:
        # El modelo a veces escribe suspected con la prueba ya en disco (cierre CTF).
        status = "proven"
    elif _inline_demo(out) and not _is_note:
        # Prueba en el cuerpo (evidence:{…}, explain largo) o un suspected
        # que dejó el sidecar tras vaciar el dict: no degradar otra vez.
        status = "proven"
    else:
        status = "suspected"
        if sev == "critical":
            sev = "high"
    if mode == "recon":
        mode_ok = out.get("mode_ok") or []
        exploitative = sev in {"critical", "high"} or (
            isinstance(mode_ok, list) and "full" in mode_ok and "recon" not in mode_ok
        )
        if exploitative:
            status = "suspected"
            if sev == "critical":
                sev = "high"
    if mode == "net":
        blob = " ".join(
            str(out.get(k) or "") for k in ("title", "summary", "explain", "impact", "kind")
        ).lower()
        kind_l = str(out.get("kind") or "").lower()
        exploitative = bool(_NET_EXPLOIT_RX.search(blob)) or kind_l in {"vuln", "cve"}
        infra = any(
            x in blob
            for x in (
                "firewall",
                "unifi",
                "ubiquiti",
                "switch",
                "mikrotik",
                "fortinet",
                "pfsense",
                "access point",
                "controller",
            )
        )
        exploit_mgmt = False
        brief_p = out_dir / "brief.json"
        meta_p = out_dir / "meta.json"
        for p in (brief_p, meta_p):
            if not p.is_file():
                continue
            try:
                data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
            except (OSError, json.JSONDecodeError):
                continue
            if isinstance(data, dict) and data.get("exploit_mgmt"):
                exploit_mgmt = True
                break
        if exploitative and not (exploit_mgmt and infra):
            status = "suspected"
            if sev == "critical":
                sev = "high"
    if _is_note:
        sev = "info"
    out["severity"] = sev
    out["status"] = status
    out["evidence"] = evidence
    out.setdefault("mode_ok", [mode])
    out.setdefault("summary", "")
    out.setdefault("reproduction", "")
    out.setdefault("impact", "")
    out["kind"] = infer_kind(out)
    inv_blob = " ".join(
        str(out.get(k) or "") for k in ("title", "summary", "explain", "impact")
    ).lower()
    if any(
        x in inv_blob
        for x in ("operador suministr", "cuenta de inventario", "provided by the operator")
    ):
        out["kind"] = "info"
        if sev in {"critical", "high"}:
            sev = "info"
            out["severity"] = sev
    coerce_flag_finding(out)
    if not out.get("timestamp"):
        out["timestamp"] = now_ts()
    return out


_KIND_OK = {"vuln", "flag", "cve", "misconfig", "info"}
_FLAG_RE = re.compile(
    r"(?:user|root|local|flag)(?:_proof)?\.txt|\bproof\.txt\b|FLAG\{|CTF\{|ctf.?flag",
    re.I,
)
_FLAG_TITLE_RE = re.compile(
    r"(?:user|root|local|flag)(?:_proof)?\.txt|\bproof\.txt\b|FLAG\{|CTF\{",
    re.I,
)


def coerce_flag_finding(rec: dict) -> dict:
    """Una flag es prueba de contrato, no una vuln: kind=flag y severity=info."""
    kind = str(rec.get("kind") or "").strip().lower()
    title = str(rec.get("title") or "")
    if kind == "flag" or _FLAG_TITLE_RE.search(title):
        rec["kind"] = "flag"
        rec["severity"] = "info"
    return rec
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
_MISC_RE = re.compile(r"misconfig|default.?cred|anonymous.?login|directory.?list", re.I)


def infer_kind(finding: dict) -> str:
    raw = str(finding.get("kind") or "").strip().lower()
    if raw in _KIND_OK:
        return raw
    blob = " ".join(
        str(finding.get(k) or "") for k in ("id", "title", "summary", "asset", "impact")
    )
    if _FLAG_RE.search(blob):
        return "flag"
    if _CVE_RE.search(blob):
        return "cve"
    if _MISC_RE.search(blob):
        return "misconfig"
    return "vuln"


def _summarize(args: Any) -> Any:
    text = json.dumps(args, ensure_ascii=False) if not isinstance(args, str) else args
    if len(text) > 800:
        return text[:800] + "…"
    return args if not isinstance(args, str) else text


def _trunc(val: Any, n: int = 400) -> str:
    s = "" if val is None else str(val)
    return s[:n]


def _first_int(data: dict, *keys: str) -> int:
    for k in keys:
        v = data.get(k)
        if isinstance(v, (int, float)):
            return int(v)
        if isinstance(v, dict):
            inner = v.get("tokens") or v.get("total") or v.get("read")
            if isinstance(inner, (int, float)):
                extra = v.get("write")
                return int(inner) + (int(extra) if isinstance(extra, (int, float)) else 0)
    return 0


def _is_local(ip: str) -> bool:
    return ip in {"127.0.0.1", "::1", "0.0.0.0"} or ip.startswith("127.")


_SS_ROW = re.compile(
    r"(?:(?:tcp|udp|u_str|icmp6)\s+)?"
    r"(?P<state>ESTAB|SYN-SENT)\s+"
    r"\d+\s+\d+\s+"
    r"(?P<src>\S+)\s+"
    r"(?P<dst>\S+)",
    re.I,
)
_SS_PROC = re.compile(r'users:\(\("(?P<proc>[^"]+)",pid=(?P<pid>\d+)', re.I)
_SS_SKIP_PROCS = frozenset({"opencode", "aegis-web"})


def _usable_ss_row(row: dict[str, Any]) -> bool:
    ip = str(row.get("dst_ip") or "")
    if not ip or ip in {"0", "0.0.0.0", "*", "::"}:
        return False
    if not row.get("pid"):
        return False
    if str(row.get("proc") or "").lower() in _SS_SKIP_PROCS and _is_local(ip):
        return False
    try:
        port = int(row.get("dst_port") or 0)
    except (TypeError, ValueError):
        port = 0
    return port > 0 or ("." in ip and not ip.replace(".", "").isdigit())


def _parse_ss(text: str) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for line in text.splitlines():
        if "ESTAB" not in line and "SYN-SENT" not in line:
            continue
        m = _SS_ROW.search(line)
        if not m:
            continue
        ip, port = _split_hostport(m.group("dst"))
        src_ip, src_port = _split_hostport(m.group("src"))
        proc = _SS_PROC.search(line)
        rows.append(
            {
                "src": src_ip,
                "src_port": src_port,
                "dst_ip": ip,
                "dst_port": port,
                "proto": "tcp",
                "pid": int(proc.group("pid")) if proc else 0,
                "proc": proc.group("proc") if proc else "",
                "result": "estab" if m.group("state").upper() == "ESTAB" else "syn",
            }
        )
    return rows


def _split_hostport(addr: str) -> tuple[str, int]:
    addr = addr.strip()
    if addr.startswith("["):
        host, _, rest = addr[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else "0"
        return host, int(port or 0)
    if addr.count(":") == 1:
        host, port = addr.rsplit(":", 1)
        try:
            return host, int(port)
        except ValueError:
            return addr, 0
    return addr, 0


def print_live_stats(stats_path: Path) -> None:
    if not stats_path.is_file():
        print("sin stats aún", file=sys.stderr)
        return
    data = json.loads(stats_path.read_text(encoding="utf-8"))
    toks = data.get("tokens") or {}
    findings = data.get("findings_by_severity") or {}
    line = (
        f"t={data.get('elapsed')}s  "
        f"tok in/out/cache={toks.get('in')}/{toks.get('out')}/{toks.get('cache')}  "
        f"cmd={data.get('commands_count')} tools={data.get('tools_count')}  "
        f"net={data.get('net_destinations_unique')}  "
        f"findings P/S={data.get('findings_proven')}/{data.get('findings_suspected')}  "
        f"sev c/h/m/l/i={findings.get('critical')}/{findings.get('high')}/"
        f"{findings.get('medium')}/{findings.get('low')}/{findings.get('info')}  "
        f"last={data.get('last_command')!r}"
    )
    print(line)
