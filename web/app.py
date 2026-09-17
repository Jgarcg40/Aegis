from __future__ import annotations

import hmac
import json
import mimetypes
import re
import time
import traceback
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from internal.auth import run_host_logout
from internal.config import Config
from internal.inbox import InboxError, MAX_FILE
from web.authflow import LoginManager
from web.login_urls import extract_login_urls
from web.catalog import auth_status as catalog_auth, catalog, invalidate_catalog, note_activated
from web.service import RunManager, _public_queue_item

STATIC_DIR = Path(__file__).resolve().parent / "static"
_DOCTOR_TTL = 20.0
_doctor_cache: dict = {"ts": 0.0, "payload": None}
_MAX_BODY = 4 * 1024 * 1024
# run_id canónico. El enrutado ([^/]+) acepta `..`; esto bloquea path traversal.
_RUN_ID_RE = re.compile(r"^[0-9]{8}-[0-9]{6}-[a-f0-9]{6}$")
_ACTIVE_TYPES = frozenset({
    "text/html",
    "application/xhtml+xml",
    "image/svg+xml",
    "text/xml",
    "application/xml",
})
_ACTIVE_SUFFIX = frozenset({
    ".html", ".htm", ".shtml", ".xhtml", ".svg", ".xml", ".xsl", ".xslt",
})


def path_inside(base: Path, target: Path) -> bool:
    """True si target queda dentro de base. Ambos deben ir ya resueltos."""
    try:
        return target.is_relative_to(base)
    except (OSError, ValueError, TypeError):
        return False


def content_disposition_attachment(name: str) -> str:
    """filename= sin CR/LF ni comillas que partan la cabecera."""
    base = Path(str(name or "download")).name
    safe = re.sub(r'[\x00-\x1f\x7f"\\;]', "_", base).strip() or "download"
    return f'attachment; filename="{safe}"'


def evidence_content_type(name: str, *, download: bool) -> str:
    """HTML/SVG/XML del run no se sirven como documento activo."""
    if download:
        return "application/octet-stream"
    guessed = mimetypes.guess_type(name)[0] or "application/octet-stream"
    kind = guessed.split(";", 1)[0].strip().lower()
    if kind in _ACTIVE_TYPES or Path(name).suffix.lower() in _ACTIVE_SUFFIX:
        return "text/plain; charset=utf-8"
    return guessed


class Ctx:
    cfg: Config
    manager: RunManager
    login: LoginManager
    token: str = ""


def make_handler(ctx: Ctx):
    class Handler(BaseHTTPRequestHandler):
        server_version = "AegisBFF/0.1"
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt, *args):  # silenciar acceso ruidoso
            pass

        def _run_id_ok(self, path: str) -> bool:
            """False solo si la ruta es /api/runs/<id> con id fuera del formato canónico."""
            m = re.match(r"^/api/runs/([^/]+)", path)
            if not m:
                return True
            return bool(_RUN_ID_RE.match(unquote(m.group(1))))

        def _authed(self) -> bool:
            if not ctx.token:
                return True
            supplied = self.headers.get("X-Aegis-Token", "")
            if not supplied:
                q = parse_qs(urlparse(self.path).query)
                supplied = (q.get("token") or [""])[0]
            return hmac.compare_digest(supplied, ctx.token)

        def _json(self, obj, status=200):
            body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if getattr(self, "_head_only", False):
                return
            self.wfile.write(body)

        def _err(self, msg, status=400):
            self._json({"error": msg}, status)

        def _body(self) -> dict:
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0:
                return {}
            if length > _MAX_BODY:
                raise ValueError("cuerpo demasiado grande")
            raw = self.rfile.read(length)
            try:
                data = json.loads(raw.decode("utf-8"))
                return data if isinstance(data, dict) else {}
            except json.JSONDecodeError:
                return {}

        def _sse_open(self):
            self._sse_started = True
            self.close_connection = True  # sin Content-Length: cerrar al terminar el stream
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Connection", "close")
            self.send_header("X-Accel-Buffering", "no")
            self.end_headers()

        def _sse(self, data: str, event: str = "") -> bool:
            try:
                chunk = ""
                if event:
                    chunk += f"event: {event}\n"
                for line in data.splitlines() or [""]:
                    chunk += f"data: {line}\n"
                chunk += "\n"
                self.wfile.write(chunk.encode("utf-8"))
                self.wfile.flush()
                return True
            except (BrokenPipeError, ConnectionResetError, OSError):
                return False

        def _guard(self, fn):
            try:
                return fn()
            except Exception:  # noqa: BLE001
                if getattr(self, "_sse_started", False):
                    return None
                # traza solo en el log del servidor
                traceback.print_exc()
                try:
                    return self._err("error interno", 500)
                except Exception:  # noqa: BLE001
                    return None

        def do_GET(self):
            self._guard(self._route_get)

        def _head_status(self, status: int) -> None:
            self.send_response(status)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Content-Length", "0")
            self.end_headers()

        def do_HEAD(self):
            path = urlparse(self.path).path
            if path.startswith("/api/") and not self._authed():
                return self._head_status(401)
            if not self._run_id_ok(path):
                return self._head_status(400)
            m = re.match(r"^/api/runs/([^/]+)/(console|events)$", path)
            if m:
                rid = unquote(m.group(1))
                if not (ctx.cfg.runs_dir() / rid).is_dir():
                    return self._head_status(404)
                return self._head_status(200)
            m = re.match(r"^/api/auth/login/([^/]+)/stream$", path)
            if m:
                if not ctx.login.get(m.group(1)):
                    return self._head_status(404)
                return self._head_status(200)
            self._head_only = True
            try:
                self._guard(self._route_get)
            finally:
                self._head_only = False

        def do_POST(self):
            self._guard(self._route_post)

        def do_DELETE(self):
            self._guard(self._route_delete)

        def do_PATCH(self):
            self._guard(self._route_patch)

        def _route_get(self):
            path = urlparse(self.path).path
            if path.startswith("/api/") and not self._authed():
                return self._err("no autorizado", 401)
            if not self._run_id_ok(path):
                return self._err("run inválido", 400)
            if path == "/api/health":
                return self._json({"ok": True, "ts": time.time()})
            if path == "/api/doctor":
                return self._doctor()
            if path == "/api/models":
                q = parse_qs(urlparse(self.path).query)
                refresh = (q.get("refresh") or ["0"])[0] in ("1", "true")
                return self._json(catalog(ctx.cfg, refresh=refresh))
            if path == "/api/auth":
                return self._json(catalog_auth())
            if path == "/api/queue":
                return self._json(ctx.manager.queue_view())
            m = re.match(r"^/api/inbox/(ib-[a-f0-9]{12})$", path)
            if m:
                try:
                    return self._json({"id": m.group(1), "files": ctx.manager.inbox_files(m.group(1))})
                except InboxError as exc:
                    return self._err(str(exc), 404)
            if path == "/api/runs":
                return self._json(ctx.manager.list_runs())
            if path == "/api/eval":
                q = parse_qs(urlparse(self.path).query)
                ids = [x for x in (q.get("id") or []) if x]
                return self._json(ctx.manager.eval_runs(ids or None))
            if path == "/api/presets/last":
                preset = ctx.manager.last_preset()
                if not preset:
                    return self._err("no hay runs previos", 404)
                return self._json(preset)
            m = re.match(r"^/api/presets/([^/]+)$", path)
            if m:
                rid = unquote(m.group(1))
                if not _RUN_ID_RE.match(rid):
                    return self._err("run_id inválido", 400)
                try:
                    return self._json(ctx.manager.preset_for(rid))
                except FileNotFoundError:
                    return self._err("run no encontrado", 404)

            m = re.match(r"^/api/runs/([^/]+)/console$", path)
            if m:
                q = parse_qs(urlparse(self.path).query)
                if (q.get("snapshot") or ["0"])[0] in ("1", "true"):
                    return self._snapshot_text(unquote(m.group(1)), "console.log")
                return self._tail_console(unquote(m.group(1)))
            m = re.match(r"^/api/runs/([^/]+)/events$", path)
            if m:
                q = parse_qs(urlparse(self.path).query)
                if (q.get("snapshot") or ["0"])[0] in ("1", "true"):
                    return self._snapshot_text(unquote(m.group(1)), "events.jsonl")
                return self._tail_events(unquote(m.group(1)))
            m = re.match(r"^/api/runs/([^/]+)/stats$", path)
            if m:
                return self._json(ctx.manager.stats(unquote(m.group(1))))
            m = re.match(r"^/api/runs/([^/]+)/activity$", path)
            if m:
                try:
                    part = (parse_qs(urlparse(self.path).query).get("part") or ["all"])[0]
                    return self._json(ctx.manager.activity(unquote(m.group(1)), part=str(part)))
                except FileNotFoundError:
                    return self._err("run no encontrado", 404)
            m = re.match(r"^/api/runs/([^/]+)/tree$", path)
            if m:
                try:
                    return self._json(ctx.manager.tree(unquote(m.group(1))))
                except FileNotFoundError:
                    return self._err("run no encontrado", 404)
            m = re.match(r"^/api/runs/([^/]+)/state$", path)
            if m:
                return self._json({"markdown": ctx.manager.state_md(unquote(m.group(1)))})
            m = re.match(r"^/api/runs/([^/]+)/findings$", path)
            if m:
                return self._json(ctx.manager.findings(unquote(m.group(1))))
            m = re.match(r"^/api/runs/([^/]+)/report\.pdf$", path)
            if m:
                return self._report_pdf(unquote(m.group(1)))
            m = re.match(r"^/api/runs/([^/]+)/report$", path)
            if m:
                return self._json(ctx.manager.report(unquote(m.group(1))))
            m = re.match(r"^/api/runs/([^/]+)/files/(.+)$", path)
            if m:
                return self._serve_evidence(unquote(m.group(1)), unquote(m.group(2)))
            m = re.match(r"^/api/runs/([^/]+)$", path)
            if m:
                try:
                    return self._json(ctx.manager.run_detail(unquote(m.group(1))))
                except FileNotFoundError:
                    return self._err("run no encontrado", 404)

            m = re.match(r"^/api/auth/login/([^/]+)/stream$", path)
            if m:
                return self._login_stream(m.group(1))

            if path.startswith("/api/"):
                return self._err("ruta no encontrada", 404)
            return self._static(path)

        def _route_post(self):
            path = urlparse(self.path).path
            if not self._authed():
                return self._err("no autorizado", 401)
            if not self._run_id_ok(path):
                return self._err("run inválido", 400)
            if path == "/api/inbox":
                return self._json(ctx.manager.create_inbox())
            m = re.match(r"^/api/inbox/(ib-[a-f0-9]{12})$", path)
            if m:
                return self._inbox_put(m.group(1))
            if path == "/api/runs":
                return self._create_run()
            if path == "/api/auth/login":
                return self._login_create()
            if path == "/api/auth/logout":
                prov = self._body().get("provider", "")
                if not prov:
                    return self._err("provider requerido")
                try:
                    rc = run_host_logout(prov)
                except SystemExit as exc:
                    return self._err(str(exc), 500)
                invalidate_catalog()
                return self._json({"ok": rc == 0})
            m = re.match(r"^/api/auth/login/([^/]+)/input$", path)
            if m:
                sess = ctx.login.get(m.group(1))
                if not sess:
                    return self._err("sesión no encontrada", 404)
                sess.write(self._body().get("data", ""))
                return self._json({"ok": True})
            m = re.match(r"^/api/runs/([^/]+)/abort$", path)
            if m:
                try:
                    out = ctx.manager.abort(unquote(m.group(1)))
                except SystemExit as exc:
                    return self._err(str(exc), 404)
                if isinstance(out, dict):
                    out.setdefault("ok", True)
                    return self._json(out)
                return self._json({"ok": True})
            m = re.match(r"^/api/runs/([^/]+)/pause$", path)
            if m:
                try:
                    ctx.manager.pause(unquote(m.group(1)))
                except ValueError as exc:
                    return self._err(str(exc), 409)
                return self._json({"ok": True, "paused": True})
            m = re.match(r"^/api/runs/([^/]+)/unpause$", path)
            if m:
                try:
                    ctx.manager.unpause(unquote(m.group(1)))
                except ValueError as exc:
                    return self._err(str(exc), 409)
                return self._json({"ok": True, "paused": False})
            m = re.match(r"^/api/runs/([^/]+)/watch$", path)
            if m:
                try:
                    return self._json(ctx.manager.watch_run(unquote(m.group(1))))
                except FileNotFoundError:
                    return self._err("run no encontrado", 404)
                except ValueError as exc:
                    return self._err(str(exc), 409)
            m = re.match(r"^/api/runs/([^/]+)/steer$", path)
            if m:
                body = self._body()
                try:
                    dest = ctx.manager.steer(
                        unquote(m.group(1)),
                        str(body.get("text") or ""),
                        str(body.get("model") or ""),
                    )
                except FileNotFoundError:
                    return self._err("run no encontrado", 404)
                except ValueError as exc:
                    return self._err(str(exc), 422)
                return self._json({"ok": True, "path": str(dest)})
            m = re.match(r"^/api/runs/([^/]+)/resume$", path)
            if m:
                try:
                    item = ctx.manager.resume_run(unquote(m.group(1)), self._body())
                except FileNotFoundError:
                    return self._err("run no encontrado", 404)
                except ValueError as exc:
                    return self._err(str(exc), 409)
                cur = ctx.manager.current_view()
                live = bool(cur and cur.get("qid") == item.qid)
                return self._json({"queued": True, "live": live, "item": _public_queue_item(item)})
            if path == "/api/local":
                body = self._body()
                try:
                    entry = ctx.manager.set_local_endpoint(
                        str(body.get("provider") or ""), str(body.get("endpoint") or "")
                    )
                except ValueError as exc:
                    return self._err(str(exc), 422)
                invalidate_catalog()
                return self._json({"ok": True, **entry})
            if path == "/api/auth/apikey":
                body = self._body()
                from internal.auth import save_api_key

                try:
                    save_api_key(str(body.get("provider") or ""), str(body.get("key") or ""))
                except SystemExit as exc:
                    return self._err(str(exc), 422)
                note_activated(ctx.cfg, str(body.get("provider") or ""))
                invalidate_catalog()
                return self._json({"ok": True})
            return self._err("ruta no encontrada", 404)

        def _route_patch(self):
            path = urlparse(self.path).path
            if not self._authed():
                return self._err("no autorizado", 401)
            if not self._run_id_ok(path):
                return self._err("run inválido", 400)
            m = re.match(r"^/api/runs/([^/]+)$", path)
            if m:
                body = self._body()
                if "title" not in body:
                    return self._err("title requerido", 422)
                try:
                    meta = ctx.manager.rename_run(unquote(m.group(1)), str(body.get("title") or ""))
                except FileNotFoundError:
                    return self._err("run no encontrado", 404)
                except ValueError as exc:
                    return self._err(str(exc), 422)
                return self._json({"ok": True, "run_id": meta.get("run_id"), "title": meta.get("title") or ""})
            return self._err("ruta no encontrada", 404)

        def _route_delete(self):
            path = urlparse(self.path).path
            if not self._authed():
                return self._err("no autorizado", 401)
            if not self._run_id_ok(path):
                return self._err("run inválido", 400)
            m = re.match(r"^/api/inbox/(ib-[a-f0-9]{12})$", path)
            if m:
                try:
                    ctx.manager.drop_inbox(m.group(1))
                except ValueError as exc:
                    return self._err(str(exc), 409)
                return self._json({"ok": True})
            m = re.match(r"^/api/queue/([^/]+)$", path)
            if m:
                ok = ctx.manager.dequeue(unquote(m.group(1)))
                if not ok:
                    return self._err("no se puede quitar: ya está lanzando o no está en cola", 409)
                return self._json({"ok": True})
            m = re.match(r"^/api/auth/login/([^/]+)$", path)
            if m:
                return self._json({"ok": ctx.login.close(m.group(1))})
            if path == "/api/runs":
                raw = self._body().get("ids")
                if not isinstance(raw, list) or not raw:
                    return self._err("ids requerido", 422)
                ids: list[str] = []
                for item in raw[:200]:
                    rid = str(item or "").strip()
                    if not _RUN_ID_RE.match(rid):
                        return self._err("run inválido", 400)
                    ids.append(rid)
                if not ids:
                    return self._err("ids requerido", 422)
                return self._json(ctx.manager.delete_runs(ids))
            m = re.match(r"^/api/runs/([^/]+)$", path)
            if m:
                try:
                    ctx.manager.delete_run(unquote(m.group(1)))
                    return self._json({"ok": True})
                except FileNotFoundError:
                    return self._err("run no encontrado", 404)
                except ValueError as exc:
                    return self._err(str(exc), 409)
                except PermissionError as exc:
                    return self._err(str(exc), 500)
            return self._err("ruta no encontrada", 404)

        def _doctor(self):
            q = parse_qs(urlparse(self.path).query)
            refresh = (q.get("refresh") or ["0"])[0] in ("1", "true")
            now = time.time()
            cached = _doctor_cache.get("payload")
            if not refresh and cached is not None and now - float(_doctor_cache.get("ts") or 0) < _DOCTOR_TTL:
                return self._json(cached)

            from internal.sandbox import image_exists, require_docker
            from internal.auth import opencode_bin, load_auth, summarize_providers, host_auth_path

            docker_ok = True
            docker_msg = ""
            try:
                require_docker()
            except SystemExit as exc:
                docker_ok = False
                docker_msg = str(exc)
            auth = load_auth()

            payload = {
                "image": ctx.cfg.image,
                "image_ok": image_exists(ctx.cfg.image),
                "docker_ok": docker_ok,
                "docker_msg": docker_msg,
                "network_mode": ctx.cfg.network_mode,
                "opencode": str(opencode_bin() or ""),
                "auth_file": str(host_auth_path()),
                "oauth": summarize_providers(auth),
                "codex": __import__("internal.codex", fromlist=["auth_status"]).auth_status(),
                "claude": __import__("internal.claude", fromlist=["auth_status"]).auth_status(),
            }
            _doctor_cache["ts"] = now
            _doctor_cache["payload"] = payload
            return self._json(payload)

        def _create_run(self):
            body = self._body()
            try:
                item = ctx.manager.enqueue(body)
            except ValueError as exc:
                return self._err(str(exc), 422)
            cur = ctx.manager.current_view()
            live = bool(cur and cur.get("qid") == item.qid)
            return self._json({"queued": True, "live": live, "item": _public_queue_item(item)})

        def _inbox_put(self, inbox_id: str):
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0:
                return self._err("archivo vacío")
            if length > MAX_FILE:
                return self._err(f"cada anexo como mucho {MAX_FILE // (1024 * 1024)} MB")
            name = unquote(self.headers.get("X-Aegis-Name") or "")
            try:
                rec = ctx.manager.add_inbox_file(inbox_id, name, self.rfile, length)
            except ValueError as exc:
                return self._err(str(exc), 422)
            except InboxError as exc:
                return self._err(str(exc), 404)
            return self._json({"id": inbox_id, **rec})

        def _login_create(self):
            body = self._body()
            provider = str(body.get("provider") or "")
            method = str(body.get("method") or "")
            try:
                sess = ctx.login.create(provider, method)
            except RuntimeError as exc:
                return self._err(str(exc), 500)
            return self._json({"sid": sess.sid, "provider": provider, "method": method})

        def _login_stream(self, sid: str):
            sess = ctx.login.get(sid)
            if not sess:
                return self._err("sesión no encontrada", 404)
            self._sse_open()
            last = 0
            last_urls: list[str] = []
            idle = 0
            while True:
                sess.read_into_buffer()
                snap = sess.snapshot()
                if len(snap) > last:
                    # un data: JSON; si parte \\r en líneas, rompe la TUI
                    payload = json.dumps(snap[last:], ensure_ascii=False)
                    if not self._sse(payload, event="out"):
                        break
                    last = len(snap)
                    idle = 0
                    urls = extract_login_urls(snap)
                    if urls and urls != last_urls:
                        last_urls = urls
                        if not self._sse(json.dumps(urls, ensure_ascii=False), event="urls"):
                            break
                if not sess.alive:
                    self._sse(json.dumps({"exit": sess.exit_code}), event="end")
                    break
                idle += 1
                if idle % 15 == 0:
                    if not self._sse("", event="ping"):
                        break
                time.sleep(0.2)

        def _snapshot_text(self, run_id: str, name: str):
            from web.safeio import contained_file, read_contained_bytes

            root = ctx.manager.run_root(run_id)
            path = contained_file(root, name)
            q = parse_qs(urlparse(self.path).query)
            full = 0
            if name == "console.log" and path is not None and (q.get("plain") or ["0"])[0] in ("1", "true"):
                from web.consoleview import compact_console

                data, full = compact_console(path)
            else:
                data = read_contained_bytes(root, name) or b""
                full = len(data)
            if (q.get("plain") or ["0"])[0] in ("1", "true"):
                self.send_response(200)
                self.send_header("Content-Type", "text/plain; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("X-Aegis-Bytes", str(full))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)
                return
            text = data.decode("utf-8", errors="replace")
            return self._json({"text": text, "bytes": len(data)})

        def _tail_events(self, run_id: str):
            self._sse_open()
            self._tail_named(run_id, "events.jsonl")

        def _tail_console(self, run_id: str):
            self._sse_open()
            self._tail_named(run_id, "console.log")

        def _sse_start_offset(self) -> int:
            q = parse_qs(urlparse(self.path).query)
            try:
                return max(0, int((q.get("from") or ["0"])[0]))
            except ValueError:
                return 0

        def _run_ended(self, run_id: str) -> bool:
            meta = ctx.manager.run_root(run_id) / "meta.json"
            if not meta.is_file():
                # sin meta.json: arranque o run inexistente; el caller aplica gracia
                return False
            try:
                data = json.loads(meta.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                return False
            return data.get("status") == "ended"

        def _tail_named(self, run_id: str, name: str):
            from web.safeio import contained_file

            offset = self._sse_start_offset()
            buf = ""
            waited_no_meta = 0  # ciclos (~0.4s) esperando a que aparezca meta.json
            while True:
                path = contained_file(ctx.manager.run_root(run_id), name)
                try:
                    if path is not None:
                        with path.open("rb") as fh:
                            fh.seek(offset)
                            raw = fh.read()
                            offset = fh.tell()
                        chunk = raw.decode("utf-8", errors="replace")
                    else:
                        chunk = ""
                except OSError:
                    chunk = ""
                if chunk:
                    buf += chunk
                    while "\n" in buf:
                        line, buf = buf.split("\n", 1)
                        if not line:
                            continue
                        if not self._sse(line, event="line"):
                            return
                    if len(buf) > 2_000_000:  # línea gigante sin \n: emitir y no reventar RAM
                        if not self._sse(buf, event="line"):
                            return
                        buf = ""
                ended = self._run_ended(run_id)
                if not ended and not (ctx.manager.run_root(run_id) / "meta.json").is_file():
                    waited_no_meta += 1
                    if waited_no_meta > 150:  # ~60s sin meta.json -> run inexistente
                        ended = True
                else:
                    waited_no_meta = 0
                if ended:
                    if buf.strip():
                        if not self._sse(buf, event="line"):
                            return
                        buf = ""
                    self._sse("done", event="end")
                    return
                if not self._sse("", event="ping"):
                    return
                time.sleep(0.4)

        def _serve_evidence(self, run_id: str, rel: str):
            base = ctx.manager.run_root(run_id).resolve()
            target = (base / rel).resolve()
            if not path_inside(base, target) or not target.is_file():
                try:
                    from internal.telemetry import resolve_evidence_rel

                    alt = resolve_evidence_rel(base, rel)
                    if alt:
                        target = (base / alt).resolve()
                except Exception:
                    alt = None
            if not path_inside(base, target) or not target.is_file():
                return self._err("archivo no encontrado", 404)
            # .serve = password del server OpenCode
            if target.name in {".serve"} or target.name.endswith(".serve"):
                return self._err("archivo protegido", 403)
            q = parse_qs(urlparse(self.path).query)
            download = (q.get("download") or ["0"])[0] in ("1", "true")
            ctype = evidence_content_type(target.name, download=download)
            try:
                size = target.stat().st_size
            except OSError:
                return self._err("archivo no encontrado", 404)
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(size))
            if download:
                self.send_header("Content-Disposition", content_disposition_attachment(target.name))
            self.end_headers()
            if getattr(self, "_head_only", False):
                return None
            # no cargar el archivo entero en RAM
            try:
                with target.open("rb") as fh:
                    while True:
                        blk = fh.read(256 * 1024)
                        if not blk:
                            break
                        self.wfile.write(blk)
            except (BrokenPipeError, ConnectionResetError, OSError):
                return None

        def _report_pdf(self, run_id: str):
            try:
                rep = ctx.manager.report(run_id)
            except FileNotFoundError:
                return self._err("run no encontrado", 404)
            md = (rep or {}).get("markdown") or ""
            if not md.strip():
                return self._err("sin informe todavía", 404)
            try:
                from internal.report.pdf import render_report_pdf

                image = getattr(ctx.cfg, "image", "aegis-runner:latest")
                data = render_report_pdf(run_id, md, image=image)
            except Exception as exc:  # noqa: BLE001
                return self._err("no se pudo generar el PDF: " + str(exc)[:160], 500)
            self.send_response(200)
            self.send_header("Content-Type", "application/pdf")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Content-Disposition", content_disposition_attachment(f"aegis-{run_id}-informe.pdf"))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            if getattr(self, "_head_only", False):
                return None
            try:
                self.wfile.write(data)
            except (BrokenPipeError, ConnectionResetError, OSError):
                return None

        def _static(self, path: str):
            if path == "/" or path == "":
                path = "/index.html"
            rel = path.lstrip("/")
            root = STATIC_DIR.resolve()
            target = (STATIC_DIR / rel).resolve()
            if not path_inside(root, target) or not target.is_file():
                # fallback index.html (SPA)
                target = (STATIC_DIR / "index.html").resolve()
                if not path_inside(root, target) or not target.is_file():
                    return self._err("no encontrado", 404)
            ctype = mimetypes.guess_type(str(target))[0] or "application/octet-stream"
            data = target.read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            if getattr(self, "_head_only", False):
                return
            self.wfile.write(data)

    return Handler
