from __future__ import annotations

import argparse
import os
import socket
import sys
import threading
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from internal.auth import ensure_alive_cwd  # noqa: E402
from internal.config import load_config  # noqa: E402
from web.app import Ctx, make_handler  # noqa: E402
from web.authflow import LoginManager  # noqa: E402
from web.service import RunManager  # noqa: E402


def _display_bind_host(bind: str) -> str:
    """Host para la URL impresa. Si escucha en todas las interfaces, usa una IP
    de esta máquina (cualquier red de instalación) o 127.0.0.1."""
    if bind not in {"0.0.0.0", "::", ""}:
        return bind
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("192.0.2.1", 1))
            ip = sock.getsockname()[0]
        if ip and not ip.startswith("127."):
            return ip
    except OSError:
        pass
    return "127.0.0.1"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aegis-web",
        description="UI on-premise de Aegis (BFF stdlib + SPA estática).",
    )
    parser.add_argument("--host", default=os.environ.get("AEGIS_WEB_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("AEGIS_WEB_PORT", "8787")))
    parser.add_argument("--config", default="")
    args = parser.parse_args(argv)

    ensure_alive_cwd(ROOT, Path.home())
    cfg = load_config(Path(args.config) if args.config else None)
    cfg.data_dir.mkdir(parents=True, exist_ok=True)

    ctx = Ctx()
    ctx.cfg = cfg
    ctx.manager = RunManager(cfg)
    ctx.login = LoginManager()
    ctx.token = os.environ.get("AEGIS_WEB_TOKEN", "")

    handler = make_handler(ctx)
    # bind_and_activate=False para poder fijar el backlog ANTES del listen():
    # el constructor por defecto llama a server_activate() con request_queue_size=5.
    httpd = ThreadingHTTPServer((args.host, args.port), handler, bind_and_activate=False)
    httpd.daemon_threads = True
    httpd.request_queue_size = 64
    httpd.allow_reuse_address = True
    httpd.server_bind()
    httpd.server_activate()

    def gc_loop():
        import time

        while True:
            time.sleep(60)
            ctx.login.gc()

    threading.Thread(target=gc_loop, daemon=True).start()

    shown = _display_bind_host(args.host)
    print(f"aegis-web: http://{shown}:{args.port}  (bind {args.host})", file=sys.stderr)
    if ctx.token:
        print("aegis-web: token de operador ACTIVO (AEGIS_WEB_TOKEN)", file=sys.stderr)
    else:
        print("aegis-web: sin token (LAN de confianza). Exporta AEGIS_WEB_TOKEN para exigirlo.", file=sys.stderr)
    ctx.manager.start()
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("aegis-web: parando", file=sys.stderr)
    finally:
        ctx.manager.stop()
        httpd.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
