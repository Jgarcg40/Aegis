from __future__ import annotations

import argparse
import sys
from pathlib import Path

from internal.auth import (
    host_auth_path,
    load_auth,
    opencode_bin,
    run_host_login,
    run_host_logout,
    summarize_providers,
)
from internal.config import ROOT, load_config
from internal.flagspec import build_contract
from internal.run import (
    cmd_abort,
    cmd_attach,
    cmd_list,
    cmd_rename,
    cmd_report,
    cmd_status,
    cmd_steer,
    cmd_watch,
    execute,
)
from internal.sandbox import image_exists, require_docker


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="aegis",
        description="Orquestador on-premise de pentesting autorizado. Un agente OpenCode por run.",
    )
    parser.add_argument("--config", default="", help="ruta a aegis.yaml")
    sub = parser.add_subparsers(dest="cmd", required=True)

    run_p = sub.add_parser("run", help="crear sandbox, lanzar OpenCode, persistir out/, destruir contenedor")
    run_p.add_argument("--target", default="", help="IPv4/IPv6, IP:puerto, CIDR, URL, CSV o archivo")
    run_p.add_argument(
        "--resume",
        default="",
        help="reanudar un run muerto (mismo loot/engagement; nuevo contenedor)",
    )
    run_p.add_argument(
        "--account",
        action="append",
        default=[],
        help="cuenta de inventario user:secret (va a engagement.json, no al prompt)",
    )
    run_p.add_argument("--mode", choices=["full", "assess", "recon", "net"], default=None)
    run_p.add_argument(
        "--harness",
        choices=["opencode", "codex", "claude", "cursor"],
        default="opencode",
        help="runtime del agente: OpenCode, Codex CLI (ChatGPT) o Claude Code",
    )
    run_p.add_argument("--model", default="", help="grok | codex | claude | ollama | vllm | slug (sonnet, gpt-5.6-sol)")
    run_p.add_argument("--model-id", default="", help="id concreto del modelo (llama3.1, grok-4, …)")
    run_p.add_argument(
        "--endpoint",
        default="",
        help="IP o URL de Ollama/vLLM (ej. 192.168.1.10:11434 o http://10.0.0.5:8000/v1)",
    )
    run_p.add_argument("--title", default="", help="nombre visible del run (historial y UI)")
    run_p.add_argument("--note", default="", help="instrucción del operador; prevalece sobre el plan")
    run_p.add_argument("--timeout", default="", help="presupuesto de tiempo, ej. 6h")
    run_p.add_argument(
        "--inbox",
        default="",
        help="directorio de anexos (se copia a /run/aegis/inbox, solo lectura)",
    )
    run_p.add_argument(
        "--anexo",
        action="append",
        default=[],
        help="archivo anexo para el agente; repetir. Igual destino que --inbox",
    )
    run_p.add_argument(
        "--no-persist",
        action="store_true",
        help="dejar que el agente pare cuando crea que terminó; por defecto insiste hasta el timeout o hasta que lo pares",
    )
    run_p.add_argument("--image", default="", help="sobrescribe la imagen Docker")
    run_p.add_argument(
        "--i-am-authorized",
        action="store_true",
        help="obligatorio: engagement autorizado contra los targets declarados",
    )
    run_p.add_argument(
        "--smoke",
        action="store_true",
        help="ciclo de vida sin modelo: el contenedor escribe un finding de prueba y sale",
    )
    run_p.add_argument(
        "--backup-harness",
        default="",
        help="harness de respaldo (opencode|codex|claude|cursor). Vacío = sin backup",
    )
    run_p.add_argument(
        "--backup-model",
        default="",
        help="modelo de respaldo (ej. xai/grok-4.6). Vacío = sin backup",
    )
    run_p.add_argument(
        "--rescue-harness",
        default="",
        help="harness de salvaguarda (opencode|codex|claude|cursor). Vacío = el del principal, o el de --rescue-model si va como harness::modelo",
    )
    run_p.add_argument(
        "--rescue-model",
        default="",
        help="modelo de salvaguarda (Lanzar). Cualquier modelo: otra sub OpenCode u otro harness (claude::sonnet, --rescue-harness claude). Vacío = default (Grok xAI: 4.3 60s; Claude: sonnet-4-6; Codex: gpt-5.4). El backup no entra aquí",
    )
    run_p.add_argument(
        "--ctf",
        action="store_true",
        help="modo CTF: el persist cierra al completar el contrato de flags",
    )
    run_p.add_argument(
        "--flag",
        action="append",
        default=[],
        help="flag del contrato (user.txt, root.txt, FLAG{}). Repetir o una para todas",
    )
    run_p.add_argument(
        "--flag-count",
        type=int,
        default=0,
        help="número de flags CTF (default 2 = user.txt + root.txt)",
    )
    run_p.add_argument(
        "--ssh-host",
        default="",
        help="auditoría: IP del salto SSH (incompatible con --ctf)",
    )
    run_p.add_argument(
        "--exploit-mgmt",
        action="store_true",
        help="modo Red: explotar el plano de gestión de fw/switch/AP",
    )
    run_p.add_argument("--ssh-user", default="", help="usuario SSH")
    run_p.add_argument(
        "--ssh-pass",
        default="",
        help="contraseña SSH (o env AEGIS_SSH_PASS). No va al BRIEF",
    )

    for name, help_ in (
        ("attach", "TUI OpenCode del run vivo"),
        ("watch", "reenganchar sidecar/conciencia a un contenedor vivo"),
        ("status", "stats en vivo (texto)"),
        ("abort", "abort cooperativo + docker rm -f"),
        ("report", "mostrar / regenerar informe"),
    ):
        p = sub.add_parser(name, help=help_)
        p.add_argument("run_id", nargs="?", default="")
        if name == "watch":
            p.add_argument(
                "--supervise",
                action="store_true",
                help="reintenta el sidecar si muere y el contenedor sigue",
            )

    eval_p = sub.add_parser("eval", help="puntuar runs ya en disco (user/root, tiempo, tokens)")
    eval_p.add_argument("run_id", nargs="*", default=[], help="ids; vacío = todos")

    steer_p = sub.add_parser("steer", help="una frase al agente vivo (STEER.md → siguiente persist)")
    steer_p.add_argument("run_id", nargs="?", default="")
    steer_p.add_argument("text", nargs=argparse.REMAINDER, help="frase del operador")

    rename_p = sub.add_parser("rename", help="poner o cambiar el título de un run")
    rename_p.add_argument("run_id", nargs="?", default="")
    rename_p.add_argument("title", nargs=argparse.REMAINDER, help="nombre visible, ej. Lab-01")

    sub.add_parser("list", help="listar runs persistidos")
    sub.add_parser("doctor", help="comprobar Docker, imagen, OpenCode y OAuth")

    auth_p = sub.add_parser("auth", help="login OAuth de OpenCode en el HOST (suscripciones)")
    auth_sub = auth_p.add_subparsers(dest="auth_cmd")
    login_p = auth_sub.add_parser("login", help="opencode auth login (SuperGrok / ChatGPT Plus)")
    login_p.add_argument(
        "provider",
        nargs="?",
        default="",
        help="grok|xai|codex|openai|claude (vacío = menú de OpenCode)",
    )
    logout_p = auth_sub.add_parser("logout", help="cerrar sesión de un proveedor")
    logout_p.add_argument("provider")
    auth_sub.add_parser("list", help="proveedores ya logueados")

    args = parser.parse_args(argv)
    cfg_path = Path(args.config) if args.config else None
    cfg = load_config(cfg_path)

    if args.cmd == "run":
        if not args.target and not args.resume and not args.ssh_host:
            parser.error("--target es obligatorio (salvo --resume o --ssh-host)")
        mode = args.mode
        if mode is None:
            mode = "full"
        model = args.model or cfg.default_model
        timeout = args.timeout or cfg.timeout
        ctf_contract = None
        if args.ctf:
            n = args.flag_count or (len(args.flag) if args.flag else 2)
            ctf_contract = build_contract(enabled=True, flags=list(args.flag or []), count=n)
        if args.exploit_mgmt and mode != "net":
            parser.error("--exploit-mgmt solo vale con --mode net")
        if args.exploit_mgmt and args.ctf:
            parser.error("Red y CTF no se mezclan")
        return execute(
            cfg=cfg,
            target_spec=args.target,
            mode=mode,
            model_alias=model,
            note=args.note,
            timeout=timeout,
            authorized=args.i_am_authorized,
            model_id=args.model_id,
            endpoint=args.endpoint,
            image=args.image,
            smoke=args.smoke,
            harness=args.harness,
            persist=not args.no_persist,
            backup_harness=args.backup_harness,
            backup_model=args.backup_model,
            rescue_model=args.rescue_model,
            rescue_harness=args.rescue_harness,
            resume=args.resume,
            accounts=list(args.account or []),
            title=args.title,
            ctf_contract=ctf_contract,
            ssh_host=args.ssh_host,
            ssh_user=args.ssh_user,
            ssh_pass=args.ssh_pass,
            exploit_mgmt=bool(args.exploit_mgmt),
            inbox=args.inbox,
            anexo=list(args.anexo or []),
        )
    if args.cmd == "attach":
        return cmd_attach(cfg, args.run_id or None)
    if args.cmd == "watch":
        return cmd_watch(cfg, args.run_id or None, supervise=bool(getattr(args, "supervise", False)))
    if args.cmd == "eval":
        from internal.eval import format_table, score_runs

        rows = score_runs(cfg.runs_dir(), list(args.run_id) or None)
        sys.stdout.write(format_table(rows))
        return 0 if rows else 1
    if args.cmd == "status":
        return cmd_status(cfg, args.run_id or None)
    if args.cmd == "abort":
        return cmd_abort(cfg, args.run_id or None)
    if args.cmd == "report":
        return cmd_report(cfg, args.run_id or None)
    if args.cmd == "steer":
        text = " ".join(args.text).strip()
        if not text:
            parser.error("aegis steer [run_id] <frase>")
        return cmd_steer(cfg, args.run_id or None, text)
    if args.cmd == "rename":
        title = " ".join(args.title).strip()
        if not title:
            parser.error("aegis rename [run_id] <título>")
        return cmd_rename(cfg, args.run_id or None, title)
    if args.cmd == "list":
        return cmd_list(cfg)
    if args.cmd == "doctor":
        return cmd_doctor(cfg)
    if args.cmd == "auth":
        return cmd_auth(args)
    parser.error("comando desconocido")
    return 2


def cmd_doctor(cfg) -> int:
    print(f"root:     {ROOT}")
    print(f"config:   {ROOT / 'aegis.yaml'}")
    print(f"data:     {cfg.data_dir}")
    print(f"image:    {cfg.image}")
    print(f"network:  {cfg.network_mode}")
    print(f"models:   {', '.join(cfg.models) or '(ninguno)'}")
    try:
        require_docker()
        print("docker:   ok")
    except SystemExit as exc:
        print(f"docker:   FAIL — {exc}")
        return 1
    print(f"image?:   {'ok' if image_exists(cfg.image) else 'AUSENTE (make image)'}")
    binary = opencode_bin()
    print(f"opencode: {binary or 'AUSENTE (esperado en ~/.opencode/bin/opencode)'}")
    from internal.claude import auth_status as claude_status
    from internal.codex import auth_status as codex_status

    cx = codex_status()
    print(f"codex:    {cx.get('binary') or 'AUSENTE (npm i -g @openai/codex)'}")
    print(f"codex?:   {'ok ' + (cx.get('auth_mode') or 'chatgpt') if cx.get('logged_in') else 'deslogueado (codex login)'}")
    cl = claude_status()
    print(f"claude:   {cl.get('binary') or 'AUSENTE (esperado en ~/.local/bin/claude)'}")
    if cl.get("expired"):
        print("claude?:  OAuth caducado — claude auth login (no uses tokens viejos)")
    elif cl.get("logged_in"):
        print(f"claude?:  ok {cl.get('auth_mode') or 'subscription'}")
    else:
        print("claude?:  deslogueado (claude auth login)")
    from internal.cursorcli import auth_status as cursor_status

    cu = cursor_status()
    print(f"cursor:   {cu.get('binary') or 'AUSENTE (curl -fsS https://cursor.com/install | bash)'}")
    if cu.get("logged_in"):
        print(f"cursor?:  ok {cu.get('auth_mode') or 'login'}")
    else:
        print("cursor?:  deslogueado (Modelos → Login, suscripción)")
    auth = load_auth()
    creds = summarize_providers(auth)
    print(f"auth:     {host_auth_path()}")
    print(f"oauth:    {', '.join(creds) if creds else 'NINGUNO — aegis auth login grok && aegis auth login codex'}")
    missing = []
    if "xai" not in auth:
        missing.append("grok (xai / SuperGrok)")
    if "openai" not in auth:
        missing.append("codex (openai / ChatGPT Plus)")
    if missing:
        print(f"falta:    {', '.join(missing)}")
        return 1 if binary is None else 0
    return 0


def cmd_auth(args) -> int:
    cmd = getattr(args, "auth_cmd", None) or "list"
    if cmd == "login":
        return run_host_login(args.provider or None)
    if cmd == "logout":
        return run_host_logout(args.provider)
    auth = load_auth()
    creds = summarize_providers(auth)
    print(f"archivo: {host_auth_path()}")
    if creds:
        print("logueado:", ", ".join(creds))
    else:
        print("sin credenciales. En una terminal:")
        print("  aegis auth login grok     # SuperGrok Subscription")
        print("  aegis auth login codex    # ChatGPT Plus/Pro")
        print("  claude auth login         # Claude Code (suscripción Claude.ai)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
