"""Escribe el pack de agentes/skills/bin en el workspace del run."""
from __future__ import annotations

import shutil
from pathlib import Path

from internal.engage import empty_state, load, save

IDENTITY_MD = """---
description: Especialista AD/Kerberos/creds. Foothold, no inventario.
mode: subagent
permission:
  task: deny
  question: deny
---

# Identity

Lab Windows / directorio. Consigue una cuenta o un TGT **dentro del
target listado**. No escribas findings info. No enumeres IPv6 ni rootDSE.

1. `aegis-state show` y `aegis-state next`
2. Si el cuaderno ya tiene una cuenta de arranque del lab, pruébala
   (SMB, WinRM, LDAP) y anótala con `add-cred` / `add-access`.
3. Si hay users y cero cuentas: `aegis-state spray --dc <IP> --domain <dom> --corporate`
4. Parsea kerbrute/nxc: `aegis-state parse kerbrute <log>`
5. SAMR `--users` vacío en DC ≠ un usuario. Lookup de RIDs, no repitas `--users`.
6. Un hit → `add-cred` y paras. El lead sigue hacia las flags.

Prohibido: hydra infinito; findings F-xxx info.
"""

WEB_MD = """---
description: Especialista web. Vector hasta RCE/SSRF/auth, no crawler eterno.
mode: subagent
permission:
  task: deny
  question: deny
---

# Web

Foothold web. Si hay un vector (SSRF, RCE, SQLi, auth bypass), ÚSALO.
No nucleí infinito ni más dirs cuando ya hay un path. Actualiza `aegis-state`.
Findings solo vuln/flag con evidencia. Cero info de banners.
"""

CRITIC_MD = """---
description: Crítico. Mata findings basura y dice el siguiente movimiento.
mode: subagent
permission:
  bash: allow
  task: deny
  question: deny
---

# Critic

Lee `/run/aegis/out/engagement.json` y `findings/*.json`. Devuelve:

- Qué findings borrar o bajar a suspected (duplicados IPv4/IPv6, rootDSE, NTLM leak repetido, info > 8).
- Si la fase es foothold/exploit y el lead sigue enumerando: ordénale parar.
- Un solo siguiente paso (`aegis-state next`).

No lances scans. No inventes vulns.
"""

SKILL_AD = """# AD foothold

Cuando el target del lab es un DC (88+389+445):

1. Mapa corto de puertos. `aegis-state add-host`.
2. Si hay cuenta de arranque en engagement.json, pruébala ya.
3. Users. `nxc --users` / LDAP en un DC moderno (2022/2025) a menudo solo
   devuelve tu cuenta: eso NO es «el dominio tiene un usuario».
   Siguiente vector: lookup de RIDs (`nxc --rid-brute` o lookupsids), no
   repitas `--users`. `aegis-state parse kerbrute` si hay log de kerbrute.
4. Si aún no hay cuenta: `aegis-state spray --dc IP --domain dom --corporate`
5. `add-cred` / `add-access`. Luego flags.

Prohibido después del mapa: findings info, IPv6 duplicado, más kerbrute de 200k
nombres si ya hay ≥8 users. No concluyas el censo por un SAMR vacío.
"""

SKILL_WEB = """# Web foothold

1. Un servicio HTTP/S → fingerprint + 1 wordlist corta.
2. Si sale vector, explotar hasta evidencia. No más superficie.
3. `aegis-state` al día. Findings solo con body/flag, no headers sueltos.
4. HTTP: `aegis-browse URL` (guarda loot/web/). No inventes el HTML.
"""

SKILL_PHASE = """# Phase gate

- recon: mapa. Máximo 8 findings info en TODO el run.
- foothold: cred o RCE. Cada cred/RCE/vuln proven → `findings/F-xxx.json`. Cero info nuevos.
- exploit / post: usar acceso. Flags `kind=flag` Y las fichas de los vectores (vuln/misconfig/cve).

`aegis-state next` manda. Inflar info es un fallo. Omitir una vuln proven también.
Cada comando largo: `| aegis-clip`.
"""

WRAPPER = """#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aegis_engage import main

ALIASES = {
    "aegis-parse": "parse",
    "aegis-spray": "spray",
    "aegis-clip": "clip",
    "aegis-ingest": "ingest",
    "aegis-forensic": "forensic",
    "aegis-browse": "browse",
    "aegis-jobs": "jobs",
}
name = Path(sys.argv[0]).name
extra = ALIASES.get(name)
argv = sys.argv[1:]
if extra and (not argv or argv[0] != extra):
    argv = [extra, *argv]
raise SystemExit(main(argv))
"""

TOOL_WRAP = """#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aegis_engage import wrap_main

raise SystemExit(wrap_main(Path(sys.argv[0]).name, sys.argv[1:]))
"""

SHELL_WRAP = """#!/usr/bin/env python3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from aegis_shell import main

raise SystemExit(main())
"""

WRAP_TOOLS = (
    "nxc",
    "netexec",
    "crackmapexec",
    "nmap",
    "ldapsearch",
    "bloodyad",
    "bloodyAD",
    "smbclient",
    "kerbrute",
    "ffuf",
    "gobuster",
    "feroxbuster",
    "wfuzz",
    "curl",
    "wget",
    "httpx",
)

OPENCODE_WRAP = """#!/usr/bin/env python3
import os
import shutil
import sys
from pathlib import Path

here = str(Path(__file__).resolve().parent)
if len(sys.argv) > 1 and sys.argv[1] == "stats":
    raise SystemExit(0)
cleaned = ":".join(
    p for p in os.environ.get("PATH", "").split(":")
    if p and os.path.abspath(p) != os.path.abspath(here)
)
real = shutil.which("opencode", path=cleaned)
if not real:
    print("aegis-wrap: no está opencode fuera de workspace/bin", file=sys.stderr)
    raise SystemExit(127)
os.execv(real, [real, *sys.argv[1:]])
"""


def _goal_text(text: str, ctf: bool) -> str:
    """Mismo pack ofensivo; el wording de flags solo si hay contrato CTF."""
    if ctf:
        return text
    return (
        text.replace("El lead sigue hacia las flags.", "El lead sigue el impacto en scope.")
        .replace("Luego flags.", "Luego evidencia e impacto.")
        .replace("Flags kind=flag.", "Findings con evidencia.")
        .replace("Findings solo vuln/flag con evidencia.", "Findings solo vuln/cve/misconfig con evidencia.")
        .replace("Findings solo con body/flag, no headers sueltos.", "Findings solo con body/prueba, no headers sueltos.")
    )


def write_agent_pack(
    workspace: Path,
    *,
    out_dir: Path | None = None,
    targets: list[str] | None = None,
    specialists: bool = True,
    quiet: bool = False,
    ctf: bool = False,
    mode: str = "",
    exploit_mgmt: bool = False,
) -> None:
    workspace.mkdir(parents=True, exist_ok=True)
    agent_dir = workspace / ".opencode" / "agent"
    skill_dir = workspace / ".opencode" / "skill"
    bin_dir = workspace / "bin"
    agent_dir.mkdir(parents=True, exist_ok=True)
    bin_dir.mkdir(parents=True, exist_ok=True)
    if specialists:
        for d in (skill_dir / "ad-foothold", skill_dir / "web-foothold", skill_dir / "phase-gate"):
            d.mkdir(parents=True, exist_ok=True)
        (agent_dir / "identity.md").write_text(_goal_text(IDENTITY_MD, ctf), encoding="utf-8")
        (agent_dir / "web.md").write_text(_goal_text(WEB_MD, ctf), encoding="utf-8")
        (agent_dir / "critic.md").write_text(CRITIC_MD, encoding="utf-8")
        (skill_dir / "ad-foothold" / "SKILL.md").write_text(_goal_text(SKILL_AD, ctf), encoding="utf-8")
        (skill_dir / "web-foothold" / "SKILL.md").write_text(_goal_text(SKILL_WEB, ctf), encoding="utf-8")
        (skill_dir / "phase-gate" / "SKILL.md").write_text(_goal_text(SKILL_PHASE, ctf), encoding="utf-8")

    src = Path(__file__).resolve().parent / "engage.py"
    shutil.copy2(src, bin_dir / "aegis_engage.py")
    here = Path(__file__).resolve().parent
    shutil.copy2(here / "flagspec.py", bin_dir / "flagspec.py")
    shutil.copy2(here / "identities.py", bin_dir / "identities.py")
    shutil.copy2(here / "sessioncap.py", bin_dir / "aegis_sessioncap.py")
    names = [
        "aegis-state",
        "aegis-parse",
        "aegis-spray",
        "aegis-clip",
        "aegis-ingest",
        "aegis-jobs",
    ]
    if not quiet:
        shutil.copy2(Path(__file__).resolve().parent / "shellsess.py", bin_dir / "aegis_shell.py")
        names += ["aegis-forensic", "aegis-browse"]
    for name in names:
        dest = bin_dir / name
        dest.write_text(WRAPPER, encoding="utf-8")
        dest.chmod(0o755)
    for name in WRAP_TOOLS:
        dest = bin_dir / name
        dest.write_text(TOOL_WRAP, encoding="utf-8")
        dest.chmod(0o755)
    if not quiet:
        sh = bin_dir / "aegis-shell"
        sh.write_text(SHELL_WRAP, encoding="utf-8")
        sh.chmod(0o755)
    oc = bin_dir / "opencode"
    oc.write_text(OPENCODE_WRAP, encoding="utf-8")
    oc.chmod(0o755)

    if out_dir is not None:
        path = out_dir / "engagement.json"
        if path.is_file():
            save(load(path), path, sidecars=True)
        else:
            save(
                empty_state(targets, mode=mode, exploit_mgmt=exploit_mgmt),
                path,
                sidecars=True,
            )
