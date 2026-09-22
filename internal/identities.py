"""Identidades desde engagement/findings. Sin secrets=True no incluye secretos."""
from __future__ import annotations

import ipaddress
import json
import re
from pathlib import Path
from typing import Any


def _load_findings(root: Path) -> list[dict[str, Any]]:
    """Host: `internal.report` (con sync). Sandbox: solo JSON ya en disco."""
    try:
        from internal.report import load_findings

        return [f for f in load_findings(root) if isinstance(f, dict)]
    except ImportError:
        pass
    d = root / "findings"
    if not d.is_dir():
        return []
    items: list[dict[str, Any]] = []
    seen: set[str] = set()
    for path in sorted(d.rglob("F-*.json")):
        if not path.is_file():
            continue
        data = _read_json(path)
        if not isinstance(data, dict):
            continue
        fid = str(data.get("id") or path.stem)
        if not fid or fid in seen or data.get("duplicate_of") or data.get("source") == "aegis-reserved":
            continue
        seen.add(fid)
        items.append(data)
    return items


def _read_json(path: Path) -> dict[str, Any]:
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}

_EMAIL = re.compile(r"\b([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24})\b")
_EMAIL_PASS = re.compile(
    r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24})\s*[:]\s*(\S{4,80})"
)
_EMAIL_EQ = re.compile(r"\bemail=([A-Za-z0-9._%+-]+@[^\s\"'&]+)", re.I)
_EMAIL_JSON = re.compile(
    r"""["']email["']\s*:\s*["']([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,24})["']""",
    re.I,
)
_PASS_JSON = re.compile(
    r"""["'](?:password|newPassword)["']\s*:\s*["']([^"']{4,80})["']""",
    re.I,
)
_ACCOUNT_MARK = re.compile(
    r"\b(?:login|sesi[oó]n|toma de cuenta|account takeover|reset-password|"
    r"forgot-password|auth/login|inicio sesi|contrase[nñ]a)\b",
    re.I,
)
_USER_EQ = re.compile(r"\b(?:user|username|usuario)=([A-Za-z_][A-Za-z0-9._$-]*)", re.I)
_PASS_EQ = re.compile(r"\bpassword=([^\s\"'&]+)", re.I)
# «usuario 'kevin', contraseña 'MailLab2024!'» en prosa de findings.
_USUARIO_QUOTED = re.compile(
    r"(?:usuario|user(?:name)?|login)\s+['\"]([A-Za-z_][A-Za-z0-9._$-]*)['\"]"
    r"\s*[,.]?\s*(?:contrase(?:ña|n)a?|password)\s+['\"]([^'\"]{4,80})['\"]",
    re.I,
)
# Misma idea sin comillas: «usuario kevin, password LabPass2024!»
# o «Username: kevin / Password: LabPass2024!».
_USUARIO_BARE = re.compile(
    r"(?:usuario|user(?:name)?)\s*[:=]?\s+([A-Za-z_][A-Za-z0-9._$-]{1,31})"
    r"\s*[,./]?\s*(?:contrase(?:ña|n)a?|password)\s*[:=]?\s+(\S{4,80})",
    re.I,
)
# Dump SQL: (2,'haris','$2y$10$…','haris@mail.lab.test'
_SQL_USER_HASH = re.compile(
    r"'([A-Za-z_][A-Za-z0-9._$-]{1,31})'\s*,\s*'(\$2[aby]\$\d{2}\$[A-Za-z0-9./]{50,60})'",
)
# admin/admin (barra). No paths (/notes/view) ni versiones (Werkzeug/3.1.8).
_SLASH_PASS = re.compile(
    r"(?<![/.])\b([A-Za-z_][A-Za-z0-9._$-]{1,31})/([A-Za-z0-9._$!@#-]{4,80})\b"
)
# Login real: `ssh://user@host` o `ssh [-flags…] user@host`.
# No «SSH offers hmac-sha1-etm@openssh.com» (algoritmo, no cuenta).
_SSH_FLAG = r"-(?:-[A-Za-z0-9-]+|[A-Za-z]\S*)(?:\s+\S+)?"
_SSH = re.compile(
    rf"(?:ssh://|ssh(?:\s+{_SSH_FLAG})*\s+)([A-Za-z_][A-Za-z0-9._$-]*)@([A-Za-z0-9._-]+)",
    re.I,
)
_SSH_ALGO_HOST = frozenset({"openssh.com", "libssh.org"})
_CRYPTO_PRINCIPAL = re.compile(
    r"(?i)^(?:hmac-|umac-|aes\d|chacha|curve25519|mlkem|sntrup)|-etm$|-(?:sha1|sha256|sha512)$"
)
_SESSION_PLACEHOLDER_USERS = frozenset({"web", "session", "sesion", "sesión"})
_SESSION_PLACEHOLDER_SECRETS = frozenset({"(sesión)", "(sesion)", "(session)"})
_LOCAL_PASS = re.compile(r"(?<![@.\\])\b([A-Za-z_][A-Za-z0-9._$-]{1,31}):(\S{4,80})\b")
_USERS_LIST = re.compile(r"\busers\s*[=:]\s*\[([^\]]{0,400})\]", re.I)
# j.reed / jamie.cole: nombre.apellido. No host (gateway.lab.test, billing.corp.test).
_PERSON_DOT = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{0,24}\.[A-Za-z][A-Za-z0-9_-]{2,24}$")
# morgan.w: inicial de un carácter. El nombre tiene ≥3 letras.
_PERSON_INITIAL = re.compile(r"^[A-Za-z][A-Za-z0-9_-]{2,24}\.[A-Za-z]$")
_NAME_TLD = frozenset(
    {
        "com",
        "net",
        "org",
        "io",
        "lab",
        "test",
        "example",
        "local",
        "lan",
        "intern",
        "intranet",
        "dev",
        "prod",
        "loc",
        "arpa",
        "edu",
        "gov",
    }
)
# SAM DOMINIO\usuario (≥2 chars). `PING\r` / `GET dir\r` de redis-cli no es una cuenta.
_DOMAIN = re.compile(r"\b([A-Za-z0-9.-]{1,32})\\([A-Za-z][A-Za-z0-9._$-]{1,63})\b")
_UID = re.compile(r"\buid=\d+\(([A-Za-z_][A-Za-z0-9._$-]*)\)")
_COMO_NAMED = re.compile(
    r"\b(?:como|as)\s+(?:(?:el|la|un|una)\s+)?usuario\s+['\"]?"
    r"([A-Za-z_](?:[A-Za-z0-9._$-]*[A-Za-z0-9_$-])?)['\"]?",
    re.I,
)
_COMO_SERVICE = re.compile(
    r"\b(?:como|as)\s+(?:(?:el|la|un|una)\s+)?['\"]?"
    r"(www-data|root|apache|nginx|mysql|node|tomcat)['\"]?",
    re.I,
)
# /home/engineer/user.txt — el user de Linux está en la ruta, no en «como X».
_HOME_USER = re.compile(r"/home/([A-Za-z_][A-Za-z0-9._$-]{1,31})/")
# `echo bestfriends | su haris -c 'id'` — clave validada, no un intento fallido.
_ECHO_SU = re.compile(
    r"\becho\s+([A-Za-z0-9._$!@#-]{4,80})\s*\|\s*su\s+(?:-\s+)?"
    r"([A-Za-z_][A-Za-z0-9._$-]{1,31})\b",
    re.I,
)
# ssh user@host (password) en el proof. No (uid=1000) ni (CVE-…).
_SSH_TRAIL_SECRET = re.compile(r"^\s*\(([A-Za-z0-9._$!@#-]{4,80})\)")
# Letras de escape en C (\r \n \t …). En evidencia con saltos de línea literales
# (salida de redis-cli, transcripts) DOMINIO\usuario casa basura: "1\r", "nACL\r".
_ESCAPE_LETTERS = frozenset("rntfvbae0")
# Verbos de protocolo (RESP, etc.) que el regex DOMINIO\user pega a un \r\n.
_PROTO_NOISE = frozenset(
    {
        "ping",
        "pong",
        "get",
        "set",
        "del",
        "acl",
        "config",
        "info",
        "auth",
        "quit",
        "whoami",
        "keys",
        "scan",
        "ttl",
        "exists",
        "requirepass",
        "default",
        "multi",
        "exec",
        "echo",
        "select",
        "dbsize",
        "save",
        "debug",
        "sync",
        "llen",
        "hget",
        "hset",
        "zadd",
        "type",
        "list",
        "ok",
        "err",
        # `[+] done\nWARNING: …` en JSONL → `nWARNING` al partir por `\\`.
        "warning",
        "warn",
        "error",
        "notice",
        "critical",
        "fatal",
    }
)


def _resp_leftover(token: str) -> bool:
    """`nDEL` / `nACL` son el trozo tras `\\r\\n` de un verbo RESP, no un SAM."""
    t = (token or "").strip().lower()
    if not t:
        return False
    if t in _PROTO_NOISE:
        return True
    return len(t) > 1 and t[0] in _ESCAPE_LETTERS and t[1:] in _PROTO_NOISE
_OS_ROOT_SHOWN = re.compile(
    r"\b(?:uid=0(?:\(root\))?|euid=0(?:\(root\))?|whoami\s*[:=]\s*root)\b",
    re.I,
)
_IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
_URL_IP = re.compile(r"https?://(\d{1,3}(?:\.\d{1,3}){3})", re.I)
_HEX_OCTET = re.compile(r"^[0-9a-f]{1,2}$", re.I)
_HEX_COLONS = re.compile(r"^[0-9a-f]{1,2}(?::[0-9a-f]{1,2})+$", re.I)
_MAC_TAIL = re.compile(r"(?:[0-9a-f]{2}:){2,}$", re.I)
_HEX32 = re.compile(r"^[a-fA-F0-9]{32}$")
_HOST_ASSET = re.compile(
    r"^(?:host:)?([A-Za-z0-9._-]+(?:\.[A-Za-z0-9._-]+)+|\d{1,3}(?:\.\d{1,3}){3})(?::\d+)?$",
    re.I,
)
# vhost en prosa (`app.lab.test (Flowise) -> contenedor 172.18.0.2`).
# Exige TLD con letras para no tragar `3.0.5` ni una IPv4.
_DNS_HOST = re.compile(
    r"\b([A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
    r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+\.[A-Za-z]{2,24})\b"
)
_CONTAINER_NS = re.compile(r"\b(?:contenedor|container|docker)\b", re.I)
_ROOT_UID_OK = re.compile(
    r"\b(?:sudo|root\.txt|whoami\s*[:=]\s*root|root@[A-Za-z0-9._-]+:[~/#])\b",
    re.I,
)

_SKIP_PRINCIPAL = frozenset(
    {
        "file",
        "user",
        "users",
        "root.txt",
        "user.txt",
        "www",
        "http",
        "https",
        "admin@example.com",
        "example",
        "test",
        "anonymous",
        "host",
        "hostname",
        "localhost",
        "target",
        "local",
        "com",
        # «como evidencia» / «as evidence»: no es un principal
        "evidencia",
        "evidence",
        "el",
        "la",
        "los",
        "las",
        "un",
        "una",
        "the",
        "que",
        "quien",
        "quién",
        "cual",
        "cuál",
        "cuyo",
        "cuya",
        "who",
        "which",
        "whose",
        "that",
        # «usuario de dominio» / «usuario del sistema»: no son logins
        "de",
        "del",
        "en",
        "con",
        "por",
        "para",
        "sin",
        "sobre",
        "desde",
        "hasta",
        "hacia",
        "entre",
        "usuario",
        "administrador",
        "password",
        "username",
        "contrase",
        "disco",
        "sesion",
        "sesión",
        "session",
        "impacto",
        "acceso",
        "flag",
        "prueba",
        "contenido",
        "fichero",
        "archivo",
        # keywords de código/shell que un parser confunde con un login
        "except",
        "break",
        "continue",
        "return",
        "elif",
        "finally",
        "import",
        "lambda",
        "print",
        "printf",
        "echo",
        "done",
        "then",
        "esac",
        "def",
        "class",
        # Gadgets JS: `$1:__proto__:then` / `constructor:constructor` no son logins.
        "__proto__",
        "constructor",
        "prototype",
        # salida de redis INFO (role:master/slave) y el propio user del serve
        "role",
        "aegis",
        "web",
        "slave",
        "master",
        # Path PHP / querystring (FreePBX\modules\endpoint\ajax), no SAM.
        "ajax",
        "modules",
        "endpoint",
        # Flags nxc / prosa de salida: `--use-kcache`, `[+] Impersonating:`,
        # clase dMSA, named pipe \\pipe\\spoolss. No son SAM.
        "kcache",
        "impersonating",
        "dmsa",
        "spoolss",
        "pipe",
        "cd",
        "mkdir",
        "chmod",
        "chown",
        "export",
        # Dirs del workspace: `nxc -u loot/users.txt` no es un SAM.
        "loot",
        "findings",
        "warning",
        "warn",
        "error",
        "notice",
        "critical",
        "fatal",
        # AWS / YAML de jobs: no son SAM.
        "sqs",
        "sns",
        "s3",
        "iam",
        "ecr",
        "ecs",
        "lambda",
        "dynamodb",
        "kinesis",
        "cloudwatch",
        "metadata",
        "script",
        "nscript",
        "runtime",
        "yaml",
        "python3",
        "sendmessage",
    }
)
_PHP_PATH_TOKEN = frozenset({"ajax", "modules", "endpoint", "vendor", "controllers", "models", "namespace"})
_MYSQL_U_P = re.compile(
    r"\bmysql\b[^\n]{0,80}-u\s*([A-Za-z_][A-Za-z0-9._$-]*)[^\n]{0,40}-p\s*(\S{4,80})",
    re.I,
)
_AMPDB_USER = re.compile(
    r"""\bAMPDBUSER\b["'\s\]=]+["']?([A-Za-z_][A-Za-z0-9._$-]*)""",
    re.I,
)
_AMPDB_PASS = re.compile(
    r"""\bAMPDBPASS\b["'\s\]=]+["']?([A-Za-z0-9._$!@#-]{4,80})""",
    re.I,
)
_DB_USER_AT = re.compile(r"\bDB user:\s*([A-Za-z_][A-Za-z0-9._$-]*)@", re.I)
# `-u`/`-p` de verdad. No el `-u` de `--use-kcache` ni el `-p` de `--pass-pol`.
# `-p  --rid-brute` / `-p  --shares`: el flag no es la contraseña.
_NXC_U_P = re.compile(
    r"\b(?:nxc|netexec|crackmapexec|cme)\b[^\n]{0,200}(?<![A-Za-z0-9-])-u[ \t]*"
    r"(?:'([^']{1,80})'|\"([^\"]{1,80})\"|(\S{1,80}))"
    r"[^\n]{0,80}(?<![A-Za-z0-9-])-p[ \t]*"
    r"(?:'([^']{4,80})'|\"([^\"]{4,80})\"|(?!-)(\S{4,80}))",
    re.I,
)
_CLI_FLAG_SECRET = re.compile(r"^--[a-z][a-z0-9]*(?:-[a-z0-9]+)*$")
# nxc smb --users: "SMB  ip  445  DC01  ryan.brooks  2026-05-10 …"
_NXC_USERS_ROW = re.compile(
    r"(?:SMB|LDAP)\s+\d{1,3}(?:\.\d{1,3}){3}\s+\d+\s+[A-Za-z0-9._-]+\s+"
    r"([A-Za-z][A-Za-z0-9._$-]{1,63})\s+(?:\d{4}-\d{2}-\d{2}|<never>)",
    re.I,
)
# nxc --rid-brute: `1103: ACME\jake.h (SidTypeUser)`
# rpcclient lookupsids: `S-1-5-21-…-1103 ACME\jake.h (1)`  (1 = SidTypeUser)
_SID_USER = re.compile(
    r"(?:[A-Za-z0-9._-]+\\)([A-Za-z][A-Za-z0-9._$-]{1,63})\s+\((?:SidTypeUser|1)\)",
    re.I,
)
_BLOODY_SET_PW = re.compile(
    r"\bset password\s+([A-Za-z][A-Za-z0-9._$-]*)\s+'([^']{4,80})'",
    re.I,
)
_NXC_ENUM_SKIP = frozenset({"guest"})
# `[+] acme.corp.test\morgan.reed:Autumn2024!` (spray / nxc).
_NXC_PLUS = re.compile(
    r"\[\+\]\s+(?:[A-Za-z0-9._-]+\\)?([A-Za-z][A-Za-z0-9._$-]{1,63}):(\S{4,80})",
    re.I,
)
# Redis INFO / /proc / stats: snake_case con varios `_` o sufijo de campo.
# Clase, no lista de nombres (el siguiente será `master_last_io_seconds_ago`).
_METRIC_SUFFIX = re.compile(
    r"_(?:status|ago|seconds|bytes|count|human|hits|misses|ops|cpu|rss|"
    r"peak|avg|total|used|idle|link|offset|version|key|id|port|mode|sha|"
    r"memory|perc|ratio|sync)$",
    re.I,
)
# Valores de estado de protocolo que el par `campo:valor` toma por password.
_STATUS_ENUM = frozenset(
    {
        "down",
        "sync",
        "wait",
        "full",
        "lazy",
        "fail",
        "slave",
        "master",
        "password",
        "passwd",
        "secret",
        "null",
        "none",
        "true",
        "false",
    }
)
_SKIP_SECRET_EXT = frozenset({"php", "txt", "json", "html", "js", "png", "jpg"})
_SKIP_SLASH_TOKEN = frozenset(
    {
        "secure",
        "samesite",
        "httponly",
        "strict",
        "lax",
        "none",
        "csp",
        "hsts",
        "csrf",
        "referrer",
        "werkzeug",
        "python",
    }
)
_SERVICE = frozenset({"www-data", "apache", "nginx", "mysql", "postgres", "tomcat", "node"})
_PLACEHOLDER_HOST = frozenset({"db", "nxc", "target", "unknown", "web", "mysql", "local", "operator"})


def _blob(f: dict[str, Any]) -> str:
    return " ".join(
        str(f.get(k) or "")
        for k in ("title", "summary", "explain", "proof", "reproduction", "impact", "asset")
    )


def _prose_blob(f: dict[str, Any]) -> str:
    """Solo prosa (sin proof/reproduction). El proof lleva comandos y código
    (redis `aegis:agent-check\\r\\n`, python `except:break`) y los pares
    genéricos user:pass / user/pass lo leen como credenciales falsas."""
    return " ".join(
        str(f.get(k) or "") for k in ("title", "summary", "explain", "impact", "asset")
    )


def _evidence_snippets(root: Path, f: dict[str, Any]) -> str:
    """whoami / uid=N(name) en evidencias en disco. No entra al parser de creds."""
    fid = str(f.get("id") or "").strip()
    chunks: list[str] = []
    seen: set[Path] = set()
    for ev in f.get("evidence") or []:
        raw = str(ev or "").strip()
        if not raw:
            continue
        name = Path(raw).name
        cands = [
            root / "findings" / fid / name,
            root / "findings" / name,
            root / "evidence" / name,
            root / name,
        ]
        p = Path(raw)
        if p.is_absolute():
            cands.append(p)
        for cand in cands:
            try:
                if not cand.is_file():
                    continue
                resolved = cand.resolve()
                size = cand.stat().st_size
            except OSError:
                continue
            if resolved in seen or size <= 0 or size > 64_000:
                continue
            seen.add(resolved)
            try:
                chunks.append(cand.read_text(errors="replace")[:8000])
            except OSError:
                continue
            break
    return " ".join(chunks)


def _metric_principal(name: str) -> bool:
    """Campo de protocolo/métrica, no un login. `master_link_status` sí;
    `j.reed` / `admin` / `backup_admin` no."""
    raw = (name or "").strip()
    if not raw:
        return False
    if raw.count("_") >= 2 and raw == raw.lower() and raw.replace("_", "").isalnum():
        return True
    return bool(_METRIC_SUFFIX.search(raw))


def _clean_secret(secret: str) -> str:
    """`CorpLab2024!","is_error":false` → `CorpLab2024!` (JSONL de consola)."""
    s = (secret or "").strip().strip("\"';")
    s = s.split('","', 1)[0].split('"', 1)[0]
    return s.strip().strip("\"';")


def _cli_flag_secret(secret: str) -> bool:
    """`--rid-brute` / `--shares`: flag de nxc, no una contraseña."""
    return bool(_CLI_FLAG_SECRET.fullmatch((secret or "").strip().strip("'\"")))


def _secret_ok(secret: str) -> bool:
    s = _clean_secret(secret)
    if len(s) < 4 or len(s) > 80:
        return False
    if _cli_flag_secret(s):
        return False
    if s.lower() in _STATUS_ENUM:
        return False
    # Fragmento de comando/protocolo, no una contraseña: "agent-check\r\n",
    # "GET x\r\n". Escape literal (\r \n \t) o carácter de control real.
    if re.search(r"\\[rntfvb0]", s) or any(ord(ch) < 0x20 for ch in s):
        return False
    low = s.lower()
    if low.startswith("aegis:") or "agent-check" in low:
        return False
    if s.startswith("/") or s.startswith("*") or "://" in s or "=" in s or "(" in s or ")" in s:
        return False
    if s.count(":") >= 2:
        return False
    if _HEX_COLONS.fullmatch(s):
        return False
    if re.fullmatch(r"\d+(?:\.\d+)+", s):
        return False
    if _IPV4.fullmatch(s) or _HEX32.match(s):
        return False
    # Acción IAM (`SendMessage`), no una contraseña.
    if re.fullmatch(r"[A-Z][a-z]+(?:[A-Z][a-z]+)+", s):
        return False
    if "." in s and s.rsplit(".", 1)[-1].lower() in _SKIP_SECRET_EXT:
        return False
    return True


# Tokens que son algoritmos o huellas de clave (SHA256, ED25519, RSA…), no
# cuentas. Salen de fingerprints SSH (`SHA256:…`) y de `algo:hash` en evidencia.
_ALGO_TOKEN = re.compile(
    r"^(?:sha\d*|sha3|md\d|hmac|aes\d*|rsa|dsa|ecdsa|eddsa|ed25519|curve\d+|"
    r"x25519|sntrup\d*|umac|blake\d*|crc\d*|ripemd\d*|whirlpool|argon2\w*|"
    r"bcrypt|scrypt|pbkdf2|ntlm|lanman|des|3des|rc4|chacha\d*|poly1305|gcm|cbc)$",
    re.I,
)


def _looks_like_password(secret: str) -> bool:
    """Contraseña tecleada, no una huella/clave/hash. Un fingerprint SSH
    (SHA256:…), una clave o un hash largo no prueban un login."""
    s = _clean_secret(secret)
    if not _secret_ok(s):
        return False
    if "/" in s or "+" in s:  # base64 de claves/fingerprints
        return False
    if len(s) >= 32 and re.fullmatch(r"[A-Za-z0-9]+", s):  # hash/fingerprint largo
        return False
    return True


def _has_hard_evidence(row: dict[str, Any]) -> bool:
    """Prueba dura de compromiso. Sin esto, «comprometida» sería una suposición
    del parser sobre salida de comandos (fingerprints, intentos fallidos…)."""
    sec = str(row.get("_secret") or "")
    if sec and _looks_like_password(sec):
        return True
    if str(row.get("priv") or "") in {"root", "system"}:
        return True
    # Ejecución de código o shell demostrada. El accounts.json del cierre a veces
    # nombra la vía en texto libre ("rce-web (CVE-…)", "reverse shell") en lugar
    # del token canónico (webshell/privesc), así que se compara por palabra clave.
    via_l = str(row.get("via") or "").strip().lower()
    if any(k in via_l for k in ("privesc", "webshell", "rce", "shell")):
        return True
    if via_l.startswith("ssh") and str(row.get("secret_type") or "") == "ssh-key":
        return True
    if str(row.get("kind") or "").lower() == "flag":
        return True
    # Login web demostrado en un finding (JSON email / toma de cuenta).
    # Sin esto, Cuentas baja la fila a enumerada por no haber password en el ledger.
    if str(row.get("via") or "") == "web" and str(row.get("finding") or "").startswith("F-"):
        return True
    return False


def _mac_pair(user: str, secret: str) -> bool:
    """`cc:cc` / `0c:cc:cc` son octetos de MAC (CDP 01:00:0c:cc:cc:cc), no un login."""
    u = (user or "").strip()
    s = (secret or "").strip()
    if not u or not s:
        return False
    if _HEX_OCTET.fullmatch(u) and _HEX_COLONS.fullmatch(s):
        return True
    blob = f"{u}:{s}"
    return bool(re.fullmatch(r"(?:[0-9a-f]{2}:){2,}[0-9a-f]{2}", blob, flags=re.I))


def _net_accounts_ok(root: Path, eng: dict[str, Any] | None = None) -> bool:
    """En Red sin Explotar mgmt no hay cuentas que persistir ni pintar."""
    meta = _read_json(root / "meta.json")
    brief = _read_json(root / "brief.json")
    mode = ""
    if isinstance(eng, dict):
        mode = str(eng.get("mode") or "")
    if not mode:
        mode = str(meta.get("mode") or brief.get("mode") or "")
    if mode != "net":
        return True
    for src in (eng or {}, meta, brief):
        if isinstance(src, dict) and src.get("exploit_mgmt"):
            return True
    return False


def _php_namespace(dom: str, usr: str) -> bool:
    """`FreePBX\\modules\\endpoint\\ajax` es un path PHP, no DOMINIO\\usuario."""
    d = (dom or "").strip()
    u = (usr or "").strip()
    if d.lower() in _PHP_PATH_TOKEN or u.lower() in _PHP_PATH_TOKEN:
        return True
    return bool(re.search(r"[a-z][A-Z]", d) or re.search(r"[a-z][A-Z]", u))


def parse_db_creds(text: str) -> list[dict[str, str]]:
    """mysql -u/-p y AMPDBUSER/AMPDBPASS. El hash de ampusers no entra aquí."""
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()

    def add(user: str, secret: str) -> None:
        user = (user or "").strip()
        secret = (secret or "").strip().strip("\"';")
        if not user or not _principal_ok(user):
            return
        if secret and not _secret_ok(secret):
            secret = ""
        key = (user.lower(), secret)
        if key in seen:
            return
        seen.add(key)
        out.append({"user": user, "secret": secret, "type": "password", "where": "db"})

    blob = text or ""
    for m in _MYSQL_U_P.finditer(blob):
        add(m.group(1), m.group(2))
    users = [m.group(1) for m in _AMPDB_USER.finditer(blob)]
    pwds = [m.group(1).strip("\"';") for m in _AMPDB_PASS.finditer(blob)]
    if users:
        add(users[0], pwds[0] if pwds else "")
    for m in _DB_USER_AT.finditer(blob):
        add(m.group(1), "")
    return out


def _nxc_cli_user(raw: str) -> str:
    """SAM de `-u`. Tira `-u loot/users.txt` y listas `*.txt`."""
    user = (raw or "").strip().strip("'\"")
    if not user:
        return ""
    if any(sep in user for sep in "/\\"):
        return ""
    if user.lower().endswith((".txt", ".lst", ".csv", ".json")):
        return ""
    return user


def parse_nxc_cli_creds(text: str) -> list[dict[str, str]]:
    """`nxc smb … -u jamie.cole -p 'CorpLab2024!'` en tried/cmd_log."""
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for m in _NXC_U_P.finditer(text or ""):
        user = _nxc_cli_user(m.group(1) or m.group(2) or m.group(3) or "")
        # `-p 'Chec` al cortar el argv: el grupo sin comillas se come la apertura.
        raw_uq = m.group(6) or ""
        if raw_uq[:1] in {"'", '"'}:
            continue
        secret = (m.group(4) or m.group(5) or raw_uq).strip().strip("\"';")
        if not user or not _principal_ok(user):
            continue
        if secret and (_cli_flag_secret(secret) or not _secret_ok(secret)):
            secret = ""
        if not secret:
            continue
        prev = next((i for i, x in enumerate(out) if x["user"].lower() == user.lower()), None)
        if prev is not None:
            if len(secret) > len(out[prev]["secret"]):
                out[prev]["secret"] = secret
            continue
        key = (user.lower(), secret)
        if key in seen:
            continue
        seen.add(key)
        out.append({"user": user, "secret": secret, "type": "password", "where": "nxc"})
    return out


def parse_sql_users(text: str) -> list[str]:
    """Usuarios de un dump (`INSERT INTO zz_users` + bcrypt). Sin plaintext."""
    out: list[str] = []
    seen: set[str] = set()
    for m in _SQL_USER_HASH.finditer(text or ""):
        user = m.group(1)
        if not _principal_ok(user):
            continue
        key = user.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(user)
    return out


_WEB_UID_USERS = frozenset({"www-data", "apache", "nginx", "www", "tomcat", "httpd"})
# Webshell clásico o RCE no interactivo (pickle / helper TCP / reverse).
# El prompt exige ruta o home (`user@host:/app$`, `user@host:~#`).
# `user@ip: Permission denied` no cuenta: es un rechazo SSH, no un shell.
_UID_REMOTE = re.compile(
    r"\b(?:HTTP\s+200|shell\.php|\?cmd=|webshell|"
    r"pickle|rce[_-]?helper|rce2\.py|/tmp/rce|"
    r"ncat|reverse\s*shell|Connection from|"
    r"H=[A-Za-z0-9._-]+)\b|"
    r"[A-Za-z_][A-Za-z0-9._-]*@[A-Za-z0-9._-]+:[~/$]",
    re.I,
)
_SSH_KEY_MARK = re.compile(
    r"BEGIN OPENSSH PRIVATE KEY|\bssh\s+-i\b|_id_(?:ed25519|rsa|ecdsa)\b",
    re.I,
)
_KEYFILE_USER = re.compile(
    r"\b([A-Za-z_][A-Za-z0-9._$-]{1,31})_id_(?:ed25519|rsa|ecdsa)\b",
    re.I,
)


def _uid_counts(blob: str, user: str, start: int, end: int) -> bool:
    """www-data/apache/… siempre; el resto solo con prueba remota junto al `uid=`."""
    if not _principal_ok(user):
        return False
    window = blob[max(0, start - 240) : end + 240]
    remote = bool(_UID_REMOTE.search(window))
    key = user.lower()
    if key == "root":
        # uid=0 de un callback HTTP / `id` en un sidecar no es cuenta root del target.
        return bool(_ROOT_UID_OK.search(window))
    if key not in _WEB_UID_USERS and not remote:
        return False
    return True


def parse_json_auth_creds(text: str) -> list[tuple[str, str]]:
    """Pares email+password en JSON de login/reset. No inventa cuentas."""
    blob = text or ""
    out: list[tuple[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for em in _EMAIL_JSON.finditer(blob):
        window = blob[max(0, em.start() - 120) : em.end() + 280]
        pm = _PASS_JSON.search(window)
        if not pm:
            continue
        email = em.group(1)
        secret = _clean_secret(pm.group(1))
        if not email or not _looks_like_password(secret):
            continue
        key = (email.lower(), secret)
        if key in seen:
            continue
        seen.add(key)
        out.append((email, secret))
    return out


def _attach_json_auth_secrets(rows: list[dict[str, Any]], text: str) -> None:
    """Pone en la ficha el password del reset/login si el finding no lo copió."""
    by: dict[str, str] = {}
    for email, secret in parse_json_auth_creds(text):
        by.setdefault(email.lower(), secret)
    if not by:
        return
    for row in rows:
        principal = str(row.get("principal") or "")
        if "@" not in principal or row.get("has_secret"):
            continue
        secret = by.get(principal.lower())
        if not secret:
            continue
        row["has_secret"] = True
        row["_secret"] = secret
        row["secret_type"] = "password"


def parse_uid_hits(text: str) -> list[str]:
    """`uid=33(www-data)` de un webshell. No el `id` local del sandbox (root)."""
    blob = text or ""
    out: list[str] = []
    seen: set[str] = set()
    for m in _UID.finditer(blob):
        user = m.group(1)
        if not _uid_counts(blob, user, m.start(), m.end()):
            continue
        key = user.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(user)
    return out


def console_uid_snippets(root: Path) -> list[tuple[str, str]]:
    """(user, recorte) de `uid=N(user)` en console.log, para ficha + Cuentas."""
    blob = _console_enum_blob(root)
    if not blob:
        return []
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    for m in _UID.finditer(blob):
        user = m.group(1)
        if user.lower() in seen or user not in parse_uid_hits(blob):
            continue
        seen.add(user.lower())
        line_start = blob.rfind("\n", 0, m.start()) + 1
        line_end = blob.find("\n", m.end())
        if line_end < 0:
            line_end = len(blob)
        snippet = blob[line_start:line_end].strip()
        nxt = blob.find("\n", line_end + 1)
        extra = blob[line_end + 1 : nxt if nxt >= 0 else line_end + 40]
        if extra.strip().startswith("HTTP"):
            snippet = snippet + "\n" + extra.strip()
        out.append((user, snippet[:240]))
    return out


def parse_nxc_users_table(text: str) -> list[str]:
    """Tabla `nxc smb --users`: Username + Last PW Set / <never>."""
    out: list[str] = []
    seen: set[str] = set()
    for m in _NXC_USERS_ROW.finditer(text or ""):
        user = (m.group(1) or "").strip()
        if not user or user.endswith("$") or user.lower() in _NXC_ENUM_SKIP:
            continue
        if not _principal_ok(user):
            continue
        key = user.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(user)
    return out


def parse_sid_users(text: str) -> list[str]:
    """`nxc --rid-brute` (`SidTypeUser`) o `rpcclient lookupsids` (`(1)`)."""
    out: list[str] = []
    seen: set[str] = set()
    for m in _SID_USER.finditer(text or ""):
        user = (m.group(1) or "").strip()
        if not user or user.endswith("$") or user.lower() in _NXC_ENUM_SKIP:
            continue
        if not _principal_ok(user):
            continue
        key = user.lower()
        if key in seen:
            continue
        seen.add(key)
        out.append(user)
    return out


def parse_nxc_plus_hits(text: str) -> list[dict[str, str]]:
    """Hits `[+] DOMINIO\\user:pass` de nxc/netexec (spray incluido)."""
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for m in _NXC_PLUS.finditer(text or ""):
        user = (m.group(1) or "").strip()
        secret = _clean_secret(m.group(2) or "")
        if not user or not _principal_ok(user):
            continue
        if user.lower() in _NXC_ENUM_SKIP:
            continue
        if secret and not _secret_ok(secret):
            secret = ""
        key = (user.lower(), secret)
        if key in seen:
            continue
        seen.add(key)
        out.append({"user": user, "secret": secret, "type": "password", "where": "nxc"})
    return out


def parse_bloody_set_password(text: str) -> list[dict[str, str]]:
    """`bloodyAD … set password mark.davies 'Reanim8ed!2024'`."""
    out: list[dict[str, str]] = []
    seen: set[tuple[str, str]] = set()
    for m in _BLOODY_SET_PW.finditer(text or ""):
        user = (m.group(1) or "").strip()
        secret = (m.group(2) or "").strip()
        if not user or not _principal_ok(user):
            continue
        if secret and not _secret_ok(secret):
            secret = ""
        key = (user.lower(), secret)
        if key in seen:
            continue
        seen.add(key)
        out.append({"user": user, "secret": secret, "type": "password", "where": "ldap"})
    return out


def _event_tool_texts(rec: dict[str, Any]) -> list[str]:
    """Stdout de un evento de consola: Claude (message.content) u OpenCode (part.state)."""
    texts: list[str] = []
    part = rec.get("part")
    if isinstance(part, dict):
        st = part.get("state")
        if isinstance(st, dict):
            out = st.get("output")
            if isinstance(out, str) and out.strip():
                texts.append(out)
            meta = st.get("metadata")
            if isinstance(meta, dict):
                mout = meta.get("output")
                if isinstance(mout, str) and mout.strip() and mout != out:
                    texts.append(mout)
    msg = rec.get("message") if isinstance(rec.get("message"), dict) else None
    content = (msg or {}).get("content") if isinstance(msg, dict) else None
    if isinstance(content, list):
        for item in content:
            if not isinstance(item, dict):
                continue
            text = str(item.get("content") or "")
            if text.strip():
                texts.append(text)
    tur = rec.get("tool_use_result")
    if isinstance(tur, dict):
        stdout = tur.get("stdout")
        if isinstance(stdout, str) and stdout.strip() and stdout not in texts:
            texts.append(stdout)
    return texts


def _console_keep_line(line: str) -> bool:
    if "-Username-" in line or "Last PW Set" in line or "sAMAccountName" in line:
        return True
    if "SidTypeUser" in line or "lookupsids" in line.lower():
        return True
    if "S-1-5-21-" in line and "(1)" in line:
        return True
    if "[+]" in line:
        return True
    if "INSERT INTO" in line and ("$2y$" in line or "$2a$" in line or "$2b$" in line):
        return True
    if "uid=" in line:
        return True
    return False


def _console_keep_text(text: str) -> bool:
    if "-Username-" in text or "Last PW Set" in text or "[+]" in text:
        return True
    if "sAMAccountName" in text:
        return True
    if "SidTypeUser" in text or "lookupsids" in text.lower():
        return True
    if "S-1-5-21-" in text and "(1)" in text:
        return True
    if "INSERT INTO" in text and _SQL_USER_HASH.search(text):
        return True
    if _UID.search(text) and (
        "www-data" in text or _UID_REMOTE.search(text)
    ):
        return True
    return False


def _console_enum_blob(root: Path) -> str:
    """Salida de nxc --users / LDAP / dump SQL de users en console.log."""
    path = root / "console.log"
    if not path.is_file():
        return ""
    chunks: list[str] = []
    try:
        for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
            if not _console_keep_line(line):
                continue
            try:
                rec = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(rec, dict):
                continue
            for text in _event_tool_texts(rec):
                if _console_keep_text(text):
                    chunks.append(text[:20_000])
            if sum(len(c) for c in chunks) > 80_000:
                break
    except OSError:
        return ""
    return "\n".join(chunks)


def _loot_plus_blob(root: Path) -> str:
    """loot/spray-hits.txt y similares: `[+] DOMINIO\\user:pass`."""
    loot = root / "loot"
    if not loot.is_dir():
        return ""
    chunks: list[str] = []
    try:
        for path in sorted(loot.glob("*.txt")):
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue
            if "[+]" not in text:
                continue
            chunks.append(text[:20_000])
            if sum(len(c) for c in chunks) > 80_000:
                break
    except OSError:
        return ""
    return "\n".join(chunks)


def _tried_blob(eng: dict[str, Any]) -> str:
    parts: list[str] = []
    for key in ("tried", "cmd_log"):
        for t in eng.get(key) or []:
            if isinstance(t, dict):
                parts.append(str(t.get("argv") or t.get("cmd") or ""))
            elif t:
                parts.append(str(t))
    return "\n".join(parts)[:200_000]


def _ascii_name_complete(blob: str, end: int) -> bool:
    """El regex ASCII no puede comer `í`; `legítimo` no debe quedar en `leg`."""
    if end >= len(blob):
        return True
    return not blob[end].isalpha()


def _principal_ok(name: str) -> bool:
    raw = (name or "").strip()
    if not raw or raw.lower() in _SKIP_PRINCIPAL:
        return False
    # Salto real o `python3.11\nscript` (YAML). `CORP\robert` / `CORP\nancy` sí son SAM.
    if "\n" in raw or "\r" in raw:
        return False
    if raw.lower().startswith("python3"):
        return False
    # `__proto__`, `__defineGetter__`: dunder JS, no Unix (`_apt` sí es válido).
    if len(raw) > 4 and raw.startswith("__") and raw.endswith("__"):
        return False
    if _metric_principal(raw):
        return False
    if _CRYPTO_PRINCIPAL.search(raw):
        return False
    if _ALGO_TOKEN.match(raw):
        return False
    if any(ord(ch) < 0x20 for ch in raw):
        return False
    # PING\r\nDEL / r\nDEL: escapes C o verbos RESP, no CORP\robert ni CORP\nancy.
    if re.search(r"\\r\\n|\\[rntfvbae0]$", raw):
        return False
    parts = [p for p in re.split(r"[\\/]", raw) if p]
    if any(p.lower() in _SKIP_PRINCIPAL or p.lower() in _PHP_PATH_TOKEN for p in parts):
        return False
    if any(p.lower().endswith((".txt", ".json", ".php", ".py", ".md", ".conf", ".key")) for p in parts):
        return False
    if any(_resp_leftover(p) for p in parts):
        return False
    if any(len(p) == 1 and p.lower() in _ESCAPE_LETTERS for p in parts):
        return False
    if _resp_leftover(raw):
        return False
    if raw.lower() in {"r", "n", "t", "f", "v"}:
        return False
    if raw.lower().endswith("@example.com"):
        return False
    if "@" not in raw and "\\" not in raw and "." in raw:
        if _PERSON_DOT.fullmatch(raw):
            return raw.rsplit(".", 1)[-1].lower() not in _NAME_TLD
        return bool(_PERSON_INITIAL.fullmatch(raw))
    return True


def _scope(principal: str) -> str:
    p = (principal or "").strip()
    if "\\" in p:
        return "domain"
    if "@" in p:
        return "mail"
    if p.lower() in _SERVICE:
        return "service"
    return "local"


def _via_of(blob: str, default: str = "") -> str:
    t = (blob or "").lower()
    if (_SSH.search(t) or "ssh://" in t) and "como www-data" not in t:
        # SSH comando/URL. «claves SSH» en un impacto no cuenta.
        if "/admin/" in t or "email=" in t:
            return "web"
        if re.search(r"(?<!permitroot)(?<!root )\blogin\b", t) and not _SSH.search(t):
            return "web"
        return "ssh"
    if "winrm" in t:
        return "winrm"
    if "smb" in t or "psexec" in t:
        return "smb"
    if "login" in t or "/admin" in t or "email=" in t:
        return "web"
    if "tinymce" in t or "webshell" in t or re.search(r"\brce\b", t):
        return "webshell"
    if "http" in t:
        return "web"
    return default or "unknown"


def _priv_of(blob: str, principal: str, default: str = "user") -> str:
    t = (blob or "").lower()
    p = (principal or "").lower()
    if p == "root" or "root.txt" in t and "flag" in t:
        return "root"
    if p in {"www-data", "apache", "nginx", "node"}:
        return "service"
    if any(x in t for x in ("administrador", "administrative", "admin/dashboard", "domain admin")):
        return "admin"
    if p in {"administrator", "admin"} and "login" in t:
        return "admin"
    return default


def _asset_host(asset: str) -> str:
    raw = (asset or "").strip()
    if not raw:
        return ""
    m = _HOST_ASSET.match(raw)
    if m:
        return m.group(1)
    m = _DNS_HOST.search(raw)
    if m:
        return m.group(1)
    m = _IPV4.search(raw)
    return m.group(1) if m else ""


def _place_is_target(place: str, targets: list[str] | None) -> bool:
    host = (place or "").strip().split("/")[0].split(":")[0]
    if not host:
        return False
    for spec in targets or []:
        sh = str(spec or "").split("/")[0].split(":")[0]
        if sh == host or str(spec) == place:
            return True
    return False


def _container_rce_not_target(
    blob: str, place: str, targets: list[str] | None
) -> bool:
    """uid=0 en un contenedor que no es el target ≠ root del host del run."""
    if not targets or not _CONTAINER_NS.search(blob or ""):
        return False
    if re.search(r"\broot\.txt\b", blob or "", flags=re.I):
        return False
    if _place_is_target(place, targets):
        for ip in _IPV4.findall(blob or ""):
            if _place_is_target(ip, targets):
                continue
            if _usable_identity_ip(ip, targets):
                return True
        return False
    return True


def _only_off_target_container_root(
    findings: list[dict[str, Any]],
    *,
    eng: dict[str, Any],
    specs: list[str],
    fallback: str,
    root: Path,
    sibling: list[str] | None = None,
) -> bool:
    """El único uid=0 es RCE en un contenedor que no es el target del run."""
    saw_sidecar = False
    saw_os = False
    for fl in eng.get("flags") or []:
        if not isinstance(fl, dict):
            continue
        if str(fl.get("kind") or "").strip().lower() == "root":
            saw_os = True
        if "root.txt" in str(fl.get("path") or "").lower():
            saw_os = True
    sib = sibling or []
    for f in findings:
        if str(f.get("status") or "").lower() in {"discarded", "void"}:
            continue
        blob = _blob(f)
        ev = _evidence_snippets(root, f)
        id_blob = f"{blob} {ev}".strip() if ev else blob
        place = _resolve_finding_ip(
            f, fallback=fallback, targets=specs, eng=eng, sibling=sib
        )
        kind = str(f.get("kind") or "").lower()
        if "root.txt" in id_blob.lower():
            saw_os = True
        if _OS_ROOT_SHOWN.search(id_blob):
            if _container_rce_not_target(id_blob, place, specs):
                saw_sidecar = True
            else:
                saw_os = True
        elif kind == "flag" and "root.txt" in id_blob.lower():
            saw_os = True
    return saw_sidecar and not saw_os


def _target_specs(eng: dict[str, Any], meta: dict[str, Any] | None = None) -> list[str]:
    out: list[str] = []
    meta = meta if isinstance(meta, dict) else {}
    for t in list(eng.get("targets") or []) + list(meta.get("targets") or []):
        if isinstance(t, dict):
            v = str(t.get("value") or t.get("raw") or "").strip()
        else:
            v = str(t or "").strip()
        if v and v not in out:
            out.append(v)
    return out


def _versionish_ip(ip: str) -> bool:
    """FreePBX `16.0.40.7` o React `?ver=18.3.1.1` no son un host. No toca 10/8 ni 192.168."""
    try:
        a, b, c, d = (int(x) for x in (ip or "").split("."))
    except ValueError:
        return False
    if a in {10, 127} or (a == 192 and b == 168) or (a == 172 and 16 <= b <= 31):
        return False
    return 1 <= a <= 32 and max(b, c, d) <= 99


def _usable_identity_ip(ip: str, targets: list[str] | None = None) -> bool:
    """IP de máquina, no CIDR ni red/broadcast."""
    raw = (ip or "").strip()
    if not raw or "/" in raw:
        return False
    try:
        addr = ipaddress.ip_address(raw)
    except ValueError:
        return False
    if addr.is_unspecified or addr.is_link_local:
        return False
    in_target = any(
        spec == raw or spec.startswith(raw + ":") or spec.split("/")[0].split(":")[0] == raw
        for spec in (targets or [])
    )
    if _versionish_ip(raw) and not in_target:
        return False
    if addr.is_loopback:
        return in_target
    for spec in targets or []:
        if "/" not in spec:
            continue
        try:
            net = ipaddress.ip_network(spec, strict=False)
        except ValueError:
            continue
        if addr == net.network_address or addr == net.broadcast_address:
            return False
    return True


def _usable_ips_in(text: str, targets: list[str] | None = None) -> list[str]:
    found: list[str] = []
    for rx in (_URL_IP, _IPV4):
        for m in rx.finditer(text or ""):
            ip = m.group(1)
            if _usable_identity_ip(ip, targets) and ip not in found:
                found.append(ip)
    return found


def _target_ip(eng: dict[str, Any], meta: dict[str, Any]) -> str:
    specs = _target_specs(eng, meta)
    singles = [s for s in specs if _usable_identity_ip(s, specs)]
    if len(singles) == 1:
        return singles[0]
    hosts = [
        str(h.get("ip") or "").strip()
        for h in eng.get("hosts") or []
        if isinstance(h, dict) and _usable_identity_ip(str(h.get("ip") or ""), specs)
    ]
    if len(hosts) == 1:
        return hosts[0]
    return ""


def _resolve_finding_ip(
    f: dict[str, Any],
    *,
    fallback: str,
    targets: list[str],
    eng: dict[str, Any],
    sibling: list[str],
) -> str:
    asset = str(f.get("asset") or "")
    blob = _blob(f)
    found = _usable_ips_in(asset, targets) + _usable_ips_in(blob, targets)
    uniq: list[str] = []
    for ip in found:
        if ip not in uniq:
            uniq.append(ip)
    if len(uniq) == 1:
        return uniq[0]
    urls: list[str] = []
    for m in _URL_IP.finditer(asset + "\n" + blob):
        ip = m.group(1)
        if _usable_identity_ip(ip, targets) and ip not in urls:
            urls.append(ip)
    if len(urls) == 1:
        return urls[0]
    if urls:
        return urls[0]
    if len(uniq) > 1:
        return uniq[0]
    sib = list(dict.fromkeys(ip for ip in sibling if _usable_identity_ip(ip, targets)))
    if len(sib) == 1:
        return sib[0]
    titled = [
        str(h.get("ip") or "").strip()
        for h in eng.get("hosts") or []
        if isinstance(h, dict)
        and h.get("http_title")
        and _usable_identity_ip(str(h.get("ip") or ""), targets)
    ]
    if len(titled) == 1:
        return titled[0]
    hosts = [
        str(h.get("ip") or "").strip()
        for h in eng.get("hosts") or []
        if isinstance(h, dict) and _usable_identity_ip(str(h.get("ip") or ""), targets)
    ]
    if len(hosts) == 1:
        return hosts[0]
    if fallback and _usable_identity_ip(fallback, targets):
        return fallback
    return ""


def _new(
    *,
    principal: str,
    host: str = "",
    ip: str = "",
    via: str = "",
    priv: str = "user",
    status: str = "compromised",
    finding: str = "",
    ts: str = "",
    secret: str = "",
    secret_type: str = "",
    kind: str = "",
) -> dict[str, Any] | None:
    principal = (principal or "").strip()
    if not _principal_ok(principal):
        return None
    return {
        "principal": principal,
        "host": (host or ip or "").strip(),
        "ip": (ip or "").strip(),
        "via": via or "unknown",
        "priv": priv or "user",
        "scope": _scope(principal),
        "status": status,
        "finding": finding,
        "ts": ts,
        "has_secret": bool(secret),
        "secret_type": secret_type if secret else "",
        "kind": kind,
        "_secret": secret,
    }


def _key(row: dict[str, Any]) -> tuple[str, str, str]:
    host = (row.get("ip") or row.get("host") or "").lower()
    return (str(row.get("principal") or "").lower(), host, str(row.get("via") or "").lower())


def _sam_key(principal: str) -> str:
    """LABDC\\ryan.brooks y ryan.brooks$ son la misma cuenta."""
    p = (principal or "").strip()
    if "\\" in p:
        p = p.rsplit("\\", 1)[-1]
    if "@" in p:
        p = p.split("@", 1)[0]
    return p.rstrip("$").lower()


def _prefer_principal(cur: str, incoming: str) -> str:
    """`testmsa$` gana a `testmsa`; SAM suelto gana a `DOMINIO\\SAM`."""
    a, b = (cur or "").strip(), (incoming or "").strip()
    if not a:
        return b
    if not b:
        return a

    def bits(p: str) -> tuple[int, int]:
        sam = p.rsplit("\\", 1)[-1]
        return (1 if sam.endswith("$") else 0, 0 if "\\" not in p and "@" not in p else -1)

    return a if bits(a) >= bits(b) else b


def _merge(rows: list[dict[str, Any]], extra: dict[str, Any] | None) -> None:
    if not extra:
        return
    k = _key(extra)
    for row in rows:
        if _key(row) != k:
            continue
        for field in ("host", "ip", "via", "priv", "finding", "ts", "secret_type"):
            if extra.get(field) and not row.get(field):
                row[field] = extra[field]
        eh, rh = str(extra.get("host") or ""), str(row.get("host") or "")
        if eh and eh != extra.get("ip") and (not rh or rh == row.get("ip") or _IPV4.fullmatch(rh)):
            row["host"] = eh
        if extra.get("has_secret"):
            row["has_secret"] = True
            if extra.get("_secret"):
                row["_secret"] = extra["_secret"]
        if extra.get("status") == "compromised":
            row["status"] = "compromised"
        if extra.get("kind") == "flag" or (extra.get("kind") and not row.get("kind")):
            row["kind"] = extra.get("kind") or row.get("kind")
        if extra.get("priv") in {"root", "admin"} and row.get("priv") not in {"root"}:
            if extra["priv"] == "root" or row.get("priv") != "admin":
                row["priv"] = extra["priv"]
        return
    rows.append(extra)


def _placeholder_session_cred(c: dict[str, Any]) -> bool:
    """Cookie/sesión anónima (`web` + `(sesión)`), no un login con nombre."""
    typ = str(c.get("type") or "").strip().lower()
    user = str(c.get("user") or "").strip().lower()
    secret = str(c.get("secret") or "").strip()
    if typ not in {"session", "cookie"}:
        return secret in _SESSION_PLACEHOLDER_SECRETS and user in _SESSION_PLACEHOLDER_USERS
    return user in _SESSION_PLACEHOLDER_USERS or secret in _SESSION_PLACEHOLDER_SECRETS


def _from_engagement(eng: dict[str, Any], targets: list[str] | None = None) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    jump = ""
    for a in eng.get("access") or []:
        if isinstance(a, dict) and str(a.get("via") or "") == "ssh":
            jump = str(a.get("host") or "").strip()
            if jump:
                break
    loop = ""
    for spec in targets or []:
        host = spec.split("/")[0].split(":")[0]
        if host in {"127.0.0.1", "::1"}:
            loop = host
            break

    def _place(host: str, via: str, cred_type: str = "") -> tuple[str, str]:
        host = (host or "").strip()
        via_l = (via or "").strip().lower()
        typ = (cred_type or "").strip().lower()
        if host.lower() in _PLACEHOLDER_HOST:
            host = ""
        if (
            loop
            and jump
            and host == jump
            and typ != "ssh"
            and via_l in {"", "unknown", "web", "webshell", "privesc", "password", "session", "cookie"}
        ):
            return loop, loop
        ip = host if _usable_identity_ip(host, targets) else ""
        return (ip or ""), ip

    real_cred_users = {
        str(c.get("user") or "").strip().lower()
        for c in (eng.get("creds") or [])
        if isinstance(c, dict) and not _placeholder_session_cred(c) and str(c.get("user") or "").strip()
    }
    for c in eng.get("creds") or []:
        if not isinstance(c, dict) or _placeholder_session_cred(c):
            continue
        user = str(c.get("user") or "").strip()
        # basura de código/protocolo colada por el parser (except:break)
        if user and user.lower() not in _SESSION_PLACEHOLDER_USERS and not _principal_ok(user):
            continue
        secret = _clean_secret(str(c.get("secret") or ""))
        if secret in _SESSION_PLACEHOLDER_SECRETS or _cli_flag_secret(secret):
            continue
        typ = str(c.get("type") or "password")
        where = str(c.get("where") or "").strip().lower()
        via = "web" if typ in {"session", "cookie"} else (
            "ssh" if typ == "ssh" else ("smb" if where == "nxc" else "unknown")
        )
        host, ip = _place(str(c.get("where") or ""), via, typ)
        _merge(
            out,
            _new(
                principal=user,
                host=host,
                ip=ip,
                via=via,
                priv="user",
                status="compromised",
                ts=str(c.get("ts") or ""),
                secret=secret if _secret_ok(secret) else "",
                secret_type=typ,
            ),
        )
    for a in eng.get("access") or []:
        if not isinstance(a, dict):
            continue
        via = str(a.get("via") or "unknown")
        user = str(a.get("user") or "").strip()
        via_l = via.lower()
        if (
            user.lower() in _SESSION_PLACEHOLDER_USERS
            and user.lower() not in real_cred_users
            and via_l in {"web", "session", "cookie", "unknown", ""}
        ):
            continue
        host, ip = _place(str(a.get("host") or ""), via)
        _merge(
            out,
            _new(
                principal=user,
                host=host,
                ip=ip,
                via=via,
                priv=str(a.get("priv") or "user"),
                status="compromised",
                ts=str(a.get("ts") or ""),
            ),
        )
    for u in eng.get("users") or []:
        name = str(u).strip() if not isinstance(u, dict) else str(u.get("name") or u.get("user") or "").strip()
        if not name:
            continue
        if name.lower() in _SESSION_PLACEHOLDER_USERS and name.lower() not in real_cred_users:
            continue
        places = [
            spec.split("/")[0].split(":")[0]
            for spec in targets or []
            if _usable_identity_ip(spec.split("/")[0].split(":")[0], targets)
        ]
        places = list(dict.fromkeys(places))
        sip = places[0] if len(places) == 1 else ""
        _merge(
            out,
            _new(principal=name, host=sip, ip=sip, status="enumerated", via="enum"),
        )
    return out


def _finding_sidecar_creds(root: Path, fid: str) -> list[tuple[str, str]]:
    """findings/F-xxx/creds.txt (user:pass por línea). El agente lo escribe y el JSON no."""
    if not fid or not fid.startswith("F-"):
        return []
    path = root / "findings" / fid / "creds.txt"
    if not path.is_file():
        return []
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    out: list[tuple[str, str]] = []
    for line in raw.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or ":" not in line:
            continue
        user, secret = line.split(":", 1)
        user, secret = user.strip(), secret.strip()
        if user and _principal_ok(user) and secret:
            out.append((user, secret))
    return out


def _from_finding(
    f: dict[str, Any],
    fallback_ip: str,
    targets: list[str] | None = None,
    root: Path | None = None,
) -> list[dict[str, Any]]:
    status = str(f.get("status") or "").strip().lower()
    kind = str(f.get("kind") or "").strip().lower()
    # Flag CTF: Claude a veces la deja en suspected (evidencia `user.txt` suelta)
    # y el user de /home/<cuenta>/user.txt no se pintaría.
    if status not in {"proven", "confirmed"} and kind != "flag":
        return []
    blob = _blob(f)
    prose = _prose_blob(f)
    ev = _evidence_snippets(root, f) if root is not None else ""
    id_blob = f"{blob} {ev}".strip() if ev else blob
    fid = str(f.get("id") or "")
    ts = str(f.get("timestamp") or "")
    host = _asset_host(str(f.get("asset") or ""))
    if _IPV4.fullmatch(host) and (
        not _usable_identity_ip(host, targets)
        or (targets and not _place_is_target(host, targets))
    ):
        host = ""
    ip = host if _usable_identity_ip(host, targets) else fallback_ip
    if targets and _IPV4.fullmatch(ip or "") and not _place_is_target(ip, targets):
        ip = fallback_ip
    if not _usable_identity_ip(ip, targets):
        ip = fallback_ip if _usable_identity_ip(fallback_ip, targets) else ""
    if not host:
        host = ip
    rows: list[dict[str, Any]] = []

    for m in _EMAIL_PASS.finditer(blob):
        _merge(
            rows,
            _new(
                principal=m.group(1),
                host=host,
                ip=ip,
                via=_via_of(blob, "web"),
                priv=_priv_of(blob, m.group(1), "admin" if "admin" in blob.lower() else "user"),
                finding=fid,
                ts=ts,
                secret=m.group(2) if _secret_ok(m.group(2)) else "",
                secret_type="password",
            ),
        )
    for m in _USUARIO_QUOTED.finditer(id_blob):
        user, secret = m.group(1), m.group(2)
        if not _secret_ok(secret) or _mac_pair(user, secret):
            continue
        if any(str(r.get("principal") or "").lower() == user.lower() for r in rows):
            continue
        _merge(
            rows,
            _new(
                principal=user,
                host=host,
                ip=ip,
                via=_via_of(blob, "web"),
                priv=_priv_of(blob, user),
                finding=fid,
                ts=ts,
                secret=secret,
                secret_type="password",
            ),
        )
    for m in _USUARIO_BARE.finditer(id_blob):
        user, secret = m.group(1), _clean_secret(m.group(2).rstrip(").,;\"'"))
        if not _looks_like_password(secret) or _mac_pair(user, secret):
            continue
        if not re.search(r"[\d!@#$%^&*_\-]", secret):
            continue
        if user.lower() in _SESSION_PLACEHOLDER_USERS:
            continue
        if any(str(r.get("principal") or "").lower() == user.lower() for r in rows):
            continue
        _merge(
            rows,
            _new(
                principal=user,
                host=host,
                ip=ip,
                via=_via_of(blob, "web"),
                priv=_priv_of(blob, user),
                finding=fid,
                ts=ts,
                secret=secret,
                secret_type="password",
            ),
        )
    emails = [m.group(1) for m in _EMAIL_EQ.finditer(id_blob)]
    emails.extend(m.group(1) for m in _EMAIL_JSON.finditer(id_blob))
    if _ACCOUNT_MARK.search(blob) or _ACCOUNT_MARK.search(id_blob):
        emails.extend(m.group(1) for m in _EMAIL.finditer(blob))
    seen_em: set[str] = set()
    uniq_emails: list[str] = []
    for em in emails:
        key = em.lower()
        if key in seen_em:
            continue
        seen_em.add(key)
        uniq_emails.append(em)
    emails = uniq_emails
    form_users = [m.group(1) for m in _USER_EQ.finditer(blob)]
    passwords = [m.group(1) for m in _PASS_EQ.finditer(blob) if _secret_ok(m.group(1))]
    for m in _PASS_JSON.finditer(id_blob):
        cand = _clean_secret(m.group(1))
        if cand and _secret_ok(cand) and _looks_like_password(cand) and cand not in passwords:
            passwords.append(cand)
    if emails:
        secret = passwords[0] if passwords else ""
        for em in emails:
            if any(r.get("principal", "").lower() == em.lower() for r in rows):
                continue
            _merge(
                rows,
                _new(
                    principal=em,
                    host=host,
                    ip=ip,
                    via=_via_of(blob, "web"),
                    priv=_priv_of(blob, em, "admin" if "admin" in blob.lower() else "user"),
                    finding=fid,
                    ts=ts,
                    secret=secret,
                    secret_type="password" if secret else "",
                ),
            )
    cred_finding = bool(
        re.search(
            r"\b(credencial|contrase|password|login|por defecto|default cred)\b",
            " ".join(str(f.get(k) or "") for k in ("title", "summary", "kind")),
            flags=re.I,
        )
    )
    if cred_finding and form_users and passwords:
        secret = passwords[0]
        for user in form_users:
            if any(str(r.get("principal") or "").lower() == user.lower() for r in rows):
                continue
            _merge(
                rows,
                _new(
                    principal=user,
                    host=host,
                    ip=ip,
                    via="web",
                    priv=_priv_of(blob, user),
                    finding=fid,
                    ts=ts,
                    secret=secret,
                    secret_type="password",
                ),
            )
    if cred_finding:
        for m in _SLASH_PASS.finditer(prose):
            user, secret = m.group(1), m.group(2)
            # Solo el idioma clásico admin/admin (mismos tokens). Evita MIME y paths
            # (image/jpeg, tinymce/upload, admin/krayin-docker-setup).
            if user.lower() != secret.lower():
                continue
            if "@" in user or not _secret_ok(secret) or _mac_pair(user, secret):
                continue
            if user.lower() in {"http", "https", "cve"} or user.upper().startswith("F-"):
                continue
            if user.lower() in _SKIP_SLASH_TOKEN or secret.lower() in _SKIP_SLASH_TOKEN:
                continue
            if any(str(r.get("principal") or "").lower() == user.lower() for r in rows):
                continue
            _merge(
                rows,
                _new(
                    principal=user,
                    host=host,
                    ip=ip,
                    via="web",
                    priv=_priv_of(blob, user),
                    finding=fid,
                    ts=ts,
                    secret=secret,
                    secret_type="password",
                ),
            )

    for m in _SSH.finditer(blob):
        user, shost = m.group(1), m.group(2).rstrip(".")
        if shost.lower() in _SSH_ALGO_HOST or _CRYPTO_PRINCIPAL.search(user):
            continue
        sip = shost if _IPV4.fullmatch(shost) else ip
        trail = _SSH_TRAIL_SECRET.match(blob[m.end() : m.end() + 48])
        secret = trail.group(1) if trail and _looks_like_password(trail.group(1)) and "=" not in trail.group(1) else ""
        row = _new(
            principal=user,
            host=shost,
            ip=sip,
            via="ssh",
            priv=_priv_of(blob, user, "user"),
            finding=fid,
            ts=ts,
            secret=secret,
            secret_type="password" if secret else "",
        )
        if row and not secret and _SSH_KEY_MARK.search(id_blob):
            row["secret_type"] = "ssh-key"
        _merge(rows, row)

    if _SSH_KEY_MARK.search(id_blob):
        key_users: list[str] = []
        for m in _KEYFILE_USER.finditer(id_blob):
            key_users.append(m.group(1))
        for m in re.finditer(
            r"\busuario\s+[`'\"]([A-Za-z_][A-Za-z0-9._$-]*)[`'\"]",
            id_blob,
            flags=re.I,
        ):
            if _ascii_name_complete(id_blob, m.end(1)):
                key_users.append(m.group(1))
        seen_key: set[str] = set()
        for user in key_users:
            key = user.lower()
            if key in seen_key or not _principal_ok(user):
                continue
            seen_key.add(key)
            existing = next(
                (r for r in rows if str(r.get("principal") or "").lower() == key),
                None,
            )
            if existing and str(existing.get("via") or "") == "ssh":
                if not existing.get("has_secret"):
                    existing["secret_type"] = "ssh-key"
                continue
            row = _new(
                principal=user,
                host=host,
                ip=ip,
                via="ssh",
                priv=_priv_of(blob, user, "user"),
                finding=fid,
                ts=ts,
            )
            if row:
                row["secret_type"] = "ssh-key"
                _merge(rows, row)

    for m in _DOMAIN.finditer(blob):
        dom, usr = m.group(1), m.group(2)
        # DOMINIO\usuario real nunca es \r \n \t…: eso es salida de comandos, no una
        # cuenta. El regex solo deja usr de 1 letra cuando le sigue otro backslash
        # (el \n tras el \r), así que un usr suelto r/n/t es siempre un escape.
        if len(usr) == 1 and usr.lower() in _ESCAPE_LETTERS:
            continue
        if len(dom) == 1 and dom.lower() in _ESCAPE_LETTERS:
            continue
        if dom.isdigit():
            continue
        if _resp_leftover(dom) or _resp_leftover(usr):
            continue
        if _php_namespace(dom, usr):
            continue
        principal = f"{dom}\\{usr}"
        _merge(
            rows,
            _new(
                principal=principal,
                host=host,
                ip=ip,
                via=_via_of(blob, "smb"),
                priv=_priv_of(blob, principal),
                finding=fid,
                ts=ts,
                status="compromised" if str(f.get("kind") or "") != "info" else "enumerated",
            ),
        )

    for m in _LOCAL_PASS.finditer(prose):
        user, secret = m.group(1), m.group(2)
        if "@" in user or not _secret_ok(secret) or _mac_pair(user, secret):
            continue
        if _MAC_TAIL.search(prose[: m.start()]):
            continue
        if user.lower() in {"http", "https", "cve"} or user.upper().startswith("F-"):
            continue
        if user.isupper() and "_" in user:
            continue
        if _metric_principal(user):
            continue
        # user:pass es login, no RCE. «claves SSH» o «RCE» en el mismo párrafo no lo pisan.
        via = "web"
        if re.search(rf"\bssh\b[^\n]{{0,120}}\b{re.escape(user)}[:@]", blob, flags=re.I):
            via = "ssh"
        _merge(
            rows,
            _new(
                principal=user,
                host=host,
                ip=ip,
                via=via,
                priv=_priv_of(blob, user),
                finding=fid,
                ts=ts,
                secret=secret,
                secret_type="password",
            ),
        )

    for m in _USERS_LIST.finditer(blob):
        for name in re.split(r"[,;]", m.group(1)):
            user = name.strip().strip("\"'")
            if not user or any(str(r.get("principal") or "").lower() == user.lower() for r in rows):
                continue
            _merge(
                rows,
                _new(
                    principal=user,
                    host=host,
                    ip=ip,
                    via="enum",
                    priv=_priv_of(blob, user, "user"),
                    finding=fid,
                    ts=ts,
                    status="enumerated",
                ),
            )

    for m in _UID.finditer(id_blob):
        user = m.group(1)
        if not _uid_counts(id_blob, user, m.start(), m.end()):
            continue
        _merge(
            rows,
            _new(
                principal=user,
                host=host,
                ip=ip,
                via="webshell",
                priv=_priv_of(id_blob, user, "service"),
                finding=fid,
                ts=ts,
            ),
        )
    seen_como: set[str] = set()
    for rx in (_COMO_NAMED, _COMO_SERVICE):
        for m in rx.finditer(id_blob):
            name = (m.group(1) or "").strip().rstrip(".,;:!?")
            key = name.lower()
            if not name or key in seen_como:
                continue
            if not _ascii_name_complete(id_blob, m.end(1)):
                continue
            seen_como.add(key)
            _merge(
                rows,
                _new(
                    principal=name,
                    host=host,
                    ip=ip,
                    via="webshell",
                    priv=_priv_of(id_blob, name, "service"),
                    finding=fid,
                    ts=ts,
                ),
            )

    kind = str(f.get("kind") or "").lower()
    title = str(f.get("title") or "").lower()
    for m in _HOME_USER.finditer(id_blob):
        user = m.group(1)
        flag_home = kind == "flag" and "user.txt" in id_blob.lower()
        existing = next(
            (r for r in rows if str(r.get("principal") or "").lower() == user.lower()),
            None,
        )
        if existing:
            if flag_home:
                existing["status"] = "compromised"
                existing["kind"] = "flag"
                if str(existing.get("via") or "") in {"enum", "unknown", "webshell", ""}:
                    existing["via"] = "ssh"
            continue
        _merge(
            rows,
            _new(
                principal=user,
                host=host or ip,
                ip=ip,
                via="ssh" if flag_home else "enum",
                priv=_priv_of(id_blob, user, "user"),
                finding=fid,
                ts=ts,
                status="compromised" if flag_home else "enumerated",
                kind="flag" if flag_home else kind,
            ),
        )
    for m in _ECHO_SU.finditer(id_blob):
        secret, user = m.group(1), m.group(2)
        if user.lower() in {"root", "c"} or not _principal_ok(user):
            continue
        if not _looks_like_password(secret):
            continue
        existing = next(
            (r for r in rows if str(r.get("principal") or "").lower() == user.lower()),
            None,
        )
        if existing:
            existing["status"] = "compromised"
            existing["has_secret"] = True
            existing["_secret"] = secret
            existing["secret_type"] = "password"
            if str(existing.get("via") or "") in {"enum", "unknown", "mysql", "ldap", "webshell", ""}:
                existing["via"] = "ssh"
            if fid and not existing.get("finding"):
                existing["finding"] = fid
            continue
        _merge(
            rows,
            _new(
                principal=user,
                host=host or ip,
                ip=ip,
                via="ssh",
                priv=_priv_of(id_blob, user, "user"),
                finding=fid,
                ts=ts,
                secret=secret,
                secret_type="password",
            ),
        )
    want_root = (kind == "flag" and "root.txt" in id_blob.lower()) or bool(_OS_ROOT_SHOWN.search(id_blob))
    if want_root and _container_rce_not_target(id_blob, host or ip, targets):
        want_root = False
    if want_root:
        existing = next((r for r in rows if str(r.get("principal") or "").lower() == "root"), None)
        if existing:
            existing["priv"] = "root"
            if str(existing.get("via") or "") in {"webshell", "unknown", "enum", ""}:
                existing["via"] = "privesc"
        else:
            _merge(
                rows,
                _new(
                    principal="root",
                    host=host or ip,
                    ip=ip,
                    via=_via_of(blob, "privesc"),
                    priv="root",
                    finding=fid,
                    ts=ts,
                ),
            )
    if kind == "flag" and "user.txt" in title and not any(r.get("via") == "ssh" for r in rows):
        # El título a veces nombra al user (como jones) sin el patrón ssh user@host.
        # «como el usuario analyst» / «como evidencia» no son cuentas: artículos y
        # _principal_ok las tiran.
        for word in re.findall(r"\bcomo\s+([A-Za-z_][A-Za-z0-9._$-]*)", id_blob, flags=re.I):
            if word.lower() in {"el", "la", "los", "las", "un", "una", "the", "a", "an", "usuario", "user"}:
                continue
            _merge(
                rows,
                _new(
                    principal=word,
                    host=host or ip,
                    ip=ip,
                    via="ssh",
                    priv="user",
                    finding=fid,
                    ts=ts,
                    kind="flag",
                ),
            )
    for cred in parse_db_creds(id_blob):
        secret = str(cred.get("secret") or "")
        useful = bool(secret) and _looks_like_password(secret)
        _merge(
            rows,
            _new(
                principal=str(cred.get("user") or ""),
                host=host,
                ip=ip,
                via="mysql",
                priv="service",
                finding=fid,
                ts=ts,
                status="compromised" if useful else "enumerated",
                secret=secret if useful else "",
                secret_type="password" if useful else "",
            ),
        )
    return rows


ACCOUNTS_FILE = "accounts.json"


def _accounts_raw(root: Path) -> list[Any] | None:
    """Lista del veredicto de cierre. None = no hay fichero usable."""
    path = root / ACCOUNTS_FILE
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, json.JSONDecodeError):
        return None
    if isinstance(data, dict):
        data = data.get("accounts") or data.get("identities") or data.get("compromised")
    if not isinstance(data, list):
        return None
    return data


def _via_says_enum(via: str) -> bool:
    v = (via or "").strip().lower()
    if not v or v in {"enum", "unknown"}:
        return True
    return "enumerado" in v or "enumerated" in v


def accounts_override_rows(
    root: Path, *, eng: dict[str, Any] | None = None
) -> list[dict[str, Any]] | None:
    """Cuentas del pase de cierre. [] = ninguna; None = seguir el extractor."""
    raw = _accounts_raw(root)
    if raw is None:
        return None
    eng = eng if isinstance(eng, dict) else _read_json(root / "engagement.json")
    if not _net_accounts_ok(root, eng):
        return []
    meta = _read_json(root / "meta.json")
    meta = meta if isinstance(meta, dict) else {}
    specs = _target_specs(eng, meta)
    fallback = _target_ip(eng, meta)
    rows: list[dict[str, Any]] = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        user = str(
            item.get("principal") or item.get("user") or item.get("name") or ""
        ).strip()
        where = str(item.get("host") or item.get("ip") or item.get("where") or "").strip()
        ip_cand = where.split("/")[0].split(":")[0] if where else ""
        ip = ""
        if ip_cand and _usable_identity_ip(ip_cand, specs):
            ip = ip_cand
        elif fallback and _usable_identity_ip(fallback, specs):
            ip = fallback
        via_s = str(item.get("via") or "").strip()
        status = str(item.get("status") or "").strip().lower()
        if status not in {"compromised", "enumerated"}:
            status = "enumerated" if _via_says_enum(via_s) else "compromised"
        secret = str(item.get("secret") or item.get("password") or "").strip()
        if secret in _SESSION_PLACEHOLDER_SECRETS:
            secret = ""
        typ = str(item.get("secret_type") or item.get("type") or "")
        if secret and not typ:
            typ = "password"
        _merge(
            rows,
            _new(
                principal=user,
                host=where or ip,
                ip=ip,
                via=via_s or "unknown",
                priv=str(item.get("priv") or "user"),
                status=status,
                finding=str(item.get("finding") or item.get("id") or ""),
                ts=str(item.get("ts") or ""),
                secret=secret,
                secret_type=typ,
            ),
        )
    # El cierre a menudo lista el censo AD sin status. Sin prueba dura
    # (password, root/system, RCE/shell) no es comprometida.
    for r in rows:
        if r.get("status") == "compromised" and not _has_hard_evidence(r):
            r["status"] = "enumerated"
    return rows


def _apply_accounts_override(
    state: dict[str, Any], out_dir: Path, rows: list[dict[str, Any]]
) -> int:
    """engagement.json y grafo = veredicto de accounts.json (quita basura, mete faltas)."""
    from internal.engage import (
        _ok_user,
        add_access,
        add_cred,
        ensure_graph,
    )

    state["creds"] = []
    state["access"] = []
    names: list[str] = []
    added = 0
    for row in rows:
        user = str(row.get("principal") or "").strip()
        host = str(row.get("ip") or row.get("host") or "").strip()
        sam = user.split("@", 1)[0].split("\\")[-1]
        if sam and _ok_user(sam):
            names.append(sam)
        if row.get("has_secret") and row.get("_secret"):
            if add_cred(
                state,
                user,
                str(row.get("_secret") or ""),
                str(row.get("secret_type") or "password"),
                host or str(row.get("via") or ""),
                emit=False,
            ):
                added += 1
        if row.get("status") == "compromised" and user:
            via = str(row.get("via") or "")
            if via in {"enum", "unknown"}:
                via = "access"
            if add_access(
                state,
                host or "target",
                user,
                via=via,
                priv=str(row.get("priv") or "user"),
                emit=False,
            ):
                added += 1
    seen: set[str] = set()
    users: list[str] = []
    for name in names:
        key = name.lower()
        if key in seen:
            continue
        seen.add(key)
        users.append(name)
    state["users"] = users
    ensure_graph(state)
    graph = state.get("graph")
    if isinstance(graph, dict):
        state["graph"] = overlay_graph(graph, rows)
    return added


def extract_identities(root: Path, *, eng: dict[str, Any] | None = None) -> list[dict[str, Any]]:
    eng = eng if isinstance(eng, dict) else _read_json(root / "engagement.json")
    if not _net_accounts_ok(root, eng):
        return []
    override = accounts_override_rows(root, eng=eng)
    if override is not None:
        return override
    meta = _read_json(root / "meta.json")
    meta = meta if isinstance(meta, dict) else {}
    specs = _target_specs(eng, meta)
    fallback_ip = _target_ip(eng, meta)
    findings = [
        f
        for f in _load_findings(root)
        if str(f.get("status") or "").lower() not in {"discarded", "void"}
    ]
    sibling: list[str] = []
    for f in findings:
        sibling.extend(_usable_ips_in(str(f.get("asset") or ""), specs))
        sibling.extend(_usable_ips_in(_blob(f), specs))
    rows = _from_engagement(eng, specs)
    for f in findings:
        resolved = _resolve_finding_ip(
            f, fallback=fallback_ip, targets=specs, eng=eng, sibling=sibling
        )
        for row in _from_finding(f, resolved, specs, root):
            _merge(rows, row)
        fid = str(f.get("id") or "")
        place = resolved if _usable_identity_ip(resolved, specs) else (
            fallback_ip if _usable_identity_ip(fallback_ip, specs) else ""
        )
        for user, secret in _finding_sidecar_creds(root, fid):
            useful = bool(secret) and _looks_like_password(secret)
            _merge(
                rows,
                _new(
                    principal=user,
                    host=place,
                    ip=place,
                    via="smb",
                    priv="user",
                    status="compromised" if useful else "enumerated",
                    finding=fid,
                    secret=secret if useful else "",
                    secret_type="password" if useful else "",
                ),
            )
    for cred in parse_db_creds(_tried_blob(eng)):
        secret = str(cred.get("secret") or "")
        useful = bool(secret) and _looks_like_password(secret)
        sip = fallback_ip if _usable_identity_ip(fallback_ip, specs) else ""
        _merge(
            rows,
            _new(
                principal=str(cred.get("user") or ""),
                host=sip,
                ip=sip,
                via="mysql",
                priv="service",
                status="compromised" if useful else "enumerated",
                secret=secret if useful else "",
                secret_type="password" if useful else "",
            ),
        )
    tried = _tried_blob(eng)
    _attach_json_auth_secrets(rows, tried)
    enum_blob = f"{tried}\n{_console_enum_blob(root)}\n{_loot_plus_blob(root)}"
    sip = fallback_ip if _usable_identity_ip(fallback_ip, specs) else ""
    for cred in parse_nxc_plus_hits(enum_blob):
        secret = str(cred.get("secret") or "")
        useful = bool(secret) and _looks_like_password(secret)
        _merge(
            rows,
            _new(
                principal=str(cred.get("user") or ""),
                host=sip,
                ip=sip,
                via="smb",
                priv="user",
                status="compromised" if useful else "enumerated",
                secret=secret if useful else "",
                secret_type="password" if useful else "",
            ),
        )
    for cred in parse_nxc_cli_creds(tried):
        secret = str(cred.get("secret") or "")
        useful = bool(secret) and _looks_like_password(secret)
        _merge(
            rows,
            _new(
                principal=str(cred.get("user") or ""),
                host=sip,
                ip=sip,
                via="smb",
                priv="user",
                status="compromised" if useful else "enumerated",
                secret=secret if useful else "",
                secret_type="password" if useful else "",
            ),
        )
    for cred in parse_bloody_set_password(tried):
        secret = str(cred.get("secret") or "")
        useful = bool(secret) and _looks_like_password(secret)
        _merge(
            rows,
            _new(
                principal=str(cred.get("user") or ""),
                host=sip,
                ip=sip,
                via="ldap",
                priv="user",
                status="compromised" if useful else "enumerated",
                secret=secret if useful else "",
                secret_type="password" if useful else "",
            ),
        )
    for name in parse_nxc_users_table(enum_blob):
        _merge(
            rows,
            _new(
                principal=name,
                host=sip,
                ip=sip,
                via="enum",
                priv="user",
                status="enumerated",
            ),
        )
    for name in parse_sid_users(enum_blob):
        _merge(
            rows,
            _new(
                principal=name,
                host=sip,
                ip=sip,
                via="enum",
                priv="user",
                status="enumerated",
            ),
        )
    for name in parse_sql_users(enum_blob):
        _merge(
            rows,
            _new(
                principal=name,
                host=sip,
                ip=sip,
                via="mysql",
                priv="user",
                status="enumerated",
            ),
        )
    for name in parse_uid_hits(enum_blob):
        _merge(
            rows,
            _new(
                principal=name,
                host=sip,
                ip=sip,
                via="webshell",
                priv="service" if name.lower() in _SERVICE else "user",
            ),
        )
    if _only_off_target_container_root(
        findings,
        eng=eng,
        specs=specs,
        fallback=fallback_ip,
        root=root,
        sibling=sibling,
    ):
        rows = [
            r
            for r in rows
            if str(r.get("principal") or "").lower() != "root"
            or str(r.get("via") or "") == "ssh"
            or str(r.get("kind") or "") == "flag"
        ]
    guess = fallback_ip
    if not guess:
        uniq = list(dict.fromkeys(sibling))
        if len(uniq) == 1:
            guess = uniq[0]
    for row in rows:
        cur_ip = str(row.get("ip") or "")
        cur_host = str(row.get("host") or "")
        enum_only = str(row.get("via") or "") == "enum" and row.get("status") != "compromised"
        if cur_ip and not _usable_identity_ip(cur_ip, specs):
            row["ip"] = "" if enum_only else (guess if guess else "")
        if _IPV4.fullmatch(cur_host) and not _usable_identity_ip(cur_host, specs):
            row["host"] = "" if enum_only else (row.get("ip") or guess or "")
        if cur_host.lower() in _PLACEHOLDER_HOST:
            row["host"] = "" if enum_only else (row.get("ip") or guess or "")
        if not enum_only:
            if not row.get("ip") and guess and not _IPV4.fullmatch(str(row.get("host") or "")):
                row["ip"] = guess
            if not row.get("host"):
                row["host"] = row.get("ip") or ""
    priv_rank = {"root": 0, "admin": 1, "user": 2, "service": 3}
    via_rank = {"enum": 0, "unknown": 1, "web": 2, "mysql": 2, "ldap": 2, "webshell": 3, "smb": 3, "winrm": 3, "ssh": 4, "privesc": 4}

    def _place_of(row: dict[str, Any]) -> str:
        return str(row.get("ip") or row.get("host") or "").lower()

    def _fold(cur: dict[str, Any], row: dict[str, Any]) -> None:
        better = _prefer_principal(str(cur.get("principal") or ""), str(row.get("principal") or ""))
        if better != cur.get("principal"):
            cur["principal"] = better
            cur["scope"] = _scope(better)
        incoming_via = str(row.get("via") or "")
        via_better = via_rank.get(incoming_via, 1) > via_rank.get(str(cur.get("via") or ""), 1)
        # Login con password no lo convierte en webshell un finding de RCE que cita las mismas creds.
        if via_better and str(cur.get("via") or "") == "web" and cur.get("has_secret") and incoming_via == "webshell":
            via_better = False
        if via_better:
            cur["via"] = row.get("via") or cur.get("via")
            if row.get("priv"):
                cur["priv"] = row["priv"]
            if row.get("finding"):
                cur["finding"] = row["finding"]
        if row.get("status") == "compromised":
            cur["status"] = "compromised"
        if incoming_via not in {"enum", "unknown"} and not via_better:
            if priv_rank.get(str(row.get("priv") or ""), 9) < priv_rank.get(str(cur.get("priv") or ""), 9):
                cur["priv"] = row.get("priv")
        host, ip = str(row.get("host") or ""), str(row.get("ip") or "")
        cur_host = str(cur.get("host") or "")
        if host and host != ip and (not cur_host or cur_host == str(cur.get("ip") or "") or _IPV4.fullmatch(cur_host)):
            cur["host"] = host
        elif host and not cur_host:
            cur["host"] = host
        for field in ("ip", "finding", "ts", "secret_type"):
            if row.get(field) and not cur.get(field):
                cur[field] = row[field]
        if row.get("kind") == "flag" or (row.get("kind") and not cur.get("kind")):
            cur["kind"] = row.get("kind") or cur.get("kind")
        if row.get("has_secret"):
            cur["has_secret"] = True
            if row.get("_secret"):
                cur["_secret"] = row["_secret"]

    collapsed: dict[tuple[str, str], dict[str, Any]] = {}
    for row in rows:
        principal = str(row.get("principal") or "")
        sam = _sam_key(principal)
        if not sam:
            continue
        # ben@app.lab y ben (SSH) son cuentas distintas: no fundir mail con SAM.
        fold_name = principal.lower() if ("@" in principal and "\\" not in principal) else sam
        place = _place_of(row)
        key = (fold_name, place)
        if place:
            empty = collapsed.pop((fold_name, ""), None)
            if empty:
                _fold(empty, row)
                collapsed[key] = empty
                continue
        else:
            placed = next((k for k in collapsed if k[0] == fold_name and k[1]), None)
            if placed:
                _fold(collapsed[placed], row)
                continue
        cur = collapsed.get(key)
        if not cur:
            collapsed[key] = row
            continue
        _fold(cur, row)
    rows = list(collapsed.values())
    # Gate por evidencia: «comprometida» exige prueba dura (contraseña real,
    # priv root/system o RCE/shell). Lo demás baja a enumeración. Así no se
    # cuelan huellas de clave (SHA256:…), intentos SSH fallidos (nosuch@) ni
    # salida de comandos que el parser tomó por cuentas — sin lista negra.
    for r in rows:
        if r.get("status") == "compromised" and not _has_hard_evidence(r):
            r["status"] = "enumerated"
    compromised = {
        str(r.get("principal") or "").strip().lower()
        for r in rows
        if r.get("status") == "compromised"
    }
    rows = [
        r
        for r in rows
        if not (
            r.get("status") == "enumerated"
            and str(r.get("via") or "") == "enum"
            and not (r.get("ip") or r.get("host"))
            and str(r.get("principal") or "").strip().lower() in compromised
        )
    ]
    rows.sort(
        key=lambda r: (
            0 if r.get("status") == "compromised" else 1,
            priv_rank.get(str(r.get("priv") or ""), 9),
            str(r.get("principal") or "").lower(),
            str(r.get("host") or ""),
        )
    )
    try:
        from internal.claimcheck import apply_account_verdicts

        rows = apply_account_verdicts(root, rows)
        rows.sort(
            key=lambda r: (
                0 if r.get("status") == "compromised" else 1,
                priv_rank.get(str(r.get("priv") or ""), 9),
                str(r.get("principal") or "").lower(),
                str(r.get("host") or ""),
            )
        )
    except Exception:
        pass
    return rows


_VIA_HOW = {
    "ssh": "acceso SSH",
    "web": "login web autenticado",
    "webshell": "RCE / webshell (sesión de servicio, no login)",
    "privesc": "ejecución o sesión como root",
    "winrm": "WinRM",
    "rdp": "RDP",
    "smb": "SMB",
    "mysql": "MySQL / base de datos",
    "ldap": "LDAP / directorio",
    "kerberos": "Kerberos",
    "mssql": "MSSQL",
    "enum": "enumeración (sin compromiso)",
    "unknown": "vía no clasificada",
}


def _via_label(via: str) -> str:
    v = (via or "").strip()
    return _VIA_HOW.get(v, v.replace("_", " ") or "vía no clasificada")


def describe_compromise(row: dict[str, Any]) -> str:
    via = str(row.get("via") or "unknown")
    vias = [str(v) for v in (row.get("vias") or [via]) if v]
    if via and via not in vias:
        vias.insert(0, via)
    via_l = " y ".join(_via_label(v) for v in vias)
    fid = str(row.get("finding") or "").strip()
    src = f" (hallazgo {fid})" if fid else ""
    status = str(row.get("status") or "")
    if status and status != "compromised":
        return f"Enumerada por {via_l}{src}. No hay compromiso demostrado."
    has = bool(row.get("_secret") or row.get("has_secret"))
    if str(row.get("secret_type") or "") == "ssh-key":
        return f"Vulnerada por {via_l}{src}. Se obtuvo una clave SSH."
    if has:
        return f"Vulnerada por {via_l}{src}. Se obtuvo la contraseña."
    if any(k in (via or "").lower() for k in ("webshell", "privesc", "rce", "inspector")):
        return (
            f"Vulnerada por {via_l}{src}. "
            "No hay contraseña: el acceso fue por ejecución o sesión, no por login."
        )
    return f"Vulnerada por {via_l}{src}. No consta contraseña en disco."


_PRIV_RANK = {"root": 0, "admin": 1, "user": 2, "service": 3}
_VIA_RANK = {
    "enum": 0, "unknown": 1, "web": 2, "mysql": 2, "ldap": 2,
    "webshell": 3, "smb": 3, "winrm": 3, "ssh": 4, "privesc": 4,
}


def _via_rank_of(via: str) -> int:
    v = (via or "").strip().lower()
    if v in _VIA_RANK:
        return _VIA_RANK[v]
    for key, rank in _VIA_RANK.items():
        if key not in {"unknown", "web"} and key in v:
            return rank
    return 1


def _merge_identity(cur: dict[str, Any], row: dict[str, Any]) -> None:
    """Funde `row` en `cur` (mismo usuario+host, distinta vía). Se queda con la vía
    más conclusiva, el privilegio más alto y el secreto/hallazgo que haya."""
    if row.get("status") == "compromised":
        cur["status"] = "compromised"
    vias = [str(v) for v in (cur.get("vias") or ([cur.get("via")] if cur.get("via") else [])) if v]
    incoming = str(row.get("via") or "")
    if incoming and incoming not in vias:
        vias.append(incoming)
    if vias:
        cur["vias"] = vias
    if _via_rank_of(str(row.get("via") or "")) > _via_rank_of(str(cur.get("via") or "")):
        cur["via"] = row.get("via") or cur.get("via")
        if row.get("finding"):
            cur["finding"] = row["finding"]
        if row.get("priv"):
            cur["priv"] = row["priv"]
    if _PRIV_RANK.get(str(row.get("priv") or ""), 9) < _PRIV_RANK.get(str(cur.get("priv") or ""), 9):
        cur["priv"] = row.get("priv")
    if row.get("has_secret"):
        cur["has_secret"] = True
        if row.get("_secret"):
            cur["_secret"] = row["_secret"]
        if row.get("secret_type"):
            cur["secret_type"] = row["secret_type"]
    if row.get("kind") == "flag" or (row.get("kind") and not cur.get("kind")):
        cur["kind"] = row.get("kind") or cur.get("kind")
    for field in ("finding", "ts", "host", "ip"):
        if row.get(field) and not cur.get(field):
            cur[field] = row[field]


def _collapse_key(principal: str, place: str) -> tuple[str, str] | None:
    """Misma cuenta OS (SAM / user$) se funde; un email no se funde con el user OS."""
    p = (principal or "").strip()
    if not p:
        return None
    local, _, domain = p.partition("@")
    if domain and "." in domain:
        return (p.lower(), place)
    sam = _sam_key(p)
    return (sam, place) if sam else None


def _collapse_identities(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """UNA cuenta por (usuario, host) aunque se alcanzara por varias vías. El
    accounts.json del cierre lista el mismo usuario por webshell y por SSH; sin esto
    salía duplicado en Cuentas comprometidas. Un email (admin@corp) no es el
    usuario OS `admin`."""
    result: list[dict[str, Any]] = []
    index: dict[tuple[str, str], int] = {}
    for row in rows:
        place = str(row.get("ip") or row.get("host") or "").lower()
        key = _collapse_key(str(row.get("principal") or ""), place)
        if key is not None and key in index:
            _merge_identity(result[index[key]], row)
        else:
            if key is not None:
                index[key] = len(result)
            result.append(dict(row))
    return result


def public_identities(
    root: Path,
    *,
    eng: dict[str, Any] | None = None,
    secrets: bool = False,
) -> list[dict[str, Any]]:
    """Vista para UI e informe. Con secrets=True incluye la contraseña si existe."""
    out: list[dict[str, Any]] = []
    for row in _collapse_identities(extract_identities(root, eng=eng)):
        item = {k: v for k, v in row.items() if not k.startswith("_")}
        item["how"] = describe_compromise(row)
        if secrets:
            item["secret"] = str(row.get("_secret") or "")
        out.append(item)
    return out


def overlay_graph(graph: dict[str, Any], identities: list[dict[str, Any]]) -> dict[str, Any]:
    raw_nodes = [dict(n) for n in (graph.get("nodes") or []) if isinstance(n, dict)]
    drop_ids: set[str] = set()
    nodes: list[dict[str, Any]] = []
    alive = {
        str(i.get("principal") or "").strip().lower()
        for i in identities
        if isinstance(i, dict) and i.get("status") == "compromised"
    }
    alive_at = {
        (
            str(i.get("principal") or "").strip().lower(),
            str(i.get("ip") or i.get("host") or "").strip().lower(),
        )
        for i in identities
        if isinstance(i, dict) and i.get("status") == "compromised"
    }
    for n in raw_nodes:
        if str(n.get("kind") or "") == "access":
            principal = str(n.get("principal") or "").strip()
            label = str(n.get("label") or "")
            if not principal:
                principal = label.split("@", 1)[0].strip()
            host = str(n.get("parent") or "").strip()
            if not host and "@" in label:
                host = label.split("@", 1)[-1].strip()
            stale_host = bool(host) and (principal.lower(), host.lower()) not in alive_at
            if principal.lower() not in alive or not _principal_ok(principal) or stale_host:
                nid = str(n.get("id") or "")
                if nid:
                    drop_ids.add(nid)
                continue
        nodes.append(n)
    edges = [
        dict(e)
        for e in (graph.get("edges") or [])
        if isinstance(e, dict)
        and str(e.get("from") or "") not in drop_ids
        and str(e.get("to") or "") not in drop_ids
    ]
    have = {str(n.get("id") or "") for n in nodes}

    def add_node(kind: str, label: str, **kw: Any) -> str:
        nid = f"{kind}:{label}".strip().lower()
        if nid not in have:
            rec = {"id": nid, "kind": kind, "label": label}
            rec.update({k: v for k, v in kw.items() if v not in (None, "")})
            nodes.append(rec)
            have.add(nid)
        return nid

    for it in identities:
        if it.get("status") != "compromised":
            continue
        host = str(it.get("ip") or it.get("host") or "").strip()
        user = str(it.get("principal") or "").strip()
        if not host or not user:
            continue
        from internal.engage import access_label

        hid = add_node("host", host, reachable=True)
        aid = add_node("access", access_label(user, host), principal=user, parent=host, reachable=True)
        if not any(e.get("from") == hid and e.get("to") == aid for e in edges):
            edges.append({"from": hid, "to": aid, "via": it.get("via") or "access"})
    return {
        "nodes": nodes,
        "edges": edges,
        "current": str(graph.get("current") or ""),
    }


def ingest_disk_identities(state: dict[str, Any], out_dir: Path) -> int:
    """Persiste creds/access hallados en findings. No re-emite fact.*."""
    from internal.engage import (
        _ok_access_user,
        _ok_user,
        add_access,
        add_cred,
        add_users,
        ensure_graph,
    )

    users = state.get("users")
    if isinstance(users, list):
        state["users"] = [u for u in users if isinstance(u, str) and _ok_user(u)]
    access = state.get("access")
    if isinstance(access, list):
        state["access"] = [
            a
            for a in access
            if isinstance(a, dict) and _ok_access_user(str(a.get("user") or ""))
        ]
    creds = state.get("creds")
    if isinstance(creds, list):
        state["creds"] = [
            c
            for c in creds
            if isinstance(c, dict)
            and _ok_access_user(str(c.get("user") or ""))
            and not _cli_flag_secret(str(c.get("secret") or ""))
        ]

    if not _net_accounts_ok(out_dir, state):
        state["users"] = []
        state["creds"] = []
        state["access"] = []
        g = state.get("graph")
        if isinstance(g, dict):
            state["graph"] = overlay_graph(g, [])
        else:
            ensure_graph(state)
            g2 = state.get("graph")
            if isinstance(g2, dict):
                state["graph"] = overlay_graph(g2, [])
        return 0

    override = accounts_override_rows(out_dir, eng=state)
    if override is not None:
        return _apply_accounts_override(state, out_dir, override)

    added = 0
    rows = extract_identities(out_dir, eng=state)
    for row in rows:
        user = str(row.get("principal") or "")
        host = str(row.get("ip") or row.get("host") or "")
        ts = str(row.get("ts") or "")
        if row.get("has_secret") and row.get("_secret"):
            if add_cred(
                state,
                user,
                str(row.get("_secret") or ""),
                str(row.get("secret_type") or "password"),
                host or str(row.get("via") or ""),
                emit=False,
            ):
                added += 1
            for c in reversed(list(state.get("creds") or [])):
                if isinstance(c, dict) and str(c.get("user") or "").lower() == user.lower():
                    if ts:
                        c["ts"] = ts
                    break
        if row.get("status") == "compromised" and user:
            via = str(row.get("via") or "")
            if via in {"enum", "unknown"}:
                via = "access"
            if add_access(state, host or "target", user, via=via, priv=str(row.get("priv") or "user"), emit=False):
                added += 1
            for a in reversed(list(state.get("access") or [])):
                if isinstance(a, dict) and str(a.get("user") or "").lower() == user.lower():
                    if ts:
                        a["ts"] = ts
                    break
        sam = user.split("@", 1)[0].split("\\")[-1]
        if sam and (
            row.get("scope") in {"local", "domain", "service"}
            or row.get("via") == "enum"
        ):
            added += add_users(state, [sam])
    creds = state.get("creds")
    if isinstance(creds, list):
        state["creds"] = [
            c
            for c in creds
            if isinstance(c, dict)
            and str(c.get("user") or "").strip()
            and not _placeholder_session_cred(c)
            and not _cli_flag_secret(str(c.get("secret") or ""))
        ]
    ensure_graph(state)
    graph = state.get("graph")
    if isinstance(graph, dict):
        state["graph"] = overlay_graph(graph, rows)
    return added
