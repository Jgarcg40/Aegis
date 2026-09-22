"""Origen de un PoC/advisory (GitHub, Exploit-DB, searchsploit). Solo atribución."""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)
_URL_RE = re.compile(r"https?://[^\s'\"\\<>]+", re.I)
_GIT_CLONE_RE = re.compile(r"\bgit\s+clone\b(?P<rest>[^\n;|&]*)", re.I)
# Estas opciones llevan valor en el token siguiente.
_GIT_CLONE_VALUE_FLAGS = frozenset({
    "--depth", "-b", "--branch", "-c", "--config", "--origin", "--reference",
    "--template", "--separate-git-dir", "-j", "--jobs", "--reference-if-able",
})
_SEARCHSPLOIT_P_RE = re.compile(r"\bsearchsploit\s+(?:-p|--path)\s+(\d+)\b", re.I)
_SEARCHSPLOIT_Q_RE = re.compile(r"\bsearchsploit\s+(?!-p\b|--path\b|--help\b)([A-Za-z0-9._+-]+)", re.I)
_EDB_PATH_RE = re.compile(r"/usr/share/exploitdb/[A-Za-z0-9/_.-]+\.(?:py|rb|c|pl|sh|txt|md|go)", re.I)
_EDB_ID_RE = re.compile(r"/(\d+)\.(?:py|rb|c|pl|sh|txt|md|go)$", re.I)
_EDB_HEADER_CVE = re.compile(r"(?im)^#\s*CVE\s*:\s*(CVE-\d{4}-\d{4,})")
_EDB_HEADER_TITLE = re.compile(r"(?im)^#\s*Exploit Title:\s*(.+)$")
_EDB_PATH_LINE = re.compile(r"(?im)^(?:\[\+\]\s*)?Path:\s*(/usr/share/exploitdb/\S+)")

_POC_HOST_KIND = {
    "github.com": "github",
    "www.github.com": "github",
    "gist.github.com": "github",
    "raw.githubusercontent.com": "github",
    "objects.githubusercontent.com": "github",
    "api.github.com": "github",
    "gitlab.com": "gitlab",
    "www.gitlab.com": "gitlab",
    "exploit-db.com": "exploitdb",
    "www.exploit-db.com": "exploitdb",
    "packetstormsecurity.com": "packetstorm",
    "www.packetstormsecurity.com": "packetstorm",
    "sploitus.com": "sploitus",
    "0day.today": "0day",
}

_ADVISORY_HINT = ("/advisories/", "nvd.nist.gov", "cve.org", "cvedetails.com")
_SKIP_HOST_PART = (".lab", ".test", ".local", "localhost", "127.0.0.1", "example.com")
_VENDOR_REPO = re.compile(
    r"(?i)github\.com/(?:krayin|webkul|laravel|wordpress|drupal|joomla)/"
)


def _clean_url(url: str) -> str:
    return (url or "").rstrip(").,;\"'`")


def _host(url: str) -> str:
    try:
        return (urlparse(url).hostname or "").lower()
    except ValueError:
        return ""


def is_search_url(url: str) -> bool:
    u = (url or "").lower()
    return "api.github.com/search" in u or "/search?" in u or "/search/" in u


def is_poc_fetch_url(url: str) -> bool:
    """True si la URL es una bajada/clone de PoC o advisory, no el objetivo ni un search."""
    url = _clean_url(url)
    if not url.lower().startswith("http"):
        return False
    low = url.lower()
    if any(x in low for x in _SKIP_HOST_PART):
        return False
    if is_search_url(url):
        return False
    host = _host(url)
    if host in _POC_HOST_KIND:
        if host in {"api.github.com", "github.com", "www.github.com"} and "/search" in low:
            return False
        return True
    if any(x in low for x in _ADVISORY_HINT):
        return True
    return False


def iter_fetch_urls(argv: str) -> list[str]:
    out: list[str] = []
    for url in git_clone_urls(argv):
        if url not in out:
            out.append(url)
    for raw in _URL_RE.findall(argv or ""):
        url = _clean_url(raw)
        if is_poc_fetch_url(url) and url not in out:
            out.append(url)
    return out


def _git_clone_target(rest: str) -> str:
    toks = (rest or "").split()
    i = 0
    while i < len(toks):
        t = toks[i]
        if t == "--":
            return toks[i + 1] if i + 1 < len(toks) else ""
        if t.startswith("-"):
            if "=" in t:
                i += 1
                continue
            i += 2 if t in _GIT_CLONE_VALUE_FLAGS else 1
            continue
        return t
    return ""


def git_clone_urls(argv: str) -> list[str]:
    out: list[str] = []
    for m in _GIT_CLONE_RE.finditer(argv or ""):
        raw = _clean_url(_git_clone_target(m.group("rest") or ""))
        if raw.startswith("http") or raw.startswith("git@"):
            if raw.startswith("git@"):
                raw = "https://" + raw.split("@", 1)[1].replace(":", "/", 1)
            if is_poc_fetch_url(raw) or _host(raw) in _POC_HOST_KIND:
                out.append(raw)
    return out


def _kind_for_url(url: str) -> str:
    low = url.lower()
    if any(x in low for x in _ADVISORY_HINT) or "/advisories/" in low:
        return "advisory"
    host = _host(url)
    return _POC_HOST_KIND.get(host, "url")


def _tokens_from_text(*parts: str) -> set[str]:
    blob = " ".join(parts).lower()
    skip = {
        "the",
        "and",
        "for",
        "http",
        "https",
        "www",
        "com",
        "org",
        "exploit",
        "title",
        "authenticated",
        "remote",
        "code",
        "execution",
        "via",
        "admin",
        "upload",
    }
    out: set[str] = set()
    for w in re.findall(r"[a-z][a-z0-9._-]{3,}", blob):
        if w in skip or w.startswith("cve-"):
            continue
        out.add(w)
    return out


def _source(
    *,
    kind: str,
    urls: list[str] | None = None,
    local: list[str] | None = None,
    edb: str = "",
    cves: list[str] | None = None,
    tokens: set[str] | None = None,
    ts: str = "",
    argv: str = "",
) -> dict[str, Any]:
    return {
        "kind": kind,
        "urls": [u for u in (urls or []) if u],
        "local": [p for p in (local or []) if p],
        "edb": str(edb or ""),
        "cves": [c.upper() for c in (cves or []) if c],
        "tokens": sorted(tokens or []),
        "ts": ts,
        "argv": (argv or "")[:240],
    }


def _from_argv(argv: str, ts: str = "") -> list[dict[str, Any]]:
    argv = argv or ""
    out: list[dict[str, Any]] = []
    cves = [m.group(0).upper() for m in _CVE_RE.finditer(argv)]
    for url in git_clone_urls(argv):
        if _VENDOR_REPO.search(url) and not _CVE_RE.search(url):
            continue
        out.append(
            _source(
                kind=_kind_for_url(url),
                urls=[url],
                cves=cves + [m.group(0).upper() for m in _CVE_RE.finditer(url)],
                tokens=_tokens_from_text(url),
                ts=ts,
                argv=argv,
            )
        )
    for raw in _URL_RE.findall(argv):
        url = _clean_url(raw)
        if not is_poc_fetch_url(url):
            continue
        if _VENDOR_REPO.search(url) and not _CVE_RE.search(url) and "exploit" not in url.lower():
            continue
        out.append(
            _source(
                kind=_kind_for_url(url),
                urls=[url],
                cves=cves + [m.group(0).upper() for m in _CVE_RE.finditer(url)],
                tokens=_tokens_from_text(url),
                ts=ts,
                argv=argv,
            )
        )
    for m in _SEARCHSPLOIT_P_RE.finditer(argv):
        edb = m.group(1)
        out.append(
            _source(
                kind="searchsploit",
                urls=[f"https://www.exploit-db.com/exploits/{edb}"],
                edb=edb,
                cves=cves,
                ts=ts,
                argv=argv,
            )
        )
    for path in _EDB_PATH_RE.findall(argv):
        edb = ""
        mid = _EDB_ID_RE.search(path)
        if mid:
            edb = mid.group(1)
        out.append(
            _source(
                kind="searchsploit",
                urls=[f"https://www.exploit-db.com/exploits/{edb}"] if edb else [],
                local=[path],
                edb=edb,
                cves=cves,
                ts=ts,
                argv=argv,
            )
        )
    if "searchsploit" in argv.lower() and not _SEARCHSPLOIT_P_RE.search(argv):
        q = _SEARCHSPLOIT_Q_RE.search(argv)
        tok = {q.group(1).lower()} if q else set()
        out.append(
            _source(
                kind="searchsploit",
                tokens=tok,
                cves=cves,
                ts=ts,
                argv=argv,
            )
        )
    return out


def _from_result_text(text: str, ts: str = "") -> list[dict[str, Any]]:
    head = (text or "")[:4000]
    if "/usr/share/exploitdb" not in head.lower() and "exploit title" not in head.lower():
        return []
    cves = [m.group(1).upper() for m in _EDB_HEADER_CVE.finditer(head)]
    if not cves:
        cves = [m.group(0).upper() for m in _CVE_RE.finditer(head)]
    paths = [m.group(1) for m in _EDB_PATH_LINE.finditer(head)]
    if not paths:
        paths = _EDB_PATH_RE.findall(head)
    title = ""
    tm = _EDB_HEADER_TITLE.search(head)
    if tm:
        title = tm.group(1).strip()
    if not paths and not cves:
        return []
    edb = ""
    for p in paths:
        mid = _EDB_ID_RE.search(p)
        if mid:
            edb = mid.group(1)
            break
    tokens = _tokens_from_text(title, *paths)
    return [
        _source(
            kind="searchsploit",
            urls=[f"https://www.exploit-db.com/exploits/{edb}"] if edb else [],
            local=paths,
            edb=edb,
            cves=cves,
            tokens=tokens,
            ts=ts,
            argv=title,
        )
    ]


def _console_payloads(out_dir: Path) -> list[tuple[str, str, str]]:
    """(kind, text, ts) — command argv o stdout de tool_result."""
    path = out_dir / "console.log"
    if not path.is_file():
        return []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return []
    rows: list[tuple[str, str, str]] = []
    for raw in lines:
        i = raw.find("{")
        if i < 0:
            continue
        try:
            ev = json.loads(raw[i:])
        except json.JSONDecodeError:
            continue
        if not isinstance(ev, dict):
            continue
        ts = str(ev.get("timestamp") or ev.get("ts") or ev.get("time") or "")
        part = ev.get("part") if isinstance(ev.get("part"), dict) else {}
        st = part.get("state") if isinstance(part.get("state"), dict) else {}
        inp = st.get("input") if isinstance(st.get("input"), dict) else {}
        tool = str(part.get("tool") or ev.get("tool") or "").lower()
        if ev.get("type") in {"tool_use", "tool"} or part.get("type") in {"tool", "tool-invocation"}:
            cmd = str(inp.get("command") or inp.get("cmd") or "").strip()
            url = str(inp.get("url") or "").strip()
            if cmd:
                rows.append(("cmd", cmd, ts))
            if url:
                rows.append(("url", url, ts))
            out = st.get("output")
            if isinstance(out, str) and out.strip():
                rows.append(("out", out, ts))
            elif isinstance(out, dict):
                text = str(out.get("output") or out.get("stdout") or out.get("content") or "")
                if text.strip():
                    rows.append(("out", text, ts))
            continue
        if ev.get("type") == "assistant":
            msg = ev.get("message") if isinstance(ev.get("message"), dict) else {}
            for block in msg.get("content") or []:
                if not isinstance(block, dict) or block.get("type") != "tool_use":
                    continue
                cin = block.get("input") if isinstance(block.get("input"), dict) else {}
                cmd = str(cin.get("command") or cin.get("cmd") or "").strip()
                if cmd:
                    rows.append(("cmd", cmd, ts))
                url = str(cin.get("url") or "").strip()
                if url:
                    rows.append(("url", url, ts))
            continue
        if ev.get("type") == "user":
            msg = ev.get("message") if isinstance(ev.get("message"), dict) else {}
            for block in msg.get("content") or []:
                if not isinstance(block, dict):
                    continue
                if block.get("type") != "tool_result":
                    continue
                content = block.get("content")
                if isinstance(content, str) and content.strip():
                    rows.append(("out", content, ts))
            tur = ev.get("tool_use_result")
            if isinstance(tur, dict):
                text = str(tur.get("stdout") or tur.get("output") or "")
                if text.strip():
                    rows.append(("out", text, ts))
        if tool in {"webfetch", "web_fetch", "web-fetch", "fetch"} and inp.get("url"):
            rows.append(("url", str(inp.get("url")), ts))
    return rows


def collect_sources(out_dir: Path, cmds: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for c in cmds or []:
        if not isinstance(c, dict):
            continue
        rows.extend(_from_argv(str(c.get("argv") or ""), str(c.get("ts") or "")))
    audit = out_dir / ".audit" / "commands.jsonl"
    if audit.is_file():
        try:
            for line in audit.read_text(encoding="utf-8", errors="replace").splitlines():
                try:
                    rec = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if isinstance(rec, dict):
                    rows.extend(_from_argv(str(rec.get("argv") or ""), str(rec.get("ts") or "")))
        except OSError:
            pass
    for kind, text, ts in _console_payloads(out_dir):
        if kind == "out":
            rows.extend(_from_result_text(text, ts))
        elif kind == "url":
            rows.extend(_from_argv(f"curl {text}", ts))
        else:
            rows.extend(_from_argv(text, ts))
    return _dedupe_sources(rows)


def _dedupe_sources(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    best: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    for row in rows:
        key = (
            str(row.get("kind") or "")
            + "|"
            + str(row.get("edb") or "")
            + "|"
            + ",".join(row.get("urls") or [])[:160]
            + "|"
            + ",".join(row.get("local") or [])[:160]
        )
        if key not in best:
            best[key] = dict(row)
            order.append(key)
            continue
        cur = best[key]
        for field in ("urls", "local", "cves"):
            have = list(cur.get(field) or [])
            for x in row.get(field) or []:
                if x not in have:
                    have.append(x)
            cur[field] = have
        toks = set(cur.get("tokens") or []) | set(row.get("tokens") or [])
        cur["tokens"] = sorted(toks)
        if row.get("edb") and not cur.get("edb"):
            cur["edb"] = row["edb"]
    return [best[k] for k in order]


def _finding_cves(f: dict[str, Any]) -> set[str]:
    blob = " ".join(
        str(f.get(k) or "")
        for k in ("id", "title", "summary", "explain", "proof", "reproduction", "impact")
    )
    return {m.group(0).upper() for m in _CVE_RE.finditer(blob)}


def _finding_blob(f: dict[str, Any]) -> str:
    return " ".join(
        str(f.get(k) or "")
        for k in ("id", "title", "summary", "explain", "asset", "proof")
    ).lower()


def attach_poc(finding: dict[str, Any], sources: list[dict[str, Any]]) -> dict[str, Any] | None:
    if str(finding.get("kind") or "").lower() == "flag":
        return None
    cves = _finding_cves(finding)
    blob = _finding_blob(finding)
    scored: list[tuple[int, dict[str, Any]]] = []
    for src in sources:
        score = 0
        src_cves = {str(x).upper() for x in (src.get("cves") or [])}
        if cves and src_cves & cves:
            score += 50
        edb = str(src.get("edb") or "")
        if edb and edb in blob:
            score += 40
        kind = str(src.get("kind") or "")
        if kind == "searchsploit" and edb and (cves or "cve" in blob or "rce" in blob):
            if cves and src_cves and not (src_cves & cves):
                score += 0
            elif cves and src_cves & cves:
                score += 10
            elif not src_cves:
                toks = [t for t in (src.get("tokens") or []) if len(t) >= 4]
                if any(t in blob for t in toks):
                    score += 20
        if kind == "searchsploit" and not edb:
            toks = [t for t in (src.get("tokens") or []) if len(t) >= 4]
            if any(t in blob for t in toks) and (cves or "rce" in blob):
                score += 20
        toks = [t for t in (src.get("tokens") or []) if len(t) >= 4]
        hits = sum(1 for t in toks if t in blob)
        if hits and kind in {"github", "gitlab", "exploitdb", "searchsploit"}:
            score += min(15, hits * 5)
        urls = src.get("urls") or []
        for u in urls:
            ul = str(u).lower()
            if any(c.lower() in ul for c in cves):
                score += 40
        if score < 20:
            continue
        scored.append((score, src))
    if not scored:
        return None
    scored.sort(key=lambda x: -x[0])
    pick = scored[0][1]
    urls: list[str] = []
    local: list[str] = []
    cve_list: list[str] = []
    edb = ""
    kind = str(pick.get("kind") or "url")
    for _, src in scored[:6]:
        if str(src.get("kind") or "") not in {kind, "searchsploit", "exploitdb", "github", "gitlab"}:
            if kind != str(src.get("kind") or ""):
                continue
        for u in src.get("urls") or []:
            if u not in urls:
                urls.append(u)
        for p in src.get("local") or []:
            if p not in local:
                local.append(p)
        for c in src.get("cves") or []:
            if c not in cve_list:
                cve_list.append(c)
        if src.get("edb") and not edb:
            edb = str(src["edb"])
    label = _label(kind, edb, urls)
    return {
        "origin": kind,
        "label": label,
        "urls": urls[:8],
        "local": local[:6],
        "edb": edb,
        "cves": cve_list[:6],
    }


def _label(kind: str, edb: str, urls: list[str]) -> str:
    if kind == "searchsploit":
        return f"searchsploit / Exploit-DB {edb}".strip() if edb else "searchsploit / Exploit-DB (copia local)"
    if kind == "exploitdb":
        return f"Exploit-DB {edb}".strip() if edb else "Exploit-DB"
    if kind == "github":
        host = ""
        if urls:
            p = urlparse(urls[0])
            parts = [x for x in (p.path or "").split("/") if x]
            if p.hostname and "githubusercontent" in (p.hostname or "") and len(parts) >= 2:
                host = f"{parts[0]}/{parts[1]}"
            elif len(parts) >= 2:
                host = f"{parts[0]}/{parts[1]}"
        return f"GitHub {host}".strip() if host else "GitHub"
    if kind == "gitlab":
        return "GitLab"
    if kind == "advisory":
        return "Advisory (NVD / GitHub Security)"
    return kind or "URL"


def enrich_findings(
    out_dir: Path,
    findings: list[dict[str, Any]],
    *,
    cmds: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    sources = collect_sources(out_dir, cmds)
    out: list[dict[str, Any]] = []
    for raw in findings:
        it = dict(raw)
        poc = it.get("poc") if isinstance(it.get("poc"), dict) else None
        got = attach_poc(it, sources)
        if got:
            if not poc or (not poc.get("urls") and not poc.get("local")):
                it["poc"] = got
            else:
                it["poc"] = poc
        elif str(it.get("kind") or "").lower() == "cve" and not poc:
            it["poc"] = {
                "origin": "inline",
                "label": "Explotación in-line (sin PoC en red ni searchsploit)",
                "urls": [],
                "local": [],
                "edb": "",
                "cves": sorted(_finding_cves(it)),
            }
        out.append(it)
    return out


def persist_poc(out_dir: Path, findings: list[dict[str, Any]]) -> int:
    n = 0
    root = out_dir / "findings"
    if not root.is_dir():
        return 0
    for f in findings:
        poc = f.get("poc")
        fid = str(f.get("id") or "")
        if not isinstance(poc, dict) or not fid:
            continue
        path = root / f"{fid}.json"
        if not path.is_file():
            hits = sorted(root.rglob(f"{fid}.json"))
            path = hits[0] if hits else path
        if not path.is_file():
            continue
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if not isinstance(data, dict):
            continue
        if data.get("poc") == poc:
            continue
        data["poc"] = poc
        try:
            path.write_text(json.dumps(data, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
            n += 1
        except OSError:
            continue
    return n
