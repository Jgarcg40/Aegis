"""Markdown → PDF con Chromium headless en un contenedor efímero del runner."""
from __future__ import annotations

import html
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path


def _inline(s: str) -> str:
    s = html.escape(s, quote=False)
    s = re.sub(r"`([^`]+)`", lambda m: f"<code>{m.group(1)}</code>", s)
    s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
    return s


def _cells(s: str) -> list[str]:
    s = s.strip()
    if s.startswith("|"):
        s = s[1:]
    if s.endswith("|"):
        s = s[:-1]
    return [c.strip() for c in s.split("|")]


def _md_to_html(md: str) -> str:
    """Subconjunto de markdown que usan los informes de Aegis (mismo que la UI)."""
    lines = md.split("\n")
    out: list[str] = []
    in_fence = False
    list_tag = ""

    def close_list() -> None:
        nonlocal list_tag
        if list_tag:
            out.append(f"</{list_tag}>")
            list_tag = ""

    i = 0
    while i < len(lines):
        raw = lines[i]
        if raw.startswith("```"):
            if in_fence:
                out.append("</code></pre>")
                in_fence = False
            else:
                close_list()
                out.append("<pre><code>")
                in_fence = True
            i += 1
            continue
        if in_fence:
            out.append(html.escape(raw) + "\n")
            i += 1
            continue
        if raw.strip() == "":
            i += 1
            continue
        if re.match(r"^\s*(-{3,}|\*{3,}|_{3,})\s*$", raw):
            close_list()
            out.append("<hr>")
            i += 1
            continue
        if "|" in raw and i + 1 < len(lines) and "-" in lines[i + 1] and re.match(r"^\s*\|?\s*:?-{2,}", lines[i + 1]):
            close_list()
            head = _cells(raw)
            t = "<table><thead><tr>" + "".join(f"<th>{_inline(h)}</th>" for h in head) + "</tr></thead><tbody>"
            i += 2
            while i < len(lines) and "|" in lines[i] and lines[i].strip() != "":
                t += "<tr>" + "".join(f"<td>{_inline(c)}</td>" for c in _cells(lines[i])) + "</tr>"
                i += 1
            out.append(t + "</tbody></table>")
            continue
        h = re.match(r"^(#{1,6})\s+(.*)$", raw)
        if h:
            close_list()
            n = len(h.group(1))
            out.append(f"<h{n}>{_inline(h.group(2))}</h{n}>")
            i += 1
            continue
        bq = re.match(r"^\s*>\s?(.*)$", raw)
        if bq:
            close_list()
            out.append(f"<blockquote>{_inline(bq.group(1))}</blockquote>")
            i += 1
            continue
        ol = re.match(r"^\s*\d+[.)]\s+(.*)$", raw)
        if ol:
            if list_tag != "ol":
                close_list()
                out.append("<ol>")
                list_tag = "ol"
            out.append(f"<li>{_inline(ol.group(1))}</li>")
            i += 1
            continue
        ul = re.match(r"^\s*[-*]\s+(.*)$", raw)
        if ul:
            if list_tag != "ul":
                close_list()
                out.append("<ul>")
                list_tag = "ul"
            out.append(f"<li>{_inline(ul.group(1))}</li>")
            i += 1
            continue
        close_list()
        out.append(f"<p>{_inline(raw)}</p>")
        i += 1
    if in_fence:
        out.append("</code></pre>")
    close_list()
    return "".join(out)


_PDF_CSS = (
    "*{box-sizing:border-box}"
    "body{margin:0;background:#fff;color:#20242a;font:14px/1.65 'Source Sans 3',system-ui,Arial,sans-serif}"
    ".sheet{max-width:800px;margin:0 auto;padding:8px 4px 40px}"
    ".bar{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:20px;padding-bottom:10px;border-bottom:2px solid #b8742e}"
    ".bar .who{font:700 18px/1.2 'Archivo Narrow','Arial Narrow',Arial,sans-serif;letter-spacing:.14em;text-transform:uppercase;color:#b8742e}"
    ".bar .rid{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;color:#6a6f77}"
    "h1,h2,h3,h4{font-family:'Archivo Narrow','Arial Narrow',Arial,sans-serif;line-height:1.25;margin:20px 0 9px}"
    "h1{font-size:23px}h2{font-size:18px;border-bottom:1px solid #d8d2c4;padding-bottom:5px}h3{font-size:15px}"
    "h4{font-size:12px;text-transform:uppercase;letter-spacing:.08em;color:#6a6f77}"
    "p{margin:9px 0}ul,ol{margin:9px 0;padding-left:22px}li{margin:4px 0}"
    "code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:.86em;background:#efeadd;color:#7a3d12;border:1px solid #ddd6c7;border-radius:4px;padding:.5px 5px;overflow-wrap:anywhere;word-break:break-word}"
    "pre{background:#1b1e17;color:#e9e6dc;border-radius:6px;padding:12px 14px;overflow:auto;font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;line-height:1.5}"
    "pre code{background:none;border:0;color:inherit;padding:0}"
    "table{border-collapse:collapse;width:100%;margin:12px 0;font-size:13px}"
    "th,td{border:1px solid #d8d2c4;padding:6px 10px;text-align:left;vertical-align:top}th{background:#efeadd}"
    "blockquote{margin:12px 0;padding:8px 14px;border-left:3px solid #d8d2c4;background:#efeadd;color:#4a4f57}"
    "hr{border:0;border-top:1px solid #d8d2c4;margin:20px 0}"
    "@page{margin:16mm 14mm}"
)


def report_print_html(run_id: str, md: str) -> str:
    body = _md_to_html(md)
    return (
        "<!doctype html><html lang=\"es\"><head><meta charset=\"utf-8\">"
        f"<title>Aegis · Informe {html.escape(run_id)}</title><style>{_PDF_CSS}</style></head>"
        "<body><div class=\"sheet\"><div class=\"bar\">"
        f"<span class=\"who\">Aegis</span><span class=\"rid\">{html.escape(run_id)}</span></div>"
        f"<main>{body}</main></div></body></html>"
    )


def render_report_pdf(run_id: str, md: str, image: str = "aegis-runner:latest") -> bytes:
    """Imprime el informe a PDF con el Chromium de la imagen del runner. Devuelve los bytes."""
    if not (md or "").strip():
        raise ValueError("informe vacío")
    tmp = Path(tempfile.mkdtemp(prefix="aegis-pdf-"))
    try:
        (tmp / "in.html").write_text(report_print_html(run_id, md), encoding="utf-8")
        cmd = [
            "docker", "run", "--rm", "--network", "none",
            "--user", f"{os.getuid()}:{os.getgid()}",
            "-e", "HOME=/w", "-v", f"{tmp}:/w", "--entrypoint", "chromium", image,
            "--headless=new", "--no-sandbox", "--disable-gpu", "--disable-dev-shm-usage",
            "--no-pdf-header-footer", "--virtual-time-budget=6000",
            "--run-all-compositor-stages-before-draw",
            "--print-to-pdf=/w/out.pdf", "/w/in.html",
        ]
        proc = subprocess.run(cmd, capture_output=True, timeout=120)
        pdf = tmp / "out.pdf"
        if pdf.is_file() and pdf.stat().st_size > 0:
            return pdf.read_bytes()
        err = (proc.stderr or b"").decode("utf-8", "replace").strip()
        raise RuntimeError(err[-400:] or "chromium no generó el PDF")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
