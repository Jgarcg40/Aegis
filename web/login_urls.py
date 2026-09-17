"""Recompone URLs de OAuth que el TTY parte en varias líneas."""
from __future__ import annotations

import re

_ANSI = re.compile(r"\x1b(?:\[[0-9;?]*[A-Za-z]|\][^\x07\x1b]*(?:\x07|\x1b\\))")
_OSC8 = re.compile(r"\x1b\]8;;([^\x07\x1b]+)")
_HTTP = re.compile(r"https?://[^\s\"'<>]+")
_CONT = re.compile(r"(https?://[^\s\"'<>]+)\n[ \t]*([^\s\"'<>]+)")
_CONT_OK = re.compile(r"^[&/?#%=+\w.\-~]")


def _strip_ansi(text: str) -> str:
    return _ANSI.sub("", text)


def _unwrap(text: str) -> str:
    prev = None
    cur = text.replace("\r\n", "\n").replace("\r", "\n")
    while cur != prev:
        prev = cur

        def join(m: re.Match[str]) -> str:
            if _CONT_OK.match(m.group(2)):
                return m.group(1) + m.group(2)
            return m.group(0)

        cur = _CONT.sub(join, cur)
    return cur


def _dedupe(urls: list[str]) -> list[str]:
    out: list[str] = []
    for u in sorted({u for u in urls if len(u) >= 16}, key=len, reverse=True):
        if any(prev.startswith(u) for prev in out):
            continue
        out.append(u)
    return out


def extract_login_urls(text: str) -> list[str]:
    raw = text or ""
    found = [m.group(1).strip() for m in _OSC8.finditer(raw) if m.group(1).strip()]
    clean = _unwrap(_strip_ansi(raw))
    for m in _HTTP.finditer(clean):
        found.append(re.sub(r"[)\].,;]+$", "", m.group(0)))
    return _dedupe(found)
