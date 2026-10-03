"""Crash triage: reproducibility checks and signature-based dedup.

A fuzzer that reports 500 crashes is useless if they're 500 copies of one
bug. Triage answers: does it reproduce, and how many DISTINCT bugs are these?
"""
from __future__ import annotations

import hashlib
import re

from .minimize import classify_severity

_ADDR_RE = re.compile(r"0x[0-9a-fA-F]+")
_LINE_RE = re.compile(r"line \d+", re.IGNORECASE)


def crash_signature(crash: dict) -> str:
    """Stable signature: signal + keyword + normalized stderr head."""
    lines = [line for line in crash.get("stderr", "").splitlines() if line.strip()][:3]
    normalized = _LINE_RE.sub("line ?", _ADDR_RE.sub("0x?", "\n".join(lines)))
    raw = f"{crash.get('signal')}|{crash.get('keyword')}|{normalized}"
    return hashlib.sha1(raw.encode("utf-8", errors="replace")).hexdigest()[:16]


def reproduce(run_once, data: bytes, *, times: int = 3) -> bool:
    """Re-run a crashing input; True only if it crashes every time."""
    for _ in range(times):
        info = run_once(data)
        if not info.get("crash"):
            return False
    return True


def dedupe(crashes: list[dict]) -> list[dict]:
    """Group crashes by signature. Returns unique bugs with counts.

    Each group carries an exploitability severity from classify_severity().
    """
    groups: dict[str, dict] = {}
    for crash in crashes:
        sig = crash_signature(crash)
        if sig not in groups:
            sev = classify_severity(crash)
            groups[sig] = {
                "signature": sig,
                "count": 0,
                "example": crash,
                "signal": crash.get("signal"),
                "keyword": crash.get("keyword"),
                "severity": sev["severity"],
                "severity_reason": sev["reason"],
                "stderr_head": crash.get("stderr", "")[:500],
            }
        groups[sig]["count"] += 1
    return sorted(groups.values(), key=lambda g: -g["count"])
