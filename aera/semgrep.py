"""Semgrep integration: real dataflow-aware static analysis.

AERA's built-in regex rules are a triage aid. When the `semgrep` binary is
available, it becomes the primary static engine (thousands of community
rules, source→sink tracking); the regex rules remain as fallback.
Install: pip install semgrep
"""
from __future__ import annotations

import json
import shutil
import subprocess

_SEVERITY_MAP = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW"}


class SemgrepError(Exception):
    """Raised when semgrep cannot run or its output is unusable."""


def semgrep_available() -> bool:
    return shutil.which("semgrep") is not None


def run_semgrep(root: str, *, config: str = "auto", timeout_s: int = 300) -> dict:
    """Run semgrep and return its parsed JSON output.

    Note: semgrep exits 1 when findings are present — that is not an error.
    """
    if not semgrep_available():
        raise SemgrepError(
            "semgrep binary not found. Install with: pip install semgrep"
        )
    try:
        proc = subprocess.run(
            ["semgrep", "--config", config, "--json", "--quiet", str(root)],
            capture_output=True, text=True, timeout=timeout_s,
        )
    except subprocess.TimeoutExpired as exc:
        raise SemgrepError(f"semgrep timed out: {exc}") from exc
    if proc.returncode not in (0, 1):
        raise SemgrepError(f"semgrep failed: {proc.stderr[:500]}")
    try:
        return json.loads(proc.stdout or "{}")
    except json.JSONDecodeError as exc:
        raise SemgrepError(f"semgrep output was not JSON: {exc}") from exc


def semgrep_to_findings(data: dict) -> list[dict]:
    """Convert semgrep JSON to AERA's finding schema."""
    findings = []
    for result in data.get("results", []):
        extra = result.get("extra", {}) or {}
        check_id = result.get("check_id", "unknown")
        short_id = check_id.split(".")[-1].upper().replace("-", "_").replace(".", "_")
        start = result.get("start", {}) or {}
        findings.append({
            "rule_id": f"SEMGREP_{short_id}",
            "title": (extra.get("message") or check_id).split("\n")[0][:120],
            "severity": _SEVERITY_MAP.get(extra.get("severity"), "MEDIUM"),
            "fix": "",
            "file": result.get("path", ""),
            "line": start.get("line", 0),
            "snippet": (extra.get("lines") or "").strip()[:200],
        })
    return findings
