"""Crash minimization (delta debugging) + exploitability triage.

Minimization shrinks a crashing input to the smallest input that still
crashes — turning a 4KB blob into a readable repro.

Exploitability triage goes one step past crash/no-crash: not all crashes
are equal. A SIGSEGV on a heap *write* is far more interesting than an
uncaught Python IndexError. The heuristics below are documented
approximations, not proofs.
"""
from __future__ import annotations


def minimize(run_once, data: bytes, *, max_iterations: int = 2000) -> bytes:
    """Delta-debugging: remove chunks while the input still crashes."""
    if not run_once(data).get("crash"):
        raise ValueError("minimize() requires an input that crashes")
    current = data
    n = 2
    iterations = 0
    while len(current) >= 2 and iterations < max_iterations:
        iterations += 1
        chunk = max(1, len(current) // n)
        reduced = False
        for i in range(0, len(current), chunk):
            candidate = current[:i] + current[i + chunk:]
            if candidate and run_once(candidate).get("crash"):
                current = candidate
                reduced = True
                break
        if not reduced:
            if n >= len(current):
                break
            n = min(len(current), n * 2)
    return current


def classify_severity(crash: dict) -> dict:
    """Heuristic severity for a crash: {severity, reason}."""
    stderr = (crash.get("stderr") or "").lower()
    signal = crash.get("signal")
    keyword = crash.get("keyword") or ""

    if signal == 11:  # SIGSEGV
        if "write" in stderr and (
            "heap-buffer-overflow" in keyword or "addresssanitizer" in stderr
        ):
            return {
                "severity": "CRITICAL",
                "reason": "SIGSEGV on heap write — possible controlled write primitive",
            }
        return {"severity": "HIGH", "reason": "SIGSEGV (segmentation fault)"}
    if signal == 6:  # SIGABRT
        if "stack smashing" in stderr:
            return {
                "severity": "HIGH",
                "reason": "stack protector abort — stack buffer overflow confirmed",
            }
        return {"severity": "MEDIUM", "reason": "SIGABRT (abort)"}
    if keyword in ("heap-buffer-overflow", "stack-buffer-overflow",
                   "heap-use-after-free", "use-after-free"):
        return {"severity": "HIGH", "reason": f"sanitizer bug class: {keyword}"}
    if signal is None and "traceback" in stderr:
        return {"severity": "LOW",
                "reason": "uncaught Python exception — likely denial of service at worst"}
    if signal is not None:
        return {"severity": "MEDIUM", "reason": f"terminating signal {signal}"}
    if keyword:
        return {"severity": "MEDIUM", "reason": f"crash keyword: {keyword}"}
    return {"severity": "LOW",
            "reason": "uncaught exception — likely denial of service at worst"}
