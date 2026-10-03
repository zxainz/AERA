"""Sanitizer builds: compile C/C++ targets with ASan+UBSan.

Most memory bugs don't crash visibly. Building with
-fsanitize=address,undefined turns silent corruption into loud, classified
reports that AERA's triage already knows how to parse.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

_ASAN_RE = re.compile(r"ERROR: AddressSanitizer:\s*([a-z][a-z-]*)")
_UBSAN_RE = re.compile(r"runtime error:\s*([a-z][a-z- ]+?)(?::|\n|$)")


class SanitizerError(Exception):
    """Raised when a sanitizer build cannot be produced."""


def find_compiler(prefer: str | None = None) -> str | None:
    candidates = [prefer] if prefer else []
    candidates += ["clang", "gcc"]
    for candidate in candidates:
        if candidate and shutil.which(candidate):
            return candidate
    return None


def build_with_sanitizers(sources: list[str | Path], output: str | Path, *,
                          compiler: str | None = None,
                          extra_cflags: tuple[str, ...] = ()) -> Path:
    """Compile with -fsanitize=address,undefined -g -O1. Returns output path."""
    cc = find_compiler(compiler)
    if not cc:
        raise SanitizerError("No C compiler found (tried clang, gcc).")
    out = Path(output)
    # -U_FORTIFY_SOURCE: glibc's fortified functions (e.g. __strcpy_chk)
    # would otherwise abort before ASan sees the bug. For a *diagnostic*
    # build this is correct; never ship it as a hardening choice.
    cmd = [
        cc, "-fsanitize=address,undefined", "-g", "-O1",
        "-fno-omit-frame-pointer", "-U_FORTIFY_SOURCE",
        *extra_cflags,
        *[str(s) for s in sources],
        "-o", str(out),
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired as exc:
        raise SanitizerError(f"compilation timed out: {exc}") from exc
    if proc.returncode != 0:
        raise SanitizerError(f"compilation failed:\n{proc.stderr[:2000]}")
    return out


def parse_sanitizer_report(stderr: str) -> dict | None:
    """Extract {sanitizer, bug_class} from sanitizer output, else None."""
    match = _ASAN_RE.search(stderr)
    if match:
        return {"sanitizer": "ASan", "bug_class": match.group(1)}
    match = _UBSAN_RE.search(stderr)
    if match:
        return {"sanitizer": "UBSan", "bug_class": match.group(1).strip()}
    if "stack smashing detected" in stderr:
        return {"sanitizer": "SSP", "bug_class": "stack-buffer-overflow"}
    if "buffer overflow detected" in stderr:
        return {"sanitizer": "FORTIFY", "bug_class": "stack-buffer-overflow"}
    return None
