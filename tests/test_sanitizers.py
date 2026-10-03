"""Tests for sanitizer builds and report parsing."""
import shutil
import subprocess

import pytest

from aera.sanitizers import (
    SanitizerError,
    build_with_sanitizers,
    find_compiler,
    parse_sanitizer_report,
)

HAS_COMPILER = find_compiler() is not None

VULN_C = """
#include <string.h>
int main(int argc, char **argv) {
    char buf[16];
    strcpy(buf, argv[1]);   // heap/stack overflow with long input
    return 0;
}
"""


def test_parse_asan_heap_overflow():
    err = ("==1==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x123\n"
           "WRITE of size 100 at 0x123 thread T0\n")
    out = parse_sanitizer_report(err)
    assert out == {"sanitizer": "ASan", "bug_class": "heap-buffer-overflow"}


def test_parse_ubsan():
    err = "main.c:5:12: runtime error: signed integer overflow: 1 + 2147483647\n"
    out = parse_sanitizer_report(err)
    assert out["sanitizer"] == "UBSan"


def test_parse_none_when_clean():
    assert parse_sanitizer_report("all good\n") is None


@pytest.mark.skipif(not HAS_COMPILER, reason="no C compiler available")
def test_build_and_run_with_asan(tmp_path):
    src = tmp_path / "vuln.c"
    src.write_text(VULN_C)
    out = tmp_path / "vuln_asan"
    built = build_with_sanitizers([src], out)
    assert built.exists()
    proc = subprocess.run(
        [str(built), "A" * 100], capture_output=True, text=True, timeout=30,
        env={"ASAN_OPTIONS": "detect_leaks=0"},
    )
    assert proc.returncode != 0
    parsed = parse_sanitizer_report(proc.stderr)
    assert parsed is not None
    assert parsed["sanitizer"] == "ASan"
    assert "buffer-overflow" in parsed["bug_class"]


@pytest.mark.skipif(not HAS_COMPILER, reason="no C compiler available")
def test_build_failure_raises(tmp_path):
    src = tmp_path / "bad.c"
    src.write_text("this is not C {{{")
    with pytest.raises(SanitizerError, match="compilation failed"):
        build_with_sanitizers([src], tmp_path / "out")


def test_no_compiler_raises(monkeypatch):
    import aera.sanitizers as san_mod
    monkeypatch.setattr(san_mod.shutil, "which", lambda c: None)
    with pytest.raises(SanitizerError, match="No C compiler"):
        build_with_sanitizers(["x.c"], "out")
