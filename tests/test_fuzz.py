"""Tests for the mutation fuzzer. Uses LocalRunner (tests/dev only)."""
import random

from aera.fuzz import (
    LocalRunner,
    classify_result,
    mutate,
    run_campaign,
    seeds_for_findings,
)

# A deliberately buggy target: crashes on any high byte.
HARNESS = """
import sys
data = sys.stdin.buffer.read()
if any(b > 127 for b in data):
    raise IndexError("boom on high byte")
print("ok")
"""


def _write_harness(tmp_path):
    p = tmp_path / "harness.py"
    p.write_text(HARNESS)
    return p


def test_mutate_changes_input():
    rng = random.Random(42)
    out = mutate(b"hello world", rng)
    assert isinstance(out, bytes)
    assert out != b"hello world"


def test_mutate_empty_seed():
    assert mutate(b"", random.Random(1))


def test_classify_crash_on_signal():
    info = classify_result(-11, "", "", b"x")
    assert info["crash"] and info["signal"] == 11


def test_classify_crash_on_traceback():
    info = classify_result(1, "", "Traceback (most recent call last):\nIndexError", b"x")
    assert info["crash"] and info["keyword"] == "traceback"


def test_classify_plain_nonzero_exit_is_not_crash():
    info = classify_result(2, "", "usage: prog [file]", b"x")
    assert not info["crash"]


def test_classify_timeout_is_not_crash():
    info = classify_result(124, "", "", b"x")
    assert not info["crash"] and info["timed_out"]


def test_fuzzer_finds_real_crash(tmp_path):
    import sys
    harness = _write_harness(tmp_path)
    runner = LocalRunner([sys.executable, str(harness)], timeout_s=5)
    crashes = run_campaign(runner.run_once, [b"hello"], 300, rng_seed=7)
    assert crashes, "fuzzer failed to find the planted crash"
    assert all(c["crash"] for c in crashes)
    assert any(c["keyword"] == "traceback" for c in crashes)


def test_seeds_from_static_findings():
    findings = [{"rule_id": "C-STRCPY"}, {"rule_id": "PY-EVAL"}]
    seeds = seeds_for_findings(findings)
    assert any(len(s) >= 2000 for s in seeds)       # overflow seed
    assert any(b"__import__" in s for s in seeds)    # eval seed
    assert len(seeds) == len(set(seeds))            # deduped
