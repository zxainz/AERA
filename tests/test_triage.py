"""Tests for crash triage: signatures, dedup, reproducibility."""
from aera.triage import crash_signature, dedupe, reproduce


def _crash(stderr, signal=11, keyword="traceback"):
    return {"input": b"x", "exit_code": -signal, "signal": signal,
            "keyword": keyword, "stderr": stderr, "stdout": ""}


def test_signature_ignores_addresses():
    a = _crash("Traceback\n  File \"x.py\", line 12\n  at 0x7f8b2c1d\nIndexError")
    b = _crash("Traceback\n  File \"x.py\", line 99\n  at 0xdeadbeef\nIndexError")
    assert crash_signature(a) == crash_signature(b)


def test_signature_distinguishes_bugs():
    a = _crash("Traceback\nIndexError: boom")
    b = _crash("Traceback\nKeyError: missing")
    assert crash_signature(a) != crash_signature(b)


def test_dedupe_groups_identical():
    crashes = [_crash("Traceback\nIndexError"), _crash("Traceback\nIndexError"),
               _crash("Traceback\nKeyError")]
    unique = dedupe(crashes)
    assert len(unique) == 2
    counts = sorted(u["count"] for u in unique)
    assert counts == [1, 2]


def test_reproduce_true_when_always_crashes():
    run_once = lambda data: {"crash": True}
    assert reproduce(run_once, b"x", times=3)


def test_reproduce_false_when_flaky():
    calls = []
    def flaky(data):
        calls.append(1)
        return {"crash": len(calls) < 3}
    assert not reproduce(flaky, b"x", times=3)
