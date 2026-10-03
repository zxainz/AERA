"""Tests for crash minimization and exploitability severity."""
from aera.minimize import classify_severity, minimize


def _run_once_predicate(data: bytes):
    return {"crash": b"BAD" in data}


def test_minimize_shrinks_to_core():
    result = minimize(_run_once_predicate, b"xxBADxx")
    assert result == b"BAD"


def test_minimize_keeps_minimal():
    result = minimize(_run_once_predicate, b"BAD")
    assert result == b"BAD"


def test_minimize_requires_crashing_input():
    try:
        minimize(_run_once_predicate, b"nothing")
    except ValueError as exc:
        assert "crashes" in str(exc)
    else:
        raise AssertionError("should have raised")


def test_severity_critical_heap_write():
    crash = {"signal": 11, "keyword": "heap-buffer-overflow",
             "stderr": "ERROR: AddressSanitizer: heap-buffer-overflow\nWRITE of size 8"}
    out = classify_severity(crash)
    assert out["severity"] == "CRITICAL"


def test_severity_high_segv_read():
    crash = {"signal": 11, "keyword": "heap-buffer-overflow",
             "stderr": "ERROR: AddressSanitizer: heap-buffer-overflow\nREAD of size 8"}
    assert classify_severity(crash)["severity"] == "HIGH"


def test_severity_high_stack_smashing():
    crash = {"signal": 6, "keyword": None,
             "stderr": "*** stack smashing detected ***: terminated"}
    assert classify_severity(crash)["severity"] == "HIGH"


def test_severity_low_python_exception():
    crash = {"signal": None, "keyword": "IndexError",
             "stderr": "Traceback (most recent call last):\nIndexError"}
    out = classify_severity(crash)
    assert out["severity"] == "LOW"


def test_severity_medium_abort():
    crash = {"signal": 6, "keyword": None, "stderr": "Aborted"}
    assert classify_severity(crash)["severity"] == "MEDIUM"
