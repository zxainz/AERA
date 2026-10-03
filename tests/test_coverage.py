"""Tests for coverage-guided fuzzing (needs Python 3.12+).

The target uses NESTED branches on purpose: with flat branches, even edge
coverage cannot prefer combinations (a real, known fuzzing subtlety).
Nested structure — like real parsers — is where coverage guidance wins.
"""
import sys

import pytest

from aera.coverage import CoverageError, run_coverage_campaign

pytestmark = pytest.mark.skipif(
    sys.version_info < (3, 12), reason="sys.monitoring needs Python 3.12+"
)


def nested_target(data: bytes):
    """Three nested range checks; the deep crash needs all three."""
    if len(data) >= 3:
        if data[0] > 200:
            if data[1] < 50:
                if data[2] == 0x41:
                    raise RuntimeError("deep crash")


def test_coverage_guidance_finds_deep_crash():
    result = run_coverage_campaign(
        nested_target, [b"\x00\x00\x00"], 15000,
        rng_seed=0, filenames=[__file__],
    )
    assert result["crashes"], "coverage-guided run missed the deep crash"
    assert result["crashes"][0]["keyword"] == "RuntimeError"
    assert result["corpus_size"] > 1, "feedback loop never grew the corpus"


def test_tracker_records_branch_edges():
    """The mechanism itself, deterministically: taken vs not-taken
    branches must produce different edges."""
    from aera.coverage import CoverageTracker

    def f(data: bytes):
        if data:
            x = 1
        else:
            x = 2
        return x

    tracker = CoverageTracker(filenames=[__file__])
    try:
        tracker.start_run(); f(b"x"); taken = tracker.stop_run()
        tracker.start_run(); f(b""); skipped = tracker.stop_run()
    finally:
        tracker.close()
    assert taken != skipped
    assert taken - skipped, "no edge unique to the taken branch"
    assert skipped - taken, "no edge unique to the skipped branch"


def test_uncaught_exception_counts_as_crash():
    def boom(data: bytes):
        raise ValueError("x")

    result = run_coverage_campaign(boom, [b"a"], 10, filenames=[__file__])
    assert result["crashes"]
    assert result["crashes"][0]["keyword"] == "ValueError"


def test_coverage_needs_py312(monkeypatch):
    import aera.coverage as cov_mod
    monkeypatch.delattr("sys.monitoring", raising=False)
    with pytest.raises(CoverageError, match="3.12"):
        cov_mod.CoverageTracker()
