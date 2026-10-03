"""Coverage-guided input selection for in-process Python targets.

Blind mutation wastes most runs on inputs that exercise the same code.
Here, each input runs under sys.monitoring (Python 3.12+); inputs that
execute previously-unseen lines are kept and mutated further. That feedback
loop is what lets the fuzzer reach progressively deeper code.

Scope: pure-Python function targets only, run in-process. Anything that can
segfault the interpreter (C extensions) belongs in the sandboxed runner.
"""
from __future__ import annotations

import sys

from .fuzz import mutate


class CoverageError(Exception):
    """Raised when coverage guidance cannot be used."""


def _monitoring():
    mon = getattr(sys, "monitoring", None)
    if mon is None:
        raise CoverageError("Coverage-guided fuzzing needs Python 3.12+ (sys.monitoring).")
    return mon


class CoverageTracker:
    """Records executed edges (prev_line -> line) per run.

    Edge coverage, not line coverage: taking a branch is a different edge
    than skipping it, so the fuzzer can tell "condition A true" apart from
    "A and B true" — which line coverage cannot.
    """

    def __init__(self, filenames: list[str] | None = None) -> None:
        mon = _monitoring()
        self._mon = mon
        # Tool ids are 0-5; 0,1,2,5 are reserved. Try 3, then 4.
        self.tool_id = None
        for candidate in (3, 4):
            try:
                mon.use_tool_id(candidate, f"aera-cov-{candidate}")
            except ValueError:
                continue
            self.tool_id = candidate
            break
        if self.tool_id is None:
            raise CoverageError("No free sys.monitoring tool id (tried 3, 4).")
        self.filenames = set(filenames or [])
        self.current: set[tuple[str, str, int, int]] = set()
        self._prev: tuple[str, str, int, bool] | None = None

    def _handler(self, code, line_number):  # noqa: ANN001, ANN202
        here_in_scope = not self.filenames or code.co_filename in self.filenames
        if self._prev is not None and self._prev[3]:
            # Anchor at in-scope code: record the edge even if the next
            # event is out of scope (e.g. "branch not taken, left function").
            prev = self._prev
            self.current.add((prev[0], prev[1], prev[2], line_number))
        self._prev = (code.co_filename, code.co_name, line_number, here_in_scope)

    def start_run(self) -> None:
        self.current = set()
        self._prev = None
        self._mon.register_callback(
            self.tool_id, self._mon.events.LINE, self._handler
        )
        self._mon.set_events(self.tool_id, self._mon.events.LINE)

    def stop_run(self) -> set[tuple[str, str, int, int]]:
        self._mon.set_events(self.tool_id, 0)
        return set(self.current)

    def close(self) -> None:
        try:
            self._mon.set_events(self.tool_id, 0)
        finally:
            self._mon.free_tool_id(self.tool_id)


def run_coverage_campaign(target_fn, seeds: list[bytes], iterations: int,
                          *, rng_seed: int = 0,
                          filenames: list[str] | None = None) -> dict:
    """Fuzz a Python callable with coverage feedback.

    target_fn(data: bytes) -> None; uncaught exceptions count as crashes.
    Returns {"crashes", "lines_covered", "corpus_size"}.
    """
    import random

    rng = random.Random(rng_seed)
    tracker = CoverageTracker(filenames)
    corpus = list(seeds) or [b"seed"]
    covered: set[tuple[str, str, int, int]] = set()
    crashes: list[dict] = []
    try:
        for i in range(iterations):
            data = mutate(corpus[i % len(corpus)], rng)
            tracker.start_run()
            try:
                target_fn(data)
                crashed, keyword, err = False, None, ""
            except Exception as exc:  # noqa: BLE001 - any escape is a crash
                crashed, keyword = True, type(exc).__name__
                err = f"{type(exc).__name__}: {exc}"
            new_lines = tracker.stop_run()
            if crashed:
                crashes.append({
                    "input": data, "crash": True, "keyword": keyword,
                    "stderr": err, "stdout": "", "signal": None,
                    "exit_code": 1, "timed_out": False,
                })
            elif new_lines - covered:
                covered |= new_lines
                if len(corpus) < 512:
                    corpus.append(data)
    finally:
        tracker.close()
    return {
        "crashes": crashes,
        "lines_covered": len(covered),
        "corpus_size": len(corpus),
    }
