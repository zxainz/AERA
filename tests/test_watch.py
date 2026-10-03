"""Tests for continuous mode: snapshots, state, and diffs."""
from aera.watch import diff_findings, load_state, save_state, snapshot_target
from aera.codebase import CodebaseTarget


def _finding(rule_id, path, line, severity="HIGH"):
    return {"rule_id": rule_id, "file": path, "line": line,
            "severity": severity, "title": "t", "snippet": "s", "fix": ""}


def test_diff_detects_new_and_fixed():
    old = [_finding("PY-EVAL", "a.py", 3), _finding("C-STRCPY", "v.c", 7)]
    new = [_finding("PY-EVAL", "a.py", 3), _finding("PY-EXEC", "b.py", 1)]
    diff = diff_findings(old, new)
    assert [(f["rule_id"], f["file"]) for f in diff["new"]] == [("PY-EXEC", "b.py")]
    assert [(f["rule_id"], f["file"]) for f in diff["fixed"]] == [("C-STRCPY", "v.c")]


def test_diff_empty_on_identical():
    old = [_finding("PY-EVAL", "a.py", 3)]
    diff = diff_findings(old, list(old))
    assert diff == {"new": [], "fixed": []}


def test_state_roundtrip(tmp_path):
    state_file = tmp_path / "state.json"
    assert load_state(state_file) == {"findings": [], "snapshot": {}}
    save_state(state_file, {"findings": [_finding("X", "f", 1)], "snapshot": {"a": "b"}})
    loaded = load_state(state_file)
    assert loaded["findings"][0]["rule_id"] == "X"
    assert loaded["snapshot"] == {"a": "b"}


def test_snapshot_changes_with_content(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    target = CodebaseTarget(tmp_path)
    snap1 = snapshot_target(target)
    (tmp_path / "a.py").write_text("x = 2\n")
    snap2 = snapshot_target(CodebaseTarget(tmp_path))
    assert snap1 != snap2
    assert set(snap1) == {"a.py"}
