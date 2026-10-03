"""Tests for semgrep integration (binary mocked; engine fallback real)."""
import pytest

import aera.semgrep as semgrep_mod
from aera.codebase import CodebaseTarget
from aera.semgrep import SemgrepError, semgrep_to_findings
from aera.static import scan_codebase

FAKE_JSON = {
    "results": [
        {
            "check_id": "python.lang.security.audit.eval-detected",
            "path": "app.py",
            "start": {"line": 3},
            "extra": {"message": "Detected eval", "severity": "ERROR",
                      "lines": "eval(x)"},
        },
        {
            "check_id": "c.lang.security.buffer.copy",
            "path": "v.c",
            "start": {"line": 10},
            "extra": {"message": "strcpy", "severity": "WARNING",
                      "lines": "strcpy(a, b)"},
        },
    ]
}


class FakeProc:
    returncode = 1  # semgrep exits 1 when findings exist
    stdout = __import__("json").dumps(FAKE_JSON)
    stderr = ""


def test_semgrep_to_findings_mapping():
    findings = semgrep_to_findings(FAKE_JSON)
    assert len(findings) == 2
    by_id = {f["rule_id"]: f for f in findings}
    assert by_id["SEMGREP_EVAL_DETECTED"]["severity"] == "HIGH"   # ERROR→HIGH
    assert by_id["SEMGREP_EVAL_DETECTED"]["file"] == "app.py"
    assert by_id["SEMGREP_EVAL_DETECTED"]["line"] == 3
    assert by_id["SEMGREP_COPY"]["severity"] == "MEDIUM"   # WARNING→MEDIUM


def test_run_semgrep_parses(monkeypatch):
    monkeypatch.setattr(semgrep_mod.shutil, "which", lambda c: "/usr/bin/semgrep")
    monkeypatch.setattr(semgrep_mod.subprocess, "run", lambda *a, **k: FakeProc())
    data = semgrep_mod.run_semgrep("/tmp/x")
    assert len(data["results"]) == 2


def test_run_semgrep_missing_binary(monkeypatch):
    monkeypatch.setattr(semgrep_mod.shutil, "which", lambda c: None)
    with pytest.raises(SemgrepError, match="not found"):
        semgrep_mod.run_semgrep("/tmp/x")


def test_engine_auto_falls_back_without_semgrep(tmp_path, monkeypatch):
    monkeypatch.setattr(semgrep_mod.shutil, "which", lambda c: None)
    (tmp_path / "a.py").write_text("eval(x)\n")
    findings = scan_codebase(CodebaseTarget(tmp_path), engine="auto")
    assert any(f["rule_id"] == "PY-EVAL" for f in findings)


def test_engine_semgrep_strict_raises_without_binary(tmp_path, monkeypatch):
    monkeypatch.setattr(semgrep_mod.shutil, "which", lambda c: None)
    with pytest.raises(SemgrepError):
        scan_codebase(CodebaseTarget(tmp_path), engine="semgrep")


def test_engine_semgrep_used_when_available(tmp_path, monkeypatch):
    monkeypatch.setattr(semgrep_mod.shutil, "which", lambda c: "/usr/bin/semgrep")
    monkeypatch.setattr(semgrep_mod.subprocess, "run", lambda *a, **k: FakeProc())
    (tmp_path / "a.py").write_text("x = 1\n")  # no regex hits; semgrep finds some
    findings = scan_codebase(CodebaseTarget(tmp_path), engine="auto")
    assert any(f["rule_id"].startswith("SEMGREP_") for f in findings)
