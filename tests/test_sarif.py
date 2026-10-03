"""Tests for SARIF output."""
import json

from aera.sarif import findings_to_sarif, write_sarif

FINDINGS = [
    {"rule_id": "PY-EVAL", "title": "eval() on untrusted input",
     "severity": "CRITICAL", "fix": "Use ast.literal_eval",
     "file": "app.py", "line": 3, "snippet": "eval(x)"},
    {"rule_id": "C-STRCPY", "title": "Unbounded strcpy()",
     "severity": "HIGH", "fix": "Use strncpy",
     "file": "v.c", "line": 7, "snippet": "strcpy(a, b)"},
]
CRASHES = [
    {"signature": "abc123", "count": 5, "severity": "HIGH",
     "example": {"signal": 11, "keyword": "heap-buffer-overflow"},
     "reproducible": True},
]


def test_sarif_structure():
    doc = findings_to_sarif(FINDINGS, CRASHES)
    assert doc["version"] == "2.1.0"
    assert doc["$schema"].endswith("sarif-2.1.0.json")
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "AERA"
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {"PY-EVAL", "C-STRCPY", "AERA-FUZZ-CRASH"} <= rule_ids
    assert len(run["results"]) == 3


def test_sarif_levels_and_locations():
    doc = findings_to_sarif(FINDINGS)
    results = {r["ruleId"]: r for r in doc["runs"][0]["results"]}
    assert results["PY-EVAL"]["level"] == "error"      # CRITICAL
    assert results["C-STRCPY"]["level"] == "error"      # HIGH
    loc = results["PY-EVAL"]["locations"][0]["physicalLocation"]
    assert loc["artifactLocation"]["uri"] == "app.py"
    assert loc["region"]["startLine"] == 3


def test_sarif_crash_result_message():
    doc = findings_to_sarif([], CRASHES)
    result = doc["runs"][0]["results"][0]
    assert result["ruleId"] == "AERA-FUZZ-CRASH"
    assert "abc123" in result["message"]["text"]
    assert "reproducible=True" in result["message"]["text"]


def test_write_sarif_file(tmp_path):
    out = write_sarif(tmp_path / "r.sarif", FINDINGS)
    doc = json.loads(out.read_text())
    assert doc["version"] == "2.1.0"
