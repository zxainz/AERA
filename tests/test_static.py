"""Tests for codebase ingestion and static analysis."""
from aera.codebase import CodebaseTarget
from aera.static import scan_codebase, scan_text


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    return p


VULN_C = """
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
void handle(char *input) {
    char buf[64];
    strcpy(buf, input);
    system(buf);
}
int main(int argc, char **argv) {
    char name[32];
    gets(name);
    handle(argv[1]);
    return 0;
}
"""

VULN_PY = """
import os, pickle
def run(cmd):
    os.system(cmd)
    return pickle.loads(b"data")
x = eval(user_input)
"""

CLEAN_PY = """
import json
def run(data):
    return json.loads(data)
"""


def test_static_finds_c_issues(tmp_path):
    _write(tmp_path, "vuln.c", VULN_C)
    target = CodebaseTarget(tmp_path)
    findings = scan_codebase(target)
    ids = {f["rule_id"] for f in findings}
    assert {"C-STRCPY", "C-SYSTEM", "C-GETS"} <= ids
    strcpy = next(f for f in findings if f["rule_id"] == "C-STRCPY")
    assert strcpy["file"] == "vuln.c"
    assert strcpy["line"] == 7
    assert strcpy["severity"] == "HIGH"


def test_static_finds_python_issues(tmp_path):
    _write(tmp_path, "app.py", VULN_PY)
    findings = scan_codebase(CodebaseTarget(tmp_path))
    ids = {f["rule_id"] for f in findings}
    assert {"PY-EVAL", "PY-OS-SYSTEM", "PY-PICKLE"} <= ids


def test_clean_file_no_findings(tmp_path):
    _write(tmp_path, "ok.py", CLEAN_PY)
    assert scan_codebase(CodebaseTarget(tmp_path)) == []


def test_codebase_stats_and_skips(tmp_path):
    _write(tmp_path, "a.c", "int x;\n")
    _write(tmp_path, "b.py", "x = 1\n")
    _write(tmp_path, "node_modules/evil.js", "eval(x)")
    _write(tmp_path, ".git/config", "eval(x)")
    _write(tmp_path, "notes.txt", "eval(x)")
    target = CodebaseTarget(tmp_path)
    stats = target.stats()
    assert stats["files"] == 2
    assert stats["by_language"] == {"c": 1, "python": 1}
    assert scan_codebase(target) == []  # skipped dirs / non-source unseen


def test_scan_text_line_numbers():
    findings = scan_text("python", "x.py", "a = 1\neval(q)\n")
    assert len(findings) == 1
    assert findings[0]["line"] == 2
    assert "eval(q)" in findings[0]["snippet"]
