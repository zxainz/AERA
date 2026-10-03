"""Unit tests for sandbox output parsing. No Docker needed."""
from aera.sandbox import parse_run_output


def test_parses_exit_code_and_vulnerable_verdict():
    code, cleaned, verdict = parse_run_output("probing...\nVULNERABLE: reflected xss\nEXIT:0\n")
    assert code == 0
    assert verdict == "vulnerable"
    assert "EXIT" not in cleaned
    assert "VULNERABLE: reflected xss" in cleaned


def test_not_vulnerable_verdict():
    code, cleaned, verdict = parse_run_output("NOT VULNERABLE\nEXIT:0\n")
    assert code == 0
    assert verdict == "not_vulnerable"


def test_crash_exit_code_and_unknown_verdict():
    out = "Traceback (most recent call last):\n  File \"x\", line 1\nNameError\nEXIT:1\n"
    code, cleaned, verdict = parse_run_output(out)
    assert code == 1
    assert verdict == "unknown"


def test_missing_exit_marker():
    code, cleaned, verdict = parse_run_output("some output, no marker")
    assert code == -1
    assert verdict == "unknown"


def test_not_vulnerable_takes_precedence():
    # "NOT VULNERABLE" contains "VULNERABLE" -- must not misread as vulnerable.
    _, _, verdict = parse_run_output("NOT VULNERABLE\nEXIT:0\n")
    assert verdict == "not_vulnerable"


def test_markdown_and_bracketed_verdict_parsing():
    _, _, v1 = parse_run_output("**VULNERABLE:** payload triggered\nEXIT:0\n")
    assert v1 == "vulnerable"

    _, _, v2 = parse_run_output("[VULNERABLE] sql injection success\nEXIT:0\n")
    assert v2 == "vulnerable"

    _, _, v3 = parse_run_output("**NOT VULNERABLE**\nEXIT:0\n")
    assert v3 == "not_vulnerable"


def test_sandbox_web_app_normalization():
    from aera.sandbox import SandboxManager
    assert SandboxManager._normalize_vuln_type("web_app") == "web"
    assert SandboxManager._normalize_vuln_type("binary") == "binary"
