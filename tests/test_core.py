"""Full-pipeline tests with mocked LLM, CVE source, intel, and sandbox.

These verify the wiring of process_vulnerability end to end without
network access, API keys, or Docker.
"""
import asyncio

import pytest

import aera.core as core_mod
from aera.core import AutonomousExploitResearchAssistant


class FakeLLM:
    def __init__(self):
        self.prompts = []

    def complete(self, system_prompt, user_prompt):
        self.prompts.append((system_prompt, user_prompt))
        if "minimal" in system_prompt.lower() or "proof-of-concept" in system_prompt.lower():
            return 'print("VULNERABLE: marker")'
        return "Root cause: test. Preconditions: lab. Mitigation: patch."


FAKE_CVE = {
    "id": "CVE-2024-TEST1",
    "description": "Test vulnerability.",
    "cvss_v3": {"score": 9.1, "severity": "CRITICAL", "vector": "CVSS:3.1/AV:N/..."},
    "cwes": ["CWE-79"],
    "cpes": ["cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*"],
    "references": [],
    "published": "2024-01-01",
}

FAKE_INTEL = {
    "epss": {"score": 0.5, "percentile": 0.8, "date": "2026-10-01"},
    "kev": {"cveID": "CVE-2024-TEST1", "vendorProject": "Acme",
            "product": "Widget", "requiredAction": "Patch", "dueDate": "2024-02-01"},
}

FAKE_TEST = {
    "exit_code": 0, "stdout": "VULNERABLE: marker", "stderr": "",
    "timestamp": "2026-10-03T00:00:00+00:00", "container_id": "abc123",
    "vuln_type": "web", "actor": "tester",
}


@pytest.fixture()
def aera(tmp_path, monkeypatch):
    monkeypatch.setenv("AERA_JWT_SECRET", "core-test-secret")
    monkeypatch.setenv("AERA_DOMAINS", "lab.example.com")
    monkeypatch.setenv("AERA_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setattr(core_mod, "get_cve_details", lambda cve_id: dict(FAKE_CVE))
    monkeypatch.setattr(core_mod, "enrich_intel", lambda cve_id: dict(FAKE_INTEL))
    assistant = AutonomousExploitResearchAssistant(
        llm=FakeLLM(), sandbox_enabled=True
    )
    # Fake the sandbox: no Docker needed.
    assistant._sandbox = FakeSandbox()
    return assistant


class FakeSandbox:
    def describe_lab(self, vuln_type):
        return {
            "image": "lab/web:test", "os": "linux", "arch": "amd64",
            "exposed_ports": ["8080/tcp"],
            "runtime": {"kernel": "Linux x86_64", "python": "Python 3.11",
                        "user": "root"},
        }

    def test_poc(self, vuln_type, poc_script, *, actor="unknown"):
        assert "marker" in poc_script
        return dict(FAKE_TEST)


@pytest.fixture()
def token(aera):
    return aera.authorization.generate_token("t@lab.example.com", "lab.example.com")


def test_full_pipeline_wiring(aera, token, tmp_path):
    result = asyncio.run(
        aera.process_vulnerability("CVE-2024-TEST1", token, vuln_type="web")
    )
    assert result["cve"]["id"] == "CVE-2024-TEST1"
    assert result["intel"] == FAKE_INTEL
    assert result["test_result"]["exit_code"] == 0
    md = result["report_markdown"]
    assert "CVE-2024-TEST1" in md
    assert "CISA KEV" in md and "YES" in md
    assert "EPSS score" in md
    # Lab facts reached the PoC prompt
    poc_prompts = [u for s, u in aera.llm.prompts if "PoC" in u or "CVE" in u]
    assert any("lab/web:test" in p for p in poc_prompts)
    # Intel reached the analysis prompt
    assert any("KEV" in p for s, p in aera.llm.prompts)


def test_pipeline_rejects_bad_token(aera):
    with pytest.raises(Exception):
        asyncio.run(aera.process_vulnerability("CVE-2024-TEST1", "garbage"))


def test_pipeline_without_intel_or_lab(aera, token):
    result = asyncio.run(
        aera.process_vulnerability(
            "CVE-2024-TEST1", token, intel=False, lab_context=False
        )
    )
    assert result["intel"] is None
    assert "Intel enrichment was unavailable" in result["report_markdown"]


def test_audit_log_written(aera, token, tmp_path):
    asyncio.run(aera.process_vulnerability("CVE-2024-TEST1", token))
    log = (tmp_path / "audit.log").read_text()
    for event in ("pipeline_started", "cve_fetched", "intel_enriched",
                  "lab_fingerprinted", "analysis_done", "poc_drafted",
                  "poc_tested", "report_generated"):
        assert event in log, f"missing audit event: {event}"


# --- v2: self-healing PoC loop and verify_fix ---


class ScriptedLLM:
    """Returns canned PoCs in order; distinguishes initial vs fix prompts."""

    def __init__(self, pocs):
        self.pocs = list(pocs)
        self.prompts = []

    def complete(self, system_prompt, user_prompt):
        self.prompts.append((system_prompt, user_prompt))
        if "FAILED" in user_prompt:
            return self.pocs.pop(0)
        if "minimal" in system_prompt.lower():
            return self.pocs.pop(0)
        return "analysis text"


class ScriptedSandbox:
    def __init__(self, results):
        self.results = list(results)

    def describe_lab(self, vuln_type):
        return {
            "image": "lab/x", "os": "linux", "arch": "amd64",
            "exposed_ports": [],
            "runtime": {"kernel": "k", "python": "p", "user": "u"},
        }

    def test_poc(self, vuln_type, poc_script, *, actor="unknown"):
        return self.results.pop(0)


def _scripted_aera(tmp_path, monkeypatch, pocs, runs):
    monkeypatch.setenv("AERA_JWT_SECRET", "core-test-secret")
    monkeypatch.setenv("AERA_DOMAINS", "lab.example.com")
    monkeypatch.setenv("AERA_AUDIT_LOG", str(tmp_path / "audit.log"))
    monkeypatch.setattr(core_mod, "get_cve_details", lambda cve_id: dict(FAKE_CVE))
    monkeypatch.setattr(core_mod, "enrich_intel", lambda cve_id: dict(FAKE_INTEL))
    assistant = AutonomousExploitResearchAssistant(
        llm=ScriptedLLM(pocs), sandbox_enabled=True
    )
    assistant._sandbox = ScriptedSandbox(runs)
    return assistant


def _scripted_token(aera):
    return aera.authorization.generate_token("t@lab.example.com", "lab.example.com")


def test_self_healing_retries_failed_poc(tmp_path, monkeypatch):
    crash = {"exit_code": 1, "stdout": "", "stderr": "Traceback: NameError",
             "verdict": "unknown"}
    fixed = {"exit_code": 0, "stdout": "VULNERABLE: marker", "stderr": "",
             "verdict": "vulnerable"}
    aera = _scripted_aera(tmp_path, monkeypatch, ["bad()", "good()"], [crash, fixed])
    result = asyncio.run(
        aera.process_vulnerability(
            "CVE-2024-TEST1", _scripted_token(aera), vuln_type="web"
        )
    )
    assert len(result["attempts"]) == 2
    assert result["test_result"]["verdict"] == "vulnerable"
    assert result["poc"] == "good()"
    fix_prompts = [u for s, u in aera.llm.prompts if "FAILED" in u]
    assert len(fix_prompts) == 1
    assert "Traceback: NameError" in fix_prompts[0]
    assert "poc_retrying" in (tmp_path / "audit.log").read_text()
    assert "Attempts" in result["report_markdown"]


def test_no_retry_when_poc_reports_not_vulnerable(tmp_path, monkeypatch):
    neg = {"exit_code": 0, "stdout": "NOT VULNERABLE", "stderr": "",
           "verdict": "not_vulnerable"}
    aera = _scripted_aera(tmp_path, monkeypatch, ["p()"], [neg])
    result = asyncio.run(
        aera.process_vulnerability(
            "CVE-2024-TEST1", _scripted_token(aera), vuln_type="web"
        )
    )
    assert len(result["attempts"]) == 1
    assert "poc_retrying" not in (tmp_path / "audit.log").read_text()


def test_auto_vuln_type_detection(tmp_path, monkeypatch):
    ok = {"exit_code": 0, "stdout": "VULNERABLE: x", "stderr": "",
          "verdict": "vulnerable"}
    aera = _scripted_aera(tmp_path, monkeypatch, ["p()"], [ok])
    result = asyncio.run(
        aera.process_vulnerability("CVE-2024-TEST1", _scripted_token(aera))
    )
    assert result["test_result"]["verdict"] == "vulnerable"
    assert "vuln_type_detected" in (tmp_path / "audit.log").read_text()


def test_verify_fix(tmp_path, monkeypatch):
    saved = {
        "cve": {"id": "CVE-2024-TEST1", "cwes": ["CWE-79"]},
        "poc": 'print("NOT VULNERABLE")',
    }
    run = {"exit_code": 0, "stdout": "NOT VULNERABLE", "stderr": "",
           "verdict": "not_vulnerable", "container_id": "c1"}
    aera = _scripted_aera(tmp_path, monkeypatch, [], [run])
    result = asyncio.run(aera.verify_fix(saved, _scripted_token(aera)))
    assert result["cve_id"] == "CVE-2024-TEST1"
    assert result["verdict"] == "not_vulnerable"
    assert "fix_verification_done" in (tmp_path / "audit.log").read_text()


def test_verify_fix_requires_poc(tmp_path, monkeypatch):
    aera = _scripted_aera(tmp_path, monkeypatch, [], [])
    with pytest.raises(ValueError, match="No PoC"):
        asyncio.run(aera.verify_fix({"cve": {"id": "X"}}, _scripted_token(aera)))


# --- v0.4.0: codebase pipeline (static-only; no Docker, no LLM key) ---


def test_analyze_codebase_static_only(tmp_path, monkeypatch):
    (tmp_path / "vuln.py").write_text(
        "import os\ndef f(cmd):\n    os.system(cmd)\n"
    )
    (tmp_path / "clean.py").write_text("x = 1\n")
    monkeypatch.setenv("AERA_JWT_SECRET", "core-test-secret")
    monkeypatch.setenv("AERA_DOMAINS", "lab.example.com")
    monkeypatch.setenv("AERA_AUDIT_LOG", str(tmp_path / "audit.log"))
    aera = AutonomousExploitResearchAssistant(
        llm=FakeLLM(), sandbox_enabled=False
    )
    token = aera.authorization.generate_token("t@lab.example.com", "lab.example.com")
    result = asyncio.run(
        aera.analyze_codebase(str(tmp_path), token, fuzz=False)
    )
    assert result["stats"]["files"] == 2
    assert any(f["rule_id"] == "PY-OS-SYSTEM" for f in result["findings"])
    assert result["crashes"] == []
    md = result["report_markdown"]
    assert "Codebase Security Report" in md
    assert "PY-OS-SYSTEM" in md
    log = (tmp_path / "audit.log").read_text()
    assert "codebase_scan_started" in log
    assert "static_scan_done" in log


def test_analyze_codebase_requires_auth(tmp_path, monkeypatch):
    monkeypatch.setenv("AERA_JWT_SECRET", "core-test-secret")
    monkeypatch.setenv("AERA_DOMAINS", "lab.example.com")
    aera = AutonomousExploitResearchAssistant(
        llm=FakeLLM(), sandbox_enabled=False
    )
    with pytest.raises(Exception):
        asyncio.run(aera.analyze_codebase(str(tmp_path), "bad-token"))


def test_analyze_codebase_fuzz_needs_target(tmp_path, monkeypatch):
    monkeypatch.setenv("AERA_JWT_SECRET", "core-test-secret")
    monkeypatch.setenv("AERA_DOMAINS", "lab.example.com")
    aera = AutonomousExploitResearchAssistant(
        llm=FakeLLM(), sandbox_enabled=False
    )
    token = aera.authorization.generate_token("t@lab.example.com", "lab.example.com")
    with pytest.raises(ValueError, match="target_cmd"):
        asyncio.run(aera.analyze_codebase(str(tmp_path), token, fuzz=True))
