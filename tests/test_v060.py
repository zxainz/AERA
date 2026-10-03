"""Tests for AERA v0.6.0 pentester upgrades.

Covers: local LLM provider, recon (nmap/version-list -> CVEs), session-aware
web fuzzing, dynamic finding verification, attack-path chaining, KEV watch,
client-ready reports, and target-aware PoC prompts.

No network, no Docker, no API keys: external calls are monkeypatched.
"""
from __future__ import annotations

import json

import pytest

# ---------------------------------------------------------------------------
# 1. Local LLM provider (Ollama)
# ---------------------------------------------------------------------------

class _OKResp:
    def raise_for_status(self):
        pass


def test_provider_from_env_ollama(monkeypatch):
    import aera.llm as llm_mod

    monkeypatch.setenv("AERA_LLM_PROVIDER", "ollama")
    monkeypatch.setenv("AERA_LLM_MODEL", "test-model")
    monkeypatch.delenv("AERA_LLM_API_KEY", raising=False)
    monkeypatch.setattr(llm_mod.requests, "get", lambda *a, **k: _OKResp())
    provider = llm_mod.provider_from_env()
    assert provider.base_url == "http://localhost:11434/v1"
    assert provider.model == "test-model"
    assert provider.api_key == "local"  # dummy key: Ollama needs none


def test_provider_from_env_ollama_server_down(monkeypatch):
    import aera.llm as llm_mod

    monkeypatch.setenv("AERA_LLM_PROVIDER", "ollama")
    monkeypatch.delenv("AERA_LLM_API_KEY", raising=False)

    def _boom(*a, **k):
        raise llm_mod.requests.ConnectionError("nope")

    monkeypatch.setattr(llm_mod.requests, "get", _boom)
    with pytest.raises(RuntimeError, match="ollama serve"):
        llm_mod.provider_from_env()


def test_provider_from_env_default_needs_key(monkeypatch):
    import aera.llm as llm_mod

    monkeypatch.setenv("AERA_LLM_PROVIDER", "zai")
    monkeypatch.delenv("AERA_LLM_API_KEY", raising=False)
    monkeypatch.delenv("AERA_LLM_BASE_URL", raising=False)
    with pytest.raises(RuntimeError, match="AERA_LLM_API_KEY"):
        llm_mod.provider_from_env()


# ---------------------------------------------------------------------------
# 2. Recon: versions -> candidate CVEs
# ---------------------------------------------------------------------------

NMAP_XML = """<?xml version="1.0"?>
<nmaprun>
  <host><status state="up"/>
    <address addr="10.0.0.5" addrtype="ipv4"/>
    <ports>
      <port protocol="tcp" portid="80"><state state="open"/>
        <service name="http" product="Apache httpd" version="2.4.49"/></port>
      <port protocol="tcp" portid="22"><state state="closed"/>
        <service name="ssh" product="OpenSSH" version="8.9"/></port>
    </ports>
  </host>
</nmaprun>
"""


def test_parse_nmap_xml(tmp_path):
    from aera.recon import parse_nmap_xml

    p = tmp_path / "scan.xml"
    p.write_text(NMAP_XML)
    services = parse_nmap_xml(p)
    assert len(services) == 1  # closed port skipped
    svc = services[0]
    assert svc["host"] == "10.0.0.5"
    assert svc["product"] == "Apache httpd"
    assert svc["version"] == "2.4.49"


def test_parse_version_list():
    from aera.recon import parse_version_list

    services = parse_version_list(
        "nginx 1.18.0\napache:2.4.49\n# comment\nopenssl==1.1.1k\n"
    )
    assert [(s["product"], s["version"]) for s in services] == [
        ("nginx", "1.18.0"),
        ("apache", "2.4.49"),
        ("openssl", "1.1.1k"),
    ]


class _NVDResp:
    def raise_for_status(self):
        pass

    def json(self):
        return {"vulnerabilities": [
            {"cve": {"id": "CVE-2021-41773",
                     "published": "2021-10-05",
                     "descriptions": [{"lang": "en",
                                       "value": "A flaw in Apache httpd 2.4.49 "
                                                "allows path traversal."}]}},
            {"cve": {"id": "CVE-1999-0001",
                     "published": "1999-01-01",
                     "descriptions": [{"lang": "en",
                                       "value": "Some old Apache issue."}]}},
        ]}


def test_candidate_cves_scoring(monkeypatch):
    import aera.recon as recon_mod

    monkeypatch.setattr(recon_mod.requests, "get", lambda *a, **k: _NVDResp())
    monkeypatch.setattr(recon_mod.time, "sleep", lambda *a: None)
    cands = recon_mod.candidate_cves("Apache httpd", "2.4.49")
    assert cands[0]["cve_id"] == "CVE-2021-41773"
    assert cands[0]["score"] == 3  # version (+2) + product (+1)
    assert cands[1]["score"] == 1  # product first-token match only


def test_write_recon_outputs(tmp_path, monkeypatch):
    import aera.recon as recon_mod

    monkeypatch.setattr(recon_mod.requests, "get", lambda *a, **k: _NVDResp())
    monkeypatch.setattr(recon_mod.time, "sleep", lambda *a: None)
    results = recon_mod.run_recon(
        [{"host": "h", "port": "80", "protocol": "tcp", "service": "http",
          "product": "Apache httpd", "version": "2.4.49"}])
    outs = recon_mod.write_recon_outputs(results, tmp_path)
    cves = (tmp_path / "cves.txt").read_text().split()
    assert "CVE-2021-41773" in cves
    assert outs["cve_count"] == len(cves)


# ---------------------------------------------------------------------------
# 3. Session-aware web fuzzing
# ---------------------------------------------------------------------------

class _FakeResp:
    def __init__(self, status=200, text="ok"):
        self.status_code = status
        self.text = text
        self.content = text.encode()


def test_webfuzz_detects_500(monkeypatch):
    from aera import webfuzz

    fuzzer = webfuzz.WebFuzzer()
    calls = {"n": 0}

    def fake_send(method, url, params):
        calls["n"] += 1
        if calls["n"] <= 3:
            return _FakeResp(200, "ok")  # baseline
        if "'" in params.get("q", ""):
            return _FakeResp(500, "Internal Server Error")
        return _FakeResp(200, "ok")

    monkeypatch.setattr(fuzzer, "_send", fake_send)
    findings = fuzzer.fuzz_params("http://lab/search", ["q"],
                                  iterations=30, seed=1)
    assert findings, "expected at least one anomaly"
    assert any(f["kind"] == "http-500" and f["param"] == "q" for f in findings)


def test_webfuzz_detects_error_disclosure(monkeypatch):
    from aera import webfuzz

    fuzzer = webfuzz.WebFuzzer()
    calls = {"n": 0}

    def fake_send(method, url, params):
        calls["n"] += 1
        if calls["n"] <= 3:
            return _FakeResp(200, "ok")
        return _FakeResp(200, "Traceback (most recent call last): ...")

    monkeypatch.setattr(fuzzer, "_send", fake_send)
    findings = fuzzer.fuzz_params("http://lab/api", ["id"], iterations=5)
    assert any(f["kind"] == "error-disclosure" for f in findings)


def test_webfuzz_login(monkeypatch):
    from aera import webfuzz

    fuzzer = webfuzz.WebFuzzer()

    class FakeSession:
        def post(self, *a, **k):
            return _FakeResp(200, "welcome")

        def get(self, *a, **k):
            return _FakeResp(200, "Logout | dashboard")

    fuzzer.session = FakeSession()
    assert fuzzer.login("http://lab/login", "user=u&pass=p",
                        check="Logout") is True
    assert fuzzer.authenticated is True


# ---------------------------------------------------------------------------
# 4. Dynamic verification
# ---------------------------------------------------------------------------

def test_parse_trigger_verdict():
    from aera.dynverify import parse_trigger_verdict

    assert parse_trigger_verdict("blah\nTRIGGERED: marker executed") == "triggered"
    assert parse_trigger_verdict("NOT TRIGGERED: input sanitized") == "not_triggered"
    assert parse_trigger_verdict("nothing here") == "unknown"


def test_verify_findings_skip_paths(tmp_path):
    from aera.dynverify import verify_findings

    findings = [
        {"rule_id": "C-STRCPY", "severity": "HIGH", "file": "a.c",
         "line": 1, "title": "t", "snippet": "s", "fix": "f"},
        {"rule_id": "PY-EVAL", "severity": "LOW", "file": "b.py",
         "line": 1, "title": "t", "snippet": "s", "fix": "f"},
    ]
    out = verify_findings(findings, tmp_path, llm=None, sandbox=None)
    by_rule = {f["rule_id"]: f for f in out}
    # C rule: no Python trigger template -> skipped
    assert by_rule["C-STRCPY"]["dynamic_verdict"] == "skipped"
    # LOW severity: below threshold -> skipped
    assert by_rule["PY-EVAL"]["dynamic_verdict"] == "skipped"


def test_verify_findings_confirmed_path(tmp_path, monkeypatch):
    from aera import dynverify

    src = tmp_path / "vuln.py"
    src.write_text("import pickle\ndef load(d):\n    return pickle.loads(d)\n")
    findings = [{"rule_id": "PY-PICKLE", "severity": "HIGH", "file": "vuln.py",
                 "line": 3, "title": "t", "snippet": "pickle.loads(d)",
                 "fix": "f"}]

    class FakeLLM:
        def complete(self, system, prompt):
            return "print('TRIGGERED: pickle.loads executed')"

    class FakeSandbox:
        pass

    def fake_run(sandbox, image, target_dir, script, actor):
        assert "/target" in script or "vuln" in script or "TRIGGERED" in script
        return {"verdict": "triggered",
                "stdout": "TRIGGERED: pickle.loads executed",
                "stderr": ""}

    monkeypatch.setattr(dynverify, "_run_trigger", fake_run)
    out = dynverify.verify_findings(findings, tmp_path, FakeLLM(), FakeSandbox())
    assert out[0]["dynamic_verdict"] == "confirmed"


# ---------------------------------------------------------------------------
# 5. Attack-path chaining
# ---------------------------------------------------------------------------

def test_build_chains_links_stages():
    from aera.chains import build_chains

    nodes = [
        {"id": "cve-1", "title": "info leak", "severity": "MEDIUM",
         "capabilities": {"info-disclosure"}, "scope": "web", "source": "cve"},
        {"id": "cve-2", "title": "default creds", "severity": "HIGH",
         "capabilities": {"credential"}, "scope": "web", "source": "cve"},
        {"id": "cve-3", "title": "auth bypass", "severity": "CRITICAL",
         "capabilities": {"auth-bypass"}, "scope": "web", "source": "cve"},
        {"id": "other", "title": "unrelated", "severity": "LOW",
         "capabilities": set(), "scope": "web", "source": "cve"},
    ]
    chains = build_chains(nodes)
    assert chains, "expected at least one chain"
    # credential -> auth-bypass chain should exist
    assert any(
        [cap for cap, *_ in c["stages"]] == ["credential", "auth-bypass"]
        for c in chains
    )
    # scopes are respected
    assert all(c["scope"] == "web" for c in chains)


def test_nodes_from_findings_capabilities():
    from aera.chains import nodes_from_findings

    nodes = nodes_from_findings(
        [{"rule_id": "PY-OS-SYSTEM", "title": "t", "severity": "HIGH",
          "file": "a.py", "line": 1}])
    assert nodes[0]["capabilities"] == {"command-exec"}


def test_render_chains_markdown():
    from aera.chains import render_chains_markdown

    md = render_chains_markdown([{
        "scope": "web", "max_severity": "CRITICAL", "length": 2,
        "narrative": "narr",
        "stages": [("credential", "c1", "t1", "HIGH"),
                   ("auth-bypass", "c2", "t2", "CRITICAL")],
    }])
    assert "Chain 1" in md and "CRITICAL" in md


# ---------------------------------------------------------------------------
# 6. KEV watch
# ---------------------------------------------------------------------------

KEV_FEED = [
    {"cveID": "CVE-2024-1234", "vendorProject": "Citrix",
     "product": "NetScaler ADC", "vulnerabilityName": "Test bug",
     "dateAdded": "2024-01-01", "dueDate": "2024-02-01",
     "requiredAction": "Apply patch"},
    {"cveID": "CVE-2024-9999", "vendorProject": "Unrelated",
     "product": "Widget", "vulnerabilityName": "Other",
     "dateAdded": "2024-01-02", "dueDate": "2024-02-02",
     "requiredAction": "Apply patch"},
]


def test_kev_watch_alerts_and_dedupes(tmp_path, monkeypatch):
    from aera import kevwatch

    monkeypatch.setattr(kevwatch, "fetch_kev_feed", lambda **k: KEV_FEED)
    stack = tmp_path / "stack.json"
    stack.write_text(json.dumps(
        {"products": [{"vendor": "Citrix", "product": "NetScaler"}],
         "cves": ["CVE-2021-44228"]}))
    state = tmp_path / "state.json"

    first = kevwatch.check_kev(stack, state)
    assert len(first["alerts"]) == 1
    assert first["alerts"][0]["cve_id"] == "CVE-2024-1234"

    second = kevwatch.check_kev(stack, state)
    assert second["alerts"] == []  # seen -> no repeat alerts


# ---------------------------------------------------------------------------
# 7. Client-ready reports
# ---------------------------------------------------------------------------

def _batch_results():
    return [{
        "cve_id": "CVE-2021-44228", "ok": True, "result": {
            "cve": {"id": "CVE-2021-44228",
                    "description": "Log4Shell RCE in Log4j",
                    "cvss_v3": {"score": 10.0, "severity": "CRITICAL"},
                    "cwes": ["CWE-94"]},
            "intel": {"kev": {"cveID": "CVE-2021-44228"},
                      "epss": {"score": 0.99}},
            "test_result": {"verdict": "vulnerable"},
        }},
        {"cve_id": "CVE-2024-0001", "ok": True, "result": {
            "cve": {"id": "CVE-2024-0001", "description": "Minor issue",
                    "cvss_v3": {"score": 4.3, "severity": "MEDIUM"},
                    "cwes": []},
            "intel": {"kev": None, "epss": {"score": 0.01}},
            "test_result": {"verdict": "not_vulnerable"},
        }},
    ]


def test_executive_summary():
    from aera.report_generator import generate_executive_summary

    md = generate_executive_summary(_batch_results())
    assert "Executive Summary" in md
    assert "CVE-2021-44228" in md  # top priority first
    assert "KEV" in md


def test_render_client_report():
    from aera.report_generator import render_client_report

    md = render_client_report(_batch_results())
    assert "Remediation Roadmap" in md
    assert "Business impact" in md
    # KEV item sorts before the medium one
    assert md.index("CVE-2021-44228") < md.index("CVE-2024-0001")


def test_impact_statement():
    from aera.report_generator import impact_statement

    assert "patch-now" in impact_statement("CRITICAL")
    assert impact_statement("bogus")  # unknown severity -> LOW default


# ---------------------------------------------------------------------------
# 8. Target-aware PoC prompt
# ---------------------------------------------------------------------------

def test_build_poc_prompt_with_target_info():
    from aera.core import build_poc_prompt

    cve = {"id": "CVE-2021-41773", "description": "d", "cwes": ["CWE-22"]}
    plain = build_poc_prompt(cve, "analysis")
    assert "Target facts" not in plain
    tuned = build_poc_prompt(cve, "analysis",
                             target_info="Server: Apache/2.4.49")
    assert "Server: Apache/2.4.49" in tuned
    assert "Target facts observed by the tester" in tuned


# ---------------------------------------------------------------------------
# CLI wiring for the new commands
# ---------------------------------------------------------------------------

def test_cli_parsers():
    from aera.cli import build_parser

    p = build_parser()
    a = p.parse_args(["recon", "scan.xml", "--token", "t"])
    assert a.command == "recon" and a.input == "scan.xml"
    a = p.parse_args(["webfuzz", "--url", "http://lab/x", "--token", "t",
                      "--params", "q,page"])
    assert a.command == "webfuzz" and a.params == "q,page"
    a = p.parse_args(["chains", "--token", "t", "--cve-dir", "d"])
    assert a.command == "chains"
    a = p.parse_args(["kev-watch", "--stack", "s.json", "--token", "t",
                      "--once"])
    assert a.command == "kev-watch" and a.once is True
    a = p.parse_args(["client-report", "batch-out", "--token", "t"])
    assert a.command == "client-report"
    a = p.parse_args(["analyze", "CVE-2021-44228", "--token", "t",
                      "--target-info", "Server: x"])
    assert a.target_info == "Server: x"
    a = p.parse_args(["scan-code", "./app", "--token", "t", "--dyn-verify"])
    assert a.dyn_verify is True
