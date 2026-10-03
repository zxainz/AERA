"""Tests for CVE utils: vuln-type detection and NVD API key."""
import aera.utils as utils_mod
from aera.utils import detect_vuln_type, get_cve_details


def test_detect_binary_from_memory_corruption_cwe():
    assert detect_vuln_type({"cwes": ["CWE-787"]}) == "binary"
    assert detect_vuln_type({"cwes": ["CWE-79", "CWE-416"]}) == "binary"


def test_detect_web_by_default():
    assert detect_vuln_type({"cwes": ["CWE-79"]}) == "web"
    assert detect_vuln_type({"cwes": []}) == "web"
    assert detect_vuln_type({}) == "web"


class FakeNVDResp:
    def raise_for_status(self):
        pass

    def json(self):
        return {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-0001",
                        "descriptions": [{"lang": "en", "value": "test"}],
                        "metrics": {},
                        "weaknesses": [],
                        "configurations": [],
                        "references": [],
                        "published": "2024-01-01",
                    }
                }
            ]
        }


def test_nvd_api_key_sent_when_configured(monkeypatch):
    captured = {}

    def fake_get(url, params=None, headers=None, timeout=None):
        captured["headers"] = headers
        return FakeNVDResp()

    monkeypatch.setattr(utils_mod.requests, "get", fake_get)
    monkeypatch.setenv("AERA_NVD_API_KEY", "secret123")
    get_cve_details("CVE-2024-0001")
    assert captured["headers"]["apiKey"] == "secret123"


def test_nvd_no_key_no_header(monkeypatch):
    captured = {}

    def fake_get(url, params=None, headers=None, timeout=None):
        captured["headers"] = headers
        return FakeNVDResp()

    monkeypatch.setattr(utils_mod.requests, "get", fake_get)
    monkeypatch.delenv("AERA_NVD_API_KEY", raising=False)
    get_cve_details("CVE-2024-0001")
    assert captured["headers"] == {}
