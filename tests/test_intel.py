"""Tests for intel enrichment. Network is mocked; no real calls."""
import csv
import io

import pytest

import aera.intel as intel_mod
from aera.intel import KEVCatalog, enrich, get_epss


class FakeResp:
    def __init__(self, json_data=None, content=b"", status=200):
        self._json = json_data
        self.content = content
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception("http error")

    def json(self):
        return self._json


def test_get_epss_parses(monkeypatch):
    monkeypatch.setattr(
        intel_mod.requests,
        "get",
        lambda *a, **k: FakeResp(
            {"data": [{"cve": "CVE-2021-44228", "epss": "0.97",
                       "percentile": "0.999", "date": "2026-10-01"}]}
        ),
    )
    out = get_epss("CVE-2021-44228")
    assert out == {"score": 0.97, "percentile": 0.999, "date": "2026-10-01"}


def test_get_epss_failure_returns_none(monkeypatch):
    def boom(*a, **k):
        raise intel_mod.requests.RequestException("down")

    monkeypatch.setattr(intel_mod.requests, "get", boom)
    assert get_epss("CVE-2021-44228") is None


KEV_CSV = (
    "cveID,vendorProject,product,vulnerabilityName,dateAdded,shortDescription,"
    "requiredAction,dueDate,notes\n"
    "CVE-2021-44228,Apache,Log4j2,Apache Log4j2 RCE,2021-12-10,desc,"
    "Apply updates,2021-12-24,\n"
)


def test_kev_lookup_from_cache(tmp_path, monkeypatch):
    cache = tmp_path / "kev.csv"
    cache.write_text(KEV_CSV)
    catalog = KEVCatalog(cache_path=cache, max_age_hours=9999)
    row = catalog.lookup("cve-2021-44228")
    assert row is not None
    assert row["vendorProject"] == "Apache"
    assert catalog.lookup("CVE-9999-00000") is None


def test_kev_lookup_refreshes_when_stale(tmp_path, monkeypatch):
    cache = tmp_path / "kev.csv"
    monkeypatch.setattr(
        intel_mod.requests,
        "get",
        lambda *a, **k: FakeResp(content=KEV_CSV.encode()),
    )
    catalog = KEVCatalog(cache_path=cache, max_age_hours=0)
    row = catalog.lookup("CVE-2021-44228")
    assert row is not None and cache.exists()


def test_enrich_never_raises(tmp_path, monkeypatch):
    def boom(*a, **k):
        raise intel_mod.requests.RequestException("down")

    monkeypatch.setattr(intel_mod.requests, "get", boom)
    out = enrich("CVE-2021-44228", kev=KEVCatalog(
        cache_path=tmp_path / "missing.csv", max_age_hours=0))
    assert out == {"epss": None, "kev": None}
