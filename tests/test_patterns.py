"""Tests for pattern aggregation and the HTML dashboard."""
from aera.patterns import render_html_dashboard, summarize


def _item(cve_id, severity="HIGH", score=7.5, cwes=("CWE-79",),
          cpes=("cpe:2.3:a:acme:widget:1.0:*:*:*:*:*:*:*",), kev=None, epss=0.42):
    return {
        "cve_id": cve_id,
        "ok": True,
        "result": {
            "cve": {
                "id": cve_id,
                "cvss_v3": {"severity": severity, "score": score},
                "cwes": list(cwes),
                "cpes": list(cpes),
            },
            "intel": {"kev": kev, "epss": {"score": epss, "percentile": 0.9}},
        },
    }


def test_summarize_aggregates():
    results = [
        _item("CVE-2024-0001", severity="CRITICAL", score=9.8, kev={"cveID": "x"}),
        _item("CVE-2024-0002", severity="HIGH", cwes=("CWE-89",)),
        {"cve_id": "CVE-2024-0003", "ok": False, "error": "boom"},
    ]
    s = summarize(results)
    assert s["total"] == 2
    assert s["failed"] == 1
    assert s["severities"] == {"CRITICAL": 1, "HIGH": 1}
    assert s["kev_hits"] == 1
    assert s["avg_epss"] == 0.42
    assert ("CWE-79", 1) in s["top_cwes"]
    assert ("CWE-89", 1) in s["top_cwes"]
    assert ("acme", 2) in s["top_vendors"]


def test_dashboard_writes_html(tmp_path):
    results = [_item("CVE-2024-0001", kev={"cveID": "x"}),
               {"cve_id": "CVE-2024-0002", "ok": False, "error": "nope"}]
    out = render_html_dashboard(summarize(results), results, tmp_path / "r.html")
    html = out.read_text()
    assert "CVE-2024-0001" in html
    assert "HIGH" in html
    assert "failed" in html
