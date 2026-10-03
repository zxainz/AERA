"""Pattern analysis across many processed CVEs + HTML dashboard."""
from __future__ import annotations

from collections import Counter
from html import escape
from pathlib import Path


def summarize(results: list[dict]) -> dict:
    """Aggregate severity, CWE, vendor, KEV and EPSS stats from batch results."""
    severities: Counter = Counter()
    cwes: Counter = Counter()
    vendors: Counter = Counter()
    kev_hits = 0
    epss_scores: list[float] = []

    for item in results:
        if not item.get("ok"):
            continue
        result = item["result"]
        cve = result.get("cve", {})
        sev = (cve.get("cvss_v3") or {}).get("severity") or "UNKNOWN"
        severities[sev] += 1
        for cwe in cve.get("cwes", []):
            cwes[cwe] += 1
        for cpe in cve.get("cpes", []):
            parts = cpe.split(":")
            if len(parts) > 4 and parts[3] not in ("*", "-"):
                vendors[parts[3]] += 1
        intel = result.get("intel") or {}
        if intel.get("kev"):
            kev_hits += 1
        score = (intel.get("epss") or {}).get("score")
        if score is not None:
            epss_scores.append(score)

    return {
        "total": sum(1 for i in results if i.get("ok")),
        "failed": sum(1 for i in results if not i.get("ok")),
        "severities": dict(severities),
        "top_cwes": cwes.most_common(10),
        "top_vendors": vendors.most_common(10),
        "kev_hits": kev_hits,
        "avg_epss": (
            round(sum(epss_scores) / len(epss_scores), 4) if epss_scores else None
        ),
    }


def _bar(label: str, value: int, maximum: int) -> str:
    pct = round(100 * value / maximum) if maximum else 0
    return (
        f'<div class="row"><span class="lbl">{escape(label)}</span>'
        f'<div class="track"><div class="fill" style="width:{pct}%"></div></div>'
        f'<span class="val">{value}</span></div>'
    )


def render_html_dashboard(
    summary: dict, results: list[dict], out_path: str | Path
) -> Path:
    """Write a self-contained HTML dashboard (no external assets)."""
    out_path = Path(out_path)
    sev_order = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"]
    sev_rank = {s: i for i, s in enumerate(sev_order)}

    def _severity_of(item: dict) -> str:
        if not item.get("ok"):
            return "UNKNOWN"
        return (item["result"].get("cve", {}).get("cvss_v3") or {}).get(
            "severity", "UNKNOWN"
        )

    ordered = sorted(
        results, key=lambda i: (sev_rank.get(_severity_of(i), 9), i.get("cve_id", ""))
    )
    max_sev = max((summary["severities"].get(s, 0) for s in sev_order), default=0)

    sev_bars = "".join(
        _bar(s, summary["severities"].get(s, 0), max_sev) for s in sev_order
    )
    cwe_rows = "".join(
        f"<tr><td>{escape(cwe)}</td><td>{n}</td></tr>"
        for cwe, n in summary["top_cwes"]
    ) or '<tr><td colspan="2">n/a</td></tr>'
    vendor_rows = "".join(
        f"<tr><td>{escape(v)}</td><td>{n}</td></tr>"
        for v, n in summary["top_vendors"]
    ) or '<tr><td colspan="2">n/a</td></tr>'

    cve_rows = ""
    for item in ordered:
        if not item.get("ok"):
            cve_rows += (
                f'<tr><td>{escape(item["cve_id"])}</td>'
                f'<td colspan="3" class="fail">failed: '
                f'{escape(str(item.get("error", ""))[:120])}</td></tr>'
            )
            continue
        cve = item["result"]["cve"]
        cvss = cve.get("cvss_v3") or {}
        intel = item["result"].get("intel") or {}
        kev = "YES" if intel.get("kev") else "no"
        epss = (intel.get("epss") or {}).get("score")
        cve_rows += (
            f"<tr><td>{escape(cve.get('id', ''))}</td>"
            f"<td>{escape(str(cvss.get('severity', 'n/a')))} "
            f"({cvss.get('score', 'n/a')})</td>"
            f"<td>{kev}</td><td>{epss if epss is not None else 'n/a'}</td></tr>"
        )

    html = f"""<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8">
<title>AERA Batch Report</title>
<style>
body{{font-family:system-ui,sans-serif;max-width:960px;margin:2rem auto;padding:0 1rem;color:#1a1a1a}}
.cards{{display:flex;gap:1rem;flex-wrap:wrap;margin:1rem 0}}
.card{{border:1px solid #ddd;border-radius:8px;padding:1rem 1.25rem;min-width:140px}}
.card b{{font-size:1.6rem;display:block}}
.row{{display:flex;align-items:center;gap:.5rem;margin:.3rem 0}}
.lbl{{width:90px;font-size:.85rem}}.val{{width:40px;text-align:right;font-size:.85rem}}
.track{{flex:1;background:#eee;border-radius:4px;height:14px}}
.fill{{background:#2563eb;height:14px;border-radius:4px}}
table{{border-collapse:collapse;width:100%;margin:1rem 0}}
th,td{{border:1px solid #ddd;padding:.4rem .6rem;text-align:left;font-size:.9rem}}
th{{background:#f5f5f5}}.fail{{color:#b91c1c}}
h2{{margin-top:2rem;border-bottom:2px solid #eee;padding-bottom:.3rem}}
.note{{color:#555;font-size:.85rem}}
</style></head><body>
<h1>AERA Batch Vulnerability Report</h1>
<p class="note">Authorized defensive research only. Generated from isolated lab validation.</p>
<div class="cards">
<div class="card"><b>{summary['total']}</b>CVEs processed</div>
<div class="card"><b>{summary['kev_hits']}</b>in CISA KEV</div>
<div class="card"><b>{summary['avg_epss'] if summary['avg_epss'] is not None else 'n/a'}</b>avg EPSS</div>
<div class="card"><b>{summary['failed']}</b>failed</div>
</div>
<h2>Severity distribution</h2>{sev_bars}
<h2>Top weakness types (CWE)</h2>
<table><tr><th>CWE</th><th>Count</th></tr>{cwe_rows}</table>
<h2>Most affected vendors</h2>
<table><tr><th>Vendor</th><th>Count</th></tr>{vendor_rows}</table>
<h2>Per-CVE results</h2>
<table><tr><th>CVE</th><th>Severity</th><th>KEV</th><th>EPSS</th></tr>{cve_rows}</table>
</body></html>"""
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(html, encoding="utf-8")
    return out_path
