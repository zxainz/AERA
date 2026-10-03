"""SARIF output: findings in the industry-standard format.

SARIF (Static Analysis Results Interchange Format) 2.1.0 lets AERA results
render natively in GitHub code scanning, VS Code SARIF Viewer, and other
tooling — no custom dashboard required.
"""
from __future__ import annotations

import json
from pathlib import Path

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"

_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note"}


def findings_to_sarif(findings: list[dict], crashes: list[dict] | None = None, *,
                      tool_name: str = "AERA") -> dict:
    """Build a SARIF 2.1.0 document from findings and fuzz crashes."""
    # Local import: avoids any import cycle with the package root.
    from . import __version__

    rules: dict[str, dict] = {}
    results: list[dict] = []

    def _rule(rule_id: str, title: str, fix: str, severity: str) -> None:
        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": title,
                "shortDescription": {"text": title},
                "fullDescription": {"text": fix or title},
                "properties": {"severity": severity},
            }

    for f in findings:
        _rule(f["rule_id"], f["title"], f.get("fix", ""), f["severity"])
        results.append({
            "ruleId": f["rule_id"],
            "level": _LEVEL.get(f["severity"], "warning"),
            "message": {"text": f["title"]},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f["file"]},
                    "region": {"startLine": max(1, f.get("line", 0))},
                }
            }],
        })

    for bug in crashes or []:
        rid = "AERA-FUZZ-CRASH"
        _rule(rid, "Fuzzer-discovered crash", "", bug.get("severity", "MEDIUM"))
        ex = bug.get("example", {})
        results.append({
            "ruleId": rid,
            "level": _LEVEL.get(bug.get("severity", "MEDIUM"), "warning"),
            "message": {"text": (
                f"crash {bug.get('signature')} ×{bug.get('count')} "
                f"(signal={ex.get('signal')}, keyword={ex.get('keyword')}, "
                f"reproducible={bug.get('reproducible')})"
            )},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": bug.get("target", "fuzz-target")},
                }
            }],
        })

    return {
        "version": SARIF_VERSION,
        "$schema": SARIF_SCHEMA,
        "runs": [{
            "tool": {"driver": {
                "name": tool_name,
                "version": __version__,
                "informationUri": "https://github.com/",
                "rules": list(rules.values()),
            }},
            "results": results,
        }],
    }


def write_sarif(path: str | Path, findings: list[dict],
                crashes: list[dict] | None = None, **kwargs) -> Path:
    """Write a SARIF document to path. Returns the path."""
    out = Path(path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(
        json.dumps(findings_to_sarif(findings, crashes, **kwargs), indent=2),
        encoding="utf-8",
    )
    return out
