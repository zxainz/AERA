"""Educational report generation -- Markdown output for defenders."""
from __future__ import annotations

from datetime import datetime, timezone

# ---------------------------------------------------------------------------
# Client-ready reporting: executive summary + business-impact framing.
# Template-based (no LLM needed) so it works offline and stays deterministic.
# ---------------------------------------------------------------------------

IMPACT_STATEMENTS = {
    "CRITICAL": (
        "Full compromise of affected systems is a realistic outcome. "
        "Exploitation typically yields privileged code execution or complete "
        "data access with low attacker effort. Treat as a patch-now item and "
        "hunt for signs of prior exploitation."
    ),
    "HIGH": (
        "Serious impact on confidentiality, integrity, or availability. "
        "Exploitation is practical for a skilled attacker and may lead to "
        "lateral movement. Schedule remediation in the current patch cycle."
    ),
    "MEDIUM": (
        "Moderate impact, usually requiring specific preconditions "
        "(authenticated access, user interaction, or adjacent network). "
        "Remediate in the normal cycle; re-assess if preconditions change."
    ),
    "LOW": (
        "Limited direct impact. Fix opportunistically or accept with "
        "documented rationale."
    ),
}


def impact_statement(severity: str) -> str:
    """Business-impact paragraph for a severity level."""
    return IMPACT_STATEMENTS.get((severity or "").upper(),
                                 IMPACT_STATEMENTS["LOW"])


def _batch_rows(results: list[dict]) -> list[dict]:
    """Flatten batch results into sortable finding rows."""
    rows = []
    for r in results:
        if not r.get("ok"):
            continue
        res = r.get("result", {})
        cve = res.get("cve", {})
        cvss = cve.get("cvss_v3") or {}
        intel = res.get("intel") or {}
        test = res.get("test_result") or {}
        rows.append({
            "cve_id": cve.get("id", r.get("cve_id", "")),
            "severity": (cvss.get("severity") or "UNKNOWN").upper(),
            "score": cvss.get("score"),
            "kev": bool(intel.get("kev")),
            "epss": (intel.get("epss") or {}).get("score"),
            "verdict": test.get("verdict", "unknown"),
            "description": (cve.get("description") or "")[:160],
        })
    return rows


def _priority_key(row: dict) -> tuple:
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "UNKNOWN": 4}
    return (
        0 if row["kev"] else 1,
        0 if row["verdict"] == "vulnerable" else 1,
        sev_rank.get(row["severity"], 4),
        -(row["epss"] or 0),
    )


def generate_executive_summary(results: list[dict]) -> str:
    """One-page executive summary from batch results (template-based)."""
    rows = _batch_rows(results)
    total = len(results)
    ok = len(rows)
    by_sev: dict[str, int] = {}
    for row in rows:
        by_sev[row["severity"]] = by_sev.get(row["severity"], 0) + 1
    kev_rows = [r for r in rows if r["kev"]]
    confirmed = [r for r in rows if r["verdict"] == "vulnerable"]
    ordered = sorted(rows, key=_priority_key)
    top = ordered[:3]

    if kev_rows or confirmed:
        risk = ("**HIGH** -- actively exploited or sandbox-confirmed "
                "vulnerabilities are present. Immediate action recommended.")
    elif by_sev.get("CRITICAL") or by_sev.get("HIGH"):
        risk = ("**ELEVATED** -- high-severity issues present but none are "
                "known-exploited or lab-confirmed. Patch in this cycle.")
    elif ok:
        risk = "**MODERATE** -- no critical exposure identified in this batch."
    else:
        risk = "**UNKNOWN** -- no successful analyses in this batch."

    lines = [
        "## Executive Summary",
        "",
        f"Assessed **{total}** CVE(s) ({ok} analyzed successfully). "
        f"Overall risk: {risk}",
        "",
        "- Severity mix: " + (", ".join(
            f"{s}: {n}" for s, n in sorted(by_sev.items())) or "n/a"),
        f"- CISA KEV (actively exploited in the wild): **{len(kev_rows)}**",
        f"- Sandbox-confirmed vulnerable: **{len(confirmed)}**",
        "",
    ]
    if top:
        lines += ["### Top priorities", ""]
        for i, row in enumerate(top, 1):
            flags = []
            if row["kev"]:
                flags.append("KEV")
            if row["verdict"] == "vulnerable":
                flags.append("confirmed")
            flag = f" ({', '.join(flags)})" if flags else ""
            lines.append(
                f"{i}. **{row['cve_id']}** [{row['severity']}]"
                f"{flag} -- {row['description']}"
            )
        lines.append("")
    return "\n".join(lines)


def render_client_report(results: list[dict]) -> str:
    """Full client-facing report: summary, findings, remediation roadmap."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    rows = sorted(_batch_rows(results), key=_priority_key)
    lines = [
        "# Penetration Test — Vulnerability Assessment",
        "",
        f"_Generated {now}. Authorized testing only._",
        "",
        generate_executive_summary(results),
        "## Scope & Method",
        "",
        "Each CVE was enriched with CISA KEV and EPSS threat intel, analyzed "
        "for root cause and attacker preconditions, and -- where a lab "
        "environment was available -- validated with a proof-of-concept run "
        "in an isolated, network-disconnected container. Findings below are "
        "ordered by remediation priority: actively exploited first, then "
        "lab-confirmed, then by severity and exploit probability.",
        "",
        "## Prioritized Findings",
        "",
    ]
    if not rows:
        lines.append("No findings to report in this batch.")
    for i, row in enumerate(rows, 1):
        flags = []
        if row["kev"]:
            flags.append("CISA KEV -- actively exploited")
        if row["verdict"] == "vulnerable":
            flags.append("lab-confirmed")
        elif row["verdict"] == "not_vulnerable":
            flags.append("not reproduced in lab")
        lines += [
            f"### {i}. {row['cve_id']} — {row['severity']}"
            + (f" (CVSS {row['score']})" if row["score"] else ""),
            "",
            f"- Status: {', '.join(flags) if flags else 'unconfirmed'}",
            f"- EPSS (exploit probability): {row['epss'] if row['epss'] is not None else 'n/a'}",
            f"- Summary: {row['description']}",
            "",
            "**Business impact.** " + impact_statement(row["severity"]),
            "",
        ]
    lines += [
        "## Remediation Roadmap",
        "",
        "1. Patch all **CISA KEV** items immediately (they are exploited now).",
        "2. Patch **lab-confirmed** items in the current cycle.",
        "3. Work down the remaining list by severity, then EPSS score.",
        "4. Re-validate each fix in the isolated lab before closing the finding.",
        "",
        "---",
        "_Unauthorized use of this report's contents is prohibited. "
        "See ETHICAL_USAGE.md._",
    ]
    return "\n".join(lines)


def generate_markdown_report(
    cve: dict,
    analysis: str,
    poc: str,
    test_result: dict | None,
    intel: dict | None = None,
    attempts: list[dict] | None = None,
) -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    cvss = cve.get("cvss_v3", {}) or {}
    lines = [
        f"# Vulnerability Research Report: {cve.get('id')}",
        "",
        f"_Generated {now} for authorized defensive research only._",
        "",
        "## CVE Summary",
        "",
        f"- **Description:** {cve.get('description')}",
        f"- **CVSS v3.1:** {cvss.get('score')} ({cvss.get('severity')})",
        f"- **Vector:** `{cvss.get('vector')}`",
        f"- **CWEs:** {', '.join(cve.get('cwes') or ['n/a'])}",
        f"- **Published:** {cve.get('published')}",
        "",
        "## Threat Intel",
        "",
    ]
    if intel:
        kev = intel.get("kev")
        epss = intel.get("epss") or {}
        lines.append(
            "- **CISA KEV (actively exploited):** "
            + ("YES -- prioritize patching" if kev else "not listed")
        )
        if kev:
            lines.append(f"  - Vendor/project: {kev.get('vendorProject')}")
            lines.append(f"  - Product: {kev.get('product')}")
            lines.append(f"  - Required action: {kev.get('requiredAction')}")
            lines.append(f"  - Due date: {kev.get('dueDate')}")
        lines.append(
            f"- **EPSS score:** {epss.get('score', 'n/a')} "
            f"(percentile {epss.get('percentile', 'n/a')}, "
            f"as of {epss.get('date', 'n/a')})"
        )
        lines.append("")
    else:
        lines += ["Intel enrichment was unavailable for this run.", ""]
    lines += [
        "## Defensive Analysis",
        "",
        analysis,
        "",
        "## Validation PoC (lab-only)",
        "",
        "> Tested in an isolated container with no network access. "
        "Intended for validating the vulnerability mechanism in your own lab.",
        "",
    ]
    if poc:
        lines += ["```python", poc, "```", ""]
    else:
        lines += ["PoC generation was skipped for this run (analysis only).", ""]
    lines += [
        "## Sandbox Test Result",
        "",
    ]
    if test_result is None:
        lines.append("Sandbox testing was disabled for this run.")
    elif test_result.get("error"):
        lines.append(f"Test error: `{test_result['error']}`")
    else:
        lines += [
            f"- Exit code: `{test_result.get('exit_code')}`",
            f"- Verdict: **{test_result.get('verdict', 'unknown')}**",
            f"- Container: `{test_result.get('container_id')}`",
        ]
        if attempts:
            lines.append(
                "- Attempts: "
                + ", ".join(
                    f"#{a['attempt']} (exit {a['exit_code']}, {a['verdict']})"
                    for a in attempts
                )
            )
        lines += [
            "",
            "```",
            (test_result.get("stdout") or "(no stdout)")[:4000],
            "```",
        ]
        if test_result.get("stderr"):
            lines += ["", "stderr:", "```", test_result["stderr"][:2000], "```"]
    lines += [
        "",
        "## Remediation Guidance",
        "",
        "Prioritize patching based on the CVSS score and the preconditions above. "
        "Verify the fix in the same isolated lab before deploying.",
        "",
        "---",
        "_Unauthorized use of this report's contents is prohibited. "
        "See ETHICAL_USAGE.md._",
    ]
    return "\n".join(lines)


def generate_codebase_report(
    stats: dict,
    findings: list[dict],
    reviews: list[dict],
    crashes: list[dict],
    iterations: int,
) -> str:
    """Structured report for the five-function codebase pipeline."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sev_rank = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    ordered = sorted(findings, key=lambda f: sev_rank.get(f["severity"], 3))
    lines = [
        "# Codebase Security Report",
        "",
        f"_Generated {now} for authorized defensive research only._",
        "",
        "## 1. Target Summary",
        "",
        f"- Path scanned: `{stats.get('root')}`",
        f"- Files: {stats.get('files')}, lines: {stats.get('lines')}",
        "- Languages: "
        + (", ".join(f"{k} ({v})" for k, v in stats.get("by_language", {}).items())
           or "none detected"),
        "",
        "## 2. Static Analysis Findings",
        "",
        f"{len(findings)} finding(s). Pattern-based triage aid — "
        "confirm before acting.",
        "",
    ]
    if ordered:
        lines.append("| Severity | Rule | Location | Issue |")
        lines.append("|---|---|---|---|")
        for f in ordered:
            lines.append(
                f"| {f['severity']} | `{f['rule_id']}` | "
                f"`{f['file']}:{f['line']}` | {f['title']} |"
            )
        lines.append("")
        for f in ordered:
            lines += [
                f"### `{f['rule_id']}` — {f['title']} ({f['severity']})",
                "",
                f"- Location: `{f['file']}:{f['line']}`",
                f"- Code: `{f['snippet']}`",
                f"- Remediation: {f['fix']}",
                "",
            ]
    else:
        lines.append("No pattern findings.")
        lines.append("")

    if reviews:
        lines += ["## 3. LLM Deep Review", ""]
        for r in reviews:
            f = r["finding"]
            lines += [
                f"### `{f['rule_id']}` at `{f['file']}:{f['line']}` — "
                f"**{r['verdict']}**",
                "",
                "```",
                r["review"][:2000],
                "```",
                "",
            ]

    lines += [
        "## 4. Dynamic Testing (Fuzzing)",
        "",
    ]
    if iterations:
        lines.append("Campaign: {} mutated inputs, network-isolated sandbox.".format(iterations))
        lines.append(
            "Unique crashes: **{}** ({} reproducible).".format(
                len(crashes), sum(1 for c in crashes if c["reproducible"])))
        lines.append("")
        for bug in crashes:
            ex = bug["example"]
            lines += [
                "### Crash `{}` ×{} — **{}** — reproducible: **{}**".format(
                    bug["signature"], bug["count"],
                    bug.get("severity", "UNKNOWN"), bug["reproducible"]),
                "",
                "- Why this severity: {}".format(
                    bug.get("severity_reason", "n/a")),
                "- Signal: {}, exit: {}, keyword: `{}`".format(
                    ex.get("signal"), ex.get("exit_code"), ex.get("keyword")),
                "- stderr head:",
                "```",
                (bug.get("stderr_head") or "(none)")[:1000],
                "```",
                "- Repro input (hex, first 128 bytes): "
                "`{}`".format(ex["input"][:128].hex()),
                "",
            ]
    else:
        lines.append("Fuzzing was not run for this scan "
                     "(use `aera scan-code --fuzz`).")
        lines.append("")

    lines += [
        "## 5. Remediation Guidance",
        "",
        "1. Triage CRITICAL/HIGH static findings first; confirm each with "
        "the LLM review or a targeted fuzz run.",
        "2. For each reproducible crash, fix the root cause (bounds check, "
        "safe API, input validation) — not just the crashing input.",
        "3. Re-run `aera scan-code --fuzz` after patching to confirm the "
        "crash class is gone.",
        "",
        "---",
        "_Authorized testing only. See ETHICAL_USAGE.md._",
    ]
    return "\n".join(lines)
