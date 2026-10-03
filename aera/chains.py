"""Attack-path chaining: link isolated findings into exploit chains.

A pentest is won by chaining: an info disclosure leaks credentials, the
credentials bypass auth, the authenticated session reaches RCE. This module
tags each finding/CVE with the *capabilities* it grants an attacker and
matches them against known chain templates -- within one scope (host/app).

Input nodes: {"id", "title", "severity", "capabilities", "scope"}.
Output: ranked chains with the narrative of how stages connect.
"""
from __future__ import annotations

# Static rule -> attacker capabilities.
RULE_CAPABILITIES: dict[str, set[str]] = {
    "C-GETS": {"memory-corruption"},
    "C-STRCPY": {"memory-corruption"},
    "C-STRCAT": {"memory-corruption"},
    "C-SPRINTF": {"memory-corruption"},
    "C-SCANF-S": {"memory-corruption"},
    "C-SYSTEM": {"command-exec"},
    "C-POPEN": {"command-exec"},
    "PY-EVAL": {"code-exec"},
    "PY-EXEC": {"code-exec"},
    "PY-OS-SYSTEM": {"command-exec"},
    "PY-SHELL-TRUE": {"command-exec"},
    "PY-PICKLE": {"deserialization"},
    "PY-YAML-LOAD": {"deserialization"},
    "JS-EVAL": {"code-exec"},
    "JS-NEW-FUNCTION": {"code-exec"},
    "JS-INNERHTML": {"xss"},
    "JS-EXEC": {"command-exec"},
}

# CWE -> attacker capabilities (for CVE nodes).
CWE_CAPABILITIES: dict[str, set[str]] = {
    "CWE-798": {"credential"},
    "CWE-259": {"credential"},
    "CWE-287": {"auth-bypass"},
    "CWE-306": {"auth-bypass"},
    "CWE-862": {"auth-bypass"},
    "CWE-78": {"command-exec"},
    "CWE-94": {"code-exec"},
    "CWE-95": {"code-exec"},
    "CWE-89": {"sqli"},
    "CWE-200": {"info-disclosure"},
    "CWE-201": {"info-disclosure"},
    "CWE-209": {"info-disclosure"},
    "CWE-22": {"file-access"},
    "CWE-73": {"file-access"},
    "CWE-918": {"ssrf"},
}

# All memory-corruption CWEs grant the memory-corruption capability.
# (Single source of truth lives in utils.BINARY_CWES.)
from .utils import BINARY_CWES  # noqa: E402

for _cwe in BINARY_CWES:
    CWE_CAPABILITIES.setdefault(_cwe, {"memory-corruption"})

# Ordered capability stages -> narrative.
CHAIN_TEMPLATES: list[tuple[list[set[str]], str]] = [
    ([{"credential"}, {"auth-bypass"}],
     "Leaked or default credentials satisfy the broken authentication check."),
    ([{"info-disclosure"}, {"credential"}],
     "The disclosure leaks secrets or credentials usable in the next step."),
    ([{"auth-bypass"}, {"command-exec", "code-exec", "sqli"}],
     "Unauthenticated access reaches a code-execution primitive: full compromise."),
    ([{"credential"}, {"command-exec", "code-exec"}],
     "Valid credentials reach an authenticated code-execution primitive."),
    ([{"ssrf"}, {"info-disclosure", "credential"}],
     "SSRF reaches internal metadata or secret stores."),
    ([{"file-access"}, {"credential", "info-disclosure"}],
     "Arbitrary file read exposes secrets or source code."),
    ([{"memory-corruption"}, {"code-exec"}],
     "Memory corruption is parlayed into code execution."),
    ([{"deserialization"}, {"code-exec"}],
     "Unsafe deserialization yields code execution."),
    ([{"xss"}, {"credential"}],
     "XSS in an authenticated context can steal session credentials."),
]

_SEV_RANK = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def nodes_from_findings(findings: list[dict], scope: str = "codebase") -> list[dict]:
    """Convert static findings into chain nodes."""
    nodes = []
    for f in findings:
        nodes.append({
            "id": f"{f.get('rule_id')}@{f.get('file')}:{f.get('line')}",
            "title": f.get("title", f.get("rule_id", "")),
            "severity": f.get("severity", "MEDIUM"),
            "capabilities": set(RULE_CAPABILITIES.get(f.get("rule_id", ""), set())),
            "scope": scope,
            "source": "static",
        })
    return nodes


def nodes_from_cves(results: list[dict], scope: str = "target") -> list[dict]:
    """Convert batch CVE results into chain nodes (CWE-derived capabilities)."""
    nodes = []
    for r in results:
        if not r.get("ok"):
            continue
        res = r.get("result", {})
        cve = res.get("cve", {})
        caps: set[str] = set()
        for cwe in cve.get("cwes", []):
            caps |= CWE_CAPABILITIES.get(cwe, set())
        test = (res.get("test_result") or {})
        if test.get("verdict") == "vulnerable":
            # A sandbox-confirmed CVE grants whatever its CWE implies, harder.
            pass
        nodes.append({
            "id": cve.get("id", r.get("cve_id", "")),
            "title": (cve.get("description", "")[:100] or "CVE finding"),
            "severity": ((cve.get("cvss_v3") or {}).get("severity") or "MEDIUM"),
            "capabilities": caps,
            "scope": scope,
            "source": "cve",
            "kev": bool((res.get("intel") or {}).get("kev")),
        })
    return nodes


CAPABILITY_TRANSITIONS: dict[str, list[tuple[set[str], str]]] = {
    "info-disclosure": [
        ({"credential"}, "Information disclosure leaks secrets or user credentials."),
        ({"file-access"}, "Information disclosure exposes path structures or file locations."),
    ],
    "file-access": [
        ({"credential", "info-disclosure"}, "Arbitrary file read exposes credentials, config files, or secrets."),
    ],
    "ssrf": [
        ({"credential", "info-disclosure"}, "SSRF reaches cloud metadata services or internal protected resources."),
        ({"auth-bypass"}, "SSRF bypasses boundary network authentication checks."),
    ],
    "xss": [
        ({"credential"}, "XSS executes in victim context to steal session cookies or tokens."),
    ],
    "credential": [
        ({"auth-bypass"}, "Acquired credentials satisfy login verification requirements."),
        ({"code-exec", "command-exec", "sqli"}, "Authenticated access reaches privileged execution sinks."),
    ],
    "auth-bypass": [
        ({"code-exec", "command-exec", "sqli"}, "Unauthenticated access directly reaches execution primitives."),
    ],
    "memory-corruption": [
        ({"code-exec"}, "Memory corruption is leveraged into arbitrary code execution."),
    ],
    "deserialization": [
        ({"code-exec"}, "Unsafe object deserialization executes arbitrary gadgets."),
    ],
    "sqli": [
        ({"credential", "info-disclosure"}, "SQL injection extracts user passwords, hashes, or sensitive tokens."),
        ({"command-exec"}, "Database functions escalate into system command execution."),
    ],
}


def build_chains(nodes: list[dict], max_depth: int = 4) -> list[dict]:
    """Match nodes against chain templates and find multi-hop graph paths within each scope."""
    chains: list[dict] = []
    seen_chains: set[tuple[str, ...]] = set()
    by_scope: dict[str, list[dict]] = {}
    for n in nodes:
        if n["capabilities"]:
            by_scope.setdefault(n["scope"], []).append(n)

    for scope, scoped in by_scope.items():
        # 1. Match predefined chain templates
        for stages, narrative in CHAIN_TEMPLATES:
            used: set[str] = set()
            filled: list[tuple[str, dict]] = []
            ok = True
            for stage in stages:
                cands = sorted(
                    (n for n in scoped
                     if n["id"] not in used and n["capabilities"] & stage),
                    key=lambda n: _SEV_RANK.get(n["severity"], 4),
                )
                if not cands:
                    ok = False
                    break
                pick = cands[0]
                used.add(pick["id"])
                cap = sorted(pick["capabilities"] & stage)[0]
                filled.append((cap, pick))
            if ok:
                node_ids = tuple(n["id"] for _, n in filled)
                if node_ids not in seen_chains:
                    seen_chains.add(node_ids)
                    worst = min((_SEV_RANK.get(n["severity"], 4) for _, n in filled))
                    chains.append({
                        "scope": scope,
                        "stages": [(cap, n["id"], n["title"], n["severity"])
                                   for cap, n in filled],
                        "narrative": narrative,
                        "max_severity": next(
                            k for k, v in _SEV_RANK.items() if v == worst),
                        "length": len(filled),
                    })

        # 2. Multi-hop graph discovery (linking 3+ stages toward execution)
        def _dfs_paths(current_node: dict, current_cap: str, path: list[tuple[str, dict]],
                       narratives: list[str], visited_ids: set[str]):
            if len(path) >= 3 and current_cap in {"code-exec", "command-exec"}:
                node_ids = tuple(n["id"] for _, n in path)
                if node_ids not in seen_chains:
                    seen_chains.add(node_ids)
                    worst = min((_SEV_RANK.get(n["severity"], 4) for _, n in path))
                    chains.append({
                        "scope": scope,
                        "stages": [(cap, n["id"], n["title"], n["severity"])
                                   for cap, n in path],
                        "narrative": " -> ".join(narratives),
                        "max_severity": next(
                            k for k, v in _SEV_RANK.items() if v == worst),
                        "length": len(path),
                    })
            if len(path) >= max_depth:
                return

            for target_caps, step_desc in CAPABILITY_TRANSITIONS.get(current_cap, []):
                next_cands = sorted(
                    (n for n in scoped if n["id"] not in visited_ids and n["capabilities"] & target_caps),
                    key=lambda n: _SEV_RANK.get(n["severity"], 4),
                )
                for cand in next_cands:
                    matched_cap = sorted(cand["capabilities"] & target_caps)[0]
                    _dfs_paths(cand, matched_cap, path + [(matched_cap, cand)],
                               narratives + [step_desc], visited_ids | {cand["id"]})

        entry_caps = {"info-disclosure", "file-access", "ssrf", "xss", "credential"}
        for start_node in scoped:
            for cap in start_node["capabilities"] & entry_caps:
                _dfs_paths(start_node, cap, [(cap, start_node)],
                           [f"Initial access: {start_node['title']}"], {start_node["id"]})

    chains.sort(key=lambda c: (_SEV_RANK.get(c["max_severity"], 4), -c["length"]))
    return chains


def render_chains_markdown(chains: list[dict]) -> str:
    """Human-readable chain report for the pentest notes."""
    if not chains:
        return "# Attack Paths\n\nNo multi-stage chains found among the findings.\n"
    lines = ["# Attack Paths", "",
             f"{len(chains)} candidate chain(s) -- verify each link live "
             "before reporting.", ""]
    for i, c in enumerate(chains, 1):
        lines.append(f"## Chain {i} — {c['max_severity']} (scope: `{c['scope']}`)")
        lines.append("")
        for j, (cap, nid, title, sev) in enumerate(c["stages"], 1):
            lines.append(f"{j}. **[{cap}]** `{nid}` ({sev}) — {title}")
        lines.append("")
        lines.append(f"> {c['narrative']}")
        lines.append("")
    return "\n".join(lines)
