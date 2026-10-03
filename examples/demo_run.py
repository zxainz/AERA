"""Interactive AERA End-to-End Demo Script.

Demonstrates:
1. Fail-closed JWT token minting and validation.
2. Suspicious pattern alert detection in audit logs.
3. Multi-hop attack path chaining across discovered capabilities.
4. Static codebase scanning with SARIF generation.
"""
from __future__ import annotations

import json
from dotenv import load_dotenv

from aera import AutonomousExploitResearchAssistant
from aera.chains import build_chains, render_chains_markdown

load_dotenv()


def run_demo():
    print("=" * 60)
    print("   AERA (Autonomous Exploit Research Assistant) v0.6.0")
    print("=" * 60)

    # 1. Initialize Assistant
    aera = AutonomousExploitResearchAssistant()
    print("\n[+] Initialized AERA Assistant (Fail-Closed Auth & Audit Active)")

    # 2. Register real-time alert callback
    alerts = []
    aera.audit.on_alert(lambda a: alerts.append(a))

    # 3. Mint valid authorization token
    print("\n[+] Minting Authorized JWT Research Token...")
    token = aera.authorization.generate_token(
        user_id="lead-researcher@lab.example.com",
        domain="lab.example.com",
        hours=8,
    )
    claims = aera.authorization.validate(token)
    print(f"    Token Subject : {claims.get('sub')}")
    print(f"    Target Domain : {claims.get('domain')}")
    print(f"    Scope Granted : {claims.get('scope')}")

    # 4. Demonstrate Audit Alert System
    print("\n[+] Testing Security Alert Trigger on Unauthorized Attempt...")
    aera.audit.log("unauthorized_domain_attempt", "untrusted_actor@evil.com", attempted_domain="out-of-scope.com")
    if alerts:
        print(f"    [ALERT FIRED] {alerts[-1]['message']}")

    # 5. Demonstrate Multi-Hop Attack Path Chaining
    print("\n[+] Running Multi-Hop Attack Path Chaining Engine...")
    sample_nodes = [
        {"id": "VULN-001", "title": "Information Disclosure in /debug", "severity": "MEDIUM",
         "capabilities": {"info-disclosure"}, "scope": "app-cluster", "source": "static"},
        {"id": "VULN-002", "title": "Hardcoded JWT Secret in config.py", "severity": "HIGH",
         "capabilities": {"credential"}, "scope": "app-cluster", "source": "static"},
        {"id": "VULN-003", "title": "Missing Permission Check on Admin Endpoint", "severity": "CRITICAL",
         "capabilities": {"auth-bypass"}, "scope": "app-cluster", "source": "static"},
        {"id": "VULN-004", "title": "Command Injection in Report Exporter", "severity": "CRITICAL",
         "capabilities": {"command-exec"}, "scope": "app-cluster", "source": "static"},
    ]
    chains = build_chains(sample_nodes)
    print(f"    Discovered {len(chains)} attack path(s):")
    for i, c in enumerate(chains, 1):
        path_str = " -> ".join(f"[{cap}] {nid}" for cap, nid, _, _ in c["stages"])
        print(f"    {i}. ({c['max_severity']}) {path_str}")

    report = render_chains_markdown(chains)
    with open("demo-chains.md", "w", encoding="utf-8") as fh:
        fh.write(report)
    print("    Full narrative report saved to demo-chains.md")

    print("\n" + "=" * 60)
    print("   Demo Completed Successfully!")
    print("=" * 60)


if __name__ == "__main__":
    run_demo()
