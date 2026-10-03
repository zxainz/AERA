"""Analysis-only example: no sandbox, no PoC execution.

Useful for triage -- understand a CVE and its threat intel without
generating or running anything.
"""
import asyncio
import os

from dotenv import load_dotenv

from aera import AutonomousExploitResearchAssistant

load_dotenv()


async def main() -> None:
    aera = AutonomousExploitResearchAssistant(
        sandbox_enabled=False,  # analysis only
    )
    token = aera.authorization.generate_token(
        user_id="researcher@lab.example.com",
        domain=os.environ["AERA_DOMAINS"].split(",")[0].strip(),
        hours=8,
    )
    result = await aera.process_vulnerability(
        cve_id="CVE-2023-4966",  # Citrix Bleed
        user_token=token,
        intel=True,
        lab_context=False,
    )
    cve = result["cve"]
    intel = result["intel"] or {}
    print(f"{cve['id']}: CVSS {cve['cvss_v3']['score']} ({cve['cvss_v3']['severity']})")
    print(f"KEV listed: {bool(intel.get('kev'))}, "
          f"EPSS: {(intel.get('epss') or {}).get('score')}")
    print("\n--- Analysis ---\n")
    print(result["analysis"])


if __name__ == "__main__":
    asyncio.run(main())
