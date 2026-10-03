"""Basic AERA usage. Requires: .env configured, Docker running."""
import asyncio
import os

from dotenv import load_dotenv

from aera import AutonomousExploitResearchAssistant

load_dotenv()


async def main() -> None:
    aera = AutonomousExploitResearchAssistant()

    # Mint a short-lived token for yourself (or your team's token service).
    token = aera.authorization.generate_token(
        user_id="researcher@lab.example.com",
        domain=os.environ["AERA_DOMAINS"].split(",")[0].strip(),
        hours=8,
    )

    result = await aera.process_vulnerability(
        cve_id="CVE-2021-44228",  # Log4Shell -- well-known, good for a first run
        user_token=token,
        vuln_type="web",
    )

    with open("report-CVE-2021-44228.md", "w", encoding="utf-8") as fh:
        fh.write(result["report_markdown"])
    print("Report written to report-CVE-2021-44228.md")


if __name__ == "__main__":
    asyncio.run(main())
