"""Batch example: process several CVEs, then build a dashboard.

Usage:
    python examples/batch_example.py CVE-2021-44228 CVE-2023-4966 ...

Requires: .env configured, Docker running.
"""
import asyncio
import os
import sys

from dotenv import load_dotenv

from aera import (
    AutonomousExploitResearchAssistant,
    BatchRunner,
    render_html_dashboard,
    summarize,
)

load_dotenv()


async def main(cve_ids: list[str]) -> None:
    aera = AutonomousExploitResearchAssistant()
    token = aera.authorization.generate_token(
        user_id="researcher@lab.example.com",
        domain=os.environ["AERA_DOMAINS"].split(",")[0].strip(),
        hours=8,
    )

    runner = BatchRunner(aera, max_concurrency=2, output_dir="batch-out")
    results = await runner.run(cve_ids, token)

    ok = sum(1 for r in results if r["ok"])
    print(f"Done: {ok}/{len(results)} succeeded. Reports in batch-out/")

    summary = summarize(results)
    dashboard = render_html_dashboard(summary, results, "batch-out/dashboard.html")
    print(f"Dashboard: {dashboard}")
    print(
        f"KEV hits: {summary['kev_hits']}, "
        f"avg EPSS: {summary['avg_epss']}, "
        f"top CWEs: {summary['top_cwes'][:3]}"
    )


if __name__ == "__main__":
    ids = sys.argv[1:] or ["CVE-2021-44228", "CVE-2023-4966"]
    asyncio.run(main(ids))
