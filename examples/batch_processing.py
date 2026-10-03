"""Batch processing example (as specified in PDF documentation).

Processes several CVEs concurrently with checkpointing and builds a summary dashboard.
Usage:
    python examples/batch_processing.py CVE-2021-44228 CVE-2023-4966
"""
from __future__ import annotations

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
        domain=os.environ.get("AERA_DOMAINS", "company.com").split(",")[0].strip(),
        hours=8,
    )

    runner = BatchRunner(aera, max_concurrency=2, output_dir="batch-out")
    results = await runner.run(cve_ids, token)

    ok = sum(1 for r in results if r["ok"])
    print(f"Done: {ok}/{len(results)} succeeded. Reports in batch-out/")

    summary = summarize(results)
    dashboard = render_html_dashboard(summary, results, "batch-out/dashboard.html")
    print(f"Dashboard generated: {dashboard}")


if __name__ == "__main__":
    ids = sys.argv[1:] or ["CVE-2021-44228", "CVE-2023-4966"]
    asyncio.run(main(ids))
