"""Batch CVE processing: concurrency-limited, checkpointed, auditable.

- Authorization is validated once up front; every item is still audit-logged.
- A checkpoint file records completed CVE IDs, so an interrupted batch
  resumes where it left off instead of redoing paid LLM calls.
- Per-CVE Markdown reports and JSON results are written to the output dir.
"""
from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from pathlib import Path


class BatchRunner:
    def __init__(
        self,
        aera,
        *,
        max_concurrency: int = 3,
        output_dir: str | Path = "batch-out",
    ) -> None:
        self.aera = aera
        self.max_concurrency = max(1, max_concurrency)
        self.output_dir = Path(output_dir)
        self.checkpoint_file = self.output_dir / "checkpoint.json"

    # -- checkpoint -----------------------------------------------------
    def _load_done(self) -> set[str]:
        if self.checkpoint_file.exists():
            try:
                return set(json.loads(self.checkpoint_file.read_text()))
            except (json.JSONDecodeError, OSError):
                return set()
        return set()

    def _save_done(self, done: set[str]) -> None:
        self.output_dir.mkdir(parents=True, exist_ok=True)
        self.checkpoint_file.write_text(
            json.dumps(sorted(done), indent=2), encoding="utf-8"
        )

    # -- outputs --------------------------------------------------------
    def _write_outputs(self, cve_id: str, result: dict) -> None:
        safe = "".join(ch if ch.isalnum() or ch in "-_" else "_" for ch in cve_id)
        self.output_dir.mkdir(parents=True, exist_ok=True)
        (self.output_dir / f"{safe}.md").write_text(
            result.get("report_markdown", ""), encoding="utf-8"
        )
        serializable = {
            "cve": result.get("cve"),
            "analysis": result.get("analysis"),
            "poc": result.get("poc"),
            "test_result": result.get("test_result"),
            "intel": result.get("intel"),
            "generated": datetime.now(timezone.utc).isoformat(),
        }
        (self.output_dir / f"{safe}.json").write_text(
            json.dumps(serializable, default=str, indent=2), encoding="utf-8"
        )

    # -- run ------------------------------------------------------------
    async def run(
        self,
        cve_ids: list[str],
        user_token: str,
        *,
        vuln_types: dict[str, str] | None = None,
    ) -> list[dict]:
        claims = self.aera.authorization.validate(user_token)  # gate once
        actor = claims.get("sub", "unknown")
        vuln_types = vuln_types or {}

        done = self._load_done()
        todo = [c for c in dict.fromkeys(cve_ids) if c not in done]
        self.aera.audit.log(
            "batch_started", actor,
            requested=len(cve_ids), queued=len(todo), skipped=len(done),
        )

        sem = asyncio.Semaphore(self.max_concurrency)
        results: list[dict] = []

        async def one(cve_id: str) -> dict:
            async with sem:
                try:
                    result = await self.aera.process_vulnerability(
                        cve_id,
                        user_token,
                        vuln_type=vuln_types.get(cve_id, "web"),
                    )
                    self._write_outputs(cve_id, result)
                    done.add(cve_id)
                    self._save_done(done)
                    self.aera.audit.log("batch_item_done", actor, cve_id=cve_id)
                    return {"cve_id": cve_id, "ok": True, "result": result}
                except Exception as exc:  # noqa: BLE001 - one bad CVE must not kill the batch
                    self.aera.audit.log(
                        "batch_item_failed", actor, cve_id=cve_id, error=str(exc)
                    )
                    return {"cve_id": cve_id, "ok": False, "error": str(exc)}

        for coro in asyncio.as_completed([one(c) for c in todo]):
            results.append(await coro)

        self.aera.audit.log(
            "batch_finished", actor,
            succeeded=sum(1 for r in results if r["ok"]),
            failed=sum(1 for r in results if not r["ok"]),
        )
        return results
