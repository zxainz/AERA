"""Continuous mode: rescan on a schedule and diff against the last run.

Turns AERA from a one-shot tool into a workflow: run `aera watch` (or
`--once` in CI) and get told only about what CHANGED — new findings,
fixed findings — instead of re-reading the full report every time.
"""
from __future__ import annotations

import hashlib
import json
from pathlib import Path

from .codebase import CodebaseTarget


def snapshot_target(target: CodebaseTarget) -> dict[str, str]:
    """Map relative path -> sha1 of contents, for change detection."""
    snapshot = {}
    for f in target.iter_files():
        snapshot[f["path"]] = hashlib.sha1(
            f["text"].encode("utf-8", errors="replace")
        ).hexdigest()
    return snapshot


def load_state(state_file: str | Path) -> dict:
    path = Path(state_file)
    if not path.exists():
        return {"findings": [], "snapshot": {}}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return {"findings": [], "snapshot": {}}


def save_state(state_file: str | Path, state: dict) -> None:
    path = Path(state_file)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(state, indent=2), encoding="utf-8")


def _finding_key(finding: dict) -> tuple:
    return (finding.get("rule_id"), finding.get("file"), finding.get("line"))


def diff_findings(old: list[dict], new: list[dict]) -> dict:
    """Return {"new": [...], "fixed": [...]} by stable finding identity."""
    old_keys = {_finding_key(f) for f in old}
    new_keys = {_finding_key(f) for f in new}
    return {
        "new": [f for f in new if _finding_key(f) not in old_keys],
        "fixed": [f for f in old if _finding_key(f) not in new_keys],
    }


async def scan_and_diff(path: str, user_token: str, state_file: str | Path, *,
                        engine: str = "auto", fuzz: bool = False,
                        target_cmd: list[str] | None = None,
                        iterations: int = 200) -> dict:
    """Run analyze_codebase and diff findings against saved state."""
    # Local import: watch is optional UI-level glue, keep core import light.
    from .core import AutonomousExploitResearchAssistant

    aera = AutonomousExploitResearchAssistant()
    result = await aera.analyze_codebase(
        path, user_token, engine=engine, fuzz=fuzz,
        target_cmd=target_cmd, iterations=iterations,
    )
    prev = load_state(state_file)
    diff = diff_findings(prev.get("findings", []), result["findings"])
    save_state(state_file, {
        "findings": result["findings"],
        "snapshot": snapshot_target(CodebaseTarget(path)),
    })
    return {**result, "new_findings": diff["new"],
            "fixed_findings": diff["fixed"]}
