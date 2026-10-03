"""Append-only audit log for AERA.

Every significant action (token minted, CVE processed, PoC tested) is
recorded as a JSON line with timestamp and actor. The log file should live
on append-only / WORM storage in production; this module just guarantees
the records are written atomically and never overwritten in-process.
"""
from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path


from collections import defaultdict
from typing import Callable


class AuditLogger:
    def __init__(self, path: str | os.PathLike | None = None) -> None:
        self.path = Path(
            path or os.environ.get("AERA_AUDIT_LOG", "aera-audit.log")
        )
        self._alert_callbacks: list[Callable[[dict], None]] = []

    def on_alert(self, callback: Callable[[dict], None]) -> None:
        """Register an alert callback for suspicious patterns."""
        self._alert_callbacks.append(callback)

    def log(self, event: str, actor: str, **details) -> dict:
        record = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "actor": actor,
            **details,
        }
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(record, default=str) + "\n")

        # Evaluate against active security alerts
        self._check_alerts(record)
        return record

    def read_records(self) -> list[dict]:
        """Read all historical audit log records."""
        if not self.path.exists():
            return []
        records = []
        with self.path.open("r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        continue
        return records

    def _check_alerts(self, new_record: dict) -> None:
        """Trigger callbacks if an alert condition is detected."""
        alerts = []
        event = new_record.get("event", "")
        actor = new_record.get("actor", "unknown")

        # Immediate single-event checks
        if event in ("auth_failed", "unauthorized_domain_attempt", "poc_test_failed"):
            if "unauthorized" in event or "domain" in event:
                alerts.append({
                    "type": "unauthorized_access_attempt",
                    "actor": actor,
                    "details": new_record,
                    "message": f"Suspicious unauthorized domain or scope access attempt by actor {actor!r}",
                })

        for alert in alerts:
            for cb in self._alert_callbacks:
                try:
                    cb(alert)
                except Exception:
                    pass

    def detect_suspicious_patterns(self, window_minutes: int = 60) -> list[dict]:
        """Analyze audit records to detect suspicious activity patterns."""
        records = self.read_records()
        if not records:
            return []

        now = datetime.now(timezone.utc)
        recent = []
        for r in records:
            try:
                ts = datetime.fromisoformat(r["ts"])
                if (now - ts).total_seconds() <= window_minutes * 60:
                    recent.append(r)
            except (ValueError, KeyError):
                continue

        patterns = []
        # 1. Burst failures by actor
        failures_by_actor = defaultdict(int)
        runs_by_actor = defaultdict(int)
        for r in recent:
            actor = r.get("actor", "unknown")
            event = r.get("event", "")
            runs_by_actor[actor] += 1
            if "failed" in event or "unauthorized" in event or "error" in event:
                failures_by_actor[actor] += 1

        for actor, count in failures_by_actor.items():
            if count >= 3:
                patterns.append({
                    "pattern": "repeated_failures",
                    "actor": actor,
                    "count": count,
                    "severity": "HIGH",
                    "description": f"Actor {actor} encountered {count} failures in {window_minutes} minutes.",
                })

        # 2. Velocity spike (> 20 actions in window)
        for actor, count in runs_by_actor.items():
            if count >= 20:
                patterns.append({
                    "pattern": "velocity_spike",
                    "actor": actor,
                    "count": count,
                    "severity": "MEDIUM",
                    "description": f"High activity velocity: actor {actor} ran {count} actions in {window_minutes} minutes.",
                })

        return patterns
