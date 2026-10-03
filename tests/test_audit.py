"""Tests for AuditLogger, alert callbacks, and suspicious pattern detection."""
from __future__ import annotations

import json
from aera.audit import AuditLogger


def test_audit_logs_event(tmp_path):
    log_file = tmp_path / "audit.log"
    logger = AuditLogger(log_file)
    logger.log("test_event", "alice@example.com", detail="abc")

    assert log_file.exists()
    records = logger.read_records()
    assert len(records) == 1
    assert records[0]["event"] == "test_event"
    assert records[0]["actor"] == "alice@example.com"
    assert records[0]["detail"] == "abc"


def test_audit_alert_callback(tmp_path):
    log_file = tmp_path / "audit.log"
    logger = AuditLogger(log_file)
    alerts = []
    logger.on_alert(lambda a: alerts.append(a))

    logger.log("unauthorized_domain_attempt", "attacker@evil.com", target="other.com")
    assert len(alerts) == 1
    assert alerts[0]["type"] == "unauthorized_access_attempt"
    assert alerts[0]["actor"] == "attacker@evil.com"


def test_detect_suspicious_patterns(tmp_path):
    log_file = tmp_path / "audit.log"
    logger = AuditLogger(log_file)

    for _ in range(4):
        logger.log("auth_failed", "bad_actor", reason="invalid_token")

    patterns = logger.detect_suspicious_patterns(window_minutes=60)
    assert any(p["pattern"] == "repeated_failures" and p["actor"] == "bad_actor" for p in patterns)
