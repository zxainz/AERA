"""Tests for the batch runner: checkpointing and resume. No LLM/Docker."""
import asyncio
import json

import pytest

from aera.audit import AuditLogger
from aera.authorization import AuthorizationManager
from aera.batch import BatchRunner


class StubAERA:
    """Minimal stand-in: real auth + audit, fake pipeline."""

    def __init__(self, tmp_path, monkeypatch, fail_on=()):
        monkeypatch.setenv("AERA_JWT_SECRET", "batch-test-secret")
        monkeypatch.setenv("AERA_DOMAINS", "lab.example.com")
        self.authorization = AuthorizationManager()
        self.audit = AuditLogger(tmp_path / "audit.log")
        self.calls = []
        self.fail_on = set(fail_on)

    async def process_vulnerability(self, cve_id, user_token, **kwargs):
        self.authorization.validate(user_token)
        self.calls.append(cve_id)
        if cve_id in self.fail_on:
            raise RuntimeError("simulated failure")
        return {
            "cve": {"id": cve_id},
            "analysis": "a",
            "poc": "p",
            "test_result": None,
            "intel": None,
            "report_markdown": f"# {cve_id}",
        }


@pytest.fixture()
def token(tmp_path, monkeypatch):
    monkeypatch.setenv("AERA_JWT_SECRET", "batch-test-secret")
    monkeypatch.setenv("AERA_DOMAINS", "lab.example.com")
    return AuthorizationManager().generate_token("t@lab.example.com", "lab.example.com")


def test_batch_processes_and_checkpoints(tmp_path, monkeypatch, token):
    aera = StubAERA(tmp_path, monkeypatch)
    runner = BatchRunner(aera, max_concurrency=2, output_dir=tmp_path / "out")
    results = asyncio.run(
        runner.run(["CVE-2024-0001", "CVE-2024-0002"], token)
    )
    assert all(r["ok"] for r in results)
    assert (tmp_path / "out" / "CVE-2024-0001.md").exists()
    assert (tmp_path / "out" / "CVE-2024-0001.json").exists()
    checkpoint = json.loads((tmp_path / "out" / "checkpoint.json").read_text())
    assert set(checkpoint) == {"CVE-2024-0001", "CVE-2024-0002"}


def test_batch_resumes_skipping_done(tmp_path, monkeypatch, token):
    aera = StubAERA(tmp_path, monkeypatch)
    runner = BatchRunner(aera, max_concurrency=2, output_dir=tmp_path / "out")
    asyncio.run(runner.run(["CVE-2024-0001"], token))
    aera.calls.clear()
    results = asyncio.run(
        runner.run(["CVE-2024-0001", "CVE-2024-0002"], token)
    )
    assert aera.calls == ["CVE-2024-0002"]  # first one skipped via checkpoint
    assert len(results) == 1


def test_batch_failure_does_not_kill_batch(tmp_path, monkeypatch, token):
    aera = StubAERA(tmp_path, monkeypatch, fail_on={"CVE-2024-000X"})
    runner = BatchRunner(aera, max_concurrency=2, output_dir=tmp_path / "out")
    results = asyncio.run(
        runner.run(["CVE-2024-000X", "CVE-2024-0001"], token)
    )
    by_id = {r["cve_id"]: r for r in results}
    assert by_id["CVE-2024-000X"]["ok"] is False
    assert by_id["CVE-2024-0001"]["ok"] is True


def test_batch_rejects_bad_token(tmp_path, monkeypatch):
    aera = StubAERA(tmp_path, monkeypatch)
    runner = BatchRunner(aera, output_dir=tmp_path / "out")
    with pytest.raises(Exception):
        asyncio.run(runner.run(["CVE-2024-0001"], "not-a-token"))
