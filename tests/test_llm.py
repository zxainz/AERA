"""Tests for the LLM client: retries and configuration."""
import pytest

import aera.llm as llm_mod
from aera.llm import OpenAICompatibleProvider


class FakeResp:
    def __init__(self, payload):
        self._payload = payload

    def raise_for_status(self):
        pass

    def json(self):
        return self._payload


def test_complete_retries_then_succeeds(monkeypatch):
    calls = []

    def flaky_post(*a, **k):
        calls.append(1)
        if len(calls) < 3:
            raise llm_mod.requests.RequestException("flaky")
        return FakeResp({"choices": [{"message": {"content": "hello"}}]})

    monkeypatch.setattr(llm_mod.requests, "post", flaky_post)
    monkeypatch.setattr(llm_mod.time, "sleep", lambda s: None)
    provider = OpenAICompatibleProvider(api_key="x", max_retries=3)
    assert provider.complete("sys", "user") == "hello"
    assert len(calls) == 3


def test_complete_raises_after_exhausting_retries(monkeypatch):
    def boom(*a, **k):
        raise llm_mod.requests.RequestException("down")

    monkeypatch.setattr(llm_mod.requests, "post", boom)
    monkeypatch.setattr(llm_mod.time, "sleep", lambda s: None)
    provider = OpenAICompatibleProvider(api_key="x", max_retries=2)
    with pytest.raises(RuntimeError, match="2 attempts"):
        provider.complete("sys", "user")


def test_missing_api_key_raises(monkeypatch):
    monkeypatch.delenv("AERA_LLM_API_KEY", raising=False)
    with pytest.raises(RuntimeError, match="AERA_LLM_API_KEY"):
        OpenAICompatibleProvider()
