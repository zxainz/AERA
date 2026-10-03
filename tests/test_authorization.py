"""Tests for the authorization module. No network or Docker needed."""
import os
import time
from datetime import datetime, timedelta, timezone

import jwt
import pytest

from aera.authorization import AuthorizationError, AuthorizationManager


@pytest.fixture()
def manager(monkeypatch):
    monkeypatch.setenv("AERA_JWT_SECRET", "test-secret-not-real")
    monkeypatch.setenv("AERA_DOMAINS", "lab.example.com,client.example.com")
    return AuthorizationManager()


def test_missing_secret_raises(monkeypatch):
    monkeypatch.delenv("AERA_JWT_SECRET", raising=False)
    with pytest.raises(AuthorizationError):
        AuthorizationManager()


def test_generate_and_validate_roundtrip(manager):
    token = manager.generate_token("alice@lab.example.com", "lab.example.com")
    claims = manager.validate(token)
    assert claims["sub"] == "alice@lab.example.com"
    assert claims["scope"] == "exploit_research"


def test_unauthorized_domain_rejected(manager):
    with pytest.raises(AuthorizationError):
        manager.generate_token("mallory@evil.com", "evil.com")


def test_expired_token_rejected(monkeypatch):
    monkeypatch.setenv("AERA_JWT_SECRET", "test-secret-not-real")
    monkeypatch.setenv("AERA_DOMAINS", "lab.example.com")
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    token = jwt.encode(
        {"sub": "x", "domain": "lab.example.com", "scope": "exploit_research",
         "exp": int(past.timestamp())},
        "test-secret-not-real",
        algorithm="HS256",
    )
    with pytest.raises(AuthorizationError, match="expired"):
        AuthorizationManager().validate(token)


def test_wrong_scope_rejected(monkeypatch):
    monkeypatch.setenv("AERA_JWT_SECRET", "test-secret-not-real")
    monkeypatch.setenv("AERA_DOMAINS", "")
    future = datetime.now(timezone.utc) + timedelta(hours=1)
    token = jwt.encode(
        {"sub": "x", "domain": "lab.example.com", "scope": "admin",
         "exp": int(future.timestamp())},
        "test-secret-not-real",
        algorithm="HS256",
    )
    with pytest.raises(AuthorizationError, match="scope"):
        AuthorizationManager().validate(token)
