"""JWT-based authorization for AERA.

Design decisions (deliberate, fail-closed):
- The signing secret MUST come from the environment (AERA_JWT_SECRET).
  AERA refuses to start without it -- no hardcoded fallback.
- Tokens are narrow-scope ("exploit_research"), short-lived (default 24h),
  and bound to an authorized research domain.
"""
from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import jwt


class AuthorizationError(Exception):
    """Raised when a request is not authorized to use exploit tooling."""


class AuthorizationManager:
    SCOPE = "exploit_research"

    def __init__(
        self,
        *,
        secret: str | None = None,
        valid_domains: list[str] | None = None,
    ) -> None:
        self._secret = secret or os.environ.get("AERA_JWT_SECRET")
        if not self._secret:
            raise AuthorizationError(
                "AERA_JWT_SECRET is not set. Refusing to start without a signing secret."
            )
        if valid_domains is None:
            valid_domains = [
                d.strip()
                for d in os.environ.get("AERA_DOMAINS", "").split(",")
                if d.strip()
            ]
        self.valid_domains = valid_domains

    def generate_token(self, user_id: str, domain: str, hours: int = 24) -> str:
        if self.valid_domains and domain not in self.valid_domains:
            raise AuthorizationError(
                f"Domain {domain!r} is not an authorized research domain."
            )
        now = datetime.now(timezone.utc)
        payload = {
            "sub": user_id,
            "user_id": user_id,  # PDF specification compatibility
            "domain": domain,
            "scope": self.SCOPE,
            "iat": int(now.timestamp()),
            "exp": int((now + timedelta(hours=hours)).timestamp()),
        }
        return jwt.encode(payload, self._secret, algorithm="HS256")

    def validate(self, token: str) -> dict:
        """Return decoded claims, or raise AuthorizationError."""
        try:
            claims = jwt.decode(token, self._secret, algorithms=["HS256"])
        except jwt.ExpiredSignatureError:
            raise AuthorizationError("Token has expired.")
        except jwt.InvalidTokenError as exc:  # noqa: BLE001 - surfaced to caller
            raise AuthorizationError(f"Invalid token: {exc}") from exc
        if claims.get("scope") != self.SCOPE:
            raise AuthorizationError("Token scope is not 'exploit_research'.")
        if self.valid_domains and claims.get("domain") not in self.valid_domains:
            raise AuthorizationError("Token domain is not authorized.")
        if "user_id" in claims and "sub" not in claims:
            claims["sub"] = claims["user_id"]
        return claims
