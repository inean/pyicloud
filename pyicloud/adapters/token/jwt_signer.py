"""HS256 JWT signer adapter."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

from pyicloud.ports import TokenSignerPort


class JwtTokenSigner(TokenSignerPort):
    """Sign and verify JWT bearer tokens for the API layer."""

    _WEAK_SECRETS = {
        "changeme",
        "default",
        "password",
        "pyicloud-api-dev-secret",
        "secret",
    }

    def __init__(
        self,
        *,
        secret: str,
        algorithm: str = "HS256",
        issuer: str = "pyicloud-api",
        audience: str = "pyicloud-cli",
        leeway_seconds: int = 0,
        enforce_strong_secret: bool = False,
    ):
        if not secret:
            raise RuntimeError("JWT secret cannot be empty")
        if enforce_strong_secret and self.is_weak_secret(secret):
            raise RuntimeError("JWT secret is too weak for non-dev runtime")
        self._secret = secret
        self._algorithm = algorithm
        self._issuer = issuer
        self._audience = audience
        self._leeway_seconds = max(0, int(leeway_seconds))

    @classmethod
    def is_weak_secret(cls, secret: str) -> bool:
        normalized = secret.strip().lower()
        return len(secret) < 32 or normalized in cls._WEAK_SECRETS

    def sign(self, *, subject: str, claims: Mapping[str, Any], expires_in_seconds: int) -> str:
        now = datetime.now(tz=UTC)
        payload: dict[str, Any] = {
            "sub": subject,
            "iat": int(now.timestamp()),
            "nbf": int(now.timestamp()),
            "exp": int((now + timedelta(seconds=expires_in_seconds)).timestamp()),
            "iss": self._issuer,
            "aud": self._audience,
        }
        payload.update(dict(claims))

        try:
            token = jwt.encode(payload, self._secret, algorithm=self._algorithm)
        except Exception as err:  # noqa: BLE001
            raise RuntimeError("Unable to sign token") from err

        if isinstance(token, bytes):
            return token.decode("utf-8")
        return token

    def verify(self, token: str) -> Mapping[str, Any]:
        try:
            claims = jwt.decode(
                token,
                self._secret,
                algorithms=[self._algorithm],
                audience=self._audience,
                issuer=self._issuer,
                options={"require": ["exp", "iat", "sub", "jti"]},
                leeway=self._leeway_seconds,
            )
        except Exception as err:  # noqa: BLE001
            raise RuntimeError("Invalid or expired token") from err

        if not isinstance(claims, dict):
            raise RuntimeError("Invalid token payload")
        return claims
