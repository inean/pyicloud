"""HS256 JWT signer adapter."""

from __future__ import annotations

from collections.abc import Mapping
from datetime import UTC, datetime, timedelta
from typing import Any

import jwt

from pyicloud.ports import TokenSignerPort


class JwtTokenSigner(TokenSignerPort):
    """Sign and verify JWT bearer tokens for the API layer."""

    def __init__(
        self,
        *,
        secret: str,
        algorithm: str = "HS256",
        issuer: str = "pyicloud-api",
        audience: str = "pyicloud-cli",
    ):
        if not secret:
            raise RuntimeError("JWT secret cannot be empty")
        self._secret = secret
        self._algorithm = algorithm
        self._issuer = issuer
        self._audience = audience

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
            )
        except Exception as err:  # noqa: BLE001
            raise RuntimeError("Invalid or expired token") from err

        if not isinstance(claims, dict):
            raise RuntimeError("Invalid token payload")
        return claims
