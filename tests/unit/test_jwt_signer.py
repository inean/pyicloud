from __future__ import annotations

from datetime import UTC, datetime

import jwt
import pytest

from pyicloud.adapters.token import JwtTokenSigner


def test_jwt_signer_reports_weak_secret() -> None:
    assert JwtTokenSigner.is_weak_secret("short")
    assert JwtTokenSigner.is_weak_secret("pyicloud-api-dev-secret")
    assert not JwtTokenSigner.is_weak_secret("test-secret-at-least-thirty-two-bytes")


def test_jwt_signer_enforces_strong_secret_when_requested() -> None:
    with pytest.raises(RuntimeError, match="too weak"):
        JwtTokenSigner(secret="short", enforce_strong_secret=True)


def test_jwt_signer_leeway_accepts_recent_expiry() -> None:
    secret = "test-secret-at-least-thirty-two-bytes"
    now = int(datetime.now(tz=UTC).timestamp())
    token = jwt.encode(
        {
            "sub": "user@example.com",
            "jti": "token-1",
            "iat": now - 60,
            "nbf": now - 60,
            "exp": now - 2,
            "iss": "pyicloud-api",
            "aud": "pyicloud-cli",
        },
        secret,
        algorithm="HS256",
    )

    strict_signer = JwtTokenSigner(secret=secret)
    with pytest.raises(RuntimeError, match="Invalid or expired token"):
        strict_signer.verify(token)

    leeway_signer = JwtTokenSigner(secret=secret, leeway_seconds=5)
    claims = leeway_signer.verify(token)
    assert claims["sub"] == "user@example.com"


def test_jwt_signer_leeway_accepts_small_not_before_skew() -> None:
    secret = "test-secret-at-least-thirty-two-bytes"
    now = int(datetime.now(tz=UTC).timestamp())
    token = jwt.encode(
        {
            "sub": "user@example.com",
            "jti": "token-2",
            "iat": now,
            "nbf": now + 2,
            "exp": now + 60,
            "iss": "pyicloud-api",
            "aud": "pyicloud-cli",
        },
        secret,
        algorithm="HS256",
    )

    strict_signer = JwtTokenSigner(secret=secret)
    with pytest.raises(RuntimeError, match="Invalid or expired token"):
        strict_signer.verify(token)

    leeway_signer = JwtTokenSigner(secret=secret, leeway_seconds=5)
    claims = leeway_signer.verify(token)
    assert claims["jti"] == "token-2"
