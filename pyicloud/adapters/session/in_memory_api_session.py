"""In-memory implementation for API challenge and token-revocation state."""

from __future__ import annotations

from collections.abc import Callable, Mapping
from time import time
from typing import Any

from pyicloud.ports import SessionCommandPort, SessionQueryPort


class InMemoryApiSessionStore(SessionQueryPort, SessionCommandPort):
    """Store auth challenges and token revocations in process memory."""

    def __init__(self, *, clock: Callable[[], float] | None = None):
        self._clock = clock or time
        self._challenges: dict[str, tuple[float, dict[str, Any]]] = {}
        self._revoked: dict[str, float] = {}

    def _cleanup(self) -> None:
        now = self._clock()

        expired_challenges = [key for key, (expires_at, _) in self._challenges.items() if expires_at <= now]
        for key in expired_challenges:
            self._challenges.pop(key, None)

        expired_revoked = [key for key, expires_at in self._revoked.items() if expires_at <= now]
        for key in expired_revoked:
            self._revoked.pop(key, None)

    def get_challenge(self, challenge_id: str) -> Mapping[str, Any] | None:
        self._cleanup()
        record = self._challenges.get(challenge_id)
        if record is None:
            return None
        return dict(record[1])

    def is_token_revoked(self, token_id: str) -> bool:
        self._cleanup()
        return token_id in self._revoked

    def put_challenge(self, *, challenge_id: str, payload: Mapping[str, Any], ttl_seconds: int) -> None:
        self._cleanup()
        self._challenges[challenge_id] = (self._clock() + ttl_seconds, dict(payload))

    def delete_challenge(self, challenge_id: str) -> None:
        self._cleanup()
        self._challenges.pop(challenge_id, None)

    def revoke_token(self, *, token_id: str, ttl_seconds: int) -> None:
        self._cleanup()
        self._revoked[token_id] = self._clock() + ttl_seconds
