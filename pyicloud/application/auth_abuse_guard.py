"""Application service for auth challenge abuse controls and lockout windows."""

from __future__ import annotations

from collections import defaultdict, deque
from collections.abc import Callable
from time import time

from pyicloud.domain import Forbidden


def _normalize_identity(value: str | None, *, fallback: str) -> str:
    normalized = str(value or "").strip().lower()
    return normalized or fallback


class AuthAbuseGuardService:
    """Track auth attempts across account/IP/session scopes and enforce lockout windows."""

    def __init__(
        self,
        *,
        clock: Callable[[], float] | None = None,
        window_seconds: int = 300,
        lockout_seconds: int = 300,
        max_attempts_per_account: int = 30,
        max_attempts_per_ip: int = 60,
        max_attempts_per_session: int = 12,
    ):
        self._clock = clock or time
        self._window_seconds = max(30, int(window_seconds))
        self._lockout_seconds = max(30, int(lockout_seconds))
        self._max_attempts_per_account = max(1, int(max_attempts_per_account))
        self._max_attempts_per_ip = max(1, int(max_attempts_per_ip))
        self._max_attempts_per_session = max(1, int(max_attempts_per_session))

        self._account_attempts: dict[str, deque[float]] = defaultdict(deque)
        self._ip_attempts: dict[str, deque[float]] = defaultdict(deque)
        self._session_attempts: dict[str, deque[float]] = defaultdict(deque)
        self._account_lockouts: dict[str, float] = {}
        self._ip_lockouts: dict[str, float] = {}
        self._session_lockouts: dict[str, float] = {}

    def _prune(self, attempts: deque[float], now: float) -> None:
        threshold = now - self._window_seconds
        while attempts and attempts[0] < threshold:
            attempts.popleft()

    @staticmethod
    def _ensure_not_locked(lockouts: dict[str, float], key: str, now: float, message: str) -> None:
        expires_at = float(lockouts.get(key, 0))
        if expires_at > now:
            raise Forbidden(message)

    def _record_and_enforce(
        self,
        *,
        attempts_by_key: dict[str, deque[float]],
        lockouts_by_key: dict[str, float],
        key: str,
        now: float,
        max_attempts: int,
        lockout_message: str,
    ) -> None:
        attempts = attempts_by_key[key]
        self._prune(attempts, now)
        attempts.append(now)
        if len(attempts) > max_attempts:
            lockouts_by_key[key] = now + self._lockout_seconds
            raise Forbidden(lockout_message)

    def guard_attempt(
        self,
        *,
        account_id: str | None,
        client_ip: str | None,
        challenge_id: str | None = None,
        session_id: str | None = None,
    ) -> None:
        now = float(self._clock())
        account_key = _normalize_identity(account_id, fallback="anonymous")
        ip_key = _normalize_identity(client_ip, fallback="unknown")
        session_key = _normalize_identity(session_id or challenge_id, fallback=f"{account_key}:{ip_key}")

        self._ensure_not_locked(
            self._account_lockouts,
            account_key,
            now,
            "Too many authentication attempts for this account. Try again later.",
        )
        self._ensure_not_locked(
            self._ip_lockouts,
            ip_key,
            now,
            "Too many authentication attempts from this IP. Try again later.",
        )
        self._ensure_not_locked(
            self._session_lockouts,
            session_key,
            now,
            "Too many authentication attempts for this session. Try again later.",
        )

        self._record_and_enforce(
            attempts_by_key=self._account_attempts,
            lockouts_by_key=self._account_lockouts,
            key=account_key,
            now=now,
            max_attempts=self._max_attempts_per_account,
            lockout_message="Too many authentication attempts for this account. Try again later.",
        )
        self._record_and_enforce(
            attempts_by_key=self._ip_attempts,
            lockouts_by_key=self._ip_lockouts,
            key=ip_key,
            now=now,
            max_attempts=self._max_attempts_per_ip,
            lockout_message="Too many authentication attempts from this IP. Try again later.",
        )
        self._record_and_enforce(
            attempts_by_key=self._session_attempts,
            lockouts_by_key=self._session_lockouts,
            key=session_key,
            now=now,
            max_attempts=self._max_attempts_per_session,
            lockout_message="Too many authentication attempts for this session. Try again later.",
        )

    def record_success(
        self,
        *,
        account_id: str | None,
        client_ip: str | None,
        challenge_id: str | None = None,
        session_id: str | None = None,
    ) -> None:
        account_key = _normalize_identity(account_id, fallback="anonymous")
        ip_key = _normalize_identity(client_ip, fallback="unknown")
        session_key = _normalize_identity(session_id or challenge_id, fallback=f"{account_key}:{ip_key}")

        self._account_attempts.pop(account_key, None)
        self._ip_attempts.pop(ip_key, None)
        self._session_attempts.pop(session_key, None)
        self._account_lockouts.pop(account_key, None)
        self._ip_lockouts.pop(ip_key, None)
        self._session_lockouts.pop(session_key, None)
