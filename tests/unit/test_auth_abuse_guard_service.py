from __future__ import annotations

import pytest

from pyicloud.application.auth_abuse_guard import AuthAbuseGuardService
from pyicloud.domain import Forbidden


def test_auth_abuse_guard_locks_out_after_limit() -> None:
    now = [1000.0]
    guard = AuthAbuseGuardService(
        clock=lambda: now[0],
        window_seconds=60,
        lockout_seconds=120,
        max_attempts_per_account=2,
        max_attempts_per_ip=2,
        max_attempts_per_session=2,
    )

    guard.guard_attempt(account_id="a@example.com", client_ip="1.1.1.1", session_id="s-1")
    guard.guard_attempt(account_id="a@example.com", client_ip="1.1.1.1", session_id="s-1")
    with pytest.raises(Forbidden, match="Too many authentication attempts"):
        guard.guard_attempt(account_id="a@example.com", client_ip="1.1.1.1", session_id="s-1")

    now[0] = 1100.0
    with pytest.raises(Forbidden, match="Try again later"):
        guard.guard_attempt(account_id="a@example.com", client_ip="1.1.1.1", session_id="s-1")


def test_auth_abuse_guard_success_resets_counters() -> None:
    guard = AuthAbuseGuardService(
        max_attempts_per_account=2,
        max_attempts_per_ip=2,
        max_attempts_per_session=2,
    )

    guard.guard_attempt(account_id="a@example.com", client_ip="1.1.1.1", session_id="s-1")
    guard.record_success(account_id="a@example.com", client_ip="1.1.1.1", session_id="s-1")
    guard.guard_attempt(account_id="a@example.com", client_ip="1.1.1.1", session_id="s-1")
