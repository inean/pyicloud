"""Legacy CLI auth adapter backed by bootstrap auth/session services."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

async def authenticate_legacy_endpoint(
    *,
    username: str,
    password: str,
    interactive: bool,
    auth_runner: Callable[..., Any] | None = None,
    restore_builder: Callable[..., Any] | None = None,
) -> Any:
    """Authenticate and return a services endpoint using the bootstrap flow."""
    if auth_runner is None:
        from pyicloud.cli_auth import run_bootstrap_auth

        auth_runner = run_bootstrap_auth
    if restore_builder is None:
        from pyicloud.bootstrap.service_endpoint import build_service_endpoint_restore

        restore_builder = build_service_endpoint_restore

    await auth_runner(
        username=username,
        password=password,
        interactive=interactive,
    )

    restore = restore_builder()
    endpoint = restore.restore(
        account_id=username,
        password=password,
    )
    if endpoint is None:
        raise RuntimeError(f"Authenticated but no endpoint payload found for {username}")
    return endpoint
