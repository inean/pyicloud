"""Checks for auth application service migration into crosscutting auth context."""

from __future__ import annotations

import importlib

import pyicloud.bootstrap.api_runtime as api_runtime
import pyicloud.interfaces.api.dependencies as api_dependencies


def test_application_auth_shims_reexport_context_services() -> None:
    pairs = [
        (
            "pyicloud.application.api_auth",
            "pyicloud.contexts.crosscutting.auth.application.api_auth",
            ("AuthApiService",),
        ),
        (
            "pyicloud.application.auth_session",
            "pyicloud.contexts.crosscutting.auth.application.auth_session",
            ("AuthSessionService",),
        ),
        (
            "pyicloud.application.access_control",
            "pyicloud.contexts.crosscutting.auth.application.access_control",
            ("AccessControlApiService",),
        ),
        (
            "pyicloud.application.auth_abuse_guard",
            "pyicloud.contexts.crosscutting.auth.application.auth_abuse_guard",
            ("AuthAbuseGuardService",),
        ),
        (
            "pyicloud.application.operation_suspension",
            "pyicloud.contexts.crosscutting.auth.application.operation_suspension",
            ("OperationSuspensionService",),
        ),
        (
            "pyicloud.application.service_endpoint_restore",
            "pyicloud.contexts.crosscutting.auth.application.service_endpoint_restore",
            ("ServiceEndpointRestoreService",),
        ),
    ]
    for legacy_module_name, canonical_module_name, symbols in pairs:
        legacy_module = importlib.import_module(legacy_module_name)
        canonical_module = importlib.import_module(canonical_module_name)
        for symbol in symbols:
            assert getattr(legacy_module, symbol) is getattr(canonical_module, symbol)


def test_active_api_path_uses_context_auth_services() -> None:
    assert api_dependencies.AuthApiService.__module__.startswith("pyicloud.contexts.crosscutting.auth.application.")
    assert api_dependencies.AccessControlApiService.__module__.startswith(
        "pyicloud.contexts.crosscutting.auth.application."
    )
    assert api_dependencies.AuthAbuseGuardService.__module__.startswith(
        "pyicloud.contexts.crosscutting.auth.application."
    )
    assert api_dependencies.OperationSuspensionService.__module__.startswith(
        "pyicloud.contexts.crosscutting.auth.application."
    )
    assert api_runtime.AuthApiService.__module__.startswith("pyicloud.contexts.crosscutting.auth.application.")
