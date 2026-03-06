"""Contract checks for temporary port shims during Program 34+ migration."""

from __future__ import annotations

import importlib

import pytest


@pytest.mark.parametrize(
    ("legacy_module", "canonical_module", "symbols"),
    [
        (
            "pyicloud.ports.access_control",
            "pyicloud.contexts.crosscutting.auth.contracts.access_control",
            ("AccessControlCommandPort", "AccessControlQueryPort"),
        ),
        (
            "pyicloud.ports.auth",
            "pyicloud.contexts.crosscutting.auth.contracts.auth",
            ("AuthSessionPort", "ServiceEndpointPort", "SessionStorePort"),
        ),
        (
            "pyicloud.ports.auth_state_reset",
            "pyicloud.contexts.crosscutting.auth.contracts.auth_state_reset",
            ("AuthStateResetPolicy",),
        ),
        (
            "pyicloud.ports.operation_suspension",
            "pyicloud.contexts.crosscutting.auth.contracts.operation_suspension",
            ("SuspendedOperationCommandPort", "SuspendedOperationQueryPort"),
        ),
        (
            "pyicloud.ports.session",
            "pyicloud.contexts.crosscutting.auth.contracts.session",
            ("SessionCommandPort", "SessionQueryPort", "TokenSignerPort"),
        ),
        (
            "pyicloud.ports.tree_runtime",
            "pyicloud.contexts.crosscutting.auth.contracts.tree_runtime",
            ("TreeRuntimeLifecyclePort",),
        ),
        (
            "pyicloud.ports.services",
            "pyicloud.contexts.services.contracts.services",
            (
                "AccountServicePort",
                "CalendarServicePort",
                "ContactsServicePort",
                "DeviceServicePort",
                "DriveServicePort",
                "PhotosServicePort",
                "RemindersServicePort",
                "UbiquityServicePort",
            ),
        ),
        (
            "pyicloud.ports.observability",
            "pyicloud.contexts.crosscutting.observability.contracts.observability",
            (
                "LogQLQueryPort",
                "ObservabilityInstantQueryRequest",
                "ObservabilityLanguage",
                "ObservabilityQueryEnvelope",
                "ObservabilityRangeQueryRequest",
                "PromQLQueryPort",
                "TraceQLQueryPort",
            ),
        ),
        (
            "pyicloud.ports.upstream_probe",
            "pyicloud.contexts.crosscutting.telemetry.contracts.upstream_probe",
            ("UpstreamErrorEvent", "UpstreamRequestEvent", "UpstreamResponseEvent", "UpstreamTrafficProbePort"),
        ),
    ],
)
def test_ports_modules_reexport_canonical_context_contracts(
    legacy_module: str,
    canonical_module: str,
    symbols: tuple[str, ...],
) -> None:
    legacy = importlib.import_module(legacy_module)
    canonical = importlib.import_module(canonical_module)

    for symbol in symbols:
        assert getattr(legacy, symbol) is getattr(canonical, symbol)
