"""Checks for upstream telemetry platform extraction without legacy shims."""

from __future__ import annotations

import importlib

import pyicloud.adapters.session.service_http as service_http
import pyicloud.platform.telemetry.upstream as upstream_exports


def test_platform_upstream_package_exports_platform_symbols() -> None:
    assert upstream_exports.bind_upstream_context.__module__.startswith("pyicloud.platform.telemetry.upstream.")
    assert upstream_exports.build_request_event.__module__.startswith("pyicloud.platform.telemetry.upstream.")
    assert upstream_exports.get_upstream_probe.__module__.startswith("pyicloud.platform.telemetry.upstream.")


def test_platform_upstream_modules_resolve_canonical_symbols() -> None:
    module_pairs = [
        (
            "pyicloud.platform.telemetry.upstream.classification",
            "pyicloud.platform.telemetry.upstream.classification",
            "classify_upstream_request",
        ),
        (
            "pyicloud.platform.telemetry.upstream.context",
            "pyicloud.platform.telemetry.upstream.context",
            "bind_upstream_context",
        ),
        (
            "pyicloud.platform.telemetry.upstream.events",
            "pyicloud.platform.telemetry.upstream.events",
            "build_request_event",
        ),
        (
            "pyicloud.platform.telemetry.upstream.runtime",
            "pyicloud.platform.telemetry.upstream.runtime",
            "get_upstream_probe",
        ),
        (
            "pyicloud.platform.telemetry.upstream.sanitize",
            "pyicloud.platform.telemetry.upstream.sanitize",
            "sanitize_body",
        ),
    ]
    for source_module_name, target_module_name, symbol in module_pairs:
        source_module = importlib.import_module(source_module_name)
        target_module = importlib.import_module(target_module_name)
        assert getattr(source_module, symbol) is getattr(target_module, symbol)


def test_active_transport_path_uses_platform_upstream_event_builders() -> None:
    assert service_http.build_request_event.__module__.startswith("pyicloud.platform.telemetry.upstream.")
    assert service_http.build_response_event.__module__.startswith("pyicloud.platform.telemetry.upstream.")
    assert service_http.build_error_event.__module__.startswith("pyicloud.platform.telemetry.upstream.")
