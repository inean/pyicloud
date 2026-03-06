"""Checks for upstream telemetry platform extraction with compatibility shims."""

from __future__ import annotations

import importlib

import pyicloud.adapters.session.service_http as service_http
import pyicloud.upstream as upstream_exports


def test_upstream_package_exports_platform_symbols() -> None:
    assert upstream_exports.bind_upstream_context.__module__.startswith("pyicloud.platform.telemetry.upstream.")
    assert upstream_exports.build_request_event.__module__.startswith("pyicloud.platform.telemetry.upstream.")
    assert upstream_exports.get_upstream_probe.__module__.startswith("pyicloud.platform.telemetry.upstream.")


def test_upstream_module_shims_reexport_platform_modules() -> None:
    module_pairs = [
        (
            "pyicloud.upstream.classification",
            "pyicloud.platform.telemetry.upstream.classification",
            "classify_upstream_request",
        ),
        ("pyicloud.upstream.context", "pyicloud.platform.telemetry.upstream.context", "bind_upstream_context"),
        ("pyicloud.upstream.events", "pyicloud.platform.telemetry.upstream.events", "build_request_event"),
        ("pyicloud.upstream.runtime", "pyicloud.platform.telemetry.upstream.runtime", "get_upstream_probe"),
        ("pyicloud.upstream.sanitize", "pyicloud.platform.telemetry.upstream.sanitize", "sanitize_body"),
    ]
    for legacy_module_name, platform_module_name, symbol in module_pairs:
        legacy_module = importlib.import_module(legacy_module_name)
        platform_module = importlib.import_module(platform_module_name)
        assert getattr(legacy_module, symbol) is getattr(platform_module, symbol)


def test_active_transport_path_uses_platform_upstream_event_builders() -> None:
    assert service_http.build_request_event.__module__.startswith("pyicloud.platform.telemetry.upstream.")
    assert service_http.build_response_event.__module__.startswith("pyicloud.platform.telemetry.upstream.")
    assert service_http.build_error_event.__module__.startswith("pyicloud.platform.telemetry.upstream.")
