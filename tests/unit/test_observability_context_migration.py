"""Checks for observability query-side migration into crosscutting observability context."""

from __future__ import annotations

import importlib

import pytest

import pyicloud.adapters.session.service_http as service_http
import pyicloud.interfaces.api.app as api_app
import pyicloud.interfaces.api.dependencies as api_dependencies
import pyicloud.platform.composition.api as api_composition


def test_application_observability_shim_module_is_removed() -> None:
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("pyicloud.application.observability")


def test_active_api_path_uses_context_observability_service() -> None:
    assert api_dependencies.ObservabilityApi.__module__.startswith(
        "pyicloud.contexts.crosscutting.observability.application."
    )
    assert api_composition.ObservabilityApi.__module__.startswith(
        "pyicloud.contexts.crosscutting.observability.application."
    )
    assert api_composition.NullObservabilityAdapter.__module__.startswith(
        "pyicloud.contexts.crosscutting.observability.adapters."
    )
    assert api_composition.OTelObservabilityAdapter.__module__.startswith(
        "pyicloud.contexts.crosscutting.observability.adapters."
    )


def test_observability_adapter_shims_reexport_context_adapters() -> None:
    legacy_null_module = importlib.import_module("pyicloud.adapters.observability.null")
    legacy_otel_module = importlib.import_module("pyicloud.adapters.observability.otel")

    canonical_null_module = importlib.import_module("pyicloud.contexts.crosscutting.observability.adapters.null")
    canonical_otel_module = importlib.import_module("pyicloud.contexts.crosscutting.observability.adapters.otel")

    assert legacy_null_module.NullObservabilityAdapter is canonical_null_module.NullObservabilityAdapter
    assert legacy_otel_module.OTelObservabilityAdapter is canonical_otel_module.OTelObservabilityAdapter
    assert legacy_otel_module.ensure_otel_dependencies is canonical_otel_module.ensure_otel_dependencies


def test_upstream_probe_shims_reexport_context_runtime() -> None:
    legacy_runtime = importlib.import_module("pyicloud.adapters.upstream_probe.runtime")
    canonical_runtime = importlib.import_module(
        "pyicloud.contexts.crosscutting.telemetry.adapters.upstream_probe.runtime"
    )

    assert legacy_runtime.get_upstream_probe is canonical_runtime.get_upstream_probe
    assert (
        legacy_runtime.validate_upstream_probe_configuration is canonical_runtime.validate_upstream_probe_configuration
    )
    assert legacy_runtime.upstream_capture_body_max_bytes is canonical_runtime.upstream_capture_body_max_bytes
    assert legacy_runtime.reset_upstream_probe_cache is canonical_runtime.reset_upstream_probe_cache


def test_active_api_and_transport_paths_use_context_telemetry_runtime() -> None:
    assert api_app.validate_upstream_probe_configuration.__module__.startswith(
        "pyicloud.contexts.crosscutting.telemetry.adapters.upstream_probe."
    )
    assert service_http.get_upstream_probe.__module__.startswith(
        "pyicloud.contexts.crosscutting.telemetry.adapters.upstream_probe."
    )
