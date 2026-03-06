"""Checks for observability query-side migration into crosscutting observability context."""

from __future__ import annotations

import importlib

import pyicloud.bootstrap.api_runtime as api_runtime
import pyicloud.interfaces.api.dependencies as api_dependencies


def test_application_observability_shim_reexports_context_service() -> None:
    legacy_module = importlib.import_module("pyicloud.application.observability")
    canonical_module = importlib.import_module("pyicloud.contexts.crosscutting.observability.application.observability")

    assert legacy_module.ObservabilityApi is canonical_module.ObservabilityApi


def test_active_api_path_uses_context_observability_service() -> None:
    assert api_dependencies.ObservabilityApi.__module__.startswith(
        "pyicloud.contexts.crosscutting.observability.application."
    )
    assert api_runtime.ObservabilityApi.__module__.startswith(
        "pyicloud.contexts.crosscutting.observability.application."
    )
