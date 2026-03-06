"""Checks for provider runtime and storage extraction into platform namespace."""

from __future__ import annotations

import importlib

import pyicloud.adapters.services.composition as services_composition
import pyicloud.bootstrap.api_runtime as api_runtime


def test_runtime_and_store_shims_reexport_platform_implementations() -> None:
    legacy_runtime = importlib.import_module("pyicloud.adapters.services.runtime")
    platform_runtime = importlib.import_module("pyicloud.platform.provider.runtime")
    assert legacy_runtime.ServiceRuntime.__module__.startswith("pyicloud.adapters.services.runtime")
    assert platform_runtime.ServiceRuntime.__module__.startswith("pyicloud.platform.provider.runtime")
    assert legacy_runtime.FileSessionStoreAdapter is platform_runtime.FileSessionStoreAdapter


def test_active_composition_and_bootstrap_paths_resolve_platform_runtime_and_storage() -> None:
    runtime = services_composition.ServiceRuntime()
    assert runtime._store.__class__.__module__.startswith("pyicloud.platform.storage.session_store")
    assert api_runtime.FileSessionStoreAdapter.__module__.startswith("pyicloud.platform.storage.session_store")
