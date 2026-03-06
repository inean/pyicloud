"""Checks for provider runtime and storage canonical platform paths."""

from __future__ import annotations

import pyicloud.adapters.services.composition as services_composition
import pyicloud.bootstrap.api_runtime as api_runtime


def test_runtime_and_store_paths_resolve_platform_implementations() -> None:
    assert services_composition.ServiceRuntime.__module__.startswith("pyicloud.platform.provider.runtime")
    assert api_runtime.FileSessionStoreAdapter.__module__.startswith("pyicloud.platform.storage.session_store")


def test_active_composition_and_bootstrap_paths_resolve_platform_runtime_and_storage() -> None:
    runtime = services_composition.ServiceRuntime()
    assert runtime._store.__class__.__module__.startswith("pyicloud.platform.storage.session_store")
    assert api_runtime.FileSessionStoreAdapter.__module__.startswith("pyicloud.platform.storage.session_store")
