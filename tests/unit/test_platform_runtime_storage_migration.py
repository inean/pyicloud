"""Checks for provider runtime and storage canonical platform paths."""

from __future__ import annotations

import pyicloud.adapters.services.composition as services_composition
import pyicloud.platform.composition.api as api_composition
from pyicloud.platform.storage import FileSessionStoreAdapter


def test_runtime_and_store_paths_resolve_platform_implementations() -> None:
    assert services_composition.ServiceRuntime.__module__.startswith("pyicloud.platform.provider.runtime")
    assert FileSessionStoreAdapter.__module__.startswith("pyicloud.platform.storage.session_store")
    assert api_composition.build_default_api_container.__module__.startswith("pyicloud.platform.composition.api")


def test_active_composition_paths_resolve_platform_runtime_and_storage() -> None:
    runtime = services_composition.ServiceRuntime()
    assert runtime._store.__class__.__module__.startswith("pyicloud.platform.storage.session_store")
    assert FileSessionStoreAdapter.__module__.startswith("pyicloud.platform.storage.session_store")
