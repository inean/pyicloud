from __future__ import annotations

import threading

import pytest

from pyicloud.adapters.services.composition import build_core_adapter_bundle
from pyicloud.adapters.services.runtime import ServiceRuntime, ServicesAdapterBase


@pytest.mark.asyncio
async def test_services_adapter_base_contains_blocking_calls_off_event_loop() -> None:
    event_loop_thread_id = threading.get_ident()
    observed_thread_id: int | None = None

    def _blocking_call() -> str:
        nonlocal observed_thread_id
        observed_thread_id = threading.get_ident()
        return "ok"

    result = await ServicesAdapterBase._run_blocking(_blocking_call)

    assert result == "ok"
    assert observed_thread_id is not None
    assert observed_thread_id != event_loop_thread_id


def test_runtime_modules_do_not_expose_legacy_alias_names() -> None:
    import pyicloud.adapters.services.composition as composition_module
    import pyicloud.adapters.services.runtime as runtime_module

    assert not hasattr(runtime_module, "LegacyServicesRuntime")
    assert not hasattr(runtime_module, "LegacyServicesAdapterBase")
    assert not hasattr(composition_module, "LegacyCoreAdapterBundle")
    assert not hasattr(composition_module, "build_legacy_core_adapter_bundle")


def test_core_adapter_bundle_uses_canonical_runtime_objects() -> None:
    adapters = build_core_adapter_bundle()

    assert isinstance(adapters.devices._runtime, ServiceRuntime)  # type: ignore[attr-defined]
    assert isinstance(adapters.drive._runtime, ServiceRuntime)  # type: ignore[attr-defined]
