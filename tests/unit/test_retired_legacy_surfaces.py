"""Retirement checks for removed legacy public surfaces."""

from __future__ import annotations

import importlib

import pytest


@pytest.mark.parametrize(
    "module_name",
    [
        "pyicloud.service",
        "pyicloud.legacy",
        "pyicloud.cmdline",
        "pyicloud.services",
        "pyicloud.adapters.session.legacy_service_http",
        "pyicloud.adapters.service_endpoint",
        "pyicloud.adapters.auth.endpoint_restore",
        "pyicloud.bootstrap.service_endpoint",
    ],
)
def test_removed_legacy_modules_are_not_importable(module_name: str) -> None:
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module(module_name)


def test_top_level_pyicloudservice_symbol_removed() -> None:
    import pyicloud

    assert not hasattr(pyicloud, "PyiCloudService")
