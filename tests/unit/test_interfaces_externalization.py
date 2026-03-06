"""Compatibility checks for API/CLI externalization to pyicloud.interfaces.*."""

from __future__ import annotations


def test_api_compat_package_forwards_to_interfaces_namespace() -> None:
    import pyicloud.api as compat_api
    import pyicloud.interfaces.api as canonical_api
    from pyicloud.api.app import create_app as compat_create_app
    from pyicloud.interfaces.api.app import create_app as canonical_create_app

    assert tuple(compat_api.__path__) == tuple(canonical_api.__path__)
    assert compat_create_app.__code__.co_filename == canonical_create_app.__code__.co_filename


def test_cli_compat_package_forwards_to_interfaces_namespace() -> None:
    import pyicloud.cli as compat_cli
    import pyicloud.interfaces.cli as canonical_cli
    from pyicloud.cli.main import main as compat_main
    from pyicloud.interfaces.cli.main import main as canonical_main

    assert tuple(compat_cli.__path__) == tuple(canonical_cli.__path__)
    assert compat_main.name == canonical_main.name
    assert set(compat_main.commands) == set(canonical_main.commands)
