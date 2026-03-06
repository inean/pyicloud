"""Checks for auth application service migration into crosscutting auth context."""

from __future__ import annotations

import ast
import importlib
from pathlib import Path

import pytest

import pyicloud.bootstrap.api_runtime as api_runtime
import pyicloud.interfaces.api.dependencies as api_dependencies

REPO_ROOT = Path(__file__).resolve().parents[2]


@pytest.mark.parametrize(
    "module_name",
    (
        "pyicloud.application.api_auth",
        "pyicloud.application.auth_session",
        "pyicloud.application.access_control",
        "pyicloud.application.auth_abuse_guard",
        "pyicloud.application.operation_suspension",
        "pyicloud.application.service_endpoint_restore",
    ),
)
def test_auth_application_shim_modules_are_removed(module_name: str) -> None:
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module(module_name)


def test_active_api_path_uses_context_auth_services() -> None:
    assert api_dependencies.AuthApiService.__module__.startswith("pyicloud.contexts.crosscutting.auth.application.")
    assert api_dependencies.AccessControlApiService.__module__.startswith(
        "pyicloud.contexts.crosscutting.auth.application."
    )
    assert api_dependencies.AuthAbuseGuardService.__module__.startswith(
        "pyicloud.contexts.crosscutting.auth.application."
    )
    assert api_dependencies.OperationSuspensionService.__module__.startswith(
        "pyicloud.contexts.crosscutting.auth.application."
    )
    assert api_runtime.AuthApiService.__module__.startswith("pyicloud.contexts.crosscutting.auth.application.")


def _iter_import_modules(path: Path) -> list[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    imports: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
            continue
        if isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module:
                imports.append(node.module)
    return imports


def test_active_auth_api_path_has_no_direct_trees_or_sessions_imports() -> None:
    guarded_files = (
        REPO_ROOT / "pyicloud/bootstrap/__init__.py",
        REPO_ROOT / "pyicloud/bootstrap/api_runtime.py",
        REPO_ROOT / "pyicloud/interfaces/api/app.py",
        REPO_ROOT / "pyicloud/interfaces/api/dependencies.py",
        REPO_ROOT / "pyicloud/interfaces/api/routers/auth.py",
    )
    forbidden_prefixes = ("pyicloud.trees", "pyicloud.sessions")
    violations: list[str] = []
    for file_path in guarded_files:
        rel = file_path.relative_to(REPO_ROOT).as_posix()
        for imported_module in _iter_import_modules(file_path):
            if any(
                imported_module == prefix or imported_module.startswith(f"{prefix}.") for prefix in forbidden_prefixes
            ):
                violations.append(f"{rel} -> {imported_module}")
    assert violations == [], f"Direct sessions/trees imports found in active auth API path: {violations}"
