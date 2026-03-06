"""Ratchet checks for the semantic rename from identity_access to auth."""

from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PYICLOUD_ROOT = REPO_ROOT / "pyicloud"

FORBIDDEN_IDENTITY_ACCESS_TOKEN = "identity_access"
FORBIDDEN_CONTEXT_MODULE = "pyicloud.contexts.crosscutting.identity_access"


def _module_name_for_path(path: Path) -> str:
    rel = path.relative_to(REPO_ROOT).with_suffix("")
    return ".".join(rel.parts)


def _resolve_import_from(current_module: str, *, level: int, module: str | None) -> str:
    if level == 0:
        return module or ""
    current_parts = current_module.split(".")
    if level > len(current_parts):
        return module or ""
    base_parts = current_parts[:-level]
    if module:
        base_parts = [*base_parts, module]
    return ".".join(base_parts)


def _iter_import_modules(path: Path) -> list[str]:
    module_name = _module_name_for_path(path)
    source = path.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(path))
    imports: list[str] = []

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.extend(alias.name for alias in node.names)
            continue
        if isinstance(node, ast.ImportFrom):
            resolved = _resolve_import_from(module_name, level=node.level, module=node.module)
            if resolved:
                imports.append(resolved)
    return imports


def test_runtime_paths_do_not_reintroduce_identity_access_names() -> None:
    offenders = sorted(
        path.relative_to(REPO_ROOT).as_posix()
        for path in PYICLOUD_ROOT.rglob("*")
        if FORBIDDEN_IDENTITY_ACCESS_TOKEN in path.name
    )
    assert offenders == [], f"Forbidden identity_access paths found: {offenders}"


def test_runtime_imports_do_not_reference_identity_access_context() -> None:
    violations: list[str] = []
    for path in sorted(PYICLOUD_ROOT.rglob("*.py")):
        rel = path.relative_to(REPO_ROOT).as_posix()
        for imported_module in _iter_import_modules(path):
            if imported_module == FORBIDDEN_CONTEXT_MODULE or imported_module.startswith(
                f"{FORBIDDEN_CONTEXT_MODULE}."
            ):
                violations.append(f"{rel} -> {imported_module}")
    assert violations == [], f"Forbidden identity_access imports found: {violations}"
