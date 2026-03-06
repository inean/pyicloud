from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PYICLOUD_ROOT = REPO_ROOT / "pyicloud"

FORBIDDEN_LEGACY_IMPORT_PREFIXES = {
    "pyicloud.service",
    "pyicloud.legacy",
    "pyicloud.cmdline",
    "pyicloud.services",
    "pyicloud.adapters.session.legacy_service_http",
    "pyicloud.adapters.service_endpoint",
    "pyicloud.adapters.auth.endpoint_restore",
    "pyicloud.bootstrap.service_endpoint",
    "pyicloud.upstream",
}


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


def _matches_forbidden_legacy_prefix(module: str) -> bool:
    return any(
        module == forbidden or module.startswith(f"{forbidden}.") for forbidden in FORBIDDEN_LEGACY_IMPORT_PREFIXES
    )


def _discover_legacy_import_violations() -> list[str]:
    violations: list[str] = []
    for path in sorted(PYICLOUD_ROOT.rglob("*.py")):
        rel = path.relative_to(REPO_ROOT).as_posix()
        for imported_module in _iter_import_modules(path):
            if _matches_forbidden_legacy_prefix(imported_module):
                violations.append(f"{rel} -> {imported_module}")
    return violations


def test_runtime_modules_do_not_reintroduce_legacy_imports() -> None:
    violations = _discover_legacy_import_violations()
    assert violations == [], f"Forbidden legacy imports detected: {violations}"
