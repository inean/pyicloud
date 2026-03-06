from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PYICLOUD_ROOT = REPO_ROOT / "pyicloud"
MANAGED_LAYERS = {
    "domain": {"domain"},
    "ports": {"ports", "domain"},
    "application": {"application", "ports", "domain"},
    "adapters": {"adapters", "ports", "domain", "sessions", "trees"},
    "api": {"api", "application", "ports", "domain", "bootstrap", "adapters"},
    "cli": {"cli", "application", "ports", "domain"},
    "bootstrap": {"bootstrap", "application", "adapters", "ports", "domain", "trees"},
    "sessions": {"sessions", "ports", "domain"},
    "trees": {"trees", "sessions", "ports", "domain"},
}


def _matches_prefix(module: str, prefixes: set[str]) -> bool:
    return any(module == prefix or module.startswith(f"{prefix}.") for prefix in prefixes)


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
            elif node.module is None:
                parent_module = _resolve_import_from(module_name, level=node.level, module="")
                for alias in node.names:
                    imports.append(f"{parent_module}.{alias.name}" if parent_module else alias.name)
    return imports


def _find_boundary_violations(*, package_dir: Path, forbidden_prefixes: set[str]) -> list[str]:
    violations: list[str] = []
    for path in package_dir.rglob("*.py"):
        rel = path.relative_to(REPO_ROOT).as_posix()
        for imported_module in _iter_import_modules(path):
            if _matches_prefix(imported_module, forbidden_prefixes):
                violations.append(f"{rel} -> {imported_module}")
    return violations


def _managed_layer_for_path(path: Path) -> str:
    rel = path.relative_to(PYICLOUD_ROOT)
    return rel.parts[0]


def _managed_layer_for_module(module: str) -> str | None:
    if not module.startswith("pyicloud."):
        return None
    parts = module.split(".")
    if len(parts) < 2:
        return None
    layer = parts[1]
    if layer not in MANAGED_LAYERS:
        return None
    return layer


def _iter_managed_layer_files() -> list[Path]:
    files: list[Path] = []
    for layer in MANAGED_LAYERS:
        files.extend((PYICLOUD_ROOT / layer).rglob("*.py"))
    return sorted(files)


def _find_layer_policy_violations() -> list[str]:
    violations: list[str] = []
    for path in _iter_managed_layer_files():
        source_layer = _managed_layer_for_path(path)
        rel = path.relative_to(REPO_ROOT).as_posix()
        allowed_layers = MANAGED_LAYERS[source_layer]
        for imported_module in _iter_import_modules(path):
            target_layer = _managed_layer_for_module(imported_module)
            if target_layer is None:
                continue
            if target_layer not in allowed_layers:
                violations.append(f"{rel} -> {imported_module} (layer {source_layer} cannot import {target_layer})")
    return violations


def test_architecture_layer_map_is_complete_for_managed_roots() -> None:
    managed_roots = {path.name for path in PYICLOUD_ROOT.iterdir() if path.is_dir() and path.name in MANAGED_LAYERS}
    assert managed_roots == set(MANAGED_LAYERS)


def test_managed_layers_follow_import_policy_matrix() -> None:
    violations = _find_layer_policy_violations()
    assert violations == [], f"Layer policy violations found: {violations}"


def test_domain_layer_has_no_outbound_layer_imports() -> None:
    forbidden = {
        "pyicloud.adapters",
        "pyicloud.api",
        "pyicloud.application",
        "pyicloud.bootstrap",
        "pyicloud.cli",
    }
    violations = _find_boundary_violations(
        package_dir=PYICLOUD_ROOT / "domain",
        forbidden_prefixes=forbidden,
    )
    assert violations == [], f"Domain layer import violations found: {violations}"


def test_application_layer_avoids_infrastructure_and_setup_coupling() -> None:
    forbidden = {
        "pyicloud.adapters",
        "pyicloud.api",
        "pyicloud.bootstrap",
        "pyicloud.cli",
        "pyicloud.models",
        "pyicloud.trees",
    }
    violations = _find_boundary_violations(
        package_dir=PYICLOUD_ROOT / "application",
        forbidden_prefixes=forbidden,
    )
    assert violations == [], f"Application layer import violations found: {violations}"


def test_adapters_layer_does_not_depend_on_cli_entrypoints() -> None:
    forbidden = {"pyicloud.cli", "pyicloud.cli_auth"}
    violations = _find_boundary_violations(
        package_dir=PYICLOUD_ROOT / "adapters",
        forbidden_prefixes=forbidden,
    )
    assert violations == [], f"Adapters layer import violations found: {violations}"


def test_sessions_and_trees_layers_avoid_direct_adapter_dependencies() -> None:
    sessions_violations = _find_boundary_violations(
        package_dir=PYICLOUD_ROOT / "sessions",
        forbidden_prefixes={"pyicloud.adapters"},
    )
    trees_violations = _find_boundary_violations(
        package_dir=PYICLOUD_ROOT / "trees",
        forbidden_prefixes={"pyicloud.adapters"},
    )
    violations = [*sessions_violations, *trees_violations]
    assert violations == [], f"Sessions/trees direct adapter import violations found: {violations}"
