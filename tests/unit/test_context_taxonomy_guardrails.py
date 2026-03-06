from __future__ import annotations

import ast
import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PYICLOUD_ROOT = REPO_ROOT / "pyicloud"
CONTEXTS_ROOT = PYICLOUD_ROOT / "contexts"

LOCKED_CONTEXT_ROOTS = {"core", "services", "crosscutting"}
LOCKED_SERVICE_CONTEXTS = {
    "devices",
    "account",
    "drive",
    "calendar",
    "contacts",
    "reminders",
    "photos",
    "ubiquity",
}
LOCKED_CROSSCUTTING_CONTEXTS = {"auth", "telemetry", "observability"}
ALLOWED_CONTEXT_INFRA_DIRS = {"contracts"}
STRICT_INWARD_POLICY = {
    "core": {"core"},
    "services": {"services", "core", "crosscutting"},
    "crosscutting": {"crosscutting", "core"},
}
SNAKE_CASE_PATTERN = re.compile(r"^[a-z][a-z0-9_]*$")


def _child_dir_names(path: Path) -> set[str]:
    return {entry.name for entry in path.iterdir() if entry.is_dir() and not entry.name.startswith("__")}


def test_context_taxonomy_roots_match_locked_semantic_groups() -> None:
    if not CONTEXTS_ROOT.exists():
        return
    unexpected = sorted(_child_dir_names(CONTEXTS_ROOT) - LOCKED_CONTEXT_ROOTS)
    assert unexpected == [], f"Unexpected semantic context roots found: {unexpected}"


def test_context_names_follow_snake_case_convention() -> None:
    if not CONTEXTS_ROOT.exists():
        return
    invalid_root_names = sorted(
        name for name in _child_dir_names(CONTEXTS_ROOT) if SNAKE_CASE_PATTERN.fullmatch(name) is None
    )
    assert invalid_root_names == [], f"Invalid context root names (must be snake_case): {invalid_root_names}"


def test_services_context_catalog_matches_locked_taxonomy() -> None:
    services_root = CONTEXTS_ROOT / "services"
    if not services_root.exists():
        return
    names = _child_dir_names(services_root)
    context_names = names - ALLOWED_CONTEXT_INFRA_DIRS
    unexpected = sorted(context_names - LOCKED_SERVICE_CONTEXTS)
    invalid_names = sorted(name for name in context_names if SNAKE_CASE_PATTERN.fullmatch(name) is None)
    assert unexpected == [], f"Unexpected services contexts found: {unexpected}"
    assert invalid_names == [], f"Invalid services context names (must be snake_case): {invalid_names}"


def test_crosscutting_context_catalog_matches_locked_taxonomy() -> None:
    crosscutting_root = CONTEXTS_ROOT / "crosscutting"
    if not crosscutting_root.exists():
        return
    names = _child_dir_names(crosscutting_root)
    unexpected = sorted(names - LOCKED_CROSSCUTTING_CONTEXTS)
    invalid_names = sorted(name for name in names if SNAKE_CASE_PATTERN.fullmatch(name) is None)
    assert unexpected == [], f"Unexpected crosscutting contexts found: {unexpected}"
    assert invalid_names == [], f"Invalid crosscutting context names (must be snake_case): {invalid_names}"


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


def _discover_strict_inward_violations() -> list[str]:
    violations: list[str] = []
    for source_context in sorted(STRICT_INWARD_POLICY):
        source_root = CONTEXTS_ROOT / source_context
        if not source_root.exists():
            continue
        allowed_targets = STRICT_INWARD_POLICY[source_context]
        for path in sorted(source_root.rglob("*.py")):
            rel = path.relative_to(REPO_ROOT).as_posix()
            for imported_module in _iter_import_modules(path):
                if not imported_module.startswith("pyicloud.contexts."):
                    continue
                parts = imported_module.split(".")
                if len(parts) < 3:
                    continue
                target_context = parts[2]
                if target_context not in allowed_targets:
                    violations.append(
                        f"{rel} -> {imported_module} "
                        f"(source context '{source_context}' cannot import context '{target_context}')"
                    )
    return violations


def test_contexts_follow_strict_inward_import_matrix() -> None:
    if not CONTEXTS_ROOT.exists():
        return
    violations = _discover_strict_inward_violations()
    assert violations == [], f"Strict inward context import violations found: {violations}"
