from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PYICLOUD_ROOT = REPO_ROOT / "pyicloud"

ALLOWED_LEGACY_ALIAS_EXPORTS = {
    "pyicloud/adapters/session/__init__.py::LegacyServiceSessionAdapter",
    "pyicloud/adapters/services/__init__.py::LegacyCoreServicesAdapter",
    "pyicloud/adapters/services/clients/__init__.py::LegacyAccountClient",
    "pyicloud/adapters/services/clients/__init__.py::LegacyCalendarClient",
    "pyicloud/adapters/services/clients/__init__.py::LegacyContactsClient",
    "pyicloud/adapters/services/clients/__init__.py::LegacyDevicesClient",
    "pyicloud/adapters/services/clients/__init__.py::LegacyDriveClient",
    "pyicloud/adapters/services/clients/__init__.py::LegacyPhotosClient",
    "pyicloud/adapters/services/clients/__init__.py::LegacyRemindersClient",
    "pyicloud/adapters/services/clients/__init__.py::LegacyUbiquityClient",
}


def _iter_string_literals(node: ast.AST) -> list[str]:
    if isinstance(node, ast.List | ast.Tuple | ast.Set):
        values: list[str] = []
        for element in node.elts:
            if isinstance(element, ast.Constant) and isinstance(element.value, str):
                values.append(element.value)
        return values
    return []


def _looks_legacy_symbol(name: str) -> bool:
    return name.startswith("Legacy") or name.startswith("build_legacy_")


def _discover_legacy_alias_exports() -> set[str]:
    exports: set[str] = set()
    for path in sorted(PYICLOUD_ROOT.rglob("*.py")):
        rel = path.relative_to(REPO_ROOT).as_posix()
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in tree.body:
            if not isinstance(node, ast.Assign):
                continue
            for target in node.targets:
                if isinstance(target, ast.Name) and _looks_legacy_symbol(target.id):
                    exports.add(f"{rel}::{target.id}")
                if isinstance(target, ast.Name) and target.id == "__all__":
                    for value in _iter_string_literals(node.value):
                        if _looks_legacy_symbol(value):
                            exports.add(f"{rel}::{value}")
    return exports


def test_no_new_legacy_alias_exports_are_introduced() -> None:
    current = _discover_legacy_alias_exports()
    unexpected = sorted(current - ALLOWED_LEGACY_ALIAS_EXPORTS)
    assert unexpected == [], f"Unexpected legacy alias exports found: {unexpected}"
