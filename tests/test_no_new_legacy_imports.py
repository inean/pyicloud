from __future__ import annotations

from pathlib import Path


ALLOWED_LEGACY_IMPORTS = {
    "pyicloud/legacy.py",
    "tests/test_legacy_imports.py",
    "tests/test_no_new_legacy_imports.py",
}


def test_no_new_pyicloud_legacy_imports_outside_approved_modules():
    repo_root = Path(__file__).resolve().parents[1]
    violations: list[str] = []

    for path in list((repo_root / "pyicloud").rglob("*.py")) + list((repo_root / "tests").rglob("*.py")):
        rel = path.relative_to(repo_root).as_posix()
        source = path.read_text(encoding="utf-8")
        if "from pyicloud.legacy import" not in source and "import pyicloud.legacy" not in source:
            continue
        if rel not in ALLOWED_LEGACY_IMPORTS:
            violations.append(rel)

    assert violations == [], f"Unexpected pyicloud.legacy imports found: {violations}"
