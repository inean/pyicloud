from __future__ import annotations

from pathlib import Path


def test_no_direct_base_imports_outside_compatibility_shim():
    repo_root = Path(__file__).resolve().parents[2]
    violations: list[str] = []

    for path in (repo_root / "pyicloud").rglob("*.py"):
        rel = path.relative_to(repo_root).as_posix()
        if rel in {"pyicloud/base.py", "pyicloud/legacy.py"}:
            continue
        source = path.read_text(encoding="utf-8")
        if "from pyicloud.base import" in source or "import pyicloud.base" in source:
            violations.append(rel)

    for path in (repo_root / "tests").rglob("*.py"):
        rel = path.relative_to(repo_root).as_posix()
        if rel == "tests/unit/test_no_direct_base_imports.py":
            continue
        source = path.read_text(encoding="utf-8")
        if "from pyicloud.base import" in source or "import pyicloud.base" in source:
            violations.append(rel)

    assert violations == [], f"Direct pyicloud.base imports found: {violations}"
