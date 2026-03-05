from __future__ import annotations

import ast
from pathlib import Path

ALLOWED_OTEL_IMPORTS = {
    "pyicloud/adapters/observability/otel.py",
    "tests/unit/test_no_direct_otel_imports.py",
}


def test_no_direct_otel_imports_outside_observability_adapter():
    repo_root = Path(__file__).resolve().parents[2]
    violations: list[str] = []

    for path in list((repo_root / "pyicloud").rglob("*.py")) + list((repo_root / "tests").rglob("*.py")):
        rel = path.relative_to(repo_root).as_posix()
        if rel in ALLOWED_OTEL_IMPORTS:
            continue
        module = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(module):
            if isinstance(node, ast.Import):
                if any(alias.name.startswith("opentelemetry") for alias in node.names):
                    violations.append(rel)
                    break
            if isinstance(node, ast.ImportFrom):
                if node.module and node.module.startswith("opentelemetry"):
                    violations.append(rel)
                    break

    assert violations == [], f"Direct opentelemetry imports found: {violations}"
