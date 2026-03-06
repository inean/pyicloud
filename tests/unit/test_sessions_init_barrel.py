from __future__ import annotations

import ast
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SESSIONS_INIT = REPO_ROOT / "pyicloud" / "sessions" / "__init__.py"


def _is_docstring_expr(node: ast.stmt) -> bool:
    return isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str)


def test_sessions_init_is_barrel_only() -> None:
    source = SESSIONS_INIT.read_text(encoding="utf-8")
    tree = ast.parse(source, filename=str(SESSIONS_INIT))

    disallowed_definitions = [
        node for node in tree.body if isinstance(node, ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef)
    ]
    assert disallowed_definitions == [], "pyicloud/sessions/__init__.py must not define classes/functions"

    allowed = (ast.ImportFrom, ast.Import, ast.Assign, ast.AnnAssign)
    disallowed_statements = [
        node for node in tree.body if not isinstance(node, allowed) and not _is_docstring_expr(node)
    ]
    assert disallowed_statements == [], "pyicloud/sessions/__init__.py should remain a barrel file"

    assert len(source.splitlines()) <= 120, "pyicloud/sessions/__init__.py should stay intentionally small"
