from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
PYICLOUD_ROOT = REPO_ROOT / "pyicloud"
CONTEXTS_ROOT = PYICLOUD_ROOT / "contexts"

LOCKED_CONTEXT_ROOTS = {"core", "services", "crosscutting"}


def _child_dir_names(path: Path) -> set[str]:
    return {entry.name for entry in path.iterdir() if entry.is_dir() and not entry.name.startswith("__")}


def test_context_taxonomy_roots_match_locked_semantic_groups() -> None:
    if not CONTEXTS_ROOT.exists():
        return
    unexpected = sorted(_child_dir_names(CONTEXTS_ROOT) - LOCKED_CONTEXT_ROOTS)
    assert unexpected == [], f"Unexpected semantic context roots found: {unexpected}"
