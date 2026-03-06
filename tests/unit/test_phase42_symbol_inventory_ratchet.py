from __future__ import annotations

import ast
import json
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
INVENTORY_PATH = REPO_ROOT / "docs" / "phase42_symbol_inventory.json"
ALLOWED_TAGS = {"active", "legacy-boundary", "dead-candidate"}
ALLOWED_DECISIONS = {"keep", "move", "remove"}


def _collect_target_files(target_roots: list[str]) -> set[str]:
    files: set[str] = set()
    for root in target_roots:
        root_path = REPO_ROOT / root
        for path in sorted(root_path.glob("*.py")):
            files.add(path.relative_to(REPO_ROOT).as_posix())
    return files


def _collect_symbols(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    return {node.name for node in tree.body if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)}


def test_phase42_inventory_tracks_all_target_files_and_symbols() -> None:
    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    target_roots = inventory["targets"]

    indexed_files = {entry["path"]: entry for entry in inventory["files"]}
    indexed_symbols: dict[str, set[str]] = {}
    for item in inventory["symbols"]:
        indexed_symbols.setdefault(item["path"], set()).add(item["name"])
        assert item["tag"] in ALLOWED_TAGS, f"Invalid symbol tag: {item}"
        assert item["decision"] in ALLOWED_DECISIONS, f"Invalid symbol decision: {item}"

    current_files = _collect_target_files(target_roots=target_roots)
    assert set(indexed_files) == current_files, (
        "Phase 42 symbol inventory is stale. Update docs/phase42_symbol_inventory.json "
        "to include every file in utils/trees/sessions/log."
    )

    for path, metadata in indexed_files.items():
        assert metadata["tag"] in ALLOWED_TAGS, f"Invalid file tag: {metadata}"
        assert metadata["decision"] in ALLOWED_DECISIONS, f"Invalid file decision: {metadata}"
        current_symbols = _collect_symbols(REPO_ROOT / path)
        assert current_symbols <= indexed_symbols.get(
            path, set()
        ), f"Untracked symbols in {path}: {sorted(current_symbols - indexed_symbols.get(path, set()))}"


def test_phase42_removed_files_remain_deleted() -> None:
    inventory = json.loads(INVENTORY_PATH.read_text(encoding="utf-8"))
    removed_files = inventory.get("removed_files", [])
    reintroduced = []
    for item in removed_files:
        assert item["tag"] == "dead-candidate", f"Removed file must be dead-candidate: {item}"
        assert item["decision"] == "remove", f"Removed file must have remove decision: {item}"
        if item.get("status") != "removed":
            continue
        if (REPO_ROOT / item["path"]).exists():
            reintroduced.append(item["path"])

    assert reintroduced == [], f"Removed dead files reintroduced: {reintroduced}"
