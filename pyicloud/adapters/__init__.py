"""Adapter layer for infra implementations of application ports."""

from .tree_runtime import FileBackedTreeRuntimeAdapter

__all__ = ["FileBackedTreeRuntimeAdapter"]
