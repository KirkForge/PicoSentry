"""State backends for cluster shared state.

- :class:`~picosentry.sandbox.cluster.backends.base.StateBackend` — abstract
  base defining the CRUD interface for nodes and scans plus leader pointer.
- :class:`~picosentry.sandbox.cluster.backends.memory.MemoryStateBackend` —
  in-memory backend for single-node or testing.
- :class:`~picosentry.sandbox.cluster.backends.sqlite.SQLiteStateBackend` —
  persistent SQLite backend for cross-restart shared state.
"""
from picosentry.sandbox.cluster.backends.base import StateBackend
from picosentry.sandbox.cluster.backends.memory import MemoryStateBackend
from picosentry.sandbox.cluster.backends.sqlite import SQLiteStateBackend

__all__ = ["MemoryStateBackend", "SQLiteStateBackend", "StateBackend"]
