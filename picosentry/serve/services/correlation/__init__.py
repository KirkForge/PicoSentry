"""PicoSentry serve — kill-chain correlation (v2.1.0 refactor).

The original ``picosentry/serve/services/correlation.py`` was 1080 lines.
v2.1.0 splits it into submodules:

- :mod:`picosentry.serve.services.correlation.models`     — dataclasses,
  ``KillChainPhase``, phase/severity/rule mapping tables
- :mod:`picosentry.serve.services.correlation.helpers`    — string↔enum
  conversion and :func:`build_event_from_intel`
- :mod:`picosentry.serve.services.correlation.narrative`  — narrative
  generation (extracted as a free function)
- :mod:`picosentry.serve.services.correlation.persistence` — SQLite
  persistence for events and chain cache (free functions, take the engine)
- :mod:`picosentry.serve.services.correlation.engine`     — the
  :class:`CorrelationEngine` class

This ``__init__`` re-exports the public API (and owns the
``correlation_engine`` singleton) for back-compat with code that imports
from ``picosentry.serve.services.correlation``.

.. note::

   The package directory and an earlier ``correlation.py`` shim cannot
   coexist at the same name — Python prefers the package. The shim was
   therefore folded into this ``__init__``. The import path is unchanged.
"""
from __future__ import annotations

# Re-export the public API from the submodules
from picosentry.serve.services.correlation.engine import CorrelationEngine
from picosentry.serve.services.correlation.helpers import (
    _confidence_from_str,
    _confidence_index,
    _severity_from_str,
    _severity_index,
    build_event_from_intel,
)
from picosentry.serve.services.correlation.models import (
    CorrelatedEvent,
    KillChainPhase,
    KillChainTimeline,
    PHASE_WEIGHTS,
)

# ── Global instance ────────────────────────────────────────────────────────
#
# api/server.py toggles ``correlation_engine.PERSIST_ENABLED`` and calls
# ``correlation_engine.load_events()``. Tests do
# ``from picosentry.serve.services.correlation import correlation_engine``.
# Owning the singleton here keeps the surface stable.

correlation_engine = CorrelationEngine()

__all__ = [
    "CorrelatedEvent",
    "CorrelationEngine",
    "KillChainPhase",
    "KillChainTimeline",
    "PHASE_WEIGHTS",
    "_confidence_from_str",
    "_confidence_index",
    "_severity_from_str",
    "_severity_index",
    "build_event_from_intel",
    "correlation_engine",
]
