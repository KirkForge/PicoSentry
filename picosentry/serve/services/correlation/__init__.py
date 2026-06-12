from __future__ import annotations


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


correlation_engine = CorrelationEngine()

__all__ = [
    "PHASE_WEIGHTS",
    "CorrelatedEvent",
    "CorrelationEngine",
    "KillChainPhase",
    "KillChainTimeline",
    "_confidence_from_str",
    "_confidence_index",
    "_severity_from_str",
    "_severity_index",
    "build_event_from_intel",
    "correlation_engine",
]
