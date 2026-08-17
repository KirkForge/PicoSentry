__version__ = "2.1.2"  # kept in lockstep with the top-level picosentry.__version__

from picosentry._core.security import constant_time_compare as constant_time_compare
from picosentry._core.time import now_ms as now_ms
from picosentry._core.tracing import (
    NoOpInstrument as NoOpInstrument,
    NoOpMeter as NoOpMeter,
    NoOpSpan as NoOpSpan,
    NoOpTracer as NoOpTracer,
)
