from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from picosentry.sandbox.l4.engine import L4Engine, analyze, create_default_engine
    from picosentry.sandbox.l4.models import (
        AnalysisResult,
        Baseline,
        BehavioralProfile,
        DriftResult,
    )
    from picosentry.sandbox.l4.profiler import profile_from_sandbox_result, profile_from_trace

# ponytail: l4/__init__ is a pure re-export layer; importing any l4 submodule
# (models, in every test conftest path) no longer pays for engine+profiler.
# Submodule names are in the map so attribute access keeps working. Upgrade
# path: none — dict lookup after first load.
_LAZY = {
    "engine": "engine",
    "L4Engine": "engine",
    "analyze": "engine",
    "create_default_engine": "engine",
    "models": "models",
    "AnalysisResult": "models",
    "Baseline": "models",
    "BehavioralProfile": "models",
    "DriftResult": "models",
    "profiler": "profiler",
    "profile_from_sandbox_result": "profiler",
    "profile_from_trace": "profiler",
}


def __getattr__(name: str) -> Any:
    submodule = _LAZY.get(name)
    if submodule is not None:
        from importlib import import_module

        return getattr(import_module(f"picosentry.sandbox.l4.{submodule}"), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "AnalysisResult",
    "Baseline",
    "BehavioralProfile",
    "DriftResult",
    "L4Engine",
    "analyze",
    "create_default_engine",
    "profile_from_sandbox_result",
    "profile_from_trace",
]
