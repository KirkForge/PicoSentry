from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from picosentry.watch.config import PicoWatchConfig
    from picosentry.watch.health import health_check
    from picosentry.watch.output_guard import OutputGuard
    from picosentry.watch.picoshogun import PicoWatchPlugin, WatchGuard
    from picosentry.watch.prompt_guard import PromptGuard
    from picosentry.watch.telemetry import TelemetrySink
    from picosentry.watch.types import (
        HealthStatus,
        PromptScanResult,
        Rule,
        ValidationResult,
        Verdict,
    )

__version__ = "2.1.2"

# ponytail: submodules are deferred so `from picosentry.watch import __version__`
# (version/health commands, every CLI --version) stays cheap; attribute access
# resolves identically. Upgrade path: none — dict lookup after first load.
_LAZY = {
    "PicoWatchConfig": "config",
    "health_check": "health",
    "OutputGuard": "output_guard",
    "PicoWatchPlugin": "picoshogun",
    "WatchGuard": "picoshogun",
    "PromptGuard": "prompt_guard",
    "TelemetrySink": "telemetry",
    "HealthStatus": "types",
    "PromptScanResult": "types",
    "Rule": "types",
    "ValidationResult": "types",
    "Verdict": "types",
}


def __getattr__(name: str) -> Any:
    submodule = _LAZY.get(name)
    if submodule is not None:
        from importlib import import_module

        return getattr(import_module(f"picosentry.watch.{submodule}"), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "HealthStatus",
    "OutputGuard",
    "PicoWatchConfig",
    "PicoWatchPlugin",
    "PromptGuard",
    "PromptScanResult",
    "Rule",
    "TelemetrySink",
    "ValidationResult",
    "Verdict",
    "WatchGuard",
    "health_check",
]
