from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .engine import ScanEngine, create_default_engine, user_corpus_dir
    from .intelligence import IntelligenceMode, OSVClient
    from .models import (
        BaselineResult,
        Confidence,
        Finding,
        RuleExecution,
        ScanResult,
        ScanStats,
        Severity,
        apply_baseline,
        load_baseline,
    )
    from .package_intel import PackageIntel, PackageIntelligence
    from .version_diff import DiffVerdict, VersionDelta, VersionDiff, format_delta

__version__ = "2.2.0"

# ponytail: all re-exports deferred so importing picosentry.scan (paid on every
# picosentry.scan.* submodule import and by test conftests) is just __version__;
# engine+intelligence are the heavy half (urllib chain). Direct submodule imports
# are unaffected. Upgrade path: none — dict lookup after first load.
_LAZY = {
    "ScanEngine": "engine",
    "create_default_engine": "engine",
    "user_corpus_dir": "engine",
    "IntelligenceMode": "intelligence",
    "OSVClient": "intelligence",
    "BaselineResult": "models",
    "Confidence": "models",
    "Finding": "models",
    "RuleExecution": "models",
    "ScanResult": "models",
    "ScanStats": "models",
    "Severity": "models",
    "apply_baseline": "models",
    "load_baseline": "models",
    "PackageIntel": "package_intel",
    "PackageIntelligence": "package_intel",
    "DiffVerdict": "version_diff",
    "VersionDelta": "version_diff",
    "VersionDiff": "version_diff",
    "format_delta": "version_diff",
}


def __getattr__(name: str) -> Any:
    submodule = _LAZY.get(name)
    if submodule is not None:
        from importlib import import_module

        return getattr(import_module(f"picosentry.scan.{submodule}"), name)
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = [
    "BaselineResult",
    "Confidence",
    "DiffVerdict",
    "Finding",
    "IntelligenceMode",
    "OSVClient",
    "PackageIntel",
    "PackageIntelligence",
    "RuleExecution",
    "ScanEngine",
    "ScanResult",
    "ScanStats",
    "Severity",
    "VersionDelta",
    "VersionDiff",
    "apply_baseline",
    "create_default_engine",
    "format_delta",
    "load_baseline",
    "user_corpus_dir",
]
