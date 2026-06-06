"""
PicoSentry — deterministic supply-chain scanner for npm/pnpm.

Same inputs + same corpus version = same findings and scan fingerprint.
No HTTP at scan time. No probabilistic heuristics. No narrative in findings.

Usage:
    from picosentry import ScanEngine, create_default_engine
    result = create_default_engine().scan("./my-project")
    print(result.to_json())

Deterministic guard stack:
    from picosentry.scan.guards import (
        DeterministicGuard, DeterminismViolation,
        deterministic_hash, fingerprint_scan,
        verify_determinism, diff_scans,
    )
"""

from .engine import ScanEngine, create_default_engine, user_corpus_dir
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

__version__ = "2.0.7"
__all__ = [
    "BaselineResult",
    "Confidence",
    "Finding",
    "RuleExecution",
    "ScanEngine",
    "ScanResult",
    "ScanStats",
    "Severity",
    "apply_baseline",
    "create_default_engine",
    "load_baseline",
    "user_corpus_dir",
]
