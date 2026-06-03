"""Health check endpoint."""

from __future__ import annotations

from picosentry.watch import __version__
from picosentry.watch.types import HealthStatus


def health_check(
    rules_loaded: int,
    corpus_hash: str,
    corpus_version: str,
    uptime_seconds: float = 0.0,
    rules_expected: int = 0,
    load_errors: list[str] | None = None,
) -> HealthStatus:
    """Return health status for PicoWatch.

    Args:
        rules_loaded: Number of defense rules successfully loaded.
        corpus_hash: SHA-256 hash of rule corpus.
        corpus_version: Version string of rule corpus.
        uptime_seconds: Process uptime in seconds.
        rules_expected: Number of rules expected from YAML files.
        load_errors: Errors encountered during rule loading.

    Returns:
        HealthStatus with healthy=True if rules are loaded and coverage is complete.
    """
    return HealthStatus(
        healthy=rules_loaded > 0 and rules_loaded >= rules_expected,
        version=__version__,
        rules_loaded=rules_loaded,
        corpus_hash=corpus_hash,
        corpus_version=corpus_version,
        uptime_seconds=uptime_seconds,
        rules_expected=rules_expected,
        load_errors=load_errors or [],
    )
