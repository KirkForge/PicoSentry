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
