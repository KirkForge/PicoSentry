"""PicoDomeDaemon factory.

Extracted in v2.1.0 (refactor) from ``picosentry/sandbox/daemon/server.py``.
"""
from __future__ import annotations

import os

from picosentry.sandbox.daemon.daemon import PicoDomeDaemon

__all__ = ["create_app"]


def create_app(
    host: str | None = None,
    port: int | None = None,
    metrics_port: int | None = None,
    job_store_dir: str | None = None,
    store_backend: str | None = None,
    tokens: str | None = None,
    background: bool = False,
) -> PicoDomeDaemon:
    """Factory function to create an PicoDomeDaemon instance.

    Convenience wrapper around ``PicoDomeDaemon`` constructor for
    programmatic use (testing, WSGI adapters, orchestration).

    Args:
        host: Bind address (default: ``PICODOME_DAEMON_HOST`` env or ``127.0.0.1``).
        port: Bind port (default: ``PICODOME_DAEMON_PORT`` env or ``8443``).
        metrics_port: Separate metrics port (default: ``PICODOME_METRICS_PORT`` env).
        job_store_dir: Directory for persistent job storage.
        store_backend: Store backend type (``jsonl`` or ``sqlite``).
        tokens: Comma-separated API tokens (sets ``PICODOME_API_TOKENS`` env).
        background: If true, start the daemon in a background thread.

    Returns:
        Configured ``PicoDomeDaemon`` instance (started if *background* is True).
    """
    if tokens:
        os.environ["PICODOME_API_TOKENS"] = tokens

    daemon = PicoDomeDaemon(
        host=host,
        port=port,
        metrics_port=metrics_port,
        job_store_dir=job_store_dir,
        store_backend=store_backend,
    )

    if background:
        daemon.start(background=True)

    return daemon
