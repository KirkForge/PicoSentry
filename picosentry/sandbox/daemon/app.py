from __future__ import annotations

import os
from typing import Any

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
    cluster_config: dict[str, Any] | None = None,
) -> PicoDomeDaemon:
    if tokens:
        os.environ["PICODOME_API_TOKENS"] = tokens

    daemon = PicoDomeDaemon(
        host=host,
        port=port,
        metrics_port=metrics_port,
        job_store_dir=job_store_dir,
        store_backend=store_backend,
        cluster_config=cluster_config,
    )

    if background:
        daemon.start(background=True)

    return daemon
