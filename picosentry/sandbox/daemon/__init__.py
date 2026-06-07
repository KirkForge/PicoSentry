"""PicoDome Daemon — HTTP API for sandbox-as-a-service.

Provides a REST API so the Shogun command center and other orchestration
tools can submit sandbox jobs, query results, and manage policies
programmatically.

Authentication: token-based (``Authorization: Bearer <token>``).
Transport: HTTP/1.1 over Unix socket or TCP.

Internal layout (v2.1.0 refactor):
- :mod:`picosentry.sandbox.daemon.constants`        — CORS, API version, enterprise mode
- :mod:`picosentry.sandbox.daemon.job_store`        — in-memory :class:`ScanJobStore`
- :mod:`picosentry.sandbox.daemon.handler_mixins`   — auth + response mixins
- :mod:`picosentry.sandbox.daemon.handler_routes_get`  — GET route mixin
- :mod:`picosentry.sandbox.daemon.handler_routes_post` — POST route mixin
- :mod:`picosentry.sandbox.daemon.handler`          — :class:`PicoDomeHandler`
- :mod:`picosentry.sandbox.daemon.daemon`           — :class:`PicoDomeDaemon`
- :mod:`picosentry.sandbox.daemon.app`              — :func:`create_app`
- :mod:`picosentry.sandbox.daemon.server`           — back-compat shim
"""
from __future__ import annotations

from picosentry.sandbox.daemon.server import PicoDomeDaemon, create_app

__all__ = ["PicoDomeDaemon", "create_app"]
