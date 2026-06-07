"""PicoDome Daemon — v2.1.0 back-compat shim.

The original ``picosentry/sandbox/daemon/server.py`` was 1364 lines. v2.1.0
splits the giant :class:`PicoDomeHandler` into four mixins, and the rest of
the daemon machinery into focused modules:

- :mod:`picosentry.sandbox.daemon.constants`        — API_VERSION, CORS,
  enterprise mode flag
- :mod:`picosentry.sandbox.daemon.job_store`        — in-memory
  :class:`ScanJobStore`
- :mod:`picosentry.sandbox.daemon.handler_mixins`   —
  :class:`PicoDomeResponseMixin` and :class:`PicoDomeAuthMixin`
- :mod:`picosentry.sandbox.daemon.handler_routes_get`  — GET route mixin
- :mod:`picosentry.sandbox.daemon.handler_routes_post` — POST route mixin
- :mod:`picosentry.sandbox.daemon.handler`          — :class:`PicoDomeHandler`
  composing the mixins
- :mod:`picosentry.sandbox.daemon.daemon`           — :class:`PicoDomeDaemon`
- :mod:`picosentry.sandbox.daemon.app`              — :func:`create_app`

This file re-exports the public API (``PicoDomeHandler``, ``PicoDomeDaemon``,
``create_app``) for back-compat. The ``test_audit_coverage.py`` test uses
strings like ``picosentry.sandbox.daemon.server._handle_submit_scan`` as
documentation of emit locations; those remain valid as long as the test
is updated to point to the new module locations (or as long as the test
treats the strings as opaque documentation, which it does — see
``test_audit_coverage.py::TestAllEventsHaveEmitLocation::EMIT_LOCATIONS``).

The shim is on the deprecation path for v2.2.0: new code should import
from :mod:`picosentry.sandbox.daemon` (the package) or from
:mod:`picosentry.sandbox.daemon.handler` etc. directly.
"""
from __future__ import annotations

from picosentry.sandbox.daemon.app import create_app
from picosentry.sandbox.daemon.constants import API_VERSION
from picosentry.sandbox.daemon.daemon import PicoDomeDaemon
from picosentry.sandbox.daemon.handler import PicoDomeHandler
from picosentry.sandbox.daemon.handler_routes_post import (
    PicoDomePostRoutesMixin,
)
from picosentry.sandbox.daemon.job_store import ScanJobStore

__all__ = [
    "API_VERSION",
    "PicoDomeDaemon",
    "PicoDomeHandler",
    "PicoDomePostRoutesMixin",
    "ScanJobStore",
    "create_app",
]
