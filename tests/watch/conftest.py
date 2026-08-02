"""Shared watch-test fixtures."""

from __future__ import annotations

from collections.abc import Generator

import pytest


@pytest.fixture(autouse=True)
def _skip_watch_secure_assert(monkeypatch: pytest.MonkeyPatch) -> None:
    """Bypass PicoWatch startup security checks in tests.

    ``PicoWatchConfig.assert_secure()`` exits the process when no API key is
    configured. Tests that exercise the HTTP server with open access need that
    check disabled. The production security behaviour is still covered by
    ``tests/watch/test_config.py``.
    """
    monkeypatch.setenv("PICOWATCH_SKIP_SECURE_ASSERT", "1")


@pytest.fixture(autouse=True)
def _shutdown_watch_otel() -> Generator[None, None, None]:
    yield
    try:
        from picosentry.watch.telemetry.otel import shutdown_tracing

        shutdown_tracing()
    except ImportError:
        pass
