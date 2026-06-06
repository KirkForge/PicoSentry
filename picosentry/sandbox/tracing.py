"""OpenTelemetry tracing hooks for distributed observability.

Provides lightweight tracing integration points for PicoDome's daemon
and scan pipeline. When the ``opentelemetry-api`` package is installed,
traces and spans are emitted. When it's not available, all operations
are no-ops with zero overhead.

This module does NOT depend on any specific OTel SDK at import time.
It degrades gracefully when OTel is not installed.

Usage in daemon mode::

    from picosentry.sandbox.tracing import get_tracer, trace_scan

    tracer = get_tracer()

    with tracer.start_as_current_span("picodome.scan") as span:
        span.set_attribute("picodome.command", " ".join(command))
        # ... execute scan ...
        span.set_attribute("picodome.verdict", verdict)

Configuration:
    PICODOME_TRACING_ENABLED — set to "1" to enable tracing (default: off)
    PICODOME_TRACING_EXPORTER — "otlp" or "none" (default: "none")
    OTEL_EXPORTER_OTLP_ENDPOINT — OTLP endpoint URL
"""

from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from typing import Any

logger = logging.getLogger("picodome.tracing")

# ─── Tracing availability check ─────────────────────────────────────────────

# `trace` is bound to the OTel module when available, or to `None` when not.
# Rebinding the module-level name to `None` trips mypy's `[assignment]`
# check, and the suppression needed for it is itself flagged as
# `[unused-ignore]` on newer mypy with `ignore_missing_imports = true`
# (since the missing-import becomes `Any` and the rebind is then safe).
# We use a separate sentinel to keep both versions of mypy happy without
# per-line ignores.
_TRACING_AVAILABLE = False
_Tracer: Any = Any  # redefined below when OTel available
_trace_module: Any = None  # the OTel `trace` module, or None if unavailable

try:
    from opentelemetry import trace as _otel_trace

    _TRACING_AVAILABLE = True
    _Tracer = _otel_trace.Tracer
    _trace_module = _otel_trace
except ImportError:
    pass


# ─── No-op tracer ───────────────────────────────────────────────────────────


class _NoopSpan:
    """A span that does nothing. Used when tracing is disabled."""

    def __enter__(self):
        return self

    def __exit__(self, *args: Any) -> None:
        pass

    def set_attribute(self, key: str, value: Any) -> None:
        pass

    def add_event(self, name: str, attributes: dict[str, Any] | None = None) -> None:
        pass

    def set_status(self, status: Any) -> None:
        pass

    def record_exception(self, exception: Exception) -> None:
        pass

    def end(self) -> None:
        pass


class _NoopTracer:
    """A tracer that creates no-op spans. Zero overhead when tracing is off."""

    def start_as_current_span(self, name: str, **kwargs: Any) -> _NoopSpan:
        return _NoopSpan()

    def start_span(self, name: str, **kwargs: Any) -> _NoopSpan:
        return _NoopSpan()


# ─── Module-level tracer ────────────────────────────────────────────────────

_tracer: _Tracer | _NoopTracer = _NoopTracer()
_tracing_enabled = os.environ.get("PICODOME_TRACING_ENABLED", "").lower() in ("1", "true", "yes")


def get_tracer() -> _Tracer | _NoopTracer:
    """Get the module-level tracer.

    Returns a real OpenTelemetry tracer if available and enabled,
    otherwise returns a no-op tracer with zero overhead.
    """
    global _tracer
    if isinstance(_tracer, _NoopTracer) and _tracing_enabled and _TRACING_AVAILABLE:
        _tracer = _trace_module.get_tracer("picodome", "0.5.0")
        logger.info("OpenTelemetry tracing enabled with tracer: picodome")
    return _tracer


def is_tracing_available() -> bool:
    """Check if OpenTelemetry tracing is available."""
    return _TRACING_AVAILABLE


def is_tracing_enabled() -> bool:
    """Check if tracing is enabled via environment variable."""
    return _tracing_enabled


# ─── Convenience trace helpers ───────────────────────────────────────────────


@contextmanager
def trace_scan(command: list[str], backend: str = "", **attrs: Any):
    """Trace a sandbox scan operation.

    Creates a span named ``picodome.scan`` with command and backend attributes.

    Args:
        command: The command being scanned.
        backend: The sandbox backend name.
        **attrs: Additional span attributes.
    """
    tracer = get_tracer()
    span = tracer.start_as_current_span("picodome.scan")
    try:
        if not isinstance(span, _NoopSpan):
            span.set_attribute("picodome.command", " ".join(command))
            if backend:
                span.set_attribute("picodome.backend", backend)
            for key, value in attrs.items():
                span.set_attribute(f"picodome.{key}", str(value))
        yield span
    except Exception:
        if not isinstance(span, _NoopSpan):
            span.record_exception(Exception)
        raise
    finally:
        if not isinstance(span, _NoopSpan):
            span.end()


@contextmanager
def trace_daemon_request(method: str, path: str, request_id: str = "", **attrs: Any):
    """Trace a daemon HTTP request.

    Creates a span named ``picodome.daemon.request`` with method, path, and
    request ID attributes.

    Args:
        method: HTTP method (GET, POST, etc.)
        path: Request path.
        request_id: X-Request-ID for distributed traceability.
        **attrs: Additional span attributes.
    """
    tracer = get_tracer()
    span = tracer.start_as_current_span("picodome.daemon.request")
    try:
        if not isinstance(span, _NoopSpan):
            span.set_attribute("http.method", method)
            span.set_attribute("http.path", path)
            if request_id:
                span.set_attribute("picodome.request_id", request_id)
            for key, value in attrs.items():
                span.set_attribute(f"picodome.{key}", str(value))
        yield span
    finally:
        if not isinstance(span, _NoopSpan):
            span.end()
