from __future__ import annotations

import logging
import os
from contextlib import contextmanager
from typing import Any

logger = logging.getLogger("picodome.tracing")


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


class _NoopSpan:
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
    def start_as_current_span(self, name: str, **kwargs: Any) -> _NoopSpan:
        return _NoopSpan()

    def start_span(self, name: str, **kwargs: Any) -> _NoopSpan:
        return _NoopSpan()


_tracer: _Tracer | _NoopTracer = _NoopTracer()
_tracing_enabled = os.environ.get("PICODOME_TRACING_ENABLED", "").lower() in ("1", "true", "yes")


def get_tracer() -> _Tracer | _NoopTracer:
    global _tracer
    if isinstance(_tracer, _NoopTracer) and _tracing_enabled and _TRACING_AVAILABLE:
        _tracer = _trace_module.get_tracer("picodome", "0.5.0")
        logger.info("OpenTelemetry tracing enabled with tracer: picodome")
    return _tracer


def is_tracing_available() -> bool:
    return _TRACING_AVAILABLE


def is_tracing_enabled() -> bool:
    return _tracing_enabled


@contextmanager
def trace_scan(command: list[str], backend: str = "", **attrs: Any):
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
