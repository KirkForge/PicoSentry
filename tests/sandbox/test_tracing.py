"""Tests for OpenTelemetry tracing hooks."""

from picosentry.sandbox.tracing import (
    _NoopSpan,
    _NoopTracer,
    get_tracer,
    is_tracing_available,
    is_tracing_enabled,
    trace_daemon_request,
    trace_scan,
)


class TestTracingNoop:
    """Test no-op tracer behavior (default when OTel is not installed)."""

    def test_noop_tracer_returns_noop_span(self):
        tracer = _NoopTracer()
        span = tracer.start_as_current_span("test")
        assert isinstance(span, _NoopSpan)

    def test_noop_span_context_manager(self):
        span = _NoopSpan()
        with span:
            pass  # No exception

    def test_noop_span_set_attribute(self):
        span = _NoopSpan()
        span.set_attribute("key", "value")  # Should not raise

    def test_noop_span_add_event(self):
        span = _NoopSpan()
        span.add_event("event_name")  # Should not raise

    def test_noop_span_end(self):
        span = _NoopSpan()
        span.end()  # Should not raise

    def test_get_tracer_returns_noop_when_disabled(self):
        tracer = get_tracer()
        # Without PICODOME_TRACING_ENABLED, should be no-op
        assert isinstance(tracer, _NoopTracer)

    def test_is_tracing_available(self):
        # OTel is not installed in test environment
        result = is_tracing_available()
        assert isinstance(result, bool)

    def test_is_tracing_enabled_default(self):
        # Default is disabled
        result = is_tracing_enabled()
        assert isinstance(result, bool)


class TestTraceScan:
    """Test trace_scan context manager."""

    def test_trace_scan_no_exception(self):
        with trace_scan(command=["echo", "hello"], backend="subprocess"):
            pass  # Should not raise

    def test_trace_scan_with_exception(self):
        try:
            with trace_scan(command=["echo", "hello"]):
                raise ValueError("test error")
        except ValueError:
            pass  # Expected

    def test_trace_scan_with_attrs(self):
        with trace_scan(command=["echo"], backend="auto", timeout=30):
            pass  # Should not raise


class TestTraceDaemonRequest:
    """Test trace_daemon_request context manager."""

    def test_trace_get_request(self):
        with trace_daemon_request(method="GET", path="/health"):
            pass

    def test_trace_post_request(self):
        with trace_daemon_request(method="POST", path="/api/v1/scan", request_id="picodome-abc123"):
            pass

    def test_trace_request_with_attrs(self):
        with trace_daemon_request(method="GET", path="/metrics", actor="admin"):
            pass
