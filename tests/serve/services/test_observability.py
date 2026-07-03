"""Unit tests for observability exception-narrowing paths."""

from __future__ import annotations

import logging
import sys
import types

import pytest

from picosentry.serve.services import observability


def _make_stub_shutdown(exc: BaseException):
    class FakeProvider:
        def shutdown(self):
            raise exc

    return FakeProvider()


@pytest.fixture
def fake_opentelemetry(monkeypatch):
    """Inject minimal fake opentelemetry modules so init_telemetry reaches exporter setup."""
    metrics_module = types.ModuleType("opentelemetry.metrics")
    metrics_module.set_meter_provider = lambda p: None
    metrics_module.get_meter = lambda *args, **kwargs: _NoOpMeter()

    trace_module = types.ModuleType("opentelemetry.trace")
    trace_module.set_tracer_provider = lambda p: None
    trace_module.get_tracer = lambda *args, **kwargs: _NoOpTracer()

    sdk_metrics = types.ModuleType("opentelemetry.sdk.metrics")
    sdk_metrics.MeterProvider = _FakeProvider

    sdk_resources = types.ModuleType("opentelemetry.sdk.resources")
    sdk_resources.Resource = _FakeResource

    sdk_trace = types.ModuleType("opentelemetry.sdk.trace")
    sdk_trace.TracerProvider = _FakeProvider

    sdk_trace_export = types.ModuleType("opentelemetry.sdk.trace.export")
    sdk_trace_export.BatchSpanProcessor = _FakeBatchSpanProcessor

    sdk_metrics_export = types.ModuleType("opentelemetry.sdk.metrics.export")
    sdk_metrics_export.PeriodicExportingMetricReader = _FakePeriodicReader

    for name, mod in [
        ("opentelemetry.metrics", metrics_module),
        ("opentelemetry.trace", trace_module),
        ("opentelemetry.sdk.metrics", sdk_metrics),
        ("opentelemetry.sdk.metrics.export", sdk_metrics_export),
        ("opentelemetry.sdk.resources", sdk_resources),
        ("opentelemetry.sdk.trace", sdk_trace),
        ("opentelemetry.sdk.trace.export", sdk_trace_export),
    ]:
        monkeypatch.setitem(sys.modules, name, mod)


class _NoOpTracer:
    def start_as_current_span(self, name, **kwargs):
        return _NoOpContextManager(_NoOpSpan())

    def start_span(self, name, **kwargs):
        return _NoOpSpan()


class _NoOpSpan:
    def set_attribute(self, key, value):
        pass

    def add_event(self, name, attributes=None):
        pass

    def set_status(self, status, description=""):
        pass

    def record_exception(self, exception, attributes=None):
        pass

    def end(self):
        pass


class _NoOpContextManager:
    def __init__(self, span):
        self._span = span

    def __enter__(self):
        return self._span

    def __exit__(self, *args):
        return False


class _NoOpMeter:
    def create_counter(self, name, **kwargs):
        return _NoOpInstrument()

    def create_histogram(self, name, **kwargs):
        return _NoOpInstrument()

    def create_gauge(self, name, **kwargs):
        return _NoOpInstrument()

    def create_up_down_counter(self, name, **kwargs):
        return _NoOpInstrument()


class _NoOpInstrument:
    def add(self, amount, attributes=None):
        pass

    def record(self, amount, attributes=None):
        pass

    def set(self, amount, attributes=None):
        pass


class _FakeProvider:
    def __init__(self, *args, **kwargs):
        pass

    def add_span_processor(self, processor):
        pass

    def shutdown(self):
        pass


class _FakeResource:
    @staticmethod
    def create(_attrs):
        return _FakeResource()


class _FakeBatchSpanProcessor:
    def __init__(self, exporter):
        pass


class _FakePeriodicReader:
    def __init__(self, exporter, export_interval_millis=None):
        pass


class TestObservabilityHardening:
    """OTel setup/shutdown must tolerate expected failures but surface programmer errors."""

    def test_otel_init_expected_failure_is_logged(self, fake_opentelemetry, monkeypatch, caplog):
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")

        def _boom(*args, **kwargs):
            raise RuntimeError("exporter unavailable")

        monkeypatch.setattr(observability, "_load_otlp_exporters", _boom)

        with caplog.at_level(logging.WARNING, logger="picoshogun.Observability"):
            result = observability.init_telemetry()

        assert result is False
        assert any("Failed to initialize OTEL" in r.message for r in caplog.records)

    def test_otel_init_unexpected_error_propagates(self, fake_opentelemetry, monkeypatch):
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")

        def _buggy(*args, **kwargs):
            raise NameError("programmer bug")

        monkeypatch.setattr(observability, "_load_otlp_exporters", _buggy)

        with pytest.raises(NameError, match="programmer bug"):
            observability.init_telemetry()

    def test_tracer_shutdown_expected_failure_is_logged(self, monkeypatch, caplog):
        monkeypatch.setattr(observability, "_tracer_provider", _make_stub_shutdown(OSError("shutdown failed")))
        monkeypatch.setattr(observability, "_meter_provider", None)

        with caplog.at_level(logging.DEBUG, logger="picoshogun.Observability"):
            observability.shutdown_telemetry()

        assert any("Tracer provider shutdown failed" in r.message for r in caplog.records)

    def test_meter_shutdown_expected_failure_is_logged(self, monkeypatch, caplog):
        monkeypatch.setattr(observability, "_tracer_provider", None)
        monkeypatch.setattr(observability, "_meter_provider", _make_stub_shutdown(RuntimeError("shutdown failed")))

        with caplog.at_level(logging.DEBUG, logger="picoshogun.Observability"):
            observability.shutdown_telemetry()

        assert any("Meter provider shutdown failed" in r.message for r in caplog.records)

    def test_fastapi_instrumentation_expected_failure_is_logged(self, monkeypatch, caplog):
        class FakeInstrumentor:
            def instrument_app(self, app):
                raise RuntimeError("instrumentation failed")

        fake_module = types.ModuleType("opentelemetry.instrumentation.fastapi")
        fake_module.FastAPIInstrumentor = FakeInstrumentor
        monkeypatch.setitem(sys.modules, "opentelemetry.instrumentation.fastapi", fake_module)

        with caplog.at_level(logging.WARNING, logger="picoshogun.Observability"):
            result = observability.setup_fastapi_instrumentation(object())

        assert result is False
        assert any("FastAPI instrumentation failed" in r.message for r in caplog.records)

    def test_fastapi_instrumentation_unexpected_error_propagates(self, monkeypatch):
        class FakeInstrumentor:
            def instrument_app(self, app):
                raise NameError("programmer bug")

        fake_module = types.ModuleType("opentelemetry.instrumentation.fastapi")
        fake_module.FastAPIInstrumentor = FakeInstrumentor
        monkeypatch.setitem(sys.modules, "opentelemetry.instrumentation.fastapi", fake_module)

        with pytest.raises(NameError, match="programmer bug"):
            observability.setup_fastapi_instrumentation(object())
