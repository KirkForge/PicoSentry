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


class TestObservabilityHardening:
    """OTel setup/shutdown must tolerate expected failures but surface programmer errors."""

    def test_otel_init_expected_failure_is_logged(self, monkeypatch, caplog):
        monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "http://localhost:4317")

        def _boom(*args, **kwargs):
            raise RuntimeError("exporter unavailable")

        monkeypatch.setattr(observability, "_load_otlp_exporters", _boom)

        with caplog.at_level(logging.WARNING, logger="picoshogun.Observability"):
            result = observability.init_telemetry()

        assert result is False
        assert any("Failed to initialize OTEL" in r.message for r in caplog.records)

    def test_otel_init_unexpected_error_propagates(self, monkeypatch):
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
