import logging
import os

from picosentry.serve.config.version import __version__

logger = logging.getLogger("picoshogun.Observability")


_tracer_provider = None
_meter_provider = None
_tracer = None
_meter = None


def init_telemetry(service_name: str = "picoshogun", endpoint: str | None = None) -> bool:
    global _tracer_provider, _meter_provider, _tracer, _meter

    endpoint = endpoint or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    if not endpoint:
        logger.info("No OTEL endpoint configured — tracing disabled")
        return False

    try:
        from opentelemetry import metrics, trace
        from opentelemetry.sdk.metrics import MeterProvider
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        OTLPSpanExporter, OTLPMetricExporter, use_grpc = _load_otlp_exporters()

        resource = Resource.create(
            {
                "service.name": service_name,
                "service.version": __version__,
                "deployment.environment": os.environ.get("PICOSHOGUN_ENV", os.environ.get("SHOGUN_ENV", "development")),
            }
        )

        _tracer_provider = TracerProvider(resource=resource)
        if use_grpc:
            span_exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
        else:
            span_exporter = OTLPSpanExporter(endpoint=endpoint)
        _tracer_provider.add_span_processor(BatchSpanProcessor(span_exporter))
        trace.set_tracer_provider(_tracer_provider)
        _tracer = trace.get_tracer(service_name, __version__)

        if use_grpc:
            _metric_exporter = OTLPMetricExporter(endpoint=endpoint, insecure=True)
        else:
            _metric_exporter = OTLPMetricExporter(endpoint=endpoint)

        from opentelemetry.sdk.metrics.export import PeriodicExportingMetricReader

        _metric_reader = PeriodicExportingMetricReader(_metric_exporter, export_interval_millis=60000)
        _meter_provider = MeterProvider(resource=resource, metric_readers=[_metric_reader])
        metrics.set_meter_provider(_meter_provider)
        _meter = metrics.get_meter(service_name, __version__)

        logger.info("OpenTelemetry initialized — endpoint=%s, grpc=%s", endpoint, use_grpc)
        return True

    except ImportError:
        logger.info("opentelemetry packages not installed — tracing disabled")
        return False
    except Exception as e:
        logger.warning("Failed to initialize OTEL: %s", e)
        return False


def shutdown_telemetry() -> None:
    """Shut down OpenTelemetry providers and reset module state.

    Call this during application shutdown or test teardown to stop background
    span/metric export threads.
    """
    global _tracer_provider, _meter_provider, _tracer, _meter

    try:
        if _tracer_provider is not None and hasattr(_tracer_provider, "shutdown"):
            _tracer_provider.shutdown()
    except Exception:
        logger.debug("Tracer provider shutdown failed", exc_info=True)

    try:
        if _meter_provider is not None and hasattr(_meter_provider, "shutdown"):
            _meter_provider.shutdown()
    except Exception:
        logger.debug("Meter provider shutdown failed", exc_info=True)

    _tracer_provider = None
    _meter_provider = None
    _tracer = None
    _meter = None


def get_tracer():
    if _tracer is None:
        return NoOpTracer()
    return _tracer


def get_meter():
    if _meter is None:
        return NoOpMeter()
    return _meter


class NoOpTracer:
    def start_as_current_span(self, name, **kwargs):
        from contextlib import nullcontext

        return nullcontext(NoOpSpan())

    def start_span(self, name, **kwargs):
        return NoOpSpan()


class NoOpSpan:
    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass

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


def _load_otlp_exporters():
    try:
        from opentelemetry.exporter.otlp.proto.grpc.metric_exporter import (
            OTLPMetricExporter as GrpcMetricExporter,
        )
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import (
            OTLPSpanExporter as GrpcSpanExporter,
        )

        return GrpcSpanExporter, GrpcMetricExporter, True
    except ImportError:
        from opentelemetry.exporter.otlp.proto.http.metric_exporter import (
            OTLPMetricExporter as HttpMetricExporter,
        )
        from opentelemetry.exporter.otlp.proto.http.trace_exporter import (
            OTLPSpanExporter as HttpSpanExporter,
        )

        return HttpSpanExporter, HttpMetricExporter, False


class NoOpMeter:
    def create_counter(self, name, **kwargs):
        return NoOpInstrument()

    def create_histogram(self, name, **kwargs):
        return NoOpInstrument()

    def create_gauge(self, name, **kwargs):
        return NoOpInstrument()

    def create_up_down_counter(self, name, **kwargs):
        return NoOpInstrument()


class NoOpInstrument:
    def add(self, amount, attributes=None):
        pass

    def record(self, amount, attributes=None):
        pass

    def set(self, amount, attributes=None):
        pass


def setup_fastapi_instrumentation(app):
    try:
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

        FastAPIInstrumentor().instrument_app(app)
        logger.info("FastAPI OTEL instrumentation enabled")
        return True
    except ImportError:
        logger.info("FastAPIInstrumentor not available — skipping auto-instrumentation")
        return False
    except Exception as e:
        logger.warning("FastAPI instrumentation failed: %s", e)
        return False


def trace_span(name: str, attributes: dict | None = None):
    def decorator(func):
        def wrapper(*args, **kwargs):
            tracer = get_tracer()
            with tracer.start_as_current_span(name) as span:
                if attributes:
                    for k, v in attributes.items():
                        span.set_attribute(k, v)
                try:
                    result = func(*args, **kwargs)
                    span.set_attribute("result", "success")
                    return result
                except Exception as e:
                    span.set_attribute("result", "error")
                    span.set_attribute("error.type", type(e).__name__)
                    span.set_attribute("error.message", str(e))
                    raise

        return wrapper

    return decorator


def trace_async_span(name: str, attributes: dict | None = None):
    def decorator(func):
        async def wrapper(*args, **kwargs):
            tracer = get_tracer()
            with tracer.start_as_current_span(name) as span:
                if attributes:
                    for k, v in attributes.items():
                        span.set_attribute(k, v)
                try:
                    result = await func(*args, **kwargs)
                    span.set_attribute("result", "success")
                    return result
                except Exception as e:
                    span.set_attribute("result", "error")
                    span.set_attribute("error.type", type(e).__name__)
                    span.set_attribute("error.message", str(e))
                    raise

        return wrapper

    return decorator
