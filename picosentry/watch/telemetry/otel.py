from __future__ import annotations

import logging
from typing import Any, TYPE_CHECKING


if TYPE_CHECKING:
    from picosentry.watch.types import PromptScanResult, ValidationResult

logger = logging.getLogger("picowatch.otel")


_tracer: Any = None
_initialized = False


def init_tracing(service_name: str = "picowatch", endpoint: str | None = None) -> bool:
    global _tracer, _initialized

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor

        resource = Resource.create({"service.name": service_name, "service.version": "1.0.1"})
        provider = TracerProvider(resource=resource)

        if endpoint:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter

            exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
            provider.add_span_processor(BatchSpanProcessor(exporter))

        trace.set_tracer_provider(provider)
        _tracer = trace.get_tracer("picowatch", "1.0.1")
        _initialized = True
        logger.info("OpenTelemetry tracing initialized (service=%s, endpoint=%s)", service_name, endpoint)
        return True

    except ImportError:
        logger.debug("OpenTelemetry dependencies not installed. Tracing disabled.")
        return False


def shutdown_tracing() -> None:
    """Shut down the OpenTelemetry tracer provider and reset module state.

    Call this during test teardown or application shutdown to stop background
    export threads that would otherwise keep the process alive.
    """
    global _tracer, _initialized

    try:
        from opentelemetry import trace

        provider = trace.get_tracer_provider()
        if hasattr(provider, "shutdown"):
            provider.shutdown()
    except Exception:
        logger.debug("Tracer provider shutdown failed or was not initialized", exc_info=True)
    finally:
        _tracer = None
        _initialized = False


def trace_prompt_scan(result: PromptScanResult, model: str | None = None) -> None:
    if not _initialized or _tracer is None:
        return

    try:
        from opentelemetry import trace

        with _tracer.start_as_current_span("picowatch.prompt_guard.scan") as span:
            span.set_attribute("picowatch.request.id", result.details.get("request_id", ""))
            span.set_attribute("picowatch.prompt.blocked", result.blocked)
            span.set_attribute("picowatch.prompt.score", result.score)
            span.set_attribute("picowatch.prompt.rules_matched", ",".join(result.rules_matched))
            span.set_attribute("picowatch.prompt.verdict", result.verdict.value)
            span.set_attribute("picowatch.prompt.corpus_hash", result.corpus_hash)
            span.set_attribute("picowatch.prompt.corpus_version", result.corpus_version)
            span.set_attribute("picowatch.latency_ms", result.duration_ms)
            if model:
                span.set_attribute("picowatch.model", model)

            if result.blocked:
                span.set_status(trace.StatusCode.ERROR, "Prompt blocked")
    except Exception:
        logger.debug("Failed to record prompt scan span", exc_info=True)


def trace_output_validation(result: ValidationResult, model: str | None = None) -> None:
    if not _initialized or _tracer is None:
        return

    try:
        from opentelemetry import trace

        with _tracer.start_as_current_span("picowatch.output_guard.validate") as span:
            span.set_attribute("picowatch.output.valid", result.valid)
            span.set_attribute("picowatch.output.score", result.score)
            span.set_attribute("picowatch.output.violations", ",".join(result.violations))
            span.set_attribute("picowatch.output.verdict", result.verdict.value)
            span.set_attribute("picowatch.output.corpus_hash", result.corpus_hash)
            span.set_attribute("picowatch.output.corpus_version", result.corpus_version)
            span.set_attribute("picowatch.latency_ms", result.duration_ms)
            if model:
                span.set_attribute("picowatch.model", model)

            if not result.valid:
                span.set_status(trace.StatusCode.ERROR, "Output validation failed")
    except Exception:
        logger.debug("Failed to record output validation span", exc_info=True)
