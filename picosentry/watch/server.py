
from __future__ import annotations

import logging
import os
import secrets
import uuid
from typing import Any

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

from picosentry.watch import __version__
from picosentry.watch.config import PicoWatchConfig
from picosentry.watch.health import health_check
from picosentry.watch.output_guard import OutputGuard
from picosentry.watch.prompt_guard import PromptGuard
from picosentry.watch.ratelimit import RateLimiter
from picosentry.watch.telemetry import TelemetrySink, init_tracing, trace_output_validation, trace_prompt_scan
from picosentry.watch.types import PromptScanResult

logger = logging.getLogger(__name__)


class PromptScanRequest(BaseModel):

    text: str = Field(..., min_length=1, description="Prompt text to scan")
    context: dict[str, Any] | None = Field(default=None, description="Optional context (user_id, model, etc.)")
    request_id: str | None = Field(default=None, description="Optional request ID for telemetry correlation")


class OutputScanRequest(BaseModel):

    model_config = {"populate_by_name": True}

    output: str = Field(..., min_length=1, description="LLM output text to validate")
    json_schema: dict[str, Any] | None = Field(
        default=None,
        alias="schema",
        description="Optional JSON Schema for structural validation",
    )
    prompt_result: dict[str, Any] | None = Field(default=None, description="Optional L5 scan result for feedback loop")
    request_id: str | None = Field(default=None, description="Optional request ID for telemetry correlation")


def _get_client_ip(request: Request) -> str:
    if os.environ.get("PICOWATCH_TRUST_PROXY") == "1":
        forwarded = request.headers.get("x-forwarded-for")
        if forwarded:
            return forwarded.split(",")[0].strip()
    if request.client:
        return request.client.host
    return "unknown"


def create_app(config: PicoWatchConfig | None = None, sink: TelemetrySink | None = None) -> FastAPI:
    config = config or PicoWatchConfig.from_env()


    config.assert_secure()  # no-op in test mode (no api_key)
    if config.api_key:
        logger.info("API key configured — write endpoints require authentication")


    prompt_guard = PromptGuard(config=config)
    output_guard = OutputGuard(config=config)
    if sink is None:
        from picosentry.watch.telemetry.sink import TelemetryConfig
        sink = TelemetrySink(config=TelemetryConfig(
            audit_retention_days=config.audit_retention_days,
            otel_endpoint=config.otel_endpoint,
        ))
    limiter = RateLimiter(max_requests=config.rate_limit, window_seconds=config.rate_limit_window)


    otel_enabled = init_tracing(service_name="picowatch", endpoint=config.otel_endpoint)
    if otel_enabled:
        import logging

        logging.getLogger("picowatch.otel").info("OpenTelemetry tracing enabled (endpoint=%s)", config.otel_endpoint)


    api_key = config.api_key or ""

    app = FastAPI(
        title="PicoWatch",
        version=__version__,
        description="LLM defender with telemetry — prompt injection detection, output validation, and observability",
    )


    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next: Any) -> Any:
        if request.method == "POST":
            client_ip = _get_client_ip(request)
            if not limiter.is_allowed(client_ip):
                return JSONResponse(
                    status_code=429,
                    content={"detail": "Rate limit exceeded. Try again later."},
                    headers={"Retry-After": str(config.rate_limit_window)},
                )
        return await call_next(request)


    async def verify_api_key(
        x_api_key: str | None = Header(None, alias="X-API-Key"),
        authorization: str | None = Header(None),
    ) -> None:
        if not api_key:
            return  # No auth required

        provided_key = ""
        if x_api_key:
            provided_key = x_api_key
        elif authorization and authorization.lower().startswith("bearer "):
            provided_key = authorization[7:].strip()

        if not provided_key or not secrets.compare_digest(provided_key, api_key):
            raise HTTPException(status_code=401, detail="Invalid or missing API key")


    @app.get("/v1/health")
    async def get_health() -> dict[str, Any]:
        h = health_check(
            rules_loaded=len(prompt_guard.rules),
            corpus_hash=prompt_guard.corpus_hash,
            corpus_version=prompt_guard.corpus_version,
            rules_expected=prompt_guard._engine.rules_expected,
            load_errors=prompt_guard._engine.load_errors,
        )
        return {
            "healthy": h.healthy,
            "version": h.version,
            "rules_loaded": h.rules_loaded,
            "rules_expected": h.rules_expected,
            "rules_coverage": f"{h.rules_loaded}/{h.rules_expected}",
            "corpus_hash": h.corpus_hash,
            "corpus_version": h.corpus_version,
            "uptime_seconds": h.uptime_seconds,
            "load_errors": h.load_errors,
        }

    @app.get("/metrics")
    async def get_metrics() -> PlainTextResponse:
        return PlainTextResponse(
            content=sink.render_prometheus(),
            media_type="text/plain",
        )

    @app.get("/v1/rules")
    async def get_rules() -> list[dict[str, Any]]:
        return [
            {
                "id": r.id,
                "category": r.category,
                "weight": r.weight,
                "description": r.description,
            }
            for r in prompt_guard.rules
        ]

    @app.get("/v1/rules/{rule_id}")
    async def get_rule(rule_id: str) -> dict[str, Any]:
        for r in prompt_guard.rules:
            if r.id == rule_id:
                return {
                    "id": r.id,
                    "category": r.category,
                    "weight": r.weight,
                    "pattern": r.pattern,
                    "description": r.description,
                    "normalization": r.normalization,
                }
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")


    @app.post("/v1/scan/prompt")
    async def scan_prompt(
        body: PromptScanRequest,
        _auth: None = Depends(verify_api_key),
    ) -> dict[str, Any]:
        text = body.text


        if len(text) > config.max_prompt_size:
            raise HTTPException(
                status_code=413,
                detail=f"Input exceeds maximum size ({config.max_prompt_size} bytes). Rejecting immediately.",
            )

        result = prompt_guard.check(text, context=body.context)


        request_id = body.request_id or f"req-{uuid.uuid4().hex[:16]}"


        sink.record_prompt_scan(result, request_id=request_id)


        model = body.context.get("model") if body.context else None
        trace_prompt_scan(result, model=model)

        response: dict[str, Any] = {
            "blocked": result.blocked,
            "score": result.score,
            "verdict": result.verdict.value,
            "rules_matched": result.rules_matched,
            "corpus_hash": result.corpus_hash,
            "corpus_version": result.corpus_version,
            "duration_ms": result.duration_ms,
        }

        if result.normalized_input:
            response["normalized_input"] = result.normalized_input
        if result.details:
            response["details"] = result.details
        response["request_id"] = request_id

        return response

    @app.post("/v1/scan/output")
    async def scan_output(
        body: OutputScanRequest,
        _auth: None = Depends(verify_api_key),
    ) -> dict[str, Any]:

        if len(body.output) > config.max_prompt_size:
            raise HTTPException(
                status_code=413,
                detail=f"Input exceeds maximum size ({config.max_prompt_size} bytes). Rejecting immediately.",
            )


        prompt_result = None
        if body.prompt_result and isinstance(body.prompt_result, dict):
            pr = body.prompt_result
            prompt_result = PromptScanResult(
                blocked=pr.get("blocked", False),
                score=pr.get("score", 0.0),
                rules_matched=pr.get("rules_matched", []),
                corpus_hash=pr.get("corpus_hash", ""),
                corpus_version=pr.get("corpus_version", ""),
                duration_ms=pr.get("duration_ms", 0.0),
            )

        result = output_guard.validate(body.output, schema=body.json_schema, prompt_result=prompt_result)


        request_id = body.request_id or f"req-{uuid.uuid4().hex[:16]}"


        sink.record_validation(result, request_id=request_id)


        model = body.prompt_result.get("model") if body.prompt_result and isinstance(body.prompt_result, dict) else None
        trace_output_validation(result, model=model)

        response: dict[str, Any] = {
            "valid": result.valid,
            "score": result.score,
            "verdict": result.verdict.value,
            "violations": result.violations,
            "corpus_hash": result.corpus_hash,
            "corpus_version": result.corpus_version,
            "duration_ms": result.duration_ms,
        }

        if result.redacted:
            response["redacted"] = result.redacted
        if result.details:
            response["details"] = result.details
        response["request_id"] = request_id

        return response

    return app


def create_admin_app(config: PicoWatchConfig | None = None, sink: TelemetrySink | None = None,
                          prompt_guard: PromptGuard | None = None) -> FastAPI:
    config = config or PicoWatchConfig.from_env()


    config.assert_secure()  # no-op in test mode (no api_key)
    if config.api_key:
        logger.info("API key configured — write endpoints require authentication")
    if prompt_guard is None:
        prompt_guard = PromptGuard(config=config)
    if sink is None:
        sink = TelemetrySink()

    app = FastAPI(
        title="PicoWatch Admin",
        version=__version__,
        description="Read-only admin endpoints for health, metrics, and rules",
    )

    @app.get("/v1/health")
    async def admin_health() -> dict[str, Any]:
        h = health_check(
            rules_loaded=len(prompt_guard.rules),
            corpus_hash=prompt_guard.corpus_hash,
            corpus_version=prompt_guard.corpus_version,
            rules_expected=prompt_guard._engine.rules_expected,
            load_errors=prompt_guard._engine.load_errors,
        )
        return {
            "healthy": h.healthy,
            "version": h.version,
            "rules_loaded": h.rules_loaded,
            "rules_expected": h.rules_expected,
            "rules_coverage": f"{h.rules_loaded}/{h.rules_expected}",
            "corpus_hash": h.corpus_hash,
            "corpus_version": h.corpus_version,
            "uptime_seconds": h.uptime_seconds,
            "load_errors": h.load_errors,
        }

    @app.get("/metrics")
    async def admin_metrics() -> PlainTextResponse:
        return PlainTextResponse(
            content=sink.render_prometheus(),
            media_type="text/plain",
        )

    @app.get("/v1/rules")
    async def admin_rules() -> list[dict[str, Any]]:
        return [
            {"id": r.id, "category": r.category, "weight": r.weight, "description": r.description}
            for r in prompt_guard.rules
        ]

    @app.get("/v1/rules/{rule_id}")
    async def admin_rule(rule_id: str) -> dict[str, Any]:
        for r in prompt_guard.rules:
            if r.id == rule_id:
                return {
                    "id": r.id,
                    "category": r.category,
                    "weight": r.weight,
                    "pattern": r.pattern,
                    "description": r.description,
                    "normalization": r.normalization,
                }
        raise HTTPException(status_code=404, detail=f"Rule '{rule_id}' not found")

    return app


def run_server(config: PicoWatchConfig | None = None, host: str = "127.0.0.1", port: int = 8766) -> None:
    import uvicorn

    config = config or PicoWatchConfig.from_env()


    config.assert_secure()  # no-op in test mode (no api_key)
    if config.api_key:
        logger.info("API key configured — write endpoints require authentication")
    shared_sink = TelemetrySink()
    app = create_app(config, sink=shared_sink)


    shared_prompt_guard = PromptGuard(config=config)


    admin_app = create_admin_app(config, sink=shared_sink, prompt_guard=shared_prompt_guard)
    import threading

    admin_thread = threading.Thread(
        target=uvicorn.run,
        args=(admin_app,),
        kwargs={"host": host, "port": config.admin_port, "log_level": "warning"},
        daemon=True,
    )
    admin_thread.start()
    print(f"PicoWatch admin endpoints on port {config.admin_port}", file=__import__("sys").stderr)

    uvicorn.run(app, host=host, port=port, log_level="info")
