"""OpenAI-compatible gateway shim (WO4.0.0-023 prototype).

Minimal drop-in passthrough that sits between an application and an
OpenAI-compatible provider and runs the PicoWatch guards on both directions:

- POST /v1/chat/completions: the concatenated prompt messages are scanned
  BEFORE forwarding; a blocked prompt never reaches the provider. The
  provider response's message content is validated by the output guard and
  the verdict is attached as a ``picowatch`` metadata field in the response.
- Per-tenant policy profiles: each gateway API key selects a rule-category
  subset and threshold overrides; keys are declared at construction time
  (``tenants``) and unknown callers fall back to the default profile.
- Verdict explanations: matched rule id + category + match span are included
  in the metadata so analysts can tune profiles (spans come from a top-level
  evaluate of the normalized prompt — decoded-variant matches contribute to
  the verdict but not to spans; ponytail: upgrade path is threading match
  provenance through PromptGuard.check).

Streaming ceiling (documented, not solved): ``stream: true`` requests forward
the FULL prompt scan (the prompt is complete up front) but the SSE response
chunks are passed through UNSCANNED — the output guard is whole-text and
cannot score a token stream. Delivery is also fully BUFFERED: the upstream
response is read to completion before the first byte reaches the caller, so
SSE chunk timing/cadence is NOT preserved (responses carry
``X-Picowatch-Streaming: buffered``). ``scan_stream_chunk`` is the hook a
buffered streaming scanner and true chunked passthrough would plug into;
until then the metadata honestly reports ``output_scanned: false`` for
streams. Do not wire a naive per-chunk scan: injection phrases split across
chunk boundaries would evade it.

Not in the prototype: retries, routing, tokens/usage rewriting, non-chat
endpoints. Requires ``httpx`` at call time (lazy import; the shim raises a
helpful error rather than adding a hard dependency).
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from picosentry.watch import __version__
from picosentry.watch.config import PicoWatchConfig
from picosentry.watch.output_guard import OutputGuard
from picosentry.watch.prompt_guard import PromptGuard
from picosentry.watch.ratelimit import RateLimiter
from picosentry.watch.server import _body_size_limit, _get_client_ip

logger = logging.getLogger("picowatch.gateway")


class TenantProfile:
    """Rule-set selection + thresholds for one gateway API key."""

    def __init__(
        self,
        *,
        name: str,
        allowed_categories: frozenset[str] | None = None,
        threshold_block: float | None = None,
    ) -> None:
        self.name = name
        self.allowed_categories = allowed_categories
        self.threshold_block = threshold_block


def scan_stream_chunk(_chunk: str) -> list[str]:  # pragma: no cover - stub, see module docstring
    """Hook for a future buffered streaming output scanner.

    Ceiling: naive per-chunk regex misses phrases split across chunk
    boundaries; a correct implementation needs a reassembly buffer with a
    bounded overlap window. Intentionally returns no violations today.
    """
    return []


def _explanations(guard: PromptGuard, text: str, limit: int = 8) -> list[dict[str, Any]]:
    """Rule id + category + match span for the top-level normalized text."""
    normalized = guard._normalizer.normalize(text)
    out: list[dict[str, Any]] = []
    for rule, match in guard._engine.evaluate(normalized):
        out.append(
            {
                "rule_id": rule.id,
                "category": rule.category,
                "match": match.group(0)[:80],
                "start": match.start(),
                "end": match.end(),
            }
        )
        if len(out) >= limit:
            break
    return out


class Gateway:
    def __init__(
        self,
        config: PicoWatchConfig | None = None,
        *,
        upstream_base_url: str = "https://api.openai.com",
        upstream_api_key: str = "",
        tenants: dict[str, TenantProfile] | None = None,
        block_on_output_violation: bool = False,
        http_client: Any = None,
    ) -> None:
        self._config = config or PicoWatchConfig()
        self._upstream_base_url = upstream_base_url.rstrip("/")
        self._upstream_api_key = upstream_api_key
        self._tenants = tenants or {}
        self._block_on_output_violation = block_on_output_violation
        self._http_client = http_client  # injectable for tests (httpx.AsyncClient)
        self._output_guard = OutputGuard(config=self._config)
        self._guards: dict[str | None, PromptGuard] = {}
        # Profiles are resolved at construction: a tenant whose category set
        # matches zero rules is a configuration error (typo), not a silently
        # rule-less guard — refuse startup instead (WO5.0.0-024).
        for tenant_profile in self._tenants.values():
            self._guard_for(tenant_profile)

    def _guard_for(self, profile: TenantProfile) -> PromptGuard:
        key = f"{profile.name}:{sorted(profile.allowed_categories or ())}:{profile.threshold_block}"
        guard = self._guards.get(key)
        if guard is None:
            cfg = self._config
            if profile.threshold_block is not None:
                import copy

                # Shallow-copying only the top config would MUTATE the shared
                # prompt_guard sub-config and leak the override into every
                # other profile — copy the sub-config too.
                cfg = copy.copy(self._config)
                pg = copy.copy(self._config.prompt_guard)
                pg.threshold_block = profile.threshold_block
                cfg.prompt_guard = pg
            guard = PromptGuard(config=cfg)
            if profile.allowed_categories is not None:
                from picosentry.watch.prompt_guard.rules import RuleEngine

                engine = RuleEngine(rules_dir=guard._rules_dir, allowed_categories=profile.allowed_categories)
                if engine.rules_loaded == 0:
                    raise ValueError(
                        f"tenant profile {profile.name!r} selects zero rules — "
                        f"allowed_categories {sorted(profile.allowed_categories)} match nothing in the corpus (typo?)"
                    )
                guard._engine = engine
            self._guards[key] = guard
        return guard

    def _profile_for_key(self, api_key: str | None) -> TenantProfile:
        if api_key and api_key in self._tenants:
            return self._tenants[api_key]
        return TenantProfile(name="default")

    async def _forward(self, method: str, path: str, body: dict[str, Any]) -> Response:
        try:
            import httpx
        except ImportError as exc:  # pragma: no cover - httpx is a dev extra
            raise HTTPException(
                status_code=503,
                detail="picowatch gateway requires httpx: pip install 'picosentry[watch-server]' or httpx",
            ) from exc
        client = self._http_client
        owns_client = client is None
        if client is None:
            client = httpx.AsyncClient(timeout=120.0)
        try:
            resp = await client.request(
                method,
                f"{self._upstream_base_url}{path}",
                json=body,
                headers={"Authorization": f"Bearer {self._upstream_api_key}"},
            )
        except httpx.HTTPError as exc:
            logger.warning("Upstream request failed: %s", exc)
            return JSONResponse(
                status_code=502,
                content={"error": {"message": "upstream unavailable", "type": "upstream_error"}},
            )
        finally:
            if owns_client:
                await client.aclose()
        return Response(
            content=resp.content,
            status_code=resp.status_code,
            media_type=resp.headers.get("content-type", "application/json"),
        )


def create_gateway_app(
    config: PicoWatchConfig | None = None,
    *,
    upstream_base_url: str = "https://api.openai.com",
    upstream_api_key: str = "",
    tenants: dict[str, TenantProfile] | None = None,
    block_on_output_violation: bool = False,
    http_client: Any = None,
) -> FastAPI:
    gateway = Gateway(
        config,
        upstream_base_url=upstream_base_url,
        upstream_api_key=upstream_api_key,
        tenants=tenants,
        block_on_output_violation=block_on_output_violation,
        http_client=http_client,
    )

    app = FastAPI(
        title="PicoWatch Gateway",
        version=__version__,
        description="OpenAI-compatible passthrough with prompt/output scanning (prototype)",
        docs_url=None,
        redoc_url=None,
    )

    # Same hardening surface as server.create_app (WO5.0.0-023): body cap
    # before parse, per-IP rate limit, security headers. Middleware glue is
    # the shared server implementation/pattern, not a gateway reimplementation.
    limiter = RateLimiter(max_requests=gateway._config.rate_limit, window_seconds=gateway._config.rate_limit_window)

    @app.middleware("http")
    async def body_size_limit_middleware(request: Request, call_next: Any) -> Any:
        return await _body_size_limit(request, call_next)

    @app.middleware("http")
    async def security_headers_middleware(request: Request, call_next: Any) -> Any:
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        return response

    @app.middleware("http")
    async def rate_limit_middleware(request: Request, call_next: Any) -> Any:
        if not limiter.is_allowed(_get_client_ip(request)):
            return JSONResponse(
                status_code=429,
                content={"detail": "Rate limit exceeded. Try again later."},
                headers={"Retry-After": str(gateway._config.rate_limit_window)},
            )
        return await call_next(request)

    @app.post("/v1/chat/completions", response_model=None)
    async def chat_completions(
        request: Request,
        authorization: str | None = Header(None),
        x_api_key: str | None = Header(None, alias="X-API-Key"),
    ) -> Response:
        body = await request.json()
        if not isinstance(body, dict) or not isinstance(body.get("messages"), list):
            raise HTTPException(status_code=400, detail="OpenAI-compatible 'messages' list required")

        api_key = x_api_key
        if not api_key and authorization and authorization.lower().startswith("bearer "):
            api_key = authorization[7:].strip()
        if gateway._tenants and (
            not api_key
            or not any(secrets.compare_digest(api_key.encode("utf-8"), key.encode("utf-8")) for key in gateway._tenants)
        ):
            # Tenant keys are the auth surface: an unknown or missing key is
            # rejected instead of silently selecting the default profile
            # (WO5.0.0-023). Constant-time compare per the server auth pattern.
            raise HTTPException(status_code=401, detail="Invalid or missing API key")
        profile = gateway._profile_for_key(api_key)
        guard = gateway._guard_for(profile)

        # WO6.0.0-003: non-dict messages (plain strings) and dict messages
        # with content must both be scanned — the old join skipped non-dict
        # messages entirely, forwarding a string-message injection unscanned.
        prompt_text = "\n".join(
            str(m.get("content", "")) if isinstance(m, dict) else str(m) for m in body["messages"] if m
        )
        # to_thread: the guards are CPU-bound regex engines — a direct sync
        # call freezes the loop (and every concurrent request) for the whole
        # scan, the exact class WO4.0.0-016 fixed in server.py.
        prompt_result = await asyncio.to_thread(guard.check, prompt_text)
        if prompt_result.blocked:
            return JSONResponse(
                status_code=400,
                content={
                    "error": {
                        "message": "Prompt blocked by PicoWatch policy",
                        "type": "picowatch_blocked",
                        "code": "prompt_policy_violation",
                    },
                    "picowatch": {
                        "profile": profile.name,
                        "blocked": True,
                        "score": prompt_result.score,
                        "verdict": prompt_result.verdict.value,
                        "rules_matched": prompt_result.rules_matched,
                        "rules_loaded": guard.rules_loaded,
                        "explanations": await asyncio.to_thread(_explanations, guard, prompt_text),
                        "corpus_hash": prompt_result.corpus_hash,
                    },
                },
            )

        is_stream = bool(body.get("stream"))
        forwarded = await gateway._forward("POST", "/v1/chat/completions", body)
        if forwarded.status_code != 200:
            return forwarded
        if is_stream:
            # Streaming ceiling — see module docstring: prompt fully scanned,
            # output chunks passed through unscanned AND buffered (delivered
            # only after upstream completes), both honestly reported.
            return Response(
                content=forwarded.body,
                status_code=200,
                media_type="text/event-stream",
                headers={
                    "X-Picowatch-Output-Scanned": "false",
                    "X-Picowatch-Streaming": "buffered",
                },
            )

        import json as _json

        try:
            completion = _json.loads(bytes(forwarded.body))
        except ValueError:
            # WO6.0.0-003: a 200 with non-JSON body is returned unscanned —
            # honest under default mode, but under block_on_output_violation
            # an unscannable response is a policy violation, not a passthrough.
            if gateway._block_on_output_violation:
                return JSONResponse(
                    status_code=400,
                    content={
                        "error": {
                            "message": "Upstream returned non-JSON 200 — output unscannable under block mode",
                            "type": "picowatch_blocked",
                            "code": "output_unscannable",
                        },
                        "picowatch": {"profile": profile.name, "output_scanned": False},
                    },
                )
            # WO7-021: add picowatch metadata so downstream can distinguish
            # "scanned clean" from "unscanned" — the raw passthrough had no
            # picowatch block, making a non-JSON 200 look like a clean scan.
            return Response(
                content=forwarded.body,
                status_code=forwarded.status_code,
                media_type=forwarded.headers.get("content-type", "application/json"),
                headers={
                    "X-Picowatch-Output-Scanned": "false",
                    "X-Picowatch-Profile": profile.name,
                },
            )
        # WO7-022: a 200 with {"error": {...}} (no choices) yields empty
        # output_parts → output_guard validates "" → output_valid: true. The
        # error message is never scanned and the empty string is falsely
        # attested as valid. Route the error message through the guard and
        # mark output_valid as false when an error body is present.
        error_body = completion.get("error")
        choices = completion.get("choices") or []
        output_parts: list[str] = []
        for choice in choices:
            if not isinstance(choice, dict):
                continue
            message = choice.get("message") or {}
            if not isinstance(message, dict):
                continue
            content = message.get("content")
            if content:
                output_parts.append(str(content))
            tool_calls = message.get("tool_calls")
            if isinstance(tool_calls, list):
                for tool_call in tool_calls:
                    if not isinstance(tool_call, dict):
                        continue
                    function = tool_call.get("function") or {}
                    if isinstance(function, dict) and function.get("arguments"):
                        output_parts.append(str(function["arguments"]))
            # Legacy function_call (OpenAI pre-2023 API shape).
            legacy_fc = message.get("function_call")
            if isinstance(legacy_fc, dict) and legacy_fc.get("arguments"):
                output_parts.append(str(legacy_fc["arguments"]))
        # WO7-022: when the upstream returns an error body (no choices), the
        # error message is part of what the client sees — scan it so an
        # injection in the error message is not silently attested valid.
        if not output_parts and isinstance(error_body, dict):
            error_msg = error_body.get("message")
            if isinstance(error_msg, str) and error_msg:
                output_parts.append(error_msg)
        output_text = "\n".join(output_parts)

        output_result = await asyncio.to_thread(gateway._output_guard.validate, output_text)
        violations = output_result.violations
        if violations and gateway._block_on_output_violation:
            return JSONResponse(
                status_code=400,
                content={
                    "error": {
                        "message": "Model output blocked by PicoWatch policy",
                        "type": "picowatch_blocked",
                        "code": "output_policy_violation",
                    },
                    "picowatch": {"profile": profile.name, "violations": violations},
                },
            )

        # WO7-022: an error body is not a valid model output — do not attest
        # output_valid: true even when the guard passes on the error message.
        effective_output_valid = output_result.valid and not (isinstance(error_body, dict) and not choices)
        completion["picowatch"] = {
            "profile": profile.name,
            "prompt_blocked": False,
            "prompt_score": prompt_result.score,
            "prompt_rules_matched": prompt_result.rules_matched,
            "rules_loaded": guard.rules_loaded,
            "output_scanned": True,
            "output_fields_scanned": [
                "choices[*].message.content",
                "choices[*].message.tool_calls[*].function.arguments",
                "choices[*].message.function_call.arguments",
                "error.message" if isinstance(error_body, dict) and not choices else "",
            ],
            "output_valid": effective_output_valid,
            "output_violations": violations,
            "upstream_error": bool(isinstance(error_body, dict) and not choices),
            # WO6.0.0-016: surface decode budget exhaustion from both sides
            # so a starved decode is visible, not a silent clean verdict.
            "prompt_decode_budget_exhausted": prompt_result.details.get("decode_budget_exhausted", False),
            "output_decode_budget_exhausted": output_result.details.get("decode_budget_exhausted", False),
        }
        return JSONResponse(content=completion)

    return app
