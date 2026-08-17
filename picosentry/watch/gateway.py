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
cannot score a token stream. ``scan_stream_chunk`` is the hook a buffered
streaming scanner would plug into; until then the metadata honestly reports
``output_scanned: false`` for streams. Do not wire a naive per-chunk scan:
injection phrases split across chunk boundaries would evade it.

Not in the prototype: retries, routing, tokens/usage rewriting, non-chat
endpoints. Requires ``httpx`` at call time (lazy import; the shim raises a
helpful error rather than adding a hard dependency).
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse, Response

from picosentry.watch import __version__
from picosentry.watch.config import PicoWatchConfig
from picosentry.watch.output_guard import OutputGuard
from picosentry.watch.prompt_guard import PromptGuard

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

                guard._engine = RuleEngine(rules_dir=guard._rules_dir, allowed_categories=profile.allowed_categories)
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
        profile = gateway._profile_for_key(api_key)
        guard = gateway._guard_for(profile)

        prompt_text = "\n".join(
            str(m.get("content", "")) for m in body["messages"] if isinstance(m, dict) and m.get("content")
        )
        prompt_result = guard.check(prompt_text)
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
                        "explanations": _explanations(guard, prompt_text),
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
            # output chunks passed through unscanned, honestly reported.
            return Response(
                content=forwarded.body,
                status_code=200,
                media_type="text/event-stream",
                headers={"X-Picowatch-Output-Scanned": "false"},
            )

        import json as _json

        try:
            completion = _json.loads(bytes(forwarded.body))
        except ValueError:
            return forwarded
        output_text = ""
        choices = completion.get("choices") or []
        if choices and isinstance(choices[0], dict):
            message = choices[0].get("message") or {}
            output_text = str(message.get("content") or "")

        output_result = gateway._output_guard.validate(output_text)
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

        completion["picowatch"] = {
            "profile": profile.name,
            "prompt_blocked": False,
            "prompt_score": prompt_result.score,
            "prompt_rules_matched": prompt_result.rules_matched,
            "output_scanned": True,
            "output_valid": output_result.valid,
            "output_violations": violations,
        }
        return JSONResponse(content=completion)

    return app
