"""WO7-022 — gateway upstream 200 with error body attests output_valid: true.

Upstream returns 200 with {"error": {...}} (no choices) → output_parts
empty → output_guard validates "" → output_valid: true. The error message
is never fed to the guard. The fix scans the error message and does NOT
attest output_valid: true.
"""

from __future__ import annotations

import httpx
from fastapi.testclient import TestClient

from picosentry.watch.config import PicoWatchConfig
from picosentry.watch.gateway import create_gateway_app


def _upstream(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def _app(client: httpx.AsyncClient, **kw) -> TestClient:
    app = create_gateway_app(
        PicoWatchConfig(),
        upstream_base_url="https://upstream.test",
        upstream_api_key="upstream-secret",
        http_client=client,
        **kw,
    )
    return TestClient(app)


class TestErrorBodyNotAttestedValid:
    def test_error_body_not_output_valid_true(self):
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"error": {"message": "model overloaded", "type": "server_error"}},
            )

        with _app(_upstream(handler)) as client:
            resp = client.post(
                "/v1/chat/completions",
                json={"model": "gpt-x", "messages": [{"role": "user", "content": "hello"}]},
            )
        assert resp.status_code == 200
        meta = resp.json()["picowatch"]
        assert meta["output_valid"] is not True, "error body must not be attested output_valid: true"
        assert meta["upstream_error"] is True

    def test_error_message_scanned(self):
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "error": {
                        "message": "The database URL is postgres://user:pass@192.168.1.100:5432/db",
                        "type": "server_error",
                    }
                },
            )

        with _app(_upstream(handler)) as client:
            resp = client.post(
                "/v1/chat/completions",
                json={"model": "gpt-x", "messages": [{"role": "user", "content": "hello"}]},
            )
        assert resp.status_code == 200
        meta = resp.json()["picowatch"]
        assert meta["output_scanned"] is True
        assert meta["output_valid"] is False, "error message with exfil content must be scanned and flagged"
        assert meta.get("output_violations"), "error message containing exfil must produce violations"

    def test_choices_present_still_attested_valid(self):
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={"choices": [{"message": {"content": "Paris"}}]},
            )

        with _app(_upstream(handler)) as client:
            resp = client.post(
                "/v1/chat/completions",
                json={"model": "gpt-x", "messages": [{"role": "user", "content": "What is the capital of France?"}]},
            )
        assert resp.status_code == 200
        meta = resp.json()["picowatch"]
        assert meta["output_valid"] is True
        assert meta.get("upstream_error") is not True

    def test_error_body_blocked_when_block_mode(self):
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(
                200,
                json={
                    "error": {
                        "message": "The database URL is postgres://user:pass@192.168.1.100:5432/db",
                        "type": "server_error",
                    }
                },
            )

        with _app(_upstream(handler), block_on_output_violation=True) as client:
            resp = client.post(
                "/v1/chat/completions",
                json={"model": "gpt-x", "messages": [{"role": "user", "content": "hello"}]},
            )
        assert resp.status_code == 400
