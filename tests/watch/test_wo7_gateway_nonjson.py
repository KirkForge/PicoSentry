"""WO7-021 — gateway non-JSON 200 passes output unscanned with no picowatch metadata.

When json.loads fails and block_on_output_violation=False, the gateway
returned the raw response with no picowatch field or header. Downstream
cannot distinguish "scanned clean" from "unscanned".
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


class TestNonJson200Metadata:
    def test_non_json_200_has_picowatch_header_unscanned(self):
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"not json at all", headers={"content-type": "text/plain"})

        with _app(_upstream(handler)) as client:
            resp = client.post(
                "/v1/chat/completions",
                json={"model": "gpt-x", "messages": [{"role": "user", "content": "hello"}]},
            )
        assert resp.status_code == 200
        assert resp.headers.get("x-picowatch-output-scanned") == "false"
        assert resp.headers.get("x-picowatch-profile") == "default"

    def test_non_json_200_body_preserved(self):
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"<html>hello</html>", headers={"content-type": "text/html"})

        with _app(_upstream(handler)) as client:
            resp = client.post(
                "/v1/chat/completions",
                json={"model": "gpt-x", "messages": [{"role": "user", "content": "hello"}]},
            )
        assert resp.status_code == 200
        assert b"<html>hello</html>" in resp.content

    def test_non_json_200_block_mode_returns_400_with_metadata(self):
        async def handler(request: httpx.Request) -> httpx.Response:
            return httpx.Response(200, content=b"not json", headers={"content-type": "text/plain"})

        with _app(_upstream(handler), block_on_output_violation=True) as client:
            resp = client.post(
                "/v1/chat/completions",
                json={"model": "gpt-x", "messages": [{"role": "user", "content": "hello"}]},
            )
        assert resp.status_code == 400
        body = resp.json()
        assert body["picowatch"]["output_scanned"] is False
