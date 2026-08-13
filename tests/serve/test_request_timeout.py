"""RequestTimeoutMiddleware: 504 observability + long-running path exemption."""

import asyncio

from fastapi import FastAPI
from fastapi.testclient import TestClient

from picosentry.serve.middleware.request_id import RequestIDMiddleware
from picosentry.serve.middleware.request_timeout import RequestTimeoutMiddleware


def _build_app() -> FastAPI:
    app = FastAPI()
    app.add_middleware(RequestIDMiddleware)
    app.add_middleware(RequestTimeoutMiddleware, timeout_seconds=0.1, long_running_paths=("/slow-run",))

    @app.get("/slow")
    async def slow():
        await asyncio.sleep(2)
        return {"ok": True}

    @app.get("/slow-run")
    async def slow_run():
        await asyncio.sleep(0.3)
        return {"ok": True}

    return app


def test_timeout_504_carries_request_id():
    client = TestClient(_build_app())
    response = client.get("/slow")
    assert response.status_code == 504
    assert response.headers.get("X-Request-ID")


def test_long_running_path_not_capped():
    client = TestClient(_build_app())
    response = client.get("/slow-run")
    assert response.status_code == 200
    assert response.json() == {"ok": True}
