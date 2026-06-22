"""Tests for additional serve surface-area hardening."""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from picosentry.serve.middleware.rate_limit import RateLimitMiddleware

ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
os.environ["PICOSHOGUN_ENV"] = "test"
os.environ["PICOSHOGUN_SECRET_KEY"] = "test-key-for-pytest-at-least-32-bytes!"


def _build_rate_limited_app(exempt_paths: set[str] | None = None) -> TestClient:
    async def catch_all(request: Request) -> JSONResponse:
        return JSONResponse({"path": request.url.path})

    routes = [Route("/{full_path:path}", catch_all, methods=["GET"])]
    app = Starlette(routes=routes)
    app.add_middleware(
        RateLimitMiddleware,
        max_requests_per_ip=5,
        window=60,
        exempt_paths=exempt_paths or set(),
    )
    return TestClient(app)


def test_rate_limit_exempts_health_paths() -> None:
    client = _build_rate_limited_app(exempt_paths={"/health", "/health/live", "/health/ready"})
    for _ in range(10):
        resp = client.get("/health")
        assert resp.status_code == 200
        resp = client.get("/health/live")
        assert resp.status_code == 200


def test_rate_limit_non_health_paths_still_limited() -> None:
    client = _build_rate_limited_app(exempt_paths={"/health"})
    last_status = None
    for _ in range(10):
        resp = client.get("/api/v1/something")
        last_status = resp.status_code
    assert last_status == 429


def test_root_page_hides_docs_link_when_docs_disabled() -> None:
    """When docs are disabled the root HTML must not advertise /docs."""
    import picosentry.serve.api.server as server_module

    from picosentry.serve.api.routers.health import root

    original_docs = getattr(server_module, "_docs_url", None)
    try:
        server_module._docs_url = None
        html = asyncio.run(root())
        assert "/docs" not in html
    finally:
        if original_docs is not None:
            server_module._docs_url = original_docs


def test_root_page_shows_docs_link_when_docs_enabled() -> None:
    import picosentry.serve.api.server as server_module

    from picosentry.serve.api.routers.health import root

    original_docs = getattr(server_module, "_docs_url", None)
    try:
        server_module._docs_url = "/docs"
        html = asyncio.run(root())
        assert "/docs" in html
    finally:
        if original_docs is not None:
            server_module._docs_url = original_docs


def test_production_validation_warns_unsigned_plugins() -> None:
    from picosentry.serve.config.settings import Settings

    settings = Settings(env="production")
    issues = settings.validate()
    assert any("Unsigned plugins" in issue for issue in issues)


def test_non_production_validation_does_not_error_unsigned_plugins() -> None:
    from picosentry.serve.config.settings import Settings

    settings = Settings(env="development")
    issues = settings.validate()
    assert not any("Unsigned plugins" in issue for issue in issues)
