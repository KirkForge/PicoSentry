"""Tests for the Redis-backed distributed rate-limit backend in serve.

Uses a mock Redis so no real Redis server is required.
"""

from __future__ import annotations

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from picosentry.serve.middleware.rate_limit import RateLimitMiddleware
from picosentry.serve.middleware.rate_limit_redis import RedisRateLimitBackend


class MockRedis:
    """Minimal mock Redis with sorted-set and pipeline behaviour."""

    def __init__(self):
        self._data: dict[str, dict[str, float]] = {}

    def ping(self):
        return True

    def zremrangebyscore(self, key, _min, _max):
        store = self._data.setdefault(key, {})
        if not isinstance(_max, (int, float)):
            _max = float(_max)
        stale = [m for m, score in list(store.items()) if score <= _max]
        for m in stale:
            store.pop(m, None)
        return len(stale)

    def zadd(self, key, mapping):
        store = self._data.setdefault(key, {})
        for member, score in mapping.items():
            store[str(member)] = float(score)
        return len(mapping)

    def zcard(self, key):
        return len(self._data.get(key, {}))

    def expire(self, _key, _seconds):
        pass

    def delete(self, *keys):
        for key in keys:
            self._data.pop(key, None)

    def scan_iter(self, match=None):
        for key in list(self._data.keys()):
            if match is None or self._match(key, match):
                yield key

    def _match(self, key: str, pattern: str) -> bool:
        import fnmatch

        return fnmatch.fnmatch(key, pattern)

    def pipeline(self):
        return MockPipeline(self)


class MockPipeline:
    def __init__(self, redis: MockRedis):
        self._redis = redis
        self._calls: list[tuple[str, tuple, dict]] = []

    def zremrangebyscore(self, key, _min, _max):
        self._calls.append(("zremrangebyscore", (key, _min, _max), {}))
        return self

    def zadd(self, key, mapping=None, **kwargs):
        self._calls.append(("zadd", (key, mapping or kwargs), {}))
        return self

    def zcard(self, key):
        self._calls.append(("zcard", (key,), {}))
        return self

    def expire(self, key, seconds):
        self._calls.append(("expire", (key, seconds), {}))
        return self

    def execute(self):
        results = []
        for method, args, kwargs in self._calls:
            func = getattr(self._redis, method)
            results.append(func(*args, **kwargs))
        return results


class _FakeRedisModule:
    """Pretends to be the optional ``redis`` package."""

    def from_url(self, url, decode_responses=True):
        return MockRedis()


def _build_redis_app(mock_redis: MockRedis, max_requests: int = 5, window: int = 60) -> TestClient:
    async def catch_all(request: Request) -> JSONResponse:
        return JSONResponse({"path": request.url.path})

    routes = [Route("/{full_path:path}", catch_all, methods=["GET"])]
    app = Starlette(routes=routes)

    backend = RedisRateLimitBackend(redis_url="redis://mock:6379/0", window=window)
    backend._client = mock_redis
    backend._available = True

    app.add_middleware(
        RateLimitMiddleware,
        max_requests_per_ip=max_requests,
        window=window,
        backend="redis",
        backend_url="redis://mock:6379/0",
        exempt_paths=set(),
    )
    # Patch the instantiated middleware backend to use our shared mock.
    app.middleware_stack._redis_backend = backend

    return TestClient(app)


def test_redis_backend_records_requests():
    mock = MockRedis()
    backend = RedisRateLimitBackend(redis_url="redis://mock:6379/0", window=60)
    backend._client = mock
    backend._available = True

    assert backend.record_and_count("ip", "1.2.3.4") == 1
    assert backend.record_and_count("ip", "1.2.3.4") == 2


def test_redis_backend_limits_across_instances():
    """Two backend instances sharing the same Redis must enforce the same window."""
    shared = MockRedis()

    def make_backend():
        b = RedisRateLimitBackend(redis_url="redis://mock:6379/0", window=60)
        b._client = shared
        b._available = True
        return b

    max_requests = 5
    for _ in range(max_requests):
        assert make_backend().record_and_count("ip", "shared-actor") <= max_requests
    # 6th request is denied by the shared counter
    assert make_backend().record_and_count("ip", "shared-actor") == max_requests + 1


def test_redis_backend_resets():
    mock = MockRedis()
    backend = RedisRateLimitBackend(redis_url="redis://mock:6379/0", window=60)
    backend._client = mock
    backend._available = True

    backend.record_and_count("ip", "actor")
    backend.reset("ip", "actor")
    assert backend.count("ip", "actor") == 0


def test_redis_backend_unavailable_returns_negative():
    backend = RedisRateLimitBackend(redis_url="redis://localhost:1/0", window=60)
    assert backend.record_and_count("ip", "actor") == -1
    assert backend.count("ip", "actor") == -1


def test_rate_limit_middleware_uses_redis_backend():
    mock = MockRedis()

    async def catch_all(request: Request) -> JSONResponse:
        return JSONResponse({"path": request.url.path})

    routes = [Route("/{full_path:path}", catch_all, methods=["GET"])]
    app = Starlette(routes=routes)

    backend = RedisRateLimitBackend(redis_url="redis://mock:6379/0", window=60)
    backend._client = mock
    backend._available = True

    app.add_middleware(
        RateLimitMiddleware,
        max_requests_per_ip=5,
        window=60,
        backend="redis",
        backend_url="redis://mock:6379/0",
        backend_instance=backend,
        exempt_paths=set(),
    )

    client = TestClient(app)
    for _ in range(5):
        assert client.get("/api/v1/x").status_code == 200

    resp = client.get("/api/v1/x")
    assert resp.status_code == 429
    assert resp.headers.get("Retry-After")


def test_rate_limit_middleware_falls_back_to_memory_on_redis_failure():
    async def catch_all(request: Request) -> JSONResponse:
        return JSONResponse({"path": request.url.path})

    routes = [Route("/{full_path:path}", catch_all, methods=["GET"])]
    app = Starlette(routes=routes)

    backend = RedisRateLimitBackend(redis_url="redis://localhost:1/0", window=60)
    backend._available = False

    app.add_middleware(
        RateLimitMiddleware,
        max_requests_per_ip=5,
        window=60,
        backend="redis",
        backend_url="redis://localhost:1/0",
        backend_instance=backend,
        exempt_paths=set(),
    )

    client = TestClient(app)
    for _ in range(5):
        assert client.get("/api/v1/x").status_code == 200

    resp = client.get("/api/v1/x")
    assert resp.status_code == 429


def test_org_rate_limit_uses_redis_backend():
    mock = MockRedis()

    async def catch_all(request: Request) -> JSONResponse:
        return JSONResponse({"path": request.url.path})

    routes = [Route("/{full_path:path}", catch_all, methods=["GET"])]
    app = Starlette(routes=routes)

    backend = RedisRateLimitBackend(redis_url="redis://mock:6379/0", window=60)
    backend._client = mock
    backend._available = True

    app.add_middleware(
        RateLimitMiddleware,
        max_requests_per_ip=100,
        max_requests_per_org=3,
        window=60,
        backend="redis",
        backend_url="redis://mock:6379/0",
        backend_instance=backend,
        exempt_paths=set(),
    )

    client = TestClient(app)
    for _ in range(3):
        assert client.get("/api/v1/x", headers={"X-Org-API-Key": "sk_test"}).status_code == 200

    resp = client.get("/api/v1/x", headers={"X-Org-API-Key": "sk_test"})
    assert resp.status_code == 429
    assert "Organization rate limit exceeded" in resp.text


def test_settings_expose_rate_limit_backend():
    from picosentry.serve.config.settings import SecurityConfig

    config = SecurityConfig()
    assert config.rate_limit_backend == "memory"
    assert "localhost" in config.redis_url
