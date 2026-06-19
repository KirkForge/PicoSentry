"""DDoS shield ``/health*`` exemption regression (P1 fix).

Pins the contract that health/readiness probes never count against
the shield's global or per-path buckets.  A load-balancer probe that's
429'd marks the pod unhealthy, which makes the shield cause the very
outage it's trying to prevent.

We test the middleware in isolation — no need to spin up the full
FastAPI app for a unit test of one middleware.  The
``tests/serve/test_api.py::TestHealthEndpoint`` tests already verify
the end-to-end ``/health`` response; this file is the unit-level
contract for the bypass.
"""

from __future__ import annotations

from collections.abc import Callable, Iterable

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import JSONResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from picosentry.serve.middleware.ddos_shield import DDoSShieldMiddleware


def _build_app(
    extra_routes: Iterable[Route] = (),
    *,
    _now: Callable[[], float] | None = None,
) -> tuple[TestClient, DDoSShieldMiddleware]:
    """Build a tiny Starlette app with the DDoS shield mounted and a
    catch-all GET route that echoes the path back.  Returns both the
    client and the constructed middleware so tests can read
    ``_global_limit`` etc. without guessing at the values.

    ``_now`` is injected into the middleware to make tests independent of
    wall-clock timing; production uses ``time.monotonic`` by default.
    """

    async def catch_all(request: Request) -> JSONResponse:
        return JSONResponse({"path": request.url.path})

    routes = [*extra_routes, Route("/{full_path:path}", catch_all, methods=["GET"])]
    app = Starlette(routes=routes)

    # Build the middleware manually so we can hold a reference to it.
    # Starlette's add_middleware wraps it in a closure we can't easily
    # reach; the underlying class is what we want anyway.
    kwargs = {"_now": _now} if _now is not None else {}
    shield = DDoSShieldMiddleware(app, enabled=True, **kwargs)
    app.add_middleware(DDoSShieldMiddleware, enabled=True, **kwargs)
    return TestClient(app), shield


def test_health_paths_bypass_global_bucket() -> None:
    """Firing more than ``_global_limit`` requests at ``/health/live``
    must NEVER return 429.  The shield's per-path bucket limit and
    global limit are the two ways a probe can fail; the exemption
    short-circuits both."""
    client, shield = _build_app()
    for _ in range(shield._global_limit + 50):
        resp = client.get("/health/live")
        assert resp.status_code == 200, f"/health/live returned {resp.status_code}; the exemption failed"


def test_health_liveness_exact_match() -> None:
    """``/health`` (no trailing slash, no subpath) is also exempt."""
    client, _ = _build_app()
    resp = client.get("/health")
    assert resp.status_code == 200


def test_healthz_is_exempt() -> None:
    """The Kubernetes-style ``/healthz`` alias is in the exemption list
    (it's the path the deployment healthchecks hit by default)."""
    client, _ = _build_app()
    resp = client.get("/healthz")
    assert resp.status_code == 200


def test_health_subpaths_are_exempt() -> None:
    """``/health/ready`` and ``/health/live`` are the K8s liveness
    variants; they must match the exemption set."""
    client, _ = _build_app()
    for path in ("/health/ready", "/health/live", "/health/history"):
        resp = client.get(path)
        assert resp.status_code == 200, f"{path} should be exempt; got {resp.status_code}"


def test_non_health_paths_still_rate_limited() -> None:
    """The bypass must NOT leak to user traffic.  Hammering an
    arbitrary path past the global limit must return 429.

    A fixed clock that advances a small delta each request keeps the
    10-second window open for the whole run, so the result is
    independent of wall-clock timing and test-machine speed."""
    now = 0.0

    def fake_now() -> float:
        nonlocal now
        now += 0.001
        return now

    client, shield = _build_app(_now=fake_now)
    last_status = None
    for _ in range(shield._global_limit + 50):
        resp = client.get("/api/v1/something")
        last_status = resp.status_code
    assert last_status == 429, (
        f"non-health path should be rate-limited past the global limit; final status was {last_status}"
    )


def test_lookalike_paths_are_not_exempt() -> None:
    """``/health-evil`` and ``/healthy`` are NOT health probes — they
    look health-flavoured but aren't on the bypass list.  The exemption
    is a closed set, not a prefix match."""
    client, shield = _build_app()
    saw_429 = False
    for _ in range(shield._global_limit + 50):
        resp = client.get("/health-evil")
        if resp.status_code == 429:
            saw_429 = True
            break
    assert saw_429, "/health-evil must be rate-limited like any other user path"


def test_is_health_path_unit() -> None:
    """The classmethod is a closed-set check, with a subpath match for
    the liveness/ready variants.  Pin the predicate directly so a
    future refactor of the dispatch logic still has to honour it."""
    assert DDoSShieldMiddleware._is_health_path("/health")
    assert DDoSShieldMiddleware._is_health_path("/healthz")
    assert DDoSShieldMiddleware._is_health_path("/health/live")
    assert DDoSShieldMiddleware._is_health_path("/health/ready")
    assert DDoSShieldMiddleware._is_health_path("/health/history")

    assert not DDoSShieldMiddleware._is_health_path("/health-evil")
    assert not DDoSShieldMiddleware._is_health_path("/healthy")
    assert not DDoSShieldMiddleware._is_health_path("/api/v1/health")
    assert not DDoSShieldMiddleware._is_health_path("/")
