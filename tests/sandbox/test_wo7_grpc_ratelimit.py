"""WO7.0.0-015: gRPC auth interceptor rate limiting."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

SUBMITTER_TOKEN = "picodome-submitter-unit-test-token-0000000001"


def _make_auth():
    from picosentry.sandbox.auth import RBAC, TokenAuth

    with patch.dict("os.environ", {"PICODOME_API_TOKENS": SUBMITTER_TOKEN}):
        return TokenAuth(rbac=RBAC())


def _make_limiter(allow_all: bool = True):
    limiter = MagicMock()
    limiter.allow.return_value = allow_all
    return limiter


def _call_details(method: str, token: str = ""):
    md = []
    if token:
        md.append(("authorization", f"Bearer {token}"))
    d = MagicMock()
    d.method = f"/picodome.PicoDomeService/{method}"
    d.invocation_metadata = md
    return d


def test_rate_limited_returns_resource_exhausted():
    from picosentry.sandbox.grpc_transport.auth import build_auth_interceptor

    auth = _make_auth()
    limiter = _make_limiter(allow_all=False)
    interceptor = build_auth_interceptor(auth, rate_limiter=limiter)

    continuation = MagicMock()
    handler = interceptor.intercept_service(continuation, _call_details("Scan", SUBMITTER_TOKEN))

    continuation.assert_not_called()
    context = MagicMock()
    handler.unary_unary(None, context)
    assert context.abort.called
    code = context.abort.call_args[0][0]
    assert code.name == "RESOURCE_EXHAUSTED"


def test_rate_limiter_called_with_actor_hash():
    from picosentry.sandbox.grpc_transport.auth import build_auth_interceptor

    auth = _make_auth()
    limiter = _make_limiter(allow_all=True)
    interceptor = build_auth_interceptor(auth, rate_limiter=limiter)

    continuation = MagicMock()
    interceptor.intercept_service(continuation, _call_details("Scan", SUBMITTER_TOKEN))

    limiter.allow.assert_called_once()
    actor = limiter.allow.call_args.kwargs["actor"]
    assert len(actor) == 16


def test_rate_limiter_not_called_for_unauthenticated():
    from picosentry.sandbox.grpc_transport.auth import build_auth_interceptor

    auth = _make_auth()
    limiter = _make_limiter(allow_all=True)
    interceptor = build_auth_interceptor(auth, rate_limiter=limiter)

    continuation = MagicMock()
    interceptor.intercept_service(continuation, _call_details("Scan", ""))
    limiter.allow.assert_not_called()


def test_rate_limiter_not_called_for_health():
    from picosentry.sandbox.grpc_transport.auth import build_auth_interceptor

    auth = _make_auth()
    limiter = _make_limiter(allow_all=True)
    interceptor = build_auth_interceptor(auth, rate_limiter=limiter)

    continuation = MagicMock()
    interceptor.intercept_service(continuation, _call_details("Health"))
    continuation.assert_called_once()
    limiter.allow.assert_not_called()
