"""Shared auth for the gRPC transport.

Mirrors the HTTP daemon's TokenAuth + RBAC semantics (handler_mixins.py):
the same token store, the same permission set per method, the same
dev/enterprise behavior. Health stays unauthenticated exactly like the
HTTP ``/health`` route.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from picosentry.sandbox.auth import TokenAuth

logger = logging.getLogger("picodome.grpc_transport.auth")


# RPC method name (last path segment of "/picodome.PicoDomeService/<method>")
# → required permission. Mirrors the HTTP route table in
# handler_routes_get/_post. Methods not listed here are unauthenticated
# (Health — same as HTTP /health and /metrics).
METHOD_PERMISSIONS: dict[str, str] = {
    "Scan": "scan:submit",
    "GetPolicy": "policy:read",
    "QueryAudit": "audit:read",
}

AUTHORIZATION_METADATA = "authorization"


def bearer_token_from_metadata(metadata: Any) -> str:
    """Extract the Bearer token from gRPC invocation metadata."""
    if not metadata:
        return ""
    try:
        items = list(metadata)
    except TypeError:
        return ""
    for key, raw in items:
        if str(key).lower() == AUTHORIZATION_METADATA:
            value = str(raw)
            if value.startswith("Bearer "):
                return value[7:].strip()
            return value.strip()
    return ""


def metadata_value(metadata: Any, name: str) -> str:
    """First value for a metadata key (case-insensitive), or ''."""
    if not metadata:
        return ""
    try:
        items = list(metadata)
    except TypeError:
        return ""
    for key, value in items:
        if str(key).lower() == name.lower():
            return str(value)
    return ""


def authorize(auth: TokenAuth, token: str, permission: str) -> bool:
    """TokenAuth.validate + RBAC permission check; mirrors _require_permission."""
    if not token or not auth.validate(token):
        return False
    return auth.has_permission(token, permission)


def is_loopback_host(host: str) -> bool:
    h = host.strip("[]").lower()
    # "[::]" and "" bind to every interface — not loopback.
    return h in ("localhost", "::1") or h.startswith("127.")


def target_host(target: str) -> str:
    """Host part of a gRPC client target ("h:1", "dns:///h:1", "[::1]:1", "unix:/…")."""
    if target.startswith("unix:"):
        return "localhost"  # unix socket — local by construction
    t = target
    for prefix in ("dns:///", "dns:", "ipv4:", "ipv6:", "tcp:"):
        if t.startswith(prefix):
            t = t[len(prefix) :]
            break
    if t.startswith("["):
        return t[1 : t.index("]")] if "]" in t else t
    return t.rsplit(":", 1)[0] if ":" in t else t


def assert_secure_transport(host: str, has_tls: bool) -> None:
    """Refuse a plaintext gRPC bind beyond loopback (mirrors serve assert_secure).

    plaintext on loopback is tolerated for local/dev use, matching the HTTP
    daemon which also serves plaintext HTTP on 127.0.0.1 when no mTLS is
    configured. Anything wider requires real TLS credentials.
    """
    if has_tls or is_loopback_host(host):
        return
    raise RuntimeError(
        f"Refusing to start plaintext gRPC server on non-loopback address '{host}'. "
        "Configure mTLS (PICODOME_TLS_CERT/PICODOME_TLS_KEY) or bind to loopback."
    )


def build_auth_interceptor(auth: TokenAuth, rate_limiter: Any | None = None):
    """Build a grpc.ServerInterceptor enforcing METHOD_PERMISSIONS via TokenAuth+RBAC.

    WO7.0.0-015: when a ``rate_limiter`` (TokenBucketLimiter) is supplied,
    authenticated requests are subject to the same per-actor rate limiting
    as the HTTP path (handler_mixins._require_auth). Without it one valid
    token can monopolize all ThreadPoolExecutor slots — DoS with valid creds.
    """
    import grpc

    def _deny(code, details):
        def _abort(_request, context):
            context.abort(code, details)

        return grpc.unary_unary_rpc_method_handler(_abort)

    class _AuthInterceptor(grpc.ServerInterceptor):
        def intercept_service(self, continuation, handler_call_details):
            method = handler_call_details.method.rsplit("/", 1)[-1]
            permission = METHOD_PERMISSIONS.get(method)
            if permission is None:
                return continuation(handler_call_details)

            metadata = getattr(handler_call_details, "invocation_metadata", None)
            token = bearer_token_from_metadata(metadata)

            if not token or not auth.validate(token):
                logger.warning("gRPC %s rejected: unauthenticated", method)
                return _deny(grpc.StatusCode.UNAUTHENTICATED, "invalid or missing token")

            if not auth.has_permission(token, permission):
                logger.warning("gRPC %s rejected: missing permission %s", method, permission)
                return _deny(grpc.StatusCode.PERMISSION_DENIED, f"insufficient permissions ({permission})")

            if rate_limiter is not None:
                import hashlib

                actor = hashlib.sha256(token.encode("utf-8")).hexdigest()[:16]
                if not rate_limiter.allow(actor=actor):
                    logger.warning("gRPC %s rejected: rate limited (actor=%s)", method, actor)
                    return _deny(grpc.StatusCode.RESOURCE_EXHAUSTED, "rate limit exceeded")

            return continuation(handler_call_details)

    return _AuthInterceptor()


__all__ = [
    "METHOD_PERMISSIONS",
    "assert_secure_transport",
    "authorize",
    "bearer_token_from_metadata",
    "build_auth_interceptor",
    "is_loopback_host",
    "metadata_value",
    "target_host",
]
