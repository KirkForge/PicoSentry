"""
Authentication and authorization for PicoSentry daemon mode.

Supports two modes:
  - Token auth: static bearer token (PICOSENTRY_AUTH_TOKEN env or --auth-token flag)
  - OIDC/JWT auth: validate JWT against an IdP (PICOSENTRY_OIDC_ISSUER, etc.)

RBAC scopes:
  - read: View scan results, metrics, health
  - write: Trigger scans, update corpus/policy
  - admin: Manage configuration, users, secrets
  - scan: Run scans
  - policy:read / policy:write: Policy management
  - corpus:read / corpus:write: Corpus management

Design: fail-closed. If auth is enabled and a request lacks valid credentials,
it is rejected with 401/403. OIDC mode REQUIRES PyJWT — unsigned tokens are
always denied, not silently accepted.

Usage:
    from picosentry.scan.auth import AuthConfig, Scope, check_auth

    config = AuthConfig(mode="token", token="s3cret", scopes={"admin": ["admin"]})
    result = check_auth(headers, config)
    if not result.ok:
        return 401 response
    if not result.has_permission(Scope.SCAN):
        return 403 response
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("picosentry.auth")

# Maximum number of rate-limit buckets before eviction of stale entries.
_MAX_RATE_LIMIT_BUCKETS = 10000

# Staleness threshold: buckets not accessed in this many seconds are evicted.
_BUCKET_STALE_SECONDS = 300  # 5 minutes


# ── RBAC scopes ────────────────────────────────────────────────────────────


class Scope:
    """RBAC permission scopes for daemon endpoints.

    Enterprise deployments need role-based access control beyond simple
    pass/fail auth. Scopes determine what actions an identity can perform.

    Scope hierarchy:
        admin > write > read

    Admin scope includes all read and write permissions.
    Write scope includes all read permissions.
    """

    READ = "read"  # View scan results, metrics, health
    WRITE = "write"  # Trigger scans, update corpus/policy
    ADMIN = "admin"  # Manage configuration, users, secrets
    SCAN = "scan"  # Run scans
    POLICY_READ = "policy:read"  # View policy configuration
    POLICY_WRITE = "policy:write"  # Modify policy configuration
    CORPUS_READ = "corpus:read"  # View corpus/IoC data
    CORPUS_WRITE = "corpus:write"  # Import/export corpus packs
    TENANT_READ = "tenant:read"  # View tenant configuration and health
    TENANT_WRITE = "tenant:write"  # Create, modify, delete tenants
    FLEET_READ = "fleet:read"  # View fleet rollout status and compliance
    FLEET_WRITE = "fleet:write"  # Create, promote, manage fleet rollouts

    ALL_SCOPES = frozenset(
        {
            READ,
            WRITE,
            ADMIN,
            SCAN,
            POLICY_READ,
            POLICY_WRITE,
            CORPUS_READ,
            CORPUS_WRITE,
            TENANT_READ,
            TENANT_WRITE,
            FLEET_READ,
            FLEET_WRITE,
        }
    )

    # Scope implied permissions: admin > write > read
    _IMPLIES = {
        ADMIN: {
            READ,
            WRITE,
            ADMIN,
            SCAN,
            POLICY_READ,
            POLICY_WRITE,
            CORPUS_READ,
            CORPUS_WRITE,
            TENANT_READ,
            TENANT_WRITE,
            FLEET_READ,
            FLEET_WRITE,
        },
        WRITE: {READ, WRITE, SCAN, POLICY_READ, CORPUS_READ, TENANT_READ, FLEET_READ},
        READ: {READ, POLICY_READ, CORPUS_READ, TENANT_READ},
        SCAN: {READ, SCAN},
        POLICY_WRITE: {POLICY_READ, POLICY_WRITE},
        CORPUS_WRITE: {CORPUS_READ, CORPUS_WRITE},
        TENANT_WRITE: {TENANT_READ, TENANT_WRITE},
        FLEET_WRITE: {FLEET_READ, FLEET_WRITE},
    }

    @staticmethod
    def resolve(scopes: list[str]) -> frozenset[str]:
        """Resolve a list of scopes into their full set of implied permissions.

        Args:
            scopes: List of scope strings (e.g. ["admin", "corpus:read"])

        Returns:
            Frozen set of all implied scope strings.
        """
        resolved: set[str] = set()
        for scope in scopes:
            resolved.update(Scope._IMPLIES.get(scope, {scope}))
        return frozenset(resolved)

    @staticmethod
    def has_permission(identity_scopes: frozenset[str], required: str) -> bool:
        """Check if an identity's scopes grant a required permission."""
        return required in identity_scopes

    @staticmethod
    def required_for_endpoint(path: str, method: str = "GET") -> list[str]:
        """Return the minimum scopes required for an endpoint.

        Args:
            path: Request path (e.g. "/metrics").
            method: HTTP method (GET, POST, PUT, DELETE).

        Returns:
            List of scope strings that grant access.
        """
        # Public endpoints — no scope required
        public_paths = {"/", "/health", "/healthz", "/ready", "/readyz"}
        if path in public_paths:
            return list(Scope.ALL_SCOPES)  # Any valid identity

        # Metrics — read access
        if path.startswith("/metrics"):
            return [Scope.READ, Scope.WRITE, Scope.ADMIN]

        # Scan endpoints — scan scope
        if path.startswith("/scan"):
            if method == "POST":
                return [Scope.SCAN, Scope.WRITE, Scope.ADMIN]
            return [Scope.READ, Scope.WRITE, Scope.ADMIN]

        # Policy management
        if path.startswith("/policy"):
            if method in ("POST", "PUT", "DELETE"):
                return [Scope.POLICY_WRITE, Scope.ADMIN]
            return [Scope.POLICY_READ, Scope.READ, Scope.ADMIN]

        # Corpus management
        if path.startswith("/corpus"):
            if method in ("POST", "PUT", "DELETE"):
                return [Scope.CORPUS_WRITE, Scope.ADMIN]
            return [Scope.CORPUS_READ, Scope.READ, Scope.ADMIN]

        # Fleet management
        if path.startswith("/fleet"):
            if method in ("POST", "PUT", "DELETE"):
                return [Scope.FLEET_WRITE, Scope.ADMIN]
            return [Scope.FLEET_READ, Scope.READ, Scope.ADMIN]

        # Tenant management
        if path.startswith("/tenant"):
            if method in ("POST", "PUT", "DELETE"):
                return [Scope.TENANT_WRITE, Scope.ADMIN]
            return [Scope.TENANT_READ, Scope.READ, Scope.ADMIN]

        # Dashboard
        if path.startswith("/dashboard"):
            # Dashboard overview allows broad read access
            if path == "/dashboard":
                return [Scope.READ, Scope.WRITE, Scope.ADMIN]
            # Tenant dashboard requires tenant scope
            if path == "/dashboard/tenants":
                return [Scope.TENANT_READ, Scope.TENANT_WRITE, Scope.ADMIN]
            # Fleet and compliance dashboards require fleet scope
            if path in ("/dashboard/fleet", "/dashboard/compliance"):
                return [Scope.FLEET_READ, Scope.FLEET_WRITE, Scope.ADMIN]
            # Other dashboard paths fall through to broad read
            return [Scope.READ, Scope.WRITE, Scope.ADMIN]

        # Default — any authenticated identity
        return [Scope.READ, Scope.WRITE, Scope.ADMIN]


@dataclass
class AuthConfig:
    """Configuration for daemon authentication.

    Attributes:
        mode: "off" (default, no auth), "token" (static bearer token),
              or "oidc" (JWT validation against an IdP).
        token: Static bearer token for token mode.
        oidc_issuer: OIDC issuer URL (e.g. https://accounts.google.com).
        oidc_audience: Expected JWT audience claim.
        oidc_jwks_url: URL to fetch JWKS for signature verification.
        scopes: Mapping of identity to list of scope strings.
        default_scopes: Scopes assigned to identities without explicit mapping.
        public_endpoints: Paths that do not require auth (e.g. /healthz).
        rate_limit_rps: Max requests per second per client IP. 0 = unlimited.
        trusted_proxies: List of trusted proxy IPs. Only these proxies' X-Forwarded-For
                        headers are respected. Empty = ignore X-Forwarded-For entirely.
    """

    mode: str = "off"
    token: str = ""
    oidc_issuer: str = ""
    oidc_audience: str = ""
    oidc_jwks_url: str = ""
    scopes: dict[str, list[str]] = field(default_factory=dict)
    default_scopes: list[str] = field(default_factory=lambda: [Scope.READ])
    public_endpoints: list[str] = field(default_factory=lambda: ["/healthz", "/readyz"])
    rate_limit_rps: float = 0  # 0 = unlimited
    trusted_proxies: list[str] = field(default_factory=list)

    @staticmethod
    def from_dict(data: dict[str, Any]) -> AuthConfig:
        """Create AuthConfig from a config dict (e.g. daemon section of .picosentry.yml)."""
        return AuthConfig(
            mode=data.get("mode", "off"),
            token=data.get("token", ""),
            oidc_issuer=data.get("oidc_issuer", ""),
            oidc_audience=data.get("oidc_audience", ""),
            oidc_jwks_url=data.get("oidc_jwks_url", ""),
            scopes=data.get("scopes", {}),
            default_scopes=data.get("default_scopes", [Scope.READ]),
            public_endpoints=data.get("public_endpoints", ["/healthz", "/readyz"]),
            rate_limit_rps=float(data.get("rate_limit_rps", 0)),
            trusted_proxies=data.get("trusted_proxies", []),
        )

    @staticmethod
    def from_env() -> AuthConfig:
        """Create AuthConfig from environment variables."""
        import os

        mode = os.environ.get("PICOSENTRY_AUTH_MODE", "off")
        token = os.environ.get("PICOSENTRY_AUTH_TOKEN", "")
        public_endpoints_str = os.environ.get("PICOSENTRY_AUTH_PUBLIC_ENDPOINTS", "")
        public_endpoints = (
            [e.strip() for e in public_endpoints_str.split(",") if e.strip()]
            if public_endpoints_str
            else ["/healthz", "/readyz"]
        )
        rate_limit_rps = float(os.environ.get("PICOSENTRY_RATE_LIMIT_RPS", "0"))
        trusted_proxies_str = os.environ.get("PICOSENTRY_TRUSTED_PROXIES", "")
        trusted_proxies = (
            [p.strip() for p in trusted_proxies_str.split(",") if p.strip()] if trusted_proxies_str else []
        )

        # Parse scopes from env: PICOSENTRY_SCOPES_<identity>=scope1,scope2
        # e.g. PICOSENTRY_SCOPES_admin=admin,scan
        scopes: dict[str, list[str]] = {}
        for key, value in os.environ.items():
            if key.startswith("PICOSENTRY_SCOPES_"):
                identity = key[len("PICOSENTRY_SCOPES_") :].lower()
                scopes[identity] = [s.strip() for s in value.split(",") if s.strip()]

        default_scopes_str = os.environ.get("PICOSENTRY_DEFAULT_SCOPES", "read")
        default_scopes = [s.strip() for s in default_scopes_str.split(",") if s.strip()]

        return AuthConfig(
            mode=mode,
            token=token,
            oidc_issuer=os.environ.get("PICOSENTRY_OIDC_ISSUER", ""),
            oidc_audience=os.environ.get("PICOSENTRY_OIDC_AUDIENCE", ""),
            oidc_jwks_url=os.environ.get("PICOSENTRY_OIDC_JWKS_URL", ""),
            scopes=scopes,
            default_scopes=default_scopes,
            public_endpoints=public_endpoints,
            rate_limit_rps=rate_limit_rps,
            trusted_proxies=trusted_proxies,
        )


@dataclass
class AuthResult:
    """Result of an authentication check."""

    ok: bool = False
    identity: str = ""
    scopes: list[str] = field(default_factory=list)
    token_type: str = ""
    error: str = ""

    def resolved_scopes(self) -> frozenset[str]:
        """Resolve this identity's scopes into their full set of implied permissions."""
        return Scope.resolve(self.scopes)

    def has_permission(self, required: str) -> bool:
        """Check if this identity has a specific permission."""
        return Scope.has_permission(self.resolved_scopes(), required)

    @staticmethod
    def success(identity: str, token_type: str = "token", scopes: list[str] | None = None) -> AuthResult:
        return AuthResult(
            ok=True,
            identity=identity,
            scopes=scopes or [],
            token_type=token_type,
        )

    @staticmethod
    def denied(error: str) -> AuthResult:
        return AuthResult(ok=False, error=error)


def _constant_time_compare(a: str, b: str) -> bool:
    """Constant-time string comparison to prevent timing attacks."""
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def check_token_auth(headers: dict[str, str], config: AuthConfig) -> AuthResult:
    """Validate a bearer token against the configured token.

    Supports both Authorization: Bearer <token> and X-API-Key: <token> headers.
    Uses constant-time comparison to prevent timing attacks.
    Returns the identity and resolved scopes on success.
    """
    if not config.token:
        return AuthResult.denied("No token configured. Set PICOSENTRY_AUTH_TOKEN or --auth-token.")

    auth_header = headers.get("authorization", "")
    api_key = headers.get("x-api-key", "")

    if auth_header.startswith("Bearer "):
        provided = auth_header[7:].strip()
    elif api_key:
        provided = api_key.strip()
    else:
        return AuthResult.denied("Missing Authorization header. Use: Authorization: Bearer <token>")

    if not _constant_time_compare(provided, config.token):
        return AuthResult.denied("Invalid token.")

    # Resolve scopes for the identity.
    # Identity is derived as "token:<sha256>", but operators configure scopes by
    # human-readable name (e.g. PICOSENTRY_SCOPES_admin=read,write). Check both
    # the token-hash identity and a "token_default" key so named scopes work.
    identity = f"token:{hashlib.sha256(provided.encode()).hexdigest()[:12]}"
    identity_scopes = (
        config.scopes.get(identity)
        if identity in config.scopes
        else config.scopes.get("token_default", config.default_scopes)
    )

    return AuthResult.success(identity=identity, token_type="token", scopes=identity_scopes)


def check_oidc_auth(headers: dict[str, str], config: AuthConfig) -> AuthResult:
    """Validate an OIDC/JWT token.

    Requires PyJWT package. Tokens are verified against the configured
    issuer and audience. JWKS is fetched for signature verification.

    Returns the subject as identity with resolved scopes.
    """
    auth_header = headers.get("authorization", "")

    if not auth_header:
        return AuthResult.denied("Missing Authorization header. Use: Authorization: Bearer <jwt>")

    if not auth_header.startswith("Bearer "):
        return AuthResult.denied("Invalid Authorization header format. Use: Bearer <jwt>")

    token = auth_header[7:]

    if not config.oidc_issuer:
        return AuthResult.denied("OIDC not configured. Set PICOSENTRY_OIDC_ISSUER.")

    try:
        import jwt

        decode_kwargs: dict[str, Any] = {
            "algorithms": ["RS256"],
            "issuer": config.oidc_issuer,
        }

        if config.oidc_audience:
            decode_kwargs["audience"] = config.oidc_audience

        if config.oidc_jwks_url:
            from picosentry.scan._network import InsecureURLError, ResponseTooLargeError, safe_urlopen

            try:
                import urllib.request

                jwks_req = urllib.request.Request(config.oidc_jwks_url, headers={"Accept": "application/json"})
                resp, jwks_data = safe_urlopen(jwks_req, timeout=10)
                jwks_json = json.loads(jwks_data)

                from jwt import PyJWKSet

                jwk_set = PyJWKSet.from_dict(jwks_json)

                # Try keys in order
                signing_key = None
                unverified_header = jwt.get_unverified_header(token)
                kid = unverified_header.get("kid")

                for key in jwk_set.keys:
                    if kid and key.key_id == kid:
                        signing_key = key
                        break

                if not signing_key and jwk_set.keys:
                    signing_key = jwk_set.keys[0]

                if not signing_key:
                    return AuthResult.denied("No signing keys found in JWKS. Cannot verify token.")

                decode_kwargs["key"] = signing_key
            except Exception as e:
                # JWKS fetch failed — DENY, do not fall through to unsigned acceptance
                if isinstance(e, (InsecureURLError, ResponseTooLargeError)):
                    logger.error("JWKS URL rejected: %s", e)
                else:
                    logger.error("Failed to fetch JWKS from %s: %s", config.oidc_jwks_url, e)
                return AuthResult.denied(f"JWKS fetch failed: {e}")

        if "key" not in decode_kwargs:
            # No JWKS URL configured and no key available — cannot verify signature
            logger.error("No JWKS URL configured and no signing key available. Cannot verify OIDC token.")
            return AuthResult.denied(
                "Cannot verify token: no signing key available. "
                "Configure PICOSENTRY_OIDC_JWKS_URL or install PyJWT with cryptography."
            )

        decoded = jwt.decode(token, **decode_kwargs)
        subject = decoded.get("sub", "unknown")

        # Resolve scopes: config mapping > JWT claims > default
        # Only check JWT claims if subject is NOT explicitly in config.scopes
        subject_in_config = subject in config.scopes
        identity_scopes = config.scopes.get(subject, config.default_scopes)

        # Also check JWT scope/picosentry_scopes claims if no explicit config mapping
        if not subject_in_config:
            jwt_scopes = decoded.get("picosentry_scopes", decoded.get("scope", ""))
            if isinstance(jwt_scopes, str) and jwt_scopes:
                identity_scopes = [s.strip() for s in jwt_scopes.split(",") if s.strip()]
            elif isinstance(jwt_scopes, list):
                identity_scopes = jwt_scopes

        logger.info("OIDC auth verified: subject=%s, issuer=%s", subject, config.oidc_issuer)
        return AuthResult.success(identity=subject, token_type="oidc", scopes=identity_scopes)

    except ImportError:
        # PyJWT not installed — CANNOT verify signature, DENY
        logger.error(
            "PyJWT not installed. Cannot verify OIDC token signature. Install PyJWT for production: pip install PyJWT"
        )
        return AuthResult.denied("OIDC token verification requires PyJWT. Install with: pip install PyJWT")
    except Exception as e:
        # Any JWT verification error — DENY
        error_msg = str(e)
        error_type = type(e).__name__
        if "Signature" in error_msg or "InvalidSignatureError" in error_type:
            return AuthResult.denied("JWT signature verification failed")
        logger.warning("JWT verification error: %s", error_msg)
        return AuthResult.denied(f"JWT verification failed: {error_msg}")


def check_auth(headers: dict[str, str], config: AuthConfig) -> AuthResult:
    """Check authentication and resolve scopes based on config mode.

    After auth check, the AuthResult.scopes field contains the
    resolved scope strings for the identity.
    """
    if config.mode == "off":
        # No auth: grant read-only scopes — auth=off does NOT grant admin
        logger.warning("Auth is disabled (PICOSENTRY_AUTH=off). Granting read-only scopes.")
        return AuthResult.success(identity="anonymous", token_type="none", scopes=[Scope.READ])

    if config.mode == "token":
        return check_token_auth(headers, config)

    if config.mode == "oidc":
        result = check_oidc_auth(headers, config)
        # OIDC scopes are already resolved in check_oidc_auth
        return result

    return AuthResult.denied(f"Unknown auth mode: {config.mode}")


def check_authorization(auth_result: AuthResult, path: str, method: str = "GET") -> AuthResult:
    """Check if an authenticated identity has permission for an endpoint.

    Returns the original auth_result if authorized, or a denied result
    with 403 error if the identity lacks required scopes.

    Args:
        auth_result: The result from check_auth().
        path: Request path (e.g. "/metrics").
        method: HTTP method (GET, POST, PUT, DELETE).

    Returns:
        AuthResult with ok=True if authorized, ok=False with 403 error if not.
    """
    if not auth_result.ok:
        return auth_result

    required_scopes = Scope.required_for_endpoint(path, method)
    resolved = auth_result.resolved_scopes()

    for scope in required_scopes:
        if scope in resolved:
            return auth_result

    return AuthResult.denied(
        f"Insufficient permissions. Identity '{auth_result.identity}' lacks required scope for {method} {path}. "
        f"Required: {required_scopes}. Have: {list(resolved)}"
    )


# ── Rate limiting ──────────────────────────────────────────────────────


class RateLimiter:
    """Thread-safe token-bucket rate limiter per client IP.

    Uses a lock for thread safety and evicts stale buckets (not accessed
    within _BUCKET_STALE_SECONDS) to bound memory.

    Args:
        rps: Requests per second per client. 0 = unlimited.
        burst: Maximum burst size (default: 2x rps). 0 = unlimited.
        max_buckets: Maximum number of client buckets before eviction.
    """

    def __init__(self, rps: float = 0, burst: int = 0, max_buckets: int = _MAX_RATE_LIMIT_BUCKETS) -> None:
        self.rps = rps
        self.burst = burst
        self.max_buckets = max_buckets
        self._lock = threading.Lock()
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()
        if self.rps > 0 and self.burst == 0:
            self.burst = int(self.rps * 2)

    def _evict_stale(self) -> None:
        """Evict stale entries to bound memory.

        Removes buckets not accessed within _BUCKET_STALE_SECONDS, then
        if still over capacity, evicts the least-recently-used entries.
        """
        now = time.monotonic()
        # First pass: remove stale entries (not accessed in _BUCKET_STALE_SECONDS)
        stale_keys = [
            key for key, (last_time, tokens) in self._buckets.items() if now - last_time > _BUCKET_STALE_SECONDS
        ]
        for key in stale_keys:
            del self._buckets[key]

        # Second pass: if still over capacity, evict LRU entries
        while len(self._buckets) > self.max_buckets:
            self._buckets.popitem(last=False)

    def check(self, client_id: str) -> bool:
        """Check if a request is allowed. Thread-safe."""
        if self.rps <= 0:
            return True

        with self._lock:
            now = time.monotonic()
            if client_id in self._buckets:
                last_time, tokens = self._buckets[client_id]
                elapsed = now - last_time
                tokens = min(self.burst, tokens + elapsed * self.rps)
            else:
                # Evict stale entries if at capacity
                self._evict_stale()
                tokens = float(self.burst)

            if tokens < 1.0:
                self._buckets[client_id] = (now, tokens)
                return False

            self._buckets[client_id] = (now, tokens - 1.0)
            self._buckets.move_to_end(client_id)
            return True

    def retry_after(self, client_id: str) -> int:
        """Return seconds until the client can retry."""
        if self.rps <= 0:
            return 0
        with self._lock:
            if client_id not in self._buckets:
                return 0
            _, tokens = self._buckets[client_id]
            if tokens >= 1.0:
                return 0
            deficit = 1.0 - tokens
            return max(1, int(deficit / self.rps) + 1)
