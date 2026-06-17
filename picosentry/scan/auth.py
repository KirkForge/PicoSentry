
from __future__ import annotations

import hashlib
import hmac
import json
import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, ClassVar

logger = logging.getLogger("picosentry.auth")


_MAX_RATE_LIMIT_BUCKETS = 10000


_BUCKET_STALE_SECONDS = 300  # 5 minutes


class Scope:

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


    _IMPLIES: ClassVar[dict[str, set[str]]] = {
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
        resolved: set[str] = set()
        for scope in scopes:
            resolved.update(Scope._IMPLIES.get(scope, {scope}))
        return frozenset(resolved)

    @staticmethod
    def has_permission(identity_scopes: frozenset[str], required: str) -> bool:
        return required in identity_scopes

    @staticmethod
    def required_for_endpoint(path: str, method: str = "GET") -> list[str]:

        public_paths = {"/", "/health", "/healthz", "/ready", "/readyz"}
        if path in public_paths:
            return list(Scope.ALL_SCOPES)  # Any valid identity


        if path.startswith("/metrics"):
            return [Scope.READ, Scope.WRITE, Scope.ADMIN]


        if path.startswith("/scan"):
            if method == "POST":
                return [Scope.SCAN, Scope.WRITE, Scope.ADMIN]
            return [Scope.READ, Scope.WRITE, Scope.ADMIN]


        if path.startswith("/policy"):
            if method in ("POST", "PUT", "DELETE"):
                return [Scope.POLICY_WRITE, Scope.ADMIN]
            return [Scope.POLICY_READ, Scope.READ, Scope.ADMIN]


        if path.startswith("/corpus"):
            if method in ("POST", "PUT", "DELETE"):
                return [Scope.CORPUS_WRITE, Scope.ADMIN]
            return [Scope.CORPUS_READ, Scope.READ, Scope.ADMIN]


        if path.startswith("/fleet"):
            if method in ("POST", "PUT", "DELETE"):
                return [Scope.FLEET_WRITE, Scope.ADMIN]
            return [Scope.FLEET_READ, Scope.READ, Scope.ADMIN]


        if path.startswith("/tenant"):
            if method in ("POST", "PUT", "DELETE"):
                return [Scope.TENANT_WRITE, Scope.ADMIN]
            return [Scope.TENANT_READ, Scope.READ, Scope.ADMIN]


        if path.startswith("/dashboard"):

            if path == "/dashboard":
                return [Scope.READ, Scope.WRITE, Scope.ADMIN]

            if path == "/dashboard/tenants":
                return [Scope.TENANT_READ, Scope.TENANT_WRITE, Scope.ADMIN]

            if path in ("/dashboard/fleet", "/dashboard/compliance"):
                return [Scope.FLEET_READ, Scope.FLEET_WRITE, Scope.ADMIN]

            return [Scope.READ, Scope.WRITE, Scope.ADMIN]


        return [Scope.READ, Scope.WRITE, Scope.ADMIN]


@dataclass
class AuthConfig:

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

    ok: bool = False
    identity: str = ""
    scopes: list[str] = field(default_factory=list)
    token_type: str = ""
    error: str = ""

    def resolved_scopes(self) -> frozenset[str]:
        return Scope.resolve(self.scopes)

    def has_permission(self, required: str) -> bool:
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
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def check_token_auth(headers: dict[str, str], config: AuthConfig) -> AuthResult:
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


    identity = f"token:{hashlib.sha256(provided.encode()).hexdigest()[:12]}"
    identity_scopes = (
        config.scopes.get(identity)
        if identity in config.scopes
        else config.scopes.get("token_default", config.default_scopes)
    )

    return AuthResult.success(identity=identity, token_type="token", scopes=identity_scopes)


def check_oidc_auth(headers: dict[str, str], config: AuthConfig) -> AuthResult:
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
                _resp, jwks_data = safe_urlopen(jwks_req, timeout=10)
                jwks_json = json.loads(jwks_data)

                from jwt import PyJWKSet

                jwk_set = PyJWKSet.from_dict(jwks_json)


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

                if isinstance(e, (InsecureURLError, ResponseTooLargeError)):
                    logger.exception("JWKS URL rejected: %s", e)
                else:
                    logger.exception("Failed to fetch JWKS from %s: %s", config.oidc_jwks_url, e)
                return AuthResult.denied(f"JWKS fetch failed: {e}")

        if "key" not in decode_kwargs:

            logger.error("No JWKS URL configured and no signing key available. Cannot verify OIDC token.")
            return AuthResult.denied(
                "Cannot verify token: no signing key available. "
                "Configure PICOSENTRY_OIDC_JWKS_URL or install PyJWT with cryptography."
            )

        decoded = jwt.decode(token, **decode_kwargs)
        subject = decoded.get("sub", "unknown")


        subject_in_config = subject in config.scopes
        identity_scopes = config.scopes.get(subject, config.default_scopes)


        if not subject_in_config:
            jwt_scopes = decoded.get("picosentry_scopes", decoded.get("scope", ""))
            if isinstance(jwt_scopes, str) and jwt_scopes:
                identity_scopes = [s.strip() for s in jwt_scopes.split(",") if s.strip()]
            elif isinstance(jwt_scopes, list):
                identity_scopes = jwt_scopes

        logger.info("OIDC auth verified: subject=%s, issuer=%s", subject, config.oidc_issuer)
        return AuthResult.success(identity=subject, token_type="oidc", scopes=identity_scopes)

    except ImportError:

        logger.exception(
            "PyJWT not installed. Cannot verify OIDC token signature. Install PyJWT for production: pip install PyJWT"
        )
        return AuthResult.denied("OIDC token verification requires PyJWT. Install with: pip install PyJWT")
    except Exception as e:

        error_msg = str(e)
        error_type = type(e).__name__
        if "Signature" in error_msg or "InvalidSignatureError" in error_type:
            return AuthResult.denied("JWT signature verification failed")
        logger.warning("JWT verification error: %s", error_msg)
        return AuthResult.denied(f"JWT verification failed: {error_msg}")


def check_auth(headers: dict[str, str], config: AuthConfig) -> AuthResult:
    if config.mode == "off":

        logger.warning("Auth is disabled (PICOSENTRY_AUTH=off). Granting read-only scopes.")
        return AuthResult.success(identity="anonymous", token_type="none", scopes=[Scope.READ])

    if config.mode == "token":
        return check_token_auth(headers, config)

    if config.mode == "oidc":
        return check_oidc_auth(headers, config)


    return AuthResult.denied(f"Unknown auth mode: {config.mode}")


def check_authorization(auth_result: AuthResult, path: str, method: str = "GET") -> AuthResult:
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


class RateLimiter:

    def __init__(self, rps: float = 0, burst: int = 0, max_buckets: int = _MAX_RATE_LIMIT_BUCKETS) -> None:
        self.rps = rps
        self.burst = burst
        self.max_buckets = max_buckets
        self._lock = threading.Lock()
        self._buckets: OrderedDict[str, tuple[float, float]] = OrderedDict()
        if self.rps > 0 and self.burst == 0:
            self.burst = int(self.rps * 2)

    def _evict_stale(self) -> None:
        now = time.monotonic()

        stale_keys = [
            key for key, (last_time, tokens) in self._buckets.items() if now - last_time > _BUCKET_STALE_SECONDS
        ]
        for key in stale_keys:
            del self._buckets[key]


        while len(self._buckets) > self.max_buckets:
            self._buckets.popitem(last=False)

    def check(self, client_id: str) -> bool:
        if self.rps <= 0:
            return True

        with self._lock:
            now = time.monotonic()
            if client_id in self._buckets:
                last_time, tokens = self._buckets[client_id]
                elapsed = now - last_time
                tokens = min(self.burst, tokens + elapsed * self.rps)
            else:

                self._evict_stale()
                tokens = float(self.burst)

            if tokens < 1.0:
                self._buckets[client_id] = (now, tokens)
                return False

            self._buckets[client_id] = (now, tokens - 1.0)
            self._buckets.move_to_end(client_id)
            return True

    def retry_after(self, client_id: str) -> int:
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
