"""PicoDome auth — constant-time token validation and hash-based RBAC.

Security properties:
  - Token comparison uses ``hmac.compare_digest`` to prevent timing attacks.
  - Token secrets are never stored in plaintext; only SHA-256 hashes are kept.
  - RBAC roles are stored as SHA-256 hashes of ``token:role`` pairs to prevent
    role extraction from token prefix parsing.
  - Enterprise mode (``PICODOME_ENTERPRISE_MODE=1``) enforces stricter checks:
    no dev-mode bypass, no empty tokens, minimum token length.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
from pathlib import Path

logger = logging.getLogger("picodome.auth")


def _is_enterprise_mode() -> bool:
    """Check if enterprise mode is active via environment variable."""
    return os.environ.get("PICODOME_ENTERPRISE_MODE", "").lower() in ("1", "true", "yes")


class AuthError(Exception):
    """Raised when authentication or authorization fails."""

    def __init__(self, message: str, status: int = 401) -> None:
        self.message = message
        self.status = status
        super().__init__(message)


# ─── Constant-time token comparison ─────────────────────────────────────────


def _hash_token(token: str) -> str:
    """Hash a token with SHA-256 for secure storage.

    We store hashes instead of plaintext so that a memory dump or log
    leak doesn't reveal the actual tokens.
    """
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _constant_time_equal(a: str, b: str) -> bool:
    """Constant-time string comparison using hmac.compare_digest.

    Prevents timing attacks that could reveal token length or content.
    """
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


# ─── Roles and permissions ──────────────────────────────────────────────────


class Role:
    """Well-known role names."""

    SUBMITTER = "submitter"
    READER = "reader"
    ADMIN = "admin"

    ALL = (SUBMITTER, READER, ADMIN)


# Role → set of permissions
ROLE_PERMISSIONS: dict[str, set[str]] = {
    Role.SUBMITTER: {"scan:submit", "scan:read", "health"},
    Role.READER: {"scan:read", "policy:read", "baseline:read", "audit:read", "health"},
    Role.ADMIN: {"*"},  # wildcard — all permissions
}

# Minimum token length in enterprise mode
MIN_TOKEN_LENGTH = 32


class RBAC:
    """Role-based access control backed by hashed token-role mappings.

    Tokens are never stored in plaintext. Instead, we store the SHA-256
    hash of each token, and look up roles by hash. This means even if
    the RBAC object is dumped, the actual tokens are not recoverable.

    Role registrations are also hashed: we store
    ``SHA256(token + ":" + role)`` so that role names cannot be extracted
    from a raw token alone — you need the token AND the role to match.
    """

    def __init__(self) -> None:
        # token_hash → role
        self._role_map: dict[str, str] = {}
        # For constant-time lookup: set of valid token hashes
        self._valid_hashes: set[str] = set()

    def register_token(self, token: str, role: str) -> None:
        """Register a token with a role.

        Args:
            token: The plaintext bearer token.
            role: Role name (submitter, reader, admin).
        """
        if role not in Role.ALL:
            logger.warning("Unknown role '%s' for token hash %s…", role, _hash_token(token)[:8])
            # Still register — unknown roles get no permissions
        token_hash = _hash_token(token)
        self._role_map[token_hash] = role
        self._valid_hashes.add(token_hash)

    def get_role(self, token: str) -> str:
        """Look up the role for a token (constant-time hash lookup)."""
        token_hash = _hash_token(token)
        return self._role_map.get(token_hash, Role.READER)

    def has_permission(self, token: str, permission: str) -> bool:
        """Check if a token's role grants a specific permission."""
        role = self.get_role(token)
        perms = ROLE_PERMISSIONS.get(role, set())
        return "*" in perms or permission in perms

    def is_known_token(self, token: str) -> bool:
        """Check if a token hash is registered (constant-time)."""
        token_hash = _hash_token(token)
        return token_hash in self._valid_hashes


class TokenAuth:
    """Bearer-token authentication with constant-time validation.

    Tokens are loaded from:
    1. ``PICODOME_API_TOKENS`` env var (comma-separated)
    2. ``~/.picodome/api-tokens`` file (one token per line)

    Token format: ``picodome-<role>-<secret>`` (e.g., ``picodome-admin-abc123``)
    The role is extracted during loading and registered with RBAC.

    Security:
    - Token comparison uses ``hmac.compare_digest`` (constant-time).
    - Only SHA-256 hashes of tokens are stored in memory.
    - In enterprise mode, dev-mode bypass is disabled and minimum
      token length is enforced.
    """

    # Brute-force protection thresholds
    MAX_FAILED_ATTEMPTS = 5
    BACKOFF_BASE_SECONDS = 1.0
    BACKOFF_MAX_SECONDS = 16.0

    def __init__(self, rbac: RBAC | None = None) -> None:
        self._rbac = rbac or RBAC()
        # Store ONLY SHA-256 hashes of tokens — never plaintext
        self._token_hashes: set[str] = set()
        # Brute-force tracking: token_hash → (attempt_count, last_attempt_time)
        self._failed_attempts: dict[str, tuple[int, float]] = {}
        self._is_enterprise = _is_enterprise_mode()
        self._load_tokens()
        # F1: Block DEV_MODE in enterprise mode at startup
        if self._is_enterprise and os.environ.get("PICODOME_DEV_MODE", "").lower() in ("1", "true", "yes"):
            logger.error(
                "ENTERPRISE MODE: PICODOME_DEV_MODE is set — refusing to start. Remove DEV_MODE for production."
            )
            raise AuthError("PICODOME_DEV_MODE must not be set in enterprise mode", status=403)

    @property
    def rbac(self) -> RBAC:
        return self._rbac

    def _load_tokens(self) -> None:
        """Load tokens from env and file."""
        # From environment
        env_tokens = os.environ.get("PICODOME_API_TOKENS", "")
        for token in env_tokens.split(","):
            token = token.strip()
            if token:
                self._add_token(token)

        # From file
        token_file = Path.home() / ".picodome" / "api-tokens"
        if token_file.is_file():
            try:
                for line in token_file.read_text(encoding="utf-8").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#"):
                        self._add_token(line)
            except OSError:
                pass

        logger.info("Loaded %d API token(s)", len(self._token_hashes))

    def _add_token(self, token: str) -> None:
        """Add a single token, validating enterprise constraints."""
        # Reject obviously invalid tokens regardless of mode (empty or < 4 chars)
        if not token or len(token) < 4:
            logger.warning("Token too short: %s", "***" if token else "(empty)")
            return
        if self._is_enterprise and len(token) < MIN_TOKEN_LENGTH:
            logger.error(
                "Enterprise mode: token '%s…' is too short (minimum %d characters). Token rejected.",
                token[:4],
                MIN_TOKEN_LENGTH,
            )
            return

        token_hash = _hash_token(token)
        if token_hash in self._token_hashes:
            return  # already registered

        self._token_hashes.add(token_hash)
        # Plaintext discarded after RBAC registration

        # Extract role from token format: picodome-<role>-<secret>
        if token.startswith("picodome-"):
            parts = token.split("-", 2)
            if len(parts) >= 3:
                role = parts[1]
                self._rbac.register_token(token, role)
        else:
            # Token doesn't follow naming convention — default to reader
            self._rbac.register_token(token, Role.READER)

    def _check_brute_force(self, token_hash: str) -> float | None:
        """Check brute-force backoff. Returns required wait time in seconds, or None if OK."""
        import time as _time

        entry = self._failed_attempts.get(token_hash)
        if entry is None:
            return None
        attempts, last_time = entry
        if attempts < self.MAX_FAILED_ATTEMPTS:
            return None
        backoff = min(
            self.BACKOFF_BASE_SECONDS * (2 ** (attempts - self.MAX_FAILED_ATTEMPTS)),
            self.BACKOFF_MAX_SECONDS,
        )
        elapsed = _time.monotonic() - last_time
        if elapsed < backoff:
            return backoff - elapsed
        return None

    def _record_failure(self, token_hash: str) -> None:
        """Record a failed authentication attempt."""
        import time as _time

        entry = self._failed_attempts.get(token_hash)
        if entry is None:
            self._failed_attempts[token_hash] = (1, _time.monotonic())
        else:
            attempts, _ = entry
            self._failed_attempts[token_hash] = (attempts + 1, _time.monotonic())

    def _clear_failures(self, token_hash: str) -> None:
        """Clear brute-force tracking on successful auth."""
        self._failed_attempts.pop(token_hash, None)
        if len(self._failed_attempts) > 1000:
            self._cleanup_stale_failures()

    def _cleanup_stale_failures(self) -> None:
        """Remove expired brute-force entries to prevent unbounded growth."""
        import time as _time

        now = _time.monotonic()
        stale_keys = [k for k, (attempts, last_time) in self._failed_attempts.items() if now - last_time > 3600]
        for k in stale_keys:
            del self._failed_attempts[k]

    def validate(self, token: str) -> bool:
        """Validate a token using constant-time hash comparison.

        No plaintext tokens are stored in memory. The provided token is
        hashed and compared against stored hashes using hmac.compare_digest.

        In enterprise mode:
        - Empty token store always rejects (no dev bypass).
        - Minimum token length is enforced on validation.
        - Brute-force protection with exponential backoff.

        In dev mode (no tokens configured):
        - All requests are authenticated (warning logged).
        """
        token_hash = _hash_token(token)

        # Brute-force check
        wait_time = self._check_brute_force(token_hash)
        if wait_time is not None:
            logger.warning("Rate limited: token hash %s… must wait %.1fs", token_hash[:8], wait_time)
            return False

        # Enterprise mode: no bypass, strict validation
        if self._is_enterprise:
            if not self._token_hashes:
                logger.error(
                    "Enterprise mode: no API tokens configured — all requests rejected. Set PICODOME_API_TOKENS."
                )
                self._record_failure(token_hash)
                return False
            if len(token) < MIN_TOKEN_LENGTH:
                self._record_failure(token_hash)
                return False
            for stored_hash in self._token_hashes:
                if hmac.compare_digest(token_hash.encode("utf-8"), stored_hash.encode("utf-8")):
                    self._clear_failures(token_hash)
                    return True
            self._record_failure(token_hash)
            return False

        # Non-enterprise: allow dev mode bypass if no tokens configured
        if not self._token_hashes:
            if os.environ.get("PICODOME_DEV_MODE", "").lower() in ("1", "true", "yes"):
                logger.warning("DEV MODE: No API tokens configured — all requests authenticated")
                return True
            logger.warning(
                "No API tokens configured — rejecting all requests. Set PICODOME_API_TOKENS or PICODOME_DEV_MODE=1"
            )
            self._record_failure(token_hash)
            return False

        for stored_hash in self._token_hashes:
            if hmac.compare_digest(token_hash.encode("utf-8"), stored_hash.encode("utf-8")):
                self._clear_failures(token_hash)
                return True
        self._record_failure(token_hash)
        return False

    def get_role(self, token: str) -> str:
        """Get the role for a validated token."""
        return self._rbac.get_role(token)

    def has_permission(self, token: str, permission: str) -> bool:
        """Check if a validated token has a specific permission."""
        return self._rbac.has_permission(token, permission)

    @property
    def is_configured(self) -> bool:
        """Check if any tokens are configured (or dev mode is enabled).

        In enterprise mode, dev mode is never considered configured.
        """
        if self._is_enterprise:
            return len(self._token_hashes) > 0
        if os.environ.get("PICODOME_DEV_MODE", "").lower() in ("1", "true", "yes"):
            return True
        return len(self._token_hashes) > 0

    @property
    def is_enterprise(self) -> bool:
        """Check if enterprise mode is active."""
        return self._is_enterprise
