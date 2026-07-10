from __future__ import annotations

import hashlib
import hmac
import logging
import os
from pathlib import Path

logger = logging.getLogger("picodome.auth")


def _is_enterprise_mode() -> bool:
    return os.environ.get("PICODOME_ENTERPRISE_MODE", "").lower() in ("1", "true", "yes")


class AuthError(Exception):
    def __init__(self, message: str, status: int = 401) -> None:
        self.message = message
        self.status = status
        super().__init__(message)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


class Role:
    SUBMITTER = "submitter"
    READER = "reader"
    ADMIN = "admin"
    NONE = "none"  # unknown / unauthenticated token

    ALL = (SUBMITTER, READER, ADMIN)


ROLE_PERMISSIONS: dict[str, set[str]] = {
    Role.SUBMITTER: {"scan:submit", "scan:read", "health"},
    Role.READER: {"scan:read", "policy:read", "baseline:read", "audit:read", "health"},
    Role.ADMIN: {"*"},  # wildcard — all permissions
    Role.NONE: set(),  # unknown tokens have no permissions
}


MIN_TOKEN_LENGTH = 32
MAX_FAILED_ATTEMPTS_CACHE = 1000
FAILED_ATTEMPT_TTL_SECONDS = 3600


class RBAC:
    def __init__(self) -> None:

        self._role_map: dict[str, str] = {}

        self._valid_hashes: set[str] = set()

    def register_token(self, token: str, role: str) -> None:
        if role not in Role.ALL:
            logger.warning("Unknown role '%s' for token hash %s…", role, _hash_token(token)[:8])

        token_hash = _hash_token(token)
        self._role_map[token_hash] = role
        self._valid_hashes.add(token_hash)

    def get_role(self, token: str) -> str:
        token_hash = _hash_token(token)
        return self._role_map.get(token_hash, Role.NONE)

    def has_permission(self, token: str, permission: str) -> bool:
        role = self.get_role(token)
        perms = ROLE_PERMISSIONS.get(role, set())
        return "*" in perms or permission in perms

    def is_known_token(self, token: str) -> bool:
        token_hash = _hash_token(token)
        return token_hash in self._valid_hashes


class TokenAuth:
    MAX_FAILED_ATTEMPTS = 5
    BACKOFF_BASE_SECONDS = 1.0
    BACKOFF_MAX_SECONDS = 16.0

    def __init__(self, rbac: RBAC | None = None) -> None:
        self._rbac = rbac or RBAC()

        self._token_hashes: set[str] = set()

        self._failed_attempts: dict[str, tuple[int, float]] = {}
        self._is_enterprise = _is_enterprise_mode()
        self._load_tokens()

        if self._is_enterprise and os.environ.get("PICODOME_DEV_MODE", "").lower() in ("1", "true", "yes"):
            logger.error(
                "ENTERPRISE MODE: PICODOME_DEV_MODE is set — refusing to start. Remove DEV_MODE for production."
            )
            raise AuthError("PICODOME_DEV_MODE must not be set in enterprise mode", status=403)

    @property
    def rbac(self) -> RBAC:
        return self._rbac

    def _load_tokens(self) -> None:

        env_tokens = os.environ.get("PICODOME_API_TOKENS", "")
        for raw_token in env_tokens.split(","):
            token = raw_token.strip()
            if token:
                self._add_token(token)

        token_file = Path.home() / ".picodome" / "api-tokens"
        if token_file.is_file():
            self._assert_token_file_permissions(token_file)
            try:
                for raw_line in token_file.read_text(encoding="utf-8").splitlines():
                    line = raw_line.strip()
                    if line and not line.startswith("#"):
                        self._add_token(line)
            except OSError:
                pass

        logger.info("Loaded %d API token(s)", len(self._token_hashes))

    @staticmethod
    def _assert_token_file_permissions(token_file: Path) -> None:
        try:
            stat = token_file.stat()
            mode = stat.st_mode
            # Reject world-readable or world-writable files.
            if mode & 0o077:
                logger.warning(
                    "Token file %s has overly permissive mode %s; it should be readable only by owner (e.g. 0o600).",
                    token_file,
                    oct(mode & 0o777),
                )
        except OSError:
            pass

    def _add_token(self, token: str) -> None:

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

        if token.startswith("picodome-"):
            parts = token.split("-", 2)
            if len(parts) >= 3:
                role = parts[1]
                self._rbac.register_token(token, role)
        else:
            self._rbac.register_token(token, Role.READER)

    def _check_brute_force(self, token_hash: str) -> float | None:
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
        import time as _time

        self._evict_stale_failures_if_needed()
        entry = self._failed_attempts.get(token_hash)
        if entry is None:
            self._failed_attempts[token_hash] = (1, _time.monotonic())
        else:
            attempts, _ = entry
            self._failed_attempts[token_hash] = (attempts + 1, _time.monotonic())

    def _clear_failures(self, token_hash: str) -> None:
        self._failed_attempts.pop(token_hash, None)

    def _evict_stale_failures_if_needed(self) -> None:
        import time as _time

        if len(self._failed_attempts) < MAX_FAILED_ATTEMPTS_CACHE:
            return
        now = _time.monotonic()
        stale_keys = [
            k for k, (_, last_time) in self._failed_attempts.items() if now - last_time > FAILED_ATTEMPT_TTL_SECONDS
        ]
        if stale_keys:
            for k in stale_keys:
                del self._failed_attempts[k]
            return
        # No stale entries: evict oldest to bound memory.
        oldest = min(self._failed_attempts.items(), key=lambda item: item[1][1])
        del self._failed_attempts[oldest[0]]

    def validate(self, token: str) -> bool:
        token_hash = _hash_token(token)

        wait_time = self._check_brute_force(token_hash)
        if wait_time is not None:
            logger.warning("Rate limited: token hash %s… must wait %.1fs", token_hash[:8], wait_time)
            return False

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
        return self._rbac.get_role(token)

    def has_permission(self, token: str, permission: str) -> bool:
        return self._rbac.has_permission(token, permission)

    @property
    def is_configured(self) -> bool:
        if self._is_enterprise:
            return len(self._token_hashes) > 0
        if os.environ.get("PICODOME_DEV_MODE", "").lower() in ("1", "true", "yes"):
            return True
        return len(self._token_hashes) > 0

    @property
    def is_enterprise(self) -> bool:
        return self._is_enterprise
