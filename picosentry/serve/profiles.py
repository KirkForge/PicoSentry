from __future__ import annotations

import logging
import os
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from picosentry.serve.config.settings import Settings as _Settings

logger = logging.getLogger("picoshogun.profiles")


@dataclass(frozen=True)
class ProfileCheck:
    name: str
    message: str


class ProductionProfileError(Exception):
    def __init__(self, failures: list[ProfileCheck]) -> None:
        self.failures = failures
        lines = [f"  - {f.name}: {f.message}" for f in failures]
        msg = (
            "Production profile checks failed — refusing to start with insecure settings:\n"
            + "\n".join(lines)
            + "\n\nFix each setting above and restart, or use --profile=development to acknowledge."
        )
        super().__init__(msg)


class ProductionProfile:
    def __init__(self, settings: _Settings) -> None:
        self._s = settings

    def check(self) -> list[ProfileCheck]:
        failures: list[ProfileCheck] = []
        s = self._s

        if not getattr(getattr(s, "security", None), "secret_key", ""):
            failures.append(
                ProfileCheck(
                    "auth",
                    "No secret key set — auth is effectively disabled. Set PICOSHOGUN_SECRET_KEY (>= 32 chars).",
                )
            )
        else:
            key = getattr(s.security, "secret_key", "")
            _WEAK = frozenset({"change-me-in-production", "changeme", "default", "secret", "password"})
            if key in _WEAK or len(key) < 32:
                failures.append(
                    ProfileCheck(
                        "auth",
                        f"Secret key is weak or too short ({len(key)} chars, min 32). "
                        "Set a strong PICOSHOGUN_SECRET_KEY.",
                    )
                )

        cors_origins = getattr(getattr(s, "api", None), "cors_origins", [])
        if cors_origins == ["*"]:
            failures.append(
                ProfileCheck(
                    "cors",
                    "CORS allows all origins ('*'). Set PICOSHOGUN_CORS_ORIGINS to explicit origins.",
                )
            )

        db_backend = getattr(getattr(s, "database", None), "backend", "")
        if db_backend == "jsonl":
            failures.append(
                ProfileCheck(
                    "store",
                    f"Store backend is '{db_backend}' — not production-grade. "
                    "Set PICOSHOGUN_DATABASE_BACKEND=sqlite or postgresql.",
                )
            )

        if not getattr(getattr(s, "security", None), "ssl_cert_path", None):
            failures.append(
                ProfileCheck(
                    "tls",
                    "No TLS certificate configured. "
                    "Set PICOSHOGUN_SSL_CERT_PATH or configure upstream TLS termination.",
                )
            )

        rate_backend = getattr(getattr(s, "security", None), "rate_limit_backend", "")
        if rate_backend == "memory":
            failures.append(
                ProfileCheck(
                    "rate_limiting",
                    f"Rate limiting backend is '{rate_backend}' — not persistent across restarts. "
                    "Set PICOSHOGUN_RATE_LIMIT_BACKEND=redis for production.",
                )
            )

        policy_signing_key = os.environ.get("PICODOME_POLICY_SIGNING_KEY", "").strip()
        if not policy_signing_key:
            failures.append(
                ProfileCheck(
                    "policy_signing",
                    "Policy signing verification is disabled (no signing key). "
                    "Set PICODOME_POLICY_SIGNING_KEY to enable policy signature verification.",
                )
            )

        admin_api_key = os.environ.get("PICOSHOGUN_ADMIN_API_KEY", "").strip()
        if not admin_api_key:
            failures.append(
                ProfileCheck(
                    "admin_auth",
                    "No admin API key set — admin endpoints are unprotected. Set PICOSHOGUN_ADMIN_API_KEY.",
                )
            )

        return failures

    def enforce(self) -> None:
        failures = self.check()
        if failures:
            raise ProductionProfileError(failures)


def enforce_production_profile(settings: _Settings) -> None:
    ProductionProfile(settings).enforce()


def warn_development_profile(settings: _Settings) -> None:
    checks = ProductionProfile(settings).check()
    if not checks:
        return

    banner_lines = [
        "=" * 60,
        "  DEVELOPMENT PROFILE — the following security features are disabled:",
    ]
    for c in checks:
        banner_lines.append(f"    - {c.name}: {c.message}")
    banner_lines.append("=" * 60)

    for line in banner_lines:
        logger.warning(line)
