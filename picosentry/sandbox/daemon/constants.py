"""PicoDome daemon constants.

Extracted in v2.1.0 (refactor) from ``picosentry/sandbox/daemon/server.py``.

- API version path segment
- CORS allow/deny policy
- Enterprise mode flag (drives fail-closed behavior)
"""
from __future__ import annotations

import os

# ─── API version ────────────────────────────────────────────────────────────

API_VERSION = "v1"

# ─── CORS Configuration ──────────────────────────────────────────────────────

CORS_ALLOW_ORIGINS = os.environ.get("PICODOME_CORS_ORIGINS", "").replace("\r", "").replace("\n", "")
CORS_ALLOW_METHODS = "GET, POST, OPTIONS"
CORS_ALLOW_HEADERS = "Content-Type, Authorization, X-Tenant, X-Request-ID"
CORS_MAX_AGE = "86400"  # 24 hours
_CORS_ALLOW_ORIGINS_LIST = [o.strip() for o in CORS_ALLOW_ORIGINS.split(",") if o.strip()]
_CORS_DENY_BY_DEFAULT = not _CORS_ALLOW_ORIGINS_LIST and CORS_ALLOW_ORIGINS != "*"
_ENTERPRISE_MODE = os.environ.get("PICODOME_ENTERPRISE_MODE", "").lower() in ("1", "true", "yes")

# F2: In enterprise mode, reject wildcard CORS origin
if _ENTERPRISE_MODE and CORS_ALLOW_ORIGINS == "*":
    import logging

    logger = logging.getLogger("picodome.daemon")
    logger.warning(
        "ENTERPRISE MODE: CORS origin is wildcard ('*'). "
        "Set PICODOME_CORS_ORIGINS to specific trusted origins for production."
    )


__all__ = [
    "API_VERSION",
    "CORS_ALLOW_HEADERS",
    "CORS_ALLOW_METHODS",
    "CORS_ALLOW_ORIGINS",
    "CORS_MAX_AGE",
    "_CORS_ALLOW_ORIGINS_LIST",
    "_CORS_DENY_BY_DEFAULT",
    "_ENTERPRISE_MODE",
]
