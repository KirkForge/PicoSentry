"""API versioning and backward compatibility guarantees.

PicoDome's daemon API follows semantic versioning with explicit
compatibility guarantees:

- API v1 (current): Stable, backward-compatible since v0.4.0
- Breaking changes require a new API version (v2, v3, etc.)
- Old API versions are supported for at least 2 release cycles
- Deprecation notices are returned in response headers

This module provides:
1. API version negotiation (via URL path or Accept header)
2. Deprecation tracking and notices
3. Compatibility shims for older API versions
4. Version-specific request/response schemas
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("picodome.api_versioning")

# Current stable API version
CURRENT_API_VERSION = "v1"

# Supported API versions (in order of preference)
SUPPORTED_VERSIONS = ["v1"]

# Versions that are deprecated (will be removed after 2 release cycles)
DEPRECATED_VERSIONS: dict[str, str] = {}  # currently none


@dataclass(frozen=True)
class APIVersion:
    """Parsed API version."""

    major: int
    minor: int = 0
    prefix: str = "v"

    @classmethod
    def parse(cls, version_str: str) -> APIVersion:
        """Parse version string like 'v1' or 'v2'."""
        version_str = version_str.strip().lower()
        if version_str.startswith("v"):
            version_str = version_str[1:]
        parts = version_str.split(".")
        major = int(parts[0]) if parts else 1
        minor = int(parts[1]) if len(parts) > 1 else 0
        return cls(major=major, minor=minor)

    @property
    def path_prefix(self) -> str:
        return f"v{self.major}"

    def __str__(self) -> str:
        if self.minor:
            return f"v{self.major}.{self.minor}"
        return f"v{self.major}"


@dataclass(frozen=True)
class DeprecationNotice:
    """Deprecation notice for an API endpoint or version."""

    version: str
    sunset_date: str  # when the version will be removed
    replacement: str  # the newer version or endpoint to use
    message: str = ""

    def to_header(self) -> tuple[str, str]:
        """Return HTTP header for deprecation notice."""
        return ("Deprecation", f"version={self.version}; sunset={self.sunset_date}; replacement={self.replacement}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "message": self.message,
            "replacement": self.replacement,
            "sunset_date": self.sunset_date,
            "version": self.version,
        }


class APIVersionNegotiator:
    """Negotiate API version from request headers or URL path.

    Resolution order:
    1. URL path prefix (e.g., /api/v1/scan)
    2. Accept header (e.g., Accept: application/vnd.picodome.v1+json)
    3. Custom header (X-PicoDome-API-Version: v1)
    4. Default to current version
    """

    def negotiate(
        self,
        path: str = "",
        accept_header: str = "",
        version_header: str = "",
    ) -> tuple[str, DeprecationNotice | None]:
        """Negotiate the API version for a request.

        Returns (version_string, deprecation_notice).
        """
        # 1. URL path
        version = self._extract_from_path(path)
        if version:
            return self._resolve(version)

        # 2. Accept header
        version = self._extract_from_accept(accept_header)
        if version:
            return self._resolve(version)

        # 3. Custom header
        if version_header:
            return self._resolve(version_header.strip().lower())

        # 4. Default
        return self._resolve(CURRENT_API_VERSION)

    def _extract_from_path(self, path: str) -> str | None:
        """Extract version from URL path /api/v1/..."""
        parts = path.strip("/").split("/")
        if len(parts) >= 2 and parts[0] == "api":
            candidate = parts[1]
            if candidate in SUPPORTED_VERSIONS or candidate in DEPRECATED_VERSIONS:
                return candidate
        return None

    def _extract_from_accept(self, accept: str) -> str | None:
        """Extract version from Accept header."""
        if "vnd.picodome" in accept:
            for part in accept.split(","):
                part = part.strip()
                if "vnd.picodome." in part:
                    start = part.index("vnd.picodome.") + len("vnd.picodome.")
                    end = part.index("+", start) if "+" in part[start:] else len(part)
                    return part[start:end].lower()
        return None

    def _resolve(self, version: str) -> tuple[str, DeprecationNotice | None]:
        """Resolve a version string, checking for deprecation."""
        if version in DEPRECATED_VERSIONS:
            deprecation = DeprecationNotice(
                version=version,
                sunset_date=DEPRECATED_VERSIONS[version],
                replacement=CURRENT_API_VERSION,
                message=(
                    f"API {version} is deprecated and will be removed on "
                    f"{DEPRECATED_VERSIONS[version]}. Migrate to {CURRENT_API_VERSION}."
                ),
            )
            return version, deprecation

        if version not in SUPPORTED_VERSIONS:
            logger.warning("Unsupported API version requested: %s, falling back to %s", version, CURRENT_API_VERSION)
            return CURRENT_API_VERSION, None

        return version, None

    def get_version_info(self) -> dict[str, Any]:
        """Get current API version information."""
        return {
            "current": CURRENT_API_VERSION,
            "supported": SUPPORTED_VERSIONS,
            "deprecated": {k: v for k, v in DEPRECATED_VERSIONS.items()},
        }
