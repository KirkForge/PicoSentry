
from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any

logger = logging.getLogger("picodome.api_versioning")


CURRENT_API_VERSION = "v1"


SUPPORTED_VERSIONS = ["v1"]


DEPRECATED_VERSIONS: dict[str, str] = {}  # currently none


@dataclass(frozen=True)
class APIVersion:

    major: int
    minor: int = 0
    prefix: str = "v"

    @classmethod
    def parse(cls, version_str: str) -> APIVersion:
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

    version: str
    sunset_date: str  # when the version will be removed
    replacement: str  # the newer version or endpoint to use
    message: str = ""

    def to_header(self) -> tuple[str, str]:
        return ("Deprecation", f"version={self.version}; sunset={self.sunset_date}; replacement={self.replacement}")

    def to_dict(self) -> dict[str, Any]:
        return {
            "message": self.message,
            "replacement": self.replacement,
            "sunset_date": self.sunset_date,
            "version": self.version,
        }


class APIVersionNegotiator:

    def negotiate(
        self,
        path: str = "",
        accept_header: str = "",
        version_header: str = "",
    ) -> tuple[str, DeprecationNotice | None]:

        version = self._extract_from_path(path)
        if version:
            return self._resolve(version)


        version = self._extract_from_accept(accept_header)
        if version:
            return self._resolve(version)


        if version_header:
            return self._resolve(version_header.strip().lower())


        return self._resolve(CURRENT_API_VERSION)

    def _extract_from_path(self, path: str) -> str | None:
        parts = path.strip("/").split("/")
        if len(parts) >= 2 and parts[0] == "api":
            candidate = parts[1]
            if candidate in SUPPORTED_VERSIONS or candidate in DEPRECATED_VERSIONS:
                return candidate
        return None

    def _extract_from_accept(self, accept: str) -> str | None:
        if "vnd.picodome" in accept:
            for part in accept.split(","):
                part = part.strip()
                if "vnd.picodome." in part:
                    start = part.index("vnd.picodome.") + len("vnd.picodome.")
                    end = part.index("+", start) if "+" in part[start:] else len(part)
                    return part[start:end].lower()
        return None

    def _resolve(self, version: str) -> tuple[str, DeprecationNotice | None]:
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
        return {
            "current": CURRENT_API_VERSION,
            "supported": SUPPORTED_VERSIONS,
            "deprecated": dict(DEPRECATED_VERSIONS.items()),
        }
