from __future__ import annotations

import logging
import os
from enum import Enum
from pathlib import Path

logger = logging.getLogger("picodome.license")

__all__ = ["LicenseInfo", "LicenseTier", "check_license", "get_license_info"]


class LicenseTier(str, Enum):
    PERSONAL = "personal"
    COMMERCIAL = "commercial"
    ENTERPRISE = "enterprise"


class LicenseInfo:
    def __init__(
        self,
        tier: LicenseTier = LicenseTier.PERSONAL,
        holder: str = "",
        organization: str = "",
        expires: str | None = None,
        key: str = "",
        source: str = "default",
    ):
        self.tier = tier
        self.holder = holder
        self.organization = organization
        self.expires = expires
        self.key = key
        self.source = source

    @property
    def is_commercial(self) -> bool:
        return self.tier in (LicenseTier.COMMERCIAL, LicenseTier.ENTERPRISE)

    @property
    def is_personal(self) -> bool:
        return self.tier == LicenseTier.PERSONAL

    def to_dict(self) -> dict:
        return {
            "tier": self.tier.value,
            "holder": self.holder,
            "organization": self.organization,
            "expires": self.expires,
            "source": self.source,
        }

    def __repr__(self) -> str:
        return f"LicenseInfo(tier={self.tier.value}, holder={self.holder!r})"


_cached_license: LicenseInfo | None = None


def _reset_cache() -> None:
    global _cached_license
    _cached_license = None


def check_license() -> LicenseInfo:
    global _cached_license
    if _cached_license is not None:
        return _cached_license

    env_key = os.environ.get("PICODOME_LICENSE_KEY", "").strip()
    if env_key:
        info = _validate_key(env_key)
        if info:
            _cached_license = info
            return info

    local_path = Path.cwd() / ".picodome-license"
    if local_path.is_file():
        info = _load_license_file(local_path)
        if info:
            _cached_license = info
            return info

    user_path = Path("~/.picodome/license.json").expanduser()
    if user_path.is_file():
        info = _load_license_file(user_path)
        if info:
            _cached_license = info
            return info

    _cached_license = LicenseInfo(
        tier=LicenseTier.PERSONAL,
        holder=os.environ.get("USER", "unknown"),
        source="default",
    )
    logger.info("No commercial license found — running in personal use mode")
    return _cached_license


def get_license_info() -> LicenseInfo:
    return check_license()


def _validate_key(key: str) -> LicenseInfo | None:
    if not key.startswith("picoshogun-"):
        logger.warning("Invalid license key format: must start with 'picoshogun-'")
        return None

    parts = key.split("-")
    if len(parts) < 4:
        logger.warning("Invalid license key format: expected picoshogun-<tier>-<org>-<hash>")
        return None

    tier_str = parts[1]
    org = parts[2]
    key_hash = parts[3]

    try:
        tier = LicenseTier(tier_str)
    except ValueError:
        logger.warning("Invalid license key tier: %s (expected: personal, commercial, enterprise)", tier_str)
        return None

    if len(key_hash) < 16:
        logger.warning("License key hash too short (%d chars, minimum 16)", len(key_hash))
        return None

    return LicenseInfo(
        tier=tier,
        holder="",
        organization=org,
        key=key[:8] + "..." if len(key) > 8 else key,
        source="key",
    )


def _load_license_file(path: str | Path) -> LicenseInfo | None:
    import json

    try:
        with Path(path).open() as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError) as e:
        logger.warning("Failed to load license file %s: %s", path, e)
        return None

    key = data.get("key", "")
    if key:
        info = _validate_key(key)
        if info:
            info.holder = data.get("holder", "")
            info.organization = data.get("organization", info.organization)
            info.expires = data.get("expires")
            info.source = f"file:{path}"
            return info

    tier_str = data.get("tier", "personal")
    try:
        tier = LicenseTier(tier_str)
    except ValueError:
        logger.warning("Invalid license tier in %s: %s", path, tier_str)
        return None

    return LicenseInfo(
        tier=tier,
        holder=data.get("holder", ""),
        organization=data.get("organization", ""),
        expires=data.get("expires"),
        source=f"file:{path}",
    )


def require_commercial(feature: str = "") -> bool:
    info = check_license()
    if info.is_commercial:
        return True

    feature_msg = f" '{feature}'" if feature else ""
    logger.warning(
        "Shogun command center license required for%s. "
        "Running in personal use mode — no command center access. "
        "See https://github.com/KirkForge/PicoShogun for commercial licensing.",
        feature_msg,
    )
    return False
