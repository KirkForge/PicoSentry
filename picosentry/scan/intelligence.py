from __future__ import annotations

import hashlib
import itertools
import json
import logging
import os
import time
from enum import Enum
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request

from ._network import ResponseTooLargeError, safe_urlopen
from .advisory import Advisory

logger = logging.getLogger("picosentry.intelligence")


class IntelligenceMode(Enum):
    OFFLINE = "offline"
    CONNECTED = "connected"


_OSV_API_URL = "https://api.osv.dev/v1/query"

# Disk-cache caps, same style as scan/cache.py. 0 entries = unlimited.
DEFAULT_OSV_MAX_ENTRIES = 512
DEFAULT_OSV_MAX_AGE_SECONDS = 30 * 24 * 3600  # 30 days
# Clean packages get a short-lived negative entry so bulk scans don't re-query
# them (10s timeout each), while newly-published advisories surface quickly.
DEFAULT_OSV_NEGATIVE_TTL_SECONDS = 300

_TMP_SEQ = itertools.count()


class OSVClient:
    def __init__(
        self,
        cache_dir: Path | None = None,
        cache_ttl_hours: int | None = None,
        timeout: int = 10,
    ) -> None:
        env_dir = os.environ.get("PICOSENTRY_INTELLIGENCE_DIR")
        if env_dir:
            self._cache_dir = Path(env_dir)
        else:
            self._cache_dir = cache_dir or Path.home() / ".local" / "share" / "picosentry" / "intelligence"
        ttl_hours: int | float
        if cache_ttl_hours is None:
            minutes = int(os.environ.get("PICOSENTRY_OSV_CACHE_MINUTES", "60"))
            ttl_hours = minutes / 60
        else:
            ttl_hours = cache_ttl_hours
        self._cache_ttl = int(ttl_hours * 3600)
        self._timeout = timeout
        self._offline = os.environ.get("PICOSENTRY_OFFLINE", "").strip() in ("1", "true", "yes")
        self._max_entries = int(os.environ.get("PICOSENTRY_OSV_MAX_ENTRIES", str(DEFAULT_OSV_MAX_ENTRIES)))
        self._max_age_seconds = int(os.environ.get("PICOSENTRY_OSV_MAX_AGE_SECONDS", str(DEFAULT_OSV_MAX_AGE_SECONDS)))
        self._negative_ttl = int(
            os.environ.get("PICOSENTRY_OSV_NEGATIVE_TTL_SECONDS", str(DEFAULT_OSV_NEGATIVE_TTL_SECONDS))
        )
        self._swept = False  # one age/count sweep per client on first load

    def _cache_key(self, ecosystem: str, package_name: str, version: str | None = None) -> str:
        # The OSV query is version-filtered, so the version must be part of the
        # key — otherwise an upgraded dep keeps receiving the old version's
        # advisories until the TTL expires.
        return hashlib.sha256(f"{ecosystem}:{package_name}:{version or ''}".encode()).hexdigest()

    def _cache_path(self, key: str) -> Path:
        return self._cache_dir / f"{key}.json"

    def _enforce_caps(self) -> int:
        """Evict cache files past the entry cap (oldest by mtime first) or the age cap."""
        entries: list[tuple[float, Path]] = []
        for path in self._cache_dir.glob("*.json"):
            try:
                entries.append((path.stat().st_mtime, path))
            except OSError:
                continue

        now = time.time()
        evicted = 0
        entries.sort(key=lambda e: e[0], reverse=True)  # newest first
        for idx, (mtime, path) in enumerate(entries):
            too_many = self._max_entries > 0 and idx >= self._max_entries
            too_old = self._max_age_seconds > 0 and now - mtime > self._max_age_seconds
            if not (too_many or too_old):
                continue
            try:
                path.unlink(missing_ok=True)
                evicted += 1
            except OSError:
                pass
        if evicted:
            logger.info("Evicted %d OSV cache entries to enforce caps", evicted)
        return evicted

    def _read_cache(self, key: str) -> list[dict] | None:
        if not self._swept:  # ponytail: one sweep per client, not per package — bulk_query stays O(n)
            self._swept = True
            self._enforce_caps()
        path = self._cache_path(key)
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            path.unlink(missing_ok=True)
            return None
        cached_at = data.get("cached_at", 0)
        ttl = self._cache_ttl
        if data.get("negative"):
            ttl = min(ttl, self._negative_ttl)
        if time.time() - cached_at > ttl:
            path.unlink(missing_ok=True)
            return None
        return data.get("advisories")

    def _write_cache(self, key: str, advisories: list[dict], negative: bool = False) -> None:
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        path = self._cache_path(key)
        entry: dict = {"cached_at": time.time(), "advisories": advisories}
        if negative:
            entry["negative"] = True
        tmp = path.with_suffix(f".tmp.{os.getpid()}.{next(_TMP_SEQ)}")
        tmp.write_text(json.dumps(entry, sort_keys=True), encoding="utf-8")
        tmp.replace(path)
        self._enforce_caps()

    def _fetch(self, payload: dict) -> list[Advisory] | None:
        """Query OSV. Returns None on transport/API failure (never cacheable as empty)."""
        if self._offline:
            return []
        body = json.dumps(payload).encode("utf-8")
        req = Request(_OSV_API_URL, data=body, headers={"Content-Type": "application/json"}, method="POST")
        try:
            resp, body = safe_urlopen(req, timeout=self._timeout)
            resp.close()
            data = json.loads(body.decode("utf-8"))
        except (URLError, OSError, TimeoutError, json.JSONDecodeError, ResponseTooLargeError) as exc:
            logger.warning("OSV API request failed: %s", exc)
            return None
        results = []
        for vuln in data.get("vulns", []):
            results.extend(Advisory.from_osv(vuln))
        return results

    def query(self, ecosystem: str, package_name: str, version: str | None = None) -> list[Advisory]:
        key = self._cache_key(ecosystem, package_name, version)
        cached = self._read_cache(key)
        if cached is not None:
            results = []
            for entry in cached:
                results.extend(Advisory.from_osv(entry))
            return results

        payload: dict = {"package": {"name": package_name, "ecosystem": ecosystem}}
        if version:
            payload["version"] = version

        advisories = self._fetch(payload)
        if advisories is None:
            # Transport failure must not be negative-cached: an unreachable API
            # is not evidence the package is clean.
            return []

        raw = [adv.to_dict() for adv in advisories]
        self._write_cache(key, raw, negative=not raw)

        return advisories

    def query_by_commit(self, commit: str) -> list[Advisory]:
        payload = {"commit": commit}
        return self._fetch(payload) or []

    def bulk_query(self, packages: list[tuple[str, str]]) -> dict[tuple[str, str], list[Advisory]]:
        results: dict[tuple[str, str], list[Advisory]] = {}
        for ecosystem, package_name in packages:
            results[(ecosystem, package_name)] = self.query(ecosystem, package_name)
        return results

    def refresh_cache(self, ecosystem: str) -> int:
        payload = {"package": {"ecosystem": ecosystem}}
        advisories = self._fetch(payload)
        if advisories is None:
            return 0
        count = 0
        by_package: dict[str, list[Advisory]] = {}
        for adv in advisories:
            by_package.setdefault(adv.package_name, []).append(adv)
            count += 1
        for pkg_name, pkg_advisories in by_package.items():
            key = self._cache_key(ecosystem, pkg_name)
            self._write_cache(key, [a.to_dict() for a in pkg_advisories])
        return count
