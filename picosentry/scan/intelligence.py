from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from enum import Enum
from pathlib import Path
from urllib.error import URLError
from urllib.request import Request, urlopen

from .advisory import Advisory

logger = logging.getLogger("picosentry.intelligence")


class IntelligenceMode(Enum):
    OFFLINE = "offline"
    CONNECTED = "connected"


_OSV_API_URL = "https://api.osv.dev/v1/query"


class OSVClient:
    def __init__(
        self,
        cache_dir: Path | None = None,
        cache_ttl_hours: int = 24,
        timeout: int = 10,
    ) -> None:
        env_dir = os.environ.get("PICOSENTRY_INTELLIGENCE_DIR")
        if env_dir:
            self._cache_dir = Path(env_dir)
        else:
            self._cache_dir = cache_dir or Path.home() / ".local" / "share" / "picosentry" / "intelligence"
        self._cache_ttl = cache_ttl_hours * 3600
        self._timeout = timeout
        self._offline = os.environ.get("PICOSENTRY_OFFLINE", "").strip() in ("1", "true", "yes")

    def _cache_key(self, ecosystem: str, package_name: str) -> str:
        return hashlib.sha256(f"{ecosystem}:{package_name}".encode()).hexdigest()

    def _cache_path(self, key: str) -> Path:
        return self._cache_dir / f"{key}.json"

    def _read_cache(self, key: str) -> list[dict] | None:
        path = self._cache_path(key)
        if not path.is_file():
            return None
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            path.unlink(missing_ok=True)
            return None
        cached_at = data.get("cached_at", 0)
        if time.time() - cached_at > self._cache_ttl:
            path.unlink(missing_ok=True)
            return None
        return data.get("advisories")

    def _write_cache(self, key: str, advisories: list[dict]) -> None:
        self._cache_dir.mkdir(parents=True, exist_ok=True)
        path = self._cache_path(key)
        entry = {"cached_at": time.time(), "advisories": advisories}
        tmp = path.with_suffix(".tmp")
        tmp.write_text(json.dumps(entry, sort_keys=True), encoding="utf-8")
        tmp.replace(path)

    def _fetch(self, payload: dict) -> list[Advisory]:
        if self._offline:
            return []
        body = json.dumps(payload).encode("utf-8")
        req = Request(_OSV_API_URL, data=body, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urlopen(req, timeout=self._timeout) as resp:
                data = json.loads(resp.read().decode("utf-8"))
        except (URLError, OSError, TimeoutError, json.JSONDecodeError) as exc:
            logger.warning("OSV API request failed: %s", exc)
            return []
        results = []
        for vuln in data.get("vulns", []):
            adv = Advisory.from_osv(vuln)
            if adv is not None:
                results.append(adv)
        return results

    def query(self, ecosystem: str, package_name: str, version: str | None = None) -> list[Advisory]:
        key = self._cache_key(ecosystem, package_name)
        cached = self._read_cache(key)
        if cached is not None:
            results = []
            for entry in cached:
                adv = Advisory.from_osv(entry)
                if adv is not None:
                    results.append(adv)
            return results

        payload: dict = {"package": {"name": package_name, "ecosystem": ecosystem}}
        if version:
            payload["version"] = version

        advisories = self._fetch(payload)

        raw = []
        for adv in advisories:
            raw.append(adv.to_dict())
        if raw:
            self._write_cache(key, raw)

        return advisories

    def query_by_commit(self, commit: str) -> list[Advisory]:
        payload = {"commit": commit}
        return self._fetch(payload)

    def bulk_query(self, packages: list[tuple[str, str]]) -> dict[tuple[str, str], list[Advisory]]:
        results: dict[tuple[str, str], list[Advisory]] = {}
        for ecosystem, package_name in packages:
            results[(ecosystem, package_name)] = self.query(ecosystem, package_name)
        return results

    def refresh_cache(self, ecosystem: str) -> int:
        payload = {"package": {"ecosystem": ecosystem}}
        advisories = self._fetch(payload)
        count = 0
        by_package: dict[str, list[Advisory]] = {}
        for adv in advisories:
            by_package.setdefault(adv.package_name, []).append(adv)
            count += 1
        for pkg_name, pkg_advisories in by_package.items():
            key = self._cache_key(ecosystem, pkg_name)
            self._write_cache(key, [a.to_dict() for a in pkg_advisories])
        return count
