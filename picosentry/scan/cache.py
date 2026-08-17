from __future__ import annotations

import contextlib
import hashlib
import hmac
import itertools
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, cast

from picosentry._core.security import constant_time_compare

logger = logging.getLogger("picosentry.cache")

DEFAULT_CACHE_DIR = Path.home() / ".cache" / "picosentry"
DEFAULT_TTL_SECONDS = 3600  # 1 hour
DEFAULT_MAX_ENTRIES = 0  # 0 = unlimited
DEFAULT_MAX_SIZE_MB = 0  # 0 = unlimited


def _cache_env(var: str, default: str = "") -> str:
    return os.environ.get(f"PICOSENTRY_{var}", default)


def cache_from_env() -> ScanCache:
    cache_dir = _cache_env("CACHE_DIR")
    ttl = _cache_env("CACHE_TTL_SECONDS")
    max_entries = _cache_env("CACHE_MAX_ENTRIES")
    max_size_mb = _cache_env("CACHE_MAX_SIZE_MB")
    kwargs: dict = {}
    if cache_dir:
        kwargs["cache_dir"] = Path(cache_dir)
    if ttl:
        try:
            kwargs["ttl"] = int(ttl)
        except ValueError:
            logger.warning("PICOSENTRY_CACHE_TTL_SECONDS invalid: %s", ttl)
    if max_entries:
        try:
            kwargs["max_entries"] = int(max_entries)
        except ValueError:
            logger.warning("PICOSENTRY_CACHE_MAX_ENTRIES invalid: %s", max_entries)
    if max_size_mb:
        try:
            kwargs["max_size_mb"] = float(max_size_mb)
        except ValueError:
            logger.warning("PICOSENTRY_CACHE_MAX_SIZE_MB invalid: %s", max_size_mb)
    return ScanCache(**kwargs)


def cache_from_config(config: Any = None) -> ScanCache:
    kwargs: dict = {}

    if config is not None:
        if getattr(config, "cache_dir", None):
            kwargs["cache_dir"] = Path(config.cache_dir)
        if getattr(config, "cache_ttl_seconds", 3600) != 3600:
            kwargs["ttl"] = config.cache_ttl_seconds
        if getattr(config, "cache_max_entries", 0) != 0:
            kwargs["max_entries"] = config.cache_max_entries
        if getattr(config, "cache_max_size_mb", 0) != 0:
            kwargs["max_size_mb"] = config.cache_max_size_mb

    env_dir = _cache_env("CACHE_DIR")
    if env_dir:
        kwargs["cache_dir"] = Path(env_dir)
    env_ttl = _cache_env("CACHE_TTL_SECONDS")
    if env_ttl:
        with contextlib.suppress(ValueError):
            kwargs["ttl"] = int(env_ttl)
    env_entries = _cache_env("CACHE_MAX_ENTRIES")
    if env_entries:
        with contextlib.suppress(ValueError):
            kwargs["max_entries"] = int(env_entries)
    env_size = _cache_env("CACHE_MAX_SIZE_MB")
    if env_size:
        with contextlib.suppress(ValueError):
            kwargs["max_size_mb"] = float(env_size)
    return ScanCache(**kwargs)


class ScanCache:
    def __init__(
        self,
        cache_dir: Path | None = None,
        ttl: int = DEFAULT_TTL_SECONDS,
        max_entries: int = DEFAULT_MAX_ENTRIES,
        max_size_mb: float = DEFAULT_MAX_SIZE_MB,
    ) -> None:
        self.cache_dir = cache_dir or DEFAULT_CACHE_DIR
        self.ttl = ttl
        self.max_entries = max_entries
        self.max_size_mb = max_size_mb
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    @staticmethod
    def from_env() -> ScanCache:
        return cache_from_env()

    @staticmethod
    def from_config(config: Any = None) -> ScanCache:
        return cache_from_config(config)

    def _cache_key(self, lockfile_hash: str, corpus_hash: str, rule_version: str, config_digest: str = "") -> str:
        # config_digest covers everything that shapes the cached post-filter
        # payload: rule selection, policy deny-lists, severity overrides,
        # ignore lists, severity threshold. Without it, `scan --rules X`
        # after a full scan would return the full cached result.
        raw = f"{lockfile_hash}:{corpus_hash}:{rule_version}:{config_digest}"
        return hashlib.sha256(raw.encode()).hexdigest()[:32]

    def _cache_path(self, key: str) -> Path:
        return self.cache_dir / f"{key}.json"

    def _hmac(self, data: str) -> str:
        return hmac.new(_CACHE_HMAC_KEY, data.encode(), hashlib.sha256).hexdigest()[:16]

    def _enforce_caps(self) -> int:
        if self.max_entries <= 0 and self.max_size_mb <= 0:
            return 0

        entries = []
        for path in self.cache_dir.glob("*.json"):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                entries.append((data.get("cached_at", 0), path))
            except (json.JSONDecodeError, OSError):
                path.unlink(missing_ok=True)

        evicted = 0
        total_size = 0
        entry_paths = []
        for _cached_at, path in sorted(entries, key=lambda x: x[0]):
            try:
                total_size += path.stat().st_size
                entry_paths.append(path)
            except OSError:
                continue

        for path in entry_paths:
            current_count = len(entry_paths) - evicted
            under_entry_cap = self.max_entries <= 0 or current_count <= self.max_entries
            under_size_cap = self.max_size_mb <= 0 or total_size / (1024 * 1024) <= self.max_size_mb

            if under_entry_cap and under_size_cap:
                break

            try:
                size = path.stat().st_size
                path.unlink(missing_ok=True)
                total_size -= size
                evicted += 1
            except OSError:
                pass

        if evicted:
            logger.info("Evicted %d cache entries to enforce caps", evicted)

            try:
                from picosentry.scan.audit import audit

                audit(
                    "cache.purge",
                    target=f"cap-eviction:{evicted}",
                    outcome="success",
                    metadata={"max_entries": self.max_entries, "max_size_mb": self.max_size_mb},
                )
            except ImportError:
                pass

        return evicted

    def get(self, lockfile_hash: str, corpus_hash: str, rule_version: str, config_digest: str = "") -> dict | None:
        key = self._cache_key(lockfile_hash, corpus_hash, rule_version, config_digest)
        path = self._cache_path(key)

        if not path.is_file():
            logger.debug("Cache miss: %s", key[:8])
            try:
                from picosentry.scan.metrics import increment

                increment("cache.misses")
            except ImportError:
                pass
            return None

        try:
            entry = json.loads(path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            path.unlink(missing_ok=True)
            return None

        stored_hmac = entry.pop("_hmac", None)
        # A missing _hmac is treated like a mismatching one: the entry was not
        # written by a trusted cache path (or was tampered with) — cache miss.
        recomputed = self._hmac(json.dumps(entry, sort_keys=True))
        if not stored_hmac or not constant_time_compare(stored_hmac, recomputed):
            logger.warning("Cache integrity check failed for %s — evicting", key[:8])
            path.unlink(missing_ok=True)
            return None

        cached_at = entry.get("cached_at", 0)
        if time.time() - cached_at > self.ttl:
            logger.debug("Cache expired: %s", key[:8])
            path.unlink(missing_ok=True)
            return None

        logger.info("Cache hit: %s (age=%ds)", key[:8], int(time.time() - cached_at))
        try:
            from picosentry.scan.metrics import increment

            increment("cache.hits")
        except ImportError:
            pass

        return cast("dict[str, Any] | None", entry.get("result"))

    def put(
        self, lockfile_hash: str, corpus_hash: str, rule_version: str, result: dict, config_digest: str = ""
    ) -> None:
        key = self._cache_key(lockfile_hash, corpus_hash, rule_version, config_digest)
        path = self._cache_path(key)

        entry = {
            "key": key,
            "cached_at": time.time(),
            "lockfile_hash": lockfile_hash,
            "corpus_hash": corpus_hash,
            "rule_version": rule_version,
            "config_digest": config_digest,
            "result": result,
        }
        entry["_hmac"] = self._hmac(json.dumps(entry, sort_keys=True))

        tmp_path = path.with_suffix(f".tmp.{os.getpid()}.{next(_TMP_SEQ)}")
        tmp_path.write_text(json.dumps(entry, sort_keys=True), encoding="utf-8")
        tmp_path.replace(path)

        logger.debug("Cached scan result: %s", key[:8])

        self._enforce_caps()

    def invalidate(
        self, lockfile_hash: str = "", corpus_hash: str = "", rule_version: str = "", config_digest: str = ""
    ) -> int:
        count = 0
        for path in self.cache_dir.glob("*.json"):
            try:
                entry = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                path.unlink(missing_ok=True)
                count += 1
                continue

            match = True
            if lockfile_hash and entry.get("lockfile_hash") != lockfile_hash:
                match = False
            if corpus_hash and entry.get("corpus_hash") != corpus_hash:
                match = False
            if rule_version and entry.get("rule_version") != rule_version:
                match = False
            if config_digest and entry.get("config_digest") != config_digest:
                match = False

            if match or (not lockfile_hash and not corpus_hash and not rule_version and not config_digest):
                path.unlink(missing_ok=True)
                count += 1

        logger.info("Invalidated %d cache entries", count)
        return count

    def purge(self, age_days: int = 0, corpus_hash: str = "", lockfile_hash: str = "") -> int:
        count = 0
        cutoff_time = time.time() - (age_days * 86400) if age_days > 0 else 0

        for path in self.cache_dir.glob("*.json"):
            try:
                entry = json.loads(path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                path.unlink(missing_ok=True)
                count += 1
                continue

            if age_days > 0:
                cached_at = entry.get("cached_at", 0)
                if cached_at > cutoff_time:
                    continue  # Too young, skip

            if corpus_hash and entry.get("corpus_hash") != corpus_hash:
                continue
            if lockfile_hash and entry.get("lockfile_hash") != lockfile_hash:
                continue

            path.unlink(missing_ok=True)
            count += 1

        logger.info(
            "Purged %d cache entries (age_days=%s, corpus=%s, lockfile=%s)",
            count,
            age_days,
            corpus_hash[:8] if corpus_hash else "*",
            lockfile_hash[:8] if lockfile_hash else "*",
        )

        try:
            from picosentry.scan.audit import audit

            audit(
                "cache.purge",
                target=f"age={age_days} entries={count}",
                outcome="success",
                metadata={
                    "age_days": age_days,
                    "corpus_hash": corpus_hash[:8] if corpus_hash else "",
                    "lockfile_hash": lockfile_hash[:8] if lockfile_hash else "",
                },
            )
        except ImportError:
            pass

        return count

    def wipe(self) -> int:
        count = self.invalidate()
        logger.warning("Cache wiped: %d entries removed", count)

        try:
            from picosentry.scan.audit import audit

            audit("cache.wipe", target=str(self.cache_dir), outcome="success", metadata={"entries_removed": count})
        except ImportError:
            pass

        return count

    def stats(self) -> dict:
        entries = 0
        size_bytes = 0
        for path in self.cache_dir.glob("*.json"):
            try:
                entries += 1
                size_bytes += path.stat().st_size
            except OSError:
                entries -= 1  # File disappeared between glob and stat

        try:
            from picosentry.scan.metrics import set_gauge

            set_gauge("cache.size_bytes", float(size_bytes))
            set_gauge("cache.entries", float(entries))
        except ImportError:
            pass

        return {
            "entries": entries,
            "size_bytes": size_bytes,
            "size_mb": round(size_bytes / 1024 / 1024, 2),
            "cache_dir": str(self.cache_dir),
            "ttl_seconds": self.ttl,
            "max_entries": self.max_entries,
            "max_size_mb": self.max_size_mb,
        }


_TMP_SEQ = itertools.count()

_HMAC_KEYFILE = ".cache_hmac_key"


def _load_or_create_hmac_key() -> bytes:
    """Resolve the cache-HMAC key with explicit precedence and no silent invalidation.

    1. ``PICOSENTRY_CACHE_HMAC_KEY`` (>=32 chars) — explicit operator choice, wins.
    2. Persistent per-machine keyfile under the default cache dir (created on
       first use, mode 0600) — the default, so entries validate across processes.
    3. Per-process random key — last resort when the keyfile is unusable; warned
       about loudly because entries written under it will not validate later.
    """
    env_key = os.environ.get("PICOSENTRY_CACHE_HMAC_KEY", "")
    if env_key:
        if len(env_key) < 32:
            logger.warning("PICOSENTRY_CACHE_HMAC_KEY is set but shorter than 32 chars — ignoring it")
        else:
            return env_key.encode("utf-8")

    keyfile = DEFAULT_CACHE_DIR / _HMAC_KEYFILE
    try:
        DEFAULT_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        try:
            fd = os.open(keyfile, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        except FileExistsError:
            # ponytail: racy first-use creation — brief read-retry instead of a lock
            for _ in range(3):
                data = keyfile.read_bytes()
                if len(data) >= 32:
                    return data
            raise OSError(f"{keyfile} exists but has no usable key") from None
        with os.fdopen(fd, "wb") as fh:
            key = os.urandom(32)
            fh.write(key)
        return key
    except OSError as exc:
        logger.warning(
            "PICOSENTRY_CACHE_HMAC_KEY not set and keyfile %s unusable (%s) — "
            "falling back to a per-process key; cache entries will NOT persist across processes",
            keyfile,
            exc,
        )
        return os.urandom(32)


_CACHE_HMAC_KEY = _load_or_create_hmac_key()
if not os.environ.get("PICOSENTRY_CACHE_HMAC_KEY", ""):
    _keyfile = DEFAULT_CACHE_DIR / _HMAC_KEYFILE
    if os.environ.get("PICOSENTRY_QUIET") == "1":
        logger.debug(
            "PICOSENTRY_CACHE_HMAC_KEY not set — using the persistent per-machine keyfile at %s",
            _keyfile,
        )
    else:
        logger.info(
            "PICOSENTRY_CACHE_HMAC_KEY not set — using the persistent per-machine keyfile at %s",
            _keyfile,
        )
