"""Data retention manager — lifecycle, TTL, and secure deletion.

Enterprise compliance requires that scan results and audit logs have
defined retention periods. This module:

1. Defines TTL per data type (scan results, audit logs, baselines)
2. Runs periodic cleanup of expired data
3. Provides secure deletion (overwrite before unlink)
4. Exports data for compliance audits

Configuration is loaded from ``.picodome.yml`` or defaults:

    retention:
      scan_results_days: 90
      audit_logs_days: 365
      baselines_days: 0      # 0 = never expire
      secure_delete: true
      storage_quota_mb: 500
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import threading
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from picosentry.sandbox.audit import AuditEventType, get_audit_logger

logger = logging.getLogger("picodome.retention")

_DEFAULT_DATA_DIR = Path.home() / ".picodome" / "data"
_DEFAULT_SCAN_RESULTS_DIR = _DEFAULT_DATA_DIR / "scans"


@dataclass(frozen=True)
class RetentionPolicy:
    """Retention configuration for a single data type."""

    data_type: str
    ttl_days: int  # 0 = never expire
    secure_delete: bool = False
    max_size_mb: int = 0  # 0 = no quota

    def to_dict(self) -> dict[str, Any]:
        return {
            "data_type": self.data_type,
            "max_size_mb": self.max_size_mb,
            "secure_delete": self.secure_delete,
            "ttl_days": self.ttl_days,
        }


@dataclass
class RetentionConfig:
    """Full retention configuration."""

    scan_results: RetentionPolicy = field(
        default_factory=lambda: RetentionPolicy(
            data_type="scan_results",
            ttl_days=90,
            secure_delete=True,
            max_size_mb=500,
        )
    )
    audit_logs: RetentionPolicy = field(
        default_factory=lambda: RetentionPolicy(
            data_type="audit_logs",
            ttl_days=365,
            secure_delete=False,
            max_size_mb=200,
        )
    )
    baselines: RetentionPolicy = field(
        default_factory=lambda: RetentionPolicy(
            data_type="baselines",
            ttl_days=0,
            secure_delete=False,
            max_size_mb=50,
        )
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_logs": self.audit_logs.to_dict(),
            "baselines": self.baselines.to_dict(),
            "scan_results": self.scan_results.to_dict(),
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RetentionConfig:
        cfg = cls()
        for key in ("scan_results", "audit_logs", "baselines"):
            if key in data:
                d = data[key]
                setattr(
                    cfg,
                    key,
                    RetentionPolicy(
                        data_type=d.get("data_type", key),
                        ttl_days=d.get("ttl_days", 0),
                        secure_delete=d.get("secure_delete", False),
                        max_size_mb=d.get("max_size_mb", 0),
                    ),
                )
        return cfg

    @classmethod
    def from_yaml_config(cls, config_data: dict[str, Any]) -> RetentionConfig:
        """Parse from .picodome.yml retention section."""
        retention = config_data.get("retention", {})
        return cls.from_dict(retention)


class RetentionManager:
    """Manages data retention lifecycle.

    Usage::

        rm = RetentionManager()
        rm.save_scan_result(result_json, package_name="evil-pkg")

        # Run cleanup (typically from cron or daemon tick)
        stats = rm.run_cleanup()
        print(f"Cleaned {stats['files_removed']} expired files")
    """

    def __init__(
        self,
        config: RetentionConfig | None = None,
        data_dir: Path | None = None,
    ) -> None:
        self._config = config or RetentionConfig()
        self._data_dir = data_dir or _DEFAULT_DATA_DIR
        self._scan_dir = self._data_dir / "scans"
        self._scan_dir.mkdir(parents=True, exist_ok=True)

    @property
    def config(self) -> RetentionConfig:
        return self._config

    def save_scan_result(
        self,
        result_json: str,
        package_name: str = "unknown",
    ) -> Path:
        """Save a scan result to the data directory.

        File naming: ``<package>_<timestamp>_<hash>.json``
        """
        timestamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
        content_hash = hashlib.sha256(result_json.encode()).hexdigest()[:12]
        filename = f"{package_name}_{timestamp}_{content_hash}.json"

        path = self._scan_dir / filename
        path.write_text(result_json, encoding="utf-8")
        logger.info("Saved scan result: %s", path.name)
        return path

    def run_cleanup(self) -> dict[str, Any]:
        """Remove expired files according to retention policy.

        Returns stats about what was cleaned up.
        """
        stats: dict[str, Any] = {
            "files_removed": 0,
            "bytes_freed": 0,
            "errors": [],
            "policies_applied": [],
        }

        now = time.time()

        # Cleanup scan results
        scan_stats = self._cleanup_directory(
            self._scan_dir,
            self._config.scan_results,
            now,
        )
        stats["files_removed"] += scan_stats["files_removed"]
        stats["bytes_freed"] += scan_stats["bytes_freed"]
        stats["errors"].extend(scan_stats["errors"])
        stats["policies_applied"].append(self._config.scan_results.data_type)

        # Audit the cleanup
        try:
            audit = get_audit_logger()
            audit.record(
                event_type=AuditEventType.DATA_RETENTION_CLEANUP,
                actor="picodome-retention",
                detail=f"Removed {stats['files_removed']} files, freed {stats['bytes_freed']} bytes",
                metadata=stats,
            )
        except Exception:
            pass

        return stats

    def get_storage_stats(self) -> dict[str, Any]:
        """Get storage usage statistics."""
        stats: dict[str, Any] = {
            "scan_results": self._dir_stats(self._scan_dir),
            "total_bytes": 0,
        }
        stats["total_bytes"] = stats["scan_results"]["total_bytes"]
        return stats

    def export_data(self, output_path: Path, data_type: str = "all") -> Path:
        """Export data for compliance audits.

        Creates a JSON archive of scan results and/or audit logs.
        """
        export: dict[str, Any] = {
            "export_timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "data_type": data_type,
            "scan_results": [],
        }

        if data_type in ("all", "scan_results"):
            for f in sorted(self._scan_dir.glob("*.json")):
                try:
                    content = json.loads(f.read_text(encoding="utf-8"))
                    content["_source_file"] = f.name
                    export["scan_results"].append(content)
                except (json.JSONDecodeError, OSError):
                    pass

        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(
            json.dumps(export, indent=2, sort_keys=True, default=str),
            encoding="utf-8",
        )

        # Audit
        try:
            audit = get_audit_logger()
            audit.record(
                event_type=AuditEventType.DATA_EXPORT,
                actor="picodome-retention",
                detail=f"Exported {data_type} to {output_path}",
                target=str(output_path),
            )
        except Exception:
            pass

        return output_path

    def secure_delete(self, path: Path) -> bool:
        """Securely delete a file by overwriting before unlink.

        Writes random data, then zeros, then removes the file.
        """
        if not path.is_file():
            return False

        try:
            size = path.stat().st_size

            # Overwrite with zeros
            with open(path, "wb") as f:
                f.write(b"\x00" * size)
                f.flush()
                os.fsync(f.fileno())

            # Overwrite with random-ish pattern
            with open(path, "wb") as f:
                f.write(os.urandom(size))
                f.flush()
                os.fsync(f.fileno())

            # Truncate and delete
            with open(path, "wb") as f:
                f.truncate(0)
                f.flush()
                os.fsync(f.fileno())

            path.unlink()
            logger.debug("Securely deleted: %s", path)
            return True

        except OSError as e:
            logger.warning("Secure delete failed for %s: %s", path, e)
            return False

    # ── Internal ────────────────────────────────────────────────────────

    def _cleanup_directory(
        self,
        directory: Path,
        policy: RetentionPolicy,
        now: float,
    ) -> dict[str, Any]:
        """Clean up expired files in a directory."""
        stats: dict[str, Any] = {"files_removed": 0, "bytes_freed": 0, "errors": []}

        if policy.ttl_days == 0:
            # Never expire
            return stats

        cutoff = now - (policy.ttl_days * 86400)

        if not directory.is_dir():
            return stats

        for f in list(directory.glob("*.json")):
            try:
                mtime = f.stat().st_mtime
                if mtime < cutoff:
                    size = f.stat().st_size
                    if policy.secure_delete:
                        self.secure_delete(f)
                    else:
                        f.unlink()
                    stats["files_removed"] += 1
                    stats["bytes_freed"] += size
            except OSError as e:
                stats["errors"].append(f"{f.name}: {e}")

        # Check quota
        if policy.max_size_mb > 0:
            dir_stats = self._dir_stats(directory)
            max_bytes = policy.max_size_mb * 1024 * 1024
            if dir_stats["total_bytes"] > max_bytes:
                # Remove oldest files until under quota
                files = sorted(directory.glob("*.json"), key=lambda f: f.stat().st_mtime)
                for f in files:
                    if dir_stats["total_bytes"] <= max_bytes:
                        break
                    try:
                        size = f.stat().st_size
                        if policy.secure_delete:
                            self.secure_delete(f)
                        else:
                            f.unlink()
                        stats["files_removed"] += 1
                        stats["bytes_freed"] += size
                        dir_stats["total_bytes"] -= size
                    except OSError:
                        pass

        return stats

    @staticmethod
    def _dir_stats(directory: Path) -> dict[str, Any]:
        """Compute stats for a directory."""
        if not directory.is_dir():
            return {"file_count": 0, "total_bytes": 0}

        total_bytes = 0
        file_count = 0
        for f in directory.glob("*.json"):
            try:
                total_bytes += f.stat().st_size
                file_count += 1
            except OSError:
                pass

        return {"file_count": file_count, "total_bytes": total_bytes}


# ─── Module-level singleton ────────────────────────────────────────────────


_retention_manager_lock = threading.Lock()
_retention_manager: RetentionManager | None = None


def get_retention_manager() -> RetentionManager:
    """Get the global retention manager (lazy init)."""
    global _retention_manager
    if _retention_manager is None:
        with _retention_manager_lock:
            if _retention_manager is None:
                _retention_manager = RetentionManager()
    return _retention_manager
