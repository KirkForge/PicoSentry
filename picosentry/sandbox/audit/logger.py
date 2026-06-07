
from __future__ import annotations

import gzip
import hashlib
import json
import logging
import shutil
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger("picodome.audit")


class AuditEventType(str, Enum):


    SCAN_START = "scan_start"
    SCAN_COMPLETE = "scan_complete"
    SCAN_ALERT = "scan_alert"


    POLICY_CREATE = "policy_create"
    POLICY_UPDATE = "policy_update"
    POLICY_ROLLBACK = "policy_rollback"
    POLICY_DELETE = "policy_delete"


    BASELINE_CREATE = "baseline_create"
    BASELINE_UPDATE = "baseline_update"
    BASELINE_DELETE = "baseline_delete"


    DAEMON_START = "daemon_start"
    DAEMON_STOP = "daemon_stop"
    AUTH_SUCCESS = "auth_success"
    AUTH_FAILURE = "auth_failure"


    COMMAND_DENIED = "command_denied"
    RATE_LIMITED = "rate_limited"


    DATA_RETENTION_CLEANUP = "data_retention_cleanup"
    DATA_EXPORT = "data_export"
    DATA_DELETE = "data_delete"


@dataclass(frozen=True)
class AuditEvent:

    event_type: AuditEventType
    actor: str
    detail: str = ""
    target: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    event_id: str = ""
    timestamp: str = ""
    prev_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "actor": self.actor,
            "detail": self.detail,
            "event_id": self.event_id,
            "event_type": self.event_type.value,
            "metadata": self.metadata,
            "prev_hash": self.prev_hash,
            "schema_version": AUDIT_SCHEMA_VERSION,
            "target": self.target,
            "timestamp": self.timestamp,
        }
        return {k: v for k, v in sorted(d.items())}

    def to_json_line(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, default=str)


_DEFAULT_LOG_DIR = Path.home() / ".picodome" / "audit"
_DEFAULT_MAX_BYTES = 50 * 1024 * 1024  # 50 MiB before rotation
_DEFAULT_ROTATE_COUNT = 10  # keep 10 rotated files

AUDIT_SCHEMA_VERSION = 2  # v2: adds schema_version field to every event
AUDIT_SCHEMA_COMPAT = {1, 2}  # Versions we can read


class AuditLogger:

    def __init__(
        self,
        log_dir: Path | None = None,
        log_file: str = "audit.jsonl",
        max_bytes: int = _DEFAULT_MAX_BYTES,
        rotate_count: int = _DEFAULT_ROTATE_COUNT,
        notary: Any | None = None,
        sinks: list[Any] | None = None,
    ) -> None:
        self._log_dir = log_dir or _DEFAULT_LOG_DIR
        self._log_path = self._log_dir / log_file
        self._max_bytes = max_bytes
        self._rotate_count = rotate_count
        self._prev_hash = ""
        self._notary = notary  # Optional AuditNotary instance
        self._sinks: list[Any] = sinks or []  # AuditSink instances
        self._lock = threading.Lock()


        self._log_dir.mkdir(parents=True, exist_ok=True)


        self._prev_hash = self._read_last_hash()


    def record(
        self,
        event_type: AuditEventType,
        actor: str,
        detail: str = "",
        target: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> AuditEvent:
        with self._lock:
            event_id = str(uuid.uuid4())
            timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

            event = AuditEvent(
                event_type=event_type,
                actor=actor,
                detail=detail,
                target=target,
                metadata=metadata or {},
                event_id=event_id,
                timestamp=timestamp,
                prev_hash=self._prev_hash,
            )

            line = event.to_json_line()
            self._append_line(line)


            self._prev_hash = hashlib.sha256(line.encode("utf-8")).hexdigest()


        if self._notary is not None:
            try:
                notary_uuid = self._notary.submit_entry(event.to_dict())
                logger.debug("Notarized event %s as %s", event.event_id[:8], notary_uuid[:8])
            except Exception as exc:

                logger.warning("Notary submission failed for %s: %s", event.event_id[:8], exc)


        for sink in self._sinks:
            try:
                sink.send(event)
            except Exception as exc:

                logger.warning("Sink %s failed for event %s: %s", sink.name, event.event_id[:8], exc)

        logger.debug(
            "Audit: %s actor=%s target=%s",
            event_type.value,
            actor,
            target,
        )

        return event

    def verify_chain(self, log_path: Path | None = None) -> list[str]:
        path = log_path or self._log_path
        if not path.is_file():
            return [f"Audit log not found: {path}"]

        violations: list[str] = []
        expected_prev = ""
        line_num = 0

        try:
            with open(path, encoding="utf-8") as f:
                for line_num, line in enumerate(f, start=1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        violations.append(f"Line {line_num}: invalid JSON")
                        continue

                    recorded_prev = data.get("prev_hash", "")
                    if line_num > 1 and recorded_prev != expected_prev:
                        violations.append(
                            f"Line {line_num}: prev_hash mismatch — "
                            f"expected {expected_prev[:16]}... "
                            f"got {recorded_prev[:16]}..."
                        )


                    expected_prev = hashlib.sha256(line.encode("utf-8")).hexdigest()

        except OSError as e:
            violations.append(f"Error reading audit log: {e}")

        return violations

    def query(
        self,
        event_type: AuditEventType | None = None,
        actor: str | None = None,
        target: str | None = None,
        since: str | None = None,
        until: str | None = None,
        limit: int = 100,
    ) -> list[AuditEvent]:
        results: list[AuditEvent] = []

        if not self._log_path.is_file():
            return results

        try:
            with open(self._log_path, encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        data = json.loads(line)
                    except json.JSONDecodeError:
                        continue


                    if event_type and data.get("event_type") != event_type.value:
                        continue
                    if actor and actor not in data.get("actor", ""):
                        continue
                    if target and target not in data.get("target", ""):
                        continue
                    if since and data.get("timestamp", "") < since:
                        continue
                    if until and data.get("timestamp", "") > until:
                        continue


                    schema_ver = data.get("schema_version", 1)
                    if schema_ver not in AUDIT_SCHEMA_COMPAT:
                        logger.warning(
                            "Audit event with unknown schema_version=%s",
                            schema_ver,
                        )

                    evt = AuditEvent(
                        event_type=AuditEventType(data["event_type"]),
                        actor=data.get("actor", ""),
                        detail=data.get("detail", ""),
                        target=data.get("target", ""),
                        metadata=data.get("metadata", {}),
                        event_id=data.get("event_id", ""),
                        timestamp=data.get("timestamp", ""),
                        prev_hash=data.get("prev_hash", ""),
                    )
                    results.append(evt)

                    if len(results) >= limit:
                        break

        except OSError:
            pass


        results.reverse()
        return results

    def get_stats(self) -> dict[str, Any]:
        if not self._log_path.is_file():
            return {"exists": False, "events": 0, "size_bytes": 0}

        stat = self._log_path.stat()
        events = 0
        try:
            with open(self._log_path, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        events += 1
        except OSError:
            pass

        return {
            "chain_intact": len(self.verify_chain()) == 0,
            "events": events,
            "exists": True,
            "last_modified": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(stat.st_mtime),
            ),
            "path": str(self._log_path),
            "schema_version": AUDIT_SCHEMA_VERSION,
            "size_bytes": stat.st_size,
        }

    @property
    def log_path(self) -> Path:
        return self._log_path

    def add_sink(self, sink: Any) -> None:
        self._sinks.append(sink)

    def remove_sink(self, sink: Any) -> None:
        if sink in self._sinks:
            try:
                sink.stop()
            except Exception:
                pass
            self._sinks.remove(sink)


    def _append_line(self, line: str) -> None:

        if self._log_path.exists() and self._log_path.stat().st_size >= self._max_bytes:
            self._rotate()

        with open(self._log_path, "a", encoding="utf-8") as f:
            f.write(line + "\n")


        try:
            self._log_path.chmod(0o600)
        except OSError:
            pass

    def _rotate(self) -> None:

        for i in range(self._rotate_count - 1, 0, -1):
            src = self._log_path.with_suffix(f".{i}.jsonl.gz")
            dst = self._log_path.with_suffix(f".{i + 1}.jsonl.gz")
            if src.exists():
                shutil.move(str(src), str(dst))


        one_path = self._log_path.with_suffix(".1.jsonl.gz")
        with open(self._log_path, "rb") as f_in, gzip.open(one_path, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)


        self._log_path.write_text("", encoding="utf-8")

    def _read_last_hash(self) -> str:
        if not self._log_path.is_file():
            return ""

        last_line = ""
        try:
            with open(self._log_path, encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        last_line = line.strip()
        except OSError:
            return ""

        if not last_line:
            return ""

        try:
            json.loads(last_line)  # validate it's valid JSON

            return hashlib.sha256(last_line.encode("utf-8")).hexdigest()
        except (json.JSONDecodeError, KeyError):
            return ""


_audit_logger_lock = threading.Lock()
_audit_logger: AuditLogger | None = None


def get_audit_logger() -> AuditLogger:
    global _audit_logger
    if _audit_logger is None:
        with _audit_logger_lock:
            if _audit_logger is None:
                _audit_logger = AuditLogger()
    return _audit_logger


def setup_audit_logger(
    log_dir: Path | None = None,
    max_bytes: int = _DEFAULT_MAX_BYTES,
    rotate_count: int = _DEFAULT_ROTATE_COUNT,
    sinks: list[Any] | None = None,
) -> AuditLogger:
    global _audit_logger
    _audit_logger = AuditLogger(
        log_dir=log_dir,
        max_bytes=max_bytes,
        rotate_count=rotate_count,
        sinks=sinks,
    )

    for sink in _audit_logger._sinks:
        try:
            sink.start()
        except Exception as exc:
            logger.warning("Failed to start sink %s: %s", sink.name, exc)
    return _audit_logger
