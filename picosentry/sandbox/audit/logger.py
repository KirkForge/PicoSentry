from __future__ import annotations

import collections
import contextlib
import gzip
import hashlib
import json
import logging
import os
import shutil
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any

logger = logging.getLogger("picodome.audit")

# Operational errors that can be raised by optional audit plugins (notary,
# external sinks). We log these and continue so a misbehaving integration does
# not block the core audit log; unexpected programmer errors must propagate.
_AUDIT_PLUGIN_ERRORS: tuple[type[BaseException], ...] = (
    OSError,
    RuntimeError,
    ValueError,
    TypeError,
    AttributeError,
)


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

    CLUSTER_GOSSIP = "cluster_gossip"


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
        return dict(sorted(d.items()))

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
        fsync: bool = True,
    ) -> None:
        self._log_dir = log_dir or _DEFAULT_LOG_DIR
        self._log_path = self._log_dir / log_file
        self._max_bytes = max_bytes
        self._rotate_count = rotate_count
        self._fsync = fsync
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
            except _AUDIT_PLUGIN_ERRORS as exc:
                logger.warning("Notary submission failed for %s: %s", event.event_id[:8], exc)

        for sink in self._sinks:
            try:
                sink.send(event)
            except _AUDIT_PLUGIN_ERRORS as exc:
                logger.warning("Sink %s failed for event %s: %s", sink.name, event.event_id[:8], exc)

        logger.debug(
            "Audit: %s actor=%s target=%s",
            event_type.value,
            actor,
            target,
        )

        return event

    def verify_chain(self, log_path: Path | None = None) -> list[str]:
        # Default: verify the whole chain — rotated archives (oldest first) then
        # the live log — carrying expected_prev across each file boundary. An
        # explicit log_path verifies a single file (backward compatibility).
        if log_path is not None:
            sources: list[tuple[Path, bool]] = [(log_path, log_path.suffix == ".gz")]
        else:
            sources = [(p, True) for p in self._rotated_archive_paths()]
            sources.append((self._log_path, False))

        if not any(p.is_file() for p, _ in sources):
            return [f"Audit log not found: {self._log_path}"]

        violations: list[str] = []
        expected_prev = ""
        line_num = 0

        for path, gzipped in sources:
            opener: Any = gzip.open if gzipped else open
            try:
                with opener(path, "rt", encoding="utf-8") as f:
                    for raw_line in f:
                        line_num += 1
                        line = raw_line.strip()
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

            except (OSError, EOFError) as e:
                violations.append(f"Error reading audit log {path.name}: {e}")

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
        """Most recent `limit` matching events, newest first (WO5.0.0-018).

        WO6.0.0-018: archive-aware — walks rotated gzip archives (oldest first)
        then the live log, so a query past the rotation boundary returns the
        full history instead of just the live-file window. The deque keeps the
        last `limit` matches in bounded memory while scanning to EOF across
        all sources. `since`/`until` are compared as raw strings — timestamps
        are normalized to ``%Y-%m-%dT%H:%M:%SZ`` (lexicographic == chronological
        for that fixed-width format); callers passing non-ISO values get the
        same empty-result fall-through the live-only scan produced.
        """
        results: collections.deque[AuditEvent] = collections.deque(maxlen=max(1, limit))

        # Sources in chronological order (oldest first): rotated archives
        # (highest rotate index == oldest) then the live log. Same ordering
        # verify_chain uses.
        sources: list[tuple[Path, bool]] = [(p, True) for p in self._rotated_archive_paths()]
        if self._log_path.is_file():
            sources.append((self._log_path, False))

        if not any(p.is_file() for p, _ in sources):
            return []

        for path, gzipped in sources:
            if not path.is_file():
                continue
            opener: Any = gzip.open if gzipped else open
            try:
                with opener(path, "rt", encoding="utf-8") as f:
                    for raw_line in f:
                        line = raw_line.strip()
                        if not line:
                            continue
                        evt = self._match_audit_line(
                            line,
                            event_type=event_type,
                            actor=actor,
                            target=target,
                            since=since,
                            until=until,
                        )
                        if evt is not None:
                            results.append(evt)
            except (OSError, EOFError):
                # A corrupt/truncated archive is logged elsewhere (verify_chain
                # surfaces it); the query degrades to the readable prefixes.
                logger.debug("Audit query could not read %s", path, exc_info=True)

        return list(results)[::-1]

    @staticmethod
    def _match_audit_line(
        line: str,
        *,
        event_type: AuditEventType | None,
        actor: str | None,
        target: str | None,
        since: str | None,
        until: str | None,
    ) -> AuditEvent | None:
        """Parse one audit log line and return the event if it matches the
        filters, else None. Shared by query() across live + archive sources."""
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        if event_type and data.get("event_type") != event_type.value:
            return None
        if actor and actor not in data.get("actor", ""):
            return None
        if target and target not in data.get("target", ""):
            return None
        if since and data.get("timestamp", "") < since:
            return None
        if until and data.get("timestamp", "") > until:
            return None

        schema_ver = data.get("schema_version", 1)
        if schema_ver not in AUDIT_SCHEMA_COMPAT:
            logger.warning("Audit event with unknown schema_version=%s", schema_ver)

        return AuditEvent(
            event_type=AuditEventType(data["event_type"]),
            actor=data.get("actor", ""),
            detail=data.get("detail", ""),
            target=data.get("target", ""),
            metadata=data.get("metadata", {}),
            event_id=data.get("event_id", ""),
            timestamp=data.get("timestamp", ""),
            prev_hash=data.get("prev_hash", ""),
        )

    def get_stats(self) -> dict[str, Any]:
        # WO6.0.0-018: archive-aware — count events across rotated archives
        # AND the live log, not just the live file (a freshly-rotated log
        # used to report events=0 while verify_chain walked the archives).
        total_events = 0
        sources: list[tuple[Path, bool]] = [(p, True) for p in self._rotated_archive_paths()]
        if self._log_path.is_file():
            sources.append((self._log_path, False))

        if not any(p.is_file() for p, _ in sources):
            return {"exists": False, "events": 0, "size_bytes": 0}

        live_stat = self._log_path.stat() if self._log_path.is_file() else None
        total_bytes = 0
        for path, gzipped in sources:
            if not path.is_file():
                continue
            opener: Any = gzip.open if gzipped else open
            try:
                with opener(path, "rt", encoding="utf-8") as f:
                    for line in f:
                        if line.strip():
                            total_events += 1
                total_bytes += path.stat().st_size
            except (OSError, EOFError):
                logger.debug("Audit stats could not read %s", path, exc_info=True)

        return {
            "chain_intact": len(self.verify_chain()) == 0,
            "events": total_events,
            "exists": True,
            "last_modified": time.strftime(
                "%Y-%m-%dT%H:%M:%SZ",
                time.gmtime(live_stat.st_mtime if live_stat else time.time()),
            ),
            "path": str(self._log_path),
            "schema_version": AUDIT_SCHEMA_VERSION,
            "size_bytes": total_bytes,
        }

    @property
    def log_path(self) -> Path:
        return self._log_path

    def add_sink(self, sink: Any) -> None:
        self._sinks.append(sink)

    def remove_sink(self, sink: Any) -> None:
        if sink in self._sinks:
            with contextlib.suppress(*_AUDIT_PLUGIN_ERRORS):
                sink.stop()
            self._sinks.remove(sink)

    def _append_line(self, line: str) -> None:

        if self._log_path.exists() and self._log_path.stat().st_size >= self._max_bytes:
            self._rotate()

        with self._log_path.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
            f.flush()
            if self._fsync:
                os.fsync(f.fileno())

        with contextlib.suppress(OSError):
            self._log_path.chmod(0o600)

    def _rotate(self) -> None:

        for i in range(self._rotate_count - 1, 0, -1):
            src = self._log_path.with_suffix(f".{i}.jsonl.gz")
            dst = self._log_path.with_suffix(f".{i + 1}.jsonl.gz")
            if src.exists():
                shutil.move(str(src), str(dst))

        one_path = self._log_path.with_suffix(".1.jsonl.gz")
        with self._log_path.open("rb") as f_in, gzip.open(one_path, "wb") as f_out:
            shutil.copyfileobj(f_in, f_out)

        self._log_path.write_text("", encoding="utf-8")

    def _rotated_archive_paths(self) -> list[Path]:
        # Rotated gzip archives in chronological order (oldest first): higher
        # rotate index == older (rotation shifts .i -> .i+1).
        archives: list[Path] = []
        for i in range(self._rotate_count, 0, -1):
            p = self._log_path.with_suffix(f".{i}.jsonl.gz")
            if p.is_file():
                archives.append(p)
        return archives

    @staticmethod
    def _last_nonempty_line(path: Path, *, gzipped: bool) -> str:
        opener: Any = gzip.open if gzipped else open
        last = ""
        try:
            with opener(path, "rt", encoding="utf-8") as f:
                for line in f:
                    if line.strip():
                        last = line.strip()
        except (OSError, EOFError):
            return ""
        return last

    def _read_last_hash(self) -> str:
        last_line = self._last_nonempty_line(self._log_path, gzipped=False)
        if not last_line:
            # Live log empty (e.g. process restarted after a rotation truncated
            # it): continue the chain from the newest rotated archive (.1).
            one = self._log_path.with_suffix(".1.jsonl.gz")
            if one.is_file():
                last_line = self._last_nonempty_line(one, gzipped=True)
        if not last_line:
            return ""
        try:
            json.loads(last_line)
        except json.JSONDecodeError:
            return ""
        return hashlib.sha256(last_line.encode("utf-8")).hexdigest()


_audit_logger_lock = threading.Lock()
_audit_logger: AuditLogger | None = None


def get_audit_logger() -> AuditLogger:
    global _audit_logger
    if _audit_logger is None:
        with _audit_logger_lock:
            if _audit_logger is None:
                _audit_logger = AuditLogger(fsync=_audit_fsync_enabled())
    return _audit_logger


def _audit_fsync_enabled() -> bool:
    return os.environ.get("PICODOME_AUDIT_FSYNC", "true").lower() not in ("0", "false", "no")


def setup_audit_logger(
    log_dir: Path | None = None,
    max_bytes: int = _DEFAULT_MAX_BYTES,
    rotate_count: int = _DEFAULT_ROTATE_COUNT,
    sinks: list[Any] | None = None,
    fsync: bool | None = None,
) -> AuditLogger:
    global _audit_logger
    _audit_logger = AuditLogger(
        log_dir=log_dir,
        max_bytes=max_bytes,
        rotate_count=rotate_count,
        sinks=sinks,
        fsync=_audit_fsync_enabled() if fsync is None else fsync,
    )

    for sink in _audit_logger._sinks:
        try:
            sink.start()
        except _AUDIT_PLUGIN_ERRORS as exc:
            logger.warning("Failed to start sink %s: %s", sink.name, exc)
    return _audit_logger
