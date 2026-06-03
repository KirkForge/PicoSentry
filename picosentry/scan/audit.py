"""
Audit event logging for PicoSentry enterprise deployments.

Emits structured JSONL audit events for security-relevant actions:
corpus import/export, IoC mutations, cache operations, auth events,
update operations, and policy changes.

Design:
- Append-only JSONL sink with configurable path
- Rotation by size (default 10MB) with retention (default 90 days)
- Forward-compatible: structured for SIEM/shipping
- Zero network calls; purely local filesystem

Usage:
    from picosentry.scan.audit import audit, AuditEvent

    audit("corpus.import", target="community-pack.json", outcome="success")
    audit("ioc.register", target="malicious-pkg@1.0.0", actor="admin", metadata={"severity": "HIGH"})
"""

from __future__ import annotations

import contextlib
import json
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, TextIO

logger = logging.getLogger("picosentry.audit")

# ── Audit event schema ─────────────────────────────────────────────────

# Well-known action names (extensible — callers can use any string)
ACTIONS = frozenset(
    {
        "corpus.import",
        "corpus.export",
        "corpus.validate",
        "ioc.register",
        "ioc.remove",
        "cache.purge",
        "cache.wipe",
        "auth.success",
        "auth.failure",
        "update.download",
        "update.verify",
        "policy.change",
        "daemon.start",
        "daemon.stop",
        "daemon.start_denied",
        "policy.load",
        "policy.apply",
        "policy.import_bundle",
    }
)

# ── Default paths ──────────────────────────────────────────────────────

DEFAULT_AUDIT_DIR = Path.home() / ".cache" / "picosentry"
DEFAULT_AUDIT_FILE = "audit.jsonl"
DEFAULT_MAX_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
DEFAULT_RETENTION_DAYS = 90


@dataclass
class AuditEvent:
    """A structured audit event.

    Attributes:
        timestamp: ISO 8601 UTC timestamp.
        action: Well-known action name (e.g. 'corpus.import').
        actor: Identity of the actor (subject from auth, or 'system').
        target: What was acted upon (e.g. pack name, IoC ID).
        outcome: 'success' or 'failure'.
        metadata: Additional key-value pairs.
        request_id: Optional request ID for tracing.
    """

    action: str
    target: str = ""
    actor: str = "system"
    outcome: str = "success"
    metadata: dict[str, Any] = field(default_factory=dict)
    request_id: str = ""
    timestamp: str = ""

    def __post_init__(self) -> None:
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "timestamp": self.timestamp,
            "action": self.action,
            "actor": self.actor,
            "target": self.target,
            "outcome": self.outcome,
        }
        if self.metadata:
            d["metadata"] = self.metadata
        if self.request_id:
            d["request_id"] = self.request_id
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True)


# ── Audit sink ──────────────────────────────────────────────────────────


class AuditSink:
    """Append-only JSONL audit log with rotation and retention.

    Thread-safe. Writes one JSON object per line to the audit file.
    Rotates when the file exceeds max_size_bytes. Cleans up files
    older than retention_days.

    Args:
        path: Path to the audit JSONL file.
        max_size_bytes: Max file size before rotation (default: 10MB).
        retention_days: Max age of rotated files in days (default: 90).
    """

    def __init__(
        self,
        path: Path | None = None,
        max_size_bytes: int = DEFAULT_MAX_SIZE_BYTES,
        retention_days: int = DEFAULT_RETENTION_DAYS,
    ) -> None:
        self.path = path or DEFAULT_AUDIT_DIR / DEFAULT_AUDIT_FILE
        self.max_size_bytes = max_size_bytes
        self.retention_days = retention_days
        self._lock = threading.Lock()
        self._file_handle: TextIO | None = None

    def write(self, event: AuditEvent) -> None:
        """Append an audit event to the JSONL file.

        Thread-safe. Rotates if the file exceeds max_size_bytes.
        Keeps the file handle open across writes to avoid repeated open/close.
        """
        with self._lock:
            self._rotate_if_needed()
            self._cleanup_old_files()

            self.path.parent.mkdir(parents=True, exist_ok=True)
            line = event.to_json() + "\n"

            try:
                # Reuse file handle across writes (avoids repeated open/close)
                if self._file_handle is None or self._file_handle.closed:
                    self._file_handle = open(self.path, "a", encoding="utf-8")  # noqa: SIM115
                self._file_handle.write(line)
                self._file_handle.flush()
            except OSError as e:
                logger.error("Failed to write audit event: %s", e)
                self._close_handle()

    def _close_handle(self) -> None:
        """Close the open file handle, if any."""
        if self._file_handle and not self._file_handle.closed:
            with contextlib.suppress(OSError):
                self._file_handle.close()
        self._file_handle = None

    def _rotate_if_needed(self) -> None:
        """Rotate the audit file if it exceeds max_size_bytes."""
        # Close handle before rotation so rename works on all platforms
        self._close_handle()
        if not self.path.exists():
            return

        try:
            size = self.path.stat().st_size
        except OSError:
            return

        if size < self.max_size_bytes:
            return

        # Rotate: audit.jsonl -> audit.jsonl.1, etc.
        # Find next available rotation number
        rot_num = 1
        while self.path.with_suffix(f".jsonl.{rot_num}").exists():
            rot_num += 1

        rotated = self.path.with_suffix(f".jsonl.{rot_num}")
        try:
            self.path.rename(rotated)
            logger.info("Rotated audit log to %s", rotated)
        except OSError as e:
            logger.error("Failed to rotate audit log: %s", e)

    def _cleanup_old_files(self) -> None:
        """Remove rotated audit files older than retention_days."""
        if self.retention_days <= 0:
            return

        cutoff = datetime.now(timezone.utc).timestamp() - (self.retention_days * 86400)
        parent = self.path.parent
        for f in parent.glob("audit.jsonl.*"):
            try:
                if f.stat().st_mtime < cutoff:
                    f.unlink()
                    logger.info("Removed old audit log: %s", f)
            except OSError:
                pass

    def read(self, limit: int = 100, action: str = "") -> list[AuditEvent]:
        """Read recent audit events from the log.

        Args:
            limit: Maximum number of events to return.
            action: Filter by action name (empty = all).

        Returns:
            List of AuditEvent objects, most recent last.
        """
        events: list[AuditEvent] = []
        if not self.path.exists():
            return events

        try:
            lines = self.path.read_text(encoding="utf-8").strip().split("\n")
        except OSError:
            return events

        for line in lines:
            line = line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
                event = AuditEvent(
                    action=data.get("action", ""),
                    target=data.get("target", ""),
                    actor=data.get("actor", "system"),
                    outcome=data.get("outcome", "success"),
                    metadata=data.get("metadata", {}),
                    request_id=data.get("request_id", ""),
                    timestamp=data.get("timestamp", ""),
                )
                if action and event.action != action:
                    continue
                events.append(event)
            except (json.JSONDecodeError, KeyError):
                continue

        return events[-limit:]


# ── Global sink ─────────────────────────────────────────────────────────

_global_sink: AuditSink | None = None
_sink_lock = threading.Lock()


def get_audit_sink() -> AuditSink:
    """Get or create the global audit sink."""
    global _global_sink
    with _sink_lock:
        if _global_sink is None:
            _global_sink = AuditSink()
        return _global_sink


def configure_audit_sink(
    path: Path | None = None,
    max_size_bytes: int = DEFAULT_MAX_SIZE_BYTES,
    retention_days: int = DEFAULT_RETENTION_DAYS,
) -> AuditSink:
    """Configure the global audit sink (call once at startup)."""
    global _global_sink
    with _sink_lock:
        _global_sink = AuditSink(
            path=path,
            max_size_bytes=max_size_bytes,
            retention_days=retention_days,
        )
        return _global_sink


def reset_audit_sink() -> None:
    """Reset the global audit sink (for testing)."""
    global _global_sink
    with _sink_lock:
        _global_sink = None


def audit(
    action: str,
    target: str = "",
    actor: str = "system",
    outcome: str = "success",
    metadata: dict[str, Any] | None = None,
    request_id: str = "",
    fail_closed: bool = False,
) -> AuditEvent:
    """Emit an audit event to the global sink.

    This is the primary API for audit logging throughout PicoSentry.

    Args:
        action: Well-known action name (e.g. 'corpus.import').
        target: What was acted upon.
        actor: Identity of the actor.
        outcome: 'success' or 'failure'.
        metadata: Additional key-value pairs.
        request_id: Request ID for tracing.
        fail_closed: If True, raise on write failure instead of silently
            swallowing the error. Use for security-critical audit paths
            where a missing audit record is worse than a crash.

    Returns:
        The AuditEvent that was emitted.
    """
    event = AuditEvent(
        action=action,
        target=target,
        actor=actor,
        outcome=outcome,
        metadata=metadata or {},
        request_id=request_id,
    )

    try:
        sink = get_audit_sink()
        sink.write(event)
    except Exception as e:
        if fail_closed:
            logger.critical("Failed to emit audit event (fail-closed): %s", e)
            raise
        # Best-effort for non-critical paths: log but do not crash
        logger.error("Failed to emit audit event: %s", e)

    return event
