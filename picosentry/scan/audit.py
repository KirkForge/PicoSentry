
from __future__ import annotations

import json
import logging
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("picosentry.audit")


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


DEFAULT_AUDIT_DIR = Path.home() / ".cache" / "picosentry"
DEFAULT_AUDIT_FILE = "audit.jsonl"
DEFAULT_MAX_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
DEFAULT_RETENTION_DAYS = 90


@dataclass
class AuditEvent:

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


class AuditSink:

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

    def write(self, event: AuditEvent) -> None:
        with self._lock:
            self._rotate_if_needed()
            self._cleanup_old_files()

            self.path.parent.mkdir(parents=True, exist_ok=True)
            line = event.to_json() + "\n"

            try:
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(line)
                    f.flush()
            except OSError:
                logger.exception("Failed to write audit event")

    def _rotate_if_needed(self) -> None:
        if not self.path.exists():
            return

        try:
            size = self.path.stat().st_size
        except OSError:
            return

        if size < self.max_size_bytes:
            return


        rot_num = 1
        while self.path.with_suffix(f".jsonl.{rot_num}").exists():
            rot_num += 1

        rotated = self.path.with_suffix(f".jsonl.{rot_num}")
        try:
            self.path.rename(rotated)
            logger.info("Rotated audit log to %s", rotated)
        except OSError:
            logger.exception("Failed to rotate audit log")

    def _cleanup_old_files(self) -> None:
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
        events: list[AuditEvent] = []
        if not self.path.exists():
            return events

        try:
            lines = self.path.read_text(encoding="utf-8").strip().split("\n")
        except OSError:
            return events

        for raw_line in lines:
            line = raw_line.strip()
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


_global_sink: AuditSink | None = None
_sink_lock = threading.Lock()


def get_audit_sink() -> AuditSink:
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
    global _global_sink
    with _sink_lock:
        _global_sink = AuditSink(
            path=path,
            max_size_bytes=max_size_bytes,
            retention_days=retention_days,
        )
        return _global_sink


def reset_audit_sink() -> None:
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

        logger.exception("Failed to emit audit event")

    return event
