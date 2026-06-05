"""PicoDome Audit — structured, tamper-evident audit logging.

Append-only JSON-lines audit log with hash chaining for integrity.
Every policy mutation, scan execution, and baseline change is recorded
with actor identity, timestamp, and a chain link to the previous entry.
"""

from __future__ import annotations

from picosentry.sandbox.audit.logger import (
    AuditEvent,
    AuditEventType,
    AuditLogger,
    get_audit_logger,
    setup_audit_logger,
)
from picosentry.sandbox.audit.sinks import AuditSink, NullSink, SinkConfig

__all__ = [
    "AuditEvent",
    "AuditEventType",
    "AuditLogger",
    "AuditSink",
    "NullSink",
    "SinkConfig",
    "get_audit_logger",
    "setup_audit_logger",
]
