"""Shared audit primitives — vendored from pico-core.

Provides the shared base types for audit logging:
- AuditEvent: structured event schema (shared)
- AuditSinkBase: abstract base for all sink implementations
- NullSink: no-op sink for testing
- HashChainedMixin: hash-chained audit log integrity
- HMAC signing: message authentication for audit entries
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

logger = logging.getLogger("picosentry._core.audit")


# -- Event schema --------------------------------------------------------------


class AuditEventType(str, Enum):
    """Well-known audit event types shared across PicoSeries."""

    SCAN_START = "scan.start"
    SCAN_COMPLETE = "scan.complete"
    POLICY_CHANGE = "policy.change"
    POLICY_LOAD = "policy.load"
    AUTH_SUCCESS = "auth.success"
    AUTH_FAILURE = "auth.failure"
    CONFIG_CHANGE = "config.change"
    DAEMON_START = "daemon.start"
    DAEMON_STOP = "daemon.stop"
    SECURITY_VIOLATION = "security.violation"


@dataclass
class AuditEvent:
    """A structured audit event.

    Shared across all PicoSeries codebases. Each codebase may add
    domain-specific fields via metadata.

    Attributes:
        action: Well-known action name (e.g. 'scan.complete').
        target: What was acted upon.
        actor: Identity of the actor (subject from auth, or 'system').
        outcome: 'success' or 'failure'.
        metadata: Additional key-value pairs.
        request_id: Optional request ID for tracing.
        timestamp: ISO 8601 UTC timestamp.
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
            self.timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

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


# -- Sink base -----------------------------------------------------------------


class AuditSinkBase(ABC):
    """Abstract base for all audit sinks.

    Subclasses must implement ``send(event)``. The base class tracks
    basic statistics and provides a health check.

    Lifecycle:
        1. Instantiate with optional SinkConfig
        2. ``start()`` — open connections / files
        3. ``send(event)`` — called for each audit event
        4. ``flush()`` — ensure buffered events are written
        5. ``stop()`` — clean up resources
    """

    def __init__(self) -> None:
        self._stats: dict[str, Any] = {
            "events_sent": 0,
            "events_failed": 0,
            "events_dropped": 0,
            "last_send_time": None,
            "last_error": None,
        }

    def start(self) -> None:
        """Open connections, create files, etc. Override if needed."""

    def stop(self) -> None:
        """Clean up resources. Override if needed."""

    def flush(self) -> None:
        """Flush any buffered events. Override if needed."""

    @abstractmethod
    def send(self, event: AuditEvent) -> None:
        """Send an audit event. Must never raise — log errors instead."""

    @property
    def stats(self) -> dict[str, Any]:
        return dict(self._stats)

    def _record_success(self) -> None:
        self._stats["events_sent"] += 1
        self._stats["last_send_time"] = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

    def _record_failure(self, error: str) -> None:
        self._stats["events_failed"] += 1
        self._stats["last_error"] = error


class NullSink(AuditSinkBase):
    """No-op audit sink for testing and development."""

    def send(self, event: AuditEvent) -> None:
        self._record_success()


# -- Hash-chained audit log ----------------------------------------------------


class HashChainedMixin:
    """Mixin for hash-chained audit log integrity.

    Each event's JSON line includes a ``prev_hash`` field that chains
    it to the previous event, making tampering detectable.

    Used by PicoDome's AuditLogger and available for any PicoSeries
    codebase that needs tamper-evident audit logs.
    """

    def compute_event_hash(self, line: str) -> str:
        """Compute SHA-256 hash of an audit log line."""
        return hashlib.sha256(line.encode("utf-8")).hexdigest()

    def chain_event(self, event_dict: dict[str, Any], prev_hash: str) -> dict[str, Any]:
        """Add prev_hash to an event dict for hash chaining."""
        event_dict["prev_hash"] = prev_hash
        return event_dict

    def verify_chain(self, lines: list[str]) -> list[str]:
        """Verify hash chain integrity. Returns list of violations."""
        violations: list[str] = []
        prev_hash = ""

        for i, line in enumerate(lines):
            line = line.strip()
            if not line:
                continue

            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                violations.append(f"Line {i}: invalid JSON")
                continue

            expected_prev = data.get("prev_hash", "")
            if expected_prev != prev_hash:
                violations.append(
                    f"Line {i}: prev_hash mismatch (chain broken)"
                )

            prev_hash = self.compute_event_hash(line)

        return violations


# -- HMAC signing --------------------------------------------------------------


def sign_event(event_json: str, secret_key: str) -> str:
    """HMAC-SHA256 sign an audit event JSON string.

    Args:
        event_json: JSON string of the event.
        secret_key: HMAC key.

    Returns:
        Hex-encoded HMAC digest.
    """
    return hmac.new(
        secret_key.encode("utf-8"),
        event_json.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_event_signature(event_json: str, signature: str, secret_key: str) -> bool:
    """Verify HMAC-SHA256 signature of an audit event.

    Uses constant-time comparison to prevent timing attacks.
    """
    expected = sign_event(event_json, secret_key)
    return hmac.compare_digest(expected, signature)


__all__ = [
    "AuditEventType",
    "AuditEvent",
    "AuditSinkBase",
    "NullSink",
    "HashChainedMixin",
    "sign_event",
    "verify_event_signature",
]