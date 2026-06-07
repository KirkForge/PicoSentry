
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


class AuditEventType(str, Enum):

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


class AuditSinkBase(ABC):

    def __init__(self) -> None:
        self._stats: dict[str, Any] = {
            "events_sent": 0,
            "events_failed": 0,
            "events_dropped": 0,
            "last_send_time": None,
            "last_error": None,
        }

    @abstractmethod
    def start(self) -> None:
        """Open connections, create files, etc. Override if needed."""

    @abstractmethod
    def stop(self) -> None:
        """Clean up resources. Override if needed."""

    @abstractmethod
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

    def send(self, event: AuditEvent) -> None:
        self._record_success()


class HashChainedMixin:

    def compute_event_hash(self, line: str) -> str:
        return hashlib.sha256(line.encode("utf-8")).hexdigest()

    def chain_event(self, event_dict: dict[str, Any], prev_hash: str) -> dict[str, Any]:
        event_dict["prev_hash"] = prev_hash
        return event_dict

    def verify_chain(self, lines: list[str]) -> list[str]:
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


def sign_event(event_json: str, secret_key: str) -> str:
    return hmac.new(
        secret_key.encode("utf-8"),
        event_json.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_event_signature(event_json: str, signature: str, secret_key: str) -> bool:
    expected = sign_event(event_json, secret_key)
    return hmac.compare_digest(expected, signature)


__all__ = [
    "AuditEvent",
    "AuditEventType",
    "AuditSinkBase",
    "HashChainedMixin",
    "NullSink",
    "sign_event",
    "verify_event_signature",
]
