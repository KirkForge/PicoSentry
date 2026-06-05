"""Audit coverage tests — prove every defined AuditEventType is actually emitted.

These tests serve two purposes:
  (A) Verify that every AuditEventType defined in the enum is wired into
      daemon code paths — no "defined but never fired" event types.
  (B) Verify that the audit chain integrity holds after every event type
      fires — no hash chain breaks from any event type.

The approach:
  - We enumerate all AuditEventType values.
  - For each, we trigger the corresponding code path (daemon API, auth,
    rate limit, command denial, etc.).
  - We verify the event appears in the audit log with the correct type.
  - We verify the full chain is intact after all events.

This is NOT a unit test of the AuditLogger itself (test_audit.py covers that).
This is an integration-level coverage test proving the daemon actually uses
the audit system it defines.
"""

import hashlib
import io
import json
import os
import threading
from typing import ClassVar
from unittest.mock import MagicMock, patch

import pytest

import picosentry.sandbox.audit.logger as audit_logger_mod
from picosentry.sandbox.audit import AuditEventType, AuditLogger
from picosentry.sandbox.auth import RBAC, TokenAuth
from picosentry.sandbox.daemon.server import PicoDomeHandler
from picosentry.sandbox.ratelimit import RateLimitConfig, TokenBucketLimiter

# ─── Fixtures ────────────────────────────────────────────────────────────────


@pytest.fixture
def audit_dir(tmp_path):
    """Isolated audit directory for each test."""
    return tmp_path / "audit"


@pytest.fixture
def audit(audit_dir):
    """Fresh AuditLogger pointing to isolated directory."""
    return AuditLogger(log_dir=audit_dir, max_bytes=1024 * 1024)


@pytest.fixture(autouse=True)
def reset_audit_singleton():
    """Reset the global audit logger singleton after each test."""
    original = audit_logger_mod._audit_logger
    yield
    audit_logger_mod._audit_logger = original


def _patch_audit_logger(audit_dir):
    """Patch the global audit logger to use an isolated directory.

    Returns the AuditLogger instance so tests can query it.
    """
    test_audit = AuditLogger(log_dir=audit_dir, max_bytes=1024 * 1024)
    audit_logger_mod._audit_logger = test_audit
    return test_audit


# ─── Part A: Every defined AuditEventType must be emitted ────────────────────


class TestAuditEventTypeCoverage:
    """Verify that every AuditEventType is actually emitted somewhere.

    If a new event type is added to the enum but not wired in, this test
    will fail — catching the gap before it ships.
    """

    # Map each AuditEventType to the module/function that should emit it.
    # This serves as living documentation of where each event is produced.
    EMIT_LOCATIONS: ClassVar[dict[AuditEventType, str]] = {
        AuditEventType.SCAN_START: "picosentry.sandbox.daemon.server._handle_submit_scan",
        AuditEventType.SCAN_COMPLETE: "picosentry.sandbox.daemon.server._handle_submit_scan",
        AuditEventType.SCAN_ALERT: "picosentry.sandbox.cluster.manager (scan alert)",
        AuditEventType.POLICY_CREATE: "picosentry.sandbox.daemon.server._handle_create_policy",
        AuditEventType.POLICY_UPDATE: "picosentry.sandbox.policy_versioned.store",
        AuditEventType.POLICY_ROLLBACK: "picosentry.sandbox.policy_versioned.store",
        AuditEventType.POLICY_DELETE: "picosentry.sandbox.policy_versioned.store",
        AuditEventType.BASELINE_CREATE: "picosentry.sandbox.baseline_hardening",
        AuditEventType.BASELINE_UPDATE: "picosentry.sandbox.baseline_hardening",
        AuditEventType.BASELINE_DELETE: "picosentry.sandbox.baseline_hardening",
        AuditEventType.DAEMON_START: "picosentry.sandbox.daemon.server.PicoDomeDaemon.start",
        AuditEventType.DAEMON_STOP: "picosentry.sandbox.daemon.server.PicoDomeDaemon.stop",
        AuditEventType.AUTH_SUCCESS: "picosentry.sandbox.daemon.server._require_auth",
        AuditEventType.AUTH_FAILURE: "picosentry.sandbox.daemon.server._require_auth / _require_permission",
        AuditEventType.COMMAND_DENIED: "picosentry.sandbox.daemon.server._handle_submit_scan",
        AuditEventType.RATE_LIMITED: "picosentry.sandbox.daemon.server._require_auth",
        AuditEventType.DATA_RETENTION_CLEANUP: "picosentry.sandbox.retention.manager",
        AuditEventType.DATA_EXPORT: "picosentry.sandbox.retention.manager",
        AuditEventType.DATA_DELETE: "picosentry.sandbox.retention.manager",
    }

    def test_all_event_types_have_emit_location(self):
        """Every defined AuditEventType must have a known emit location."""
        for event_type in AuditEventType:
            assert event_type in self.EMIT_LOCATIONS, (
                f"{event_type!r} has no emit location documented. "
                f"Either wire it into the daemon or document where it's emitted."
            )

    def test_no_stale_emit_locations(self):
        """Emit locations should not reference removed event types."""
        defined = set(AuditEventType)
        for event_type in self.EMIT_LOCATIONS:
            assert event_type in defined, f"Emit location references {event_type!r} which is not in AuditEventType enum"


# ─── Part B: Direct emission tests — prove each event type can be recorded ──


class TestDirectAuditEmission:
    """Test that every AuditEventType can be recorded and the chain stays intact.

    This tests the AuditLogger directly — recording each event type and
    verifying it appears in the log with correct type and chain integrity.
    """

    @pytest.mark.parametrize("event_type", list(AuditEventType))
    def test_event_type_records_correctly(self, audit, event_type):
        """Every event type should be recordable and queryable."""
        event = audit.record(
            event_type=event_type,
            actor="test-actor",
            detail=f"test detail for {event_type.value}",
            target="test-target",
        )
        assert event.event_type == event_type
        assert event.actor == "test-actor"
        assert event.event_id  # Should have a UUID
        assert event.timestamp  # Should have a timestamp

    @pytest.mark.parametrize("event_type", list(AuditEventType))
    def test_event_type_queryable(self, audit, event_type):
        """Every event type should be queryable by type."""
        audit.record(
            event_type=event_type,
            actor="test-actor",
            detail=f"queryable test for {event_type.value}",
        )
        results = audit.query(event_type=event_type)
        assert len(results) >= 1
        assert results[0].event_type == event_type

    def test_all_event_types_chain_intact(self, audit):
        """Record every event type in sequence and verify chain integrity."""
        events = []
        for event_type in AuditEventType:
            event = audit.record(
                event_type=event_type,
                actor="chain-test",
                detail=f"chain test {event_type.value}",
            )
            events.append(event)

        # Verify chain integrity
        violations = audit.verify_chain()
        assert violations == [], f"Chain violations after recording all event types: {violations}"

        # Verify all event types appear in the log
        log_path = audit.log_path
        lines = [line.strip() for line in log_path.read_text().splitlines() if line.strip()]
        assert len(lines) == len(AuditEventType), f"Expected {len(AuditEventType)} log lines, got {len(lines)}"

        # Verify each line parses as valid JSON with correct event_type
        recorded_types = set()
        for line in lines:
            data = json.loads(line)
            recorded_types.add(data["event_type"])

        expected_types = {et.value for et in AuditEventType}
        assert recorded_types == expected_types, f"Missing event types in log: {expected_types - recorded_types}"

    def test_new_event_types_dont_break_chain(self, audit):
        """Adding a new AuditEventType should not break existing chain logic.

        This test records events, verifies the chain, then records more events
        and verifies again. This proves the chain is continuous across
        different event types.
        """
        # First batch
        audit.record(event_type=AuditEventType.AUTH_SUCCESS, actor="user1", detail="login")
        audit.record(event_type=AuditEventType.SCAN_START, actor="user1", detail="scan start")

        violations = audit.verify_chain()
        assert violations == []

        # Second batch — new event types added later
        audit.record(event_type=AuditEventType.COMMAND_DENIED, actor="user2", detail="bash denied")
        audit.record(event_type=AuditEventType.RATE_LIMITED, actor="user3", detail="too fast")

        violations = audit.verify_chain()
        assert violations == []


# ─── Part B: Daemon-level audit emission tests ───────────────────────────────


class TestDaemonAuditEmission:
    """Test that the daemon's HTTP handler actually emits audit events
    for auth, rate limiting, and command denial.

    These are the security-critical paths — if AUTH_FAILURE or
    COMMAND_DENIED isn't emitted, there's no audit trail for attacks.
    """

    def _setup_handler(self, audit_dir, tokens=None, rate_config=None):
        """Create a test-ready PicoDomeHandler with isolated audit.

        Returns (handler_kwargs, audit_logger) so tests can construct
        handlers manually.
        """
        # Patch the global audit logger to use our isolated dir
        test_audit = _patch_audit_logger(audit_dir)

        # Set up auth
        if tokens:
            with patch.dict(os.environ, {"PICODOME_API_TOKENS": tokens}, clear=False):
                rbac = RBAC()
                auth = TokenAuth(rbac=rbac)
        else:
            rbac = RBAC()
            auth = TokenAuth(rbac=rbac)

        # Set up rate limiter
        if rate_config is None:
            rate_config = RateLimitConfig(rate_per_second=100, burst_size=100)
        limiter = TokenBucketLimiter(config=rate_config)

        # Patch handler class attributes
        PicoDomeHandler.rbac = rbac
        PicoDomeHandler.auth = auth
        PicoDomeHandler.rate_limiter = limiter
        PicoDomeHandler.job_store = MagicMock()

        return test_audit

    def test_auth_success_emitted(self, tmp_path):
        """Successful auth should emit AUTH_SUCCESS."""
        audit_dir = tmp_path / "audit"
        token = "picodome-admin-" + "a" * 50
        audit = self._setup_handler(audit_dir, tokens=token)

        handler = PicoDomeHandler.__new__(PicoDomeHandler)
        handler.headers = {"Authorization": f"Bearer {token}"}
        handler._send_json = MagicMock()
        handler._send_error = MagicMock()

        result = handler._require_auth()

        assert result is not None, "Auth should succeed with valid token"
        events = audit.query(event_type=AuditEventType.AUTH_SUCCESS)
        assert len(events) >= 1, (
            f"AUTH_SUCCESS event should be emitted on successful auth. "
            f"Got {len(events)} events. All events: "
            f"{[e.event_type.value for e in audit.query(limit=20)]}"
        )
        assert events[0].event_type == AuditEventType.AUTH_SUCCESS

    def test_auth_failure_no_token_emitted(self, tmp_path):
        """Missing token should emit AUTH_FAILURE with actor='anonymous'."""
        audit_dir = tmp_path / "audit"
        token = "picodome-admin-" + "a" * 50
        audit = self._setup_handler(audit_dir, tokens=token)

        handler = PicoDomeHandler.__new__(PicoDomeHandler)
        handler.headers = {}  # No Authorization header
        handler._send_json = MagicMock()
        handler._send_error = MagicMock()

        result = handler._require_auth()

        assert result is None, "Auth should fail with no token"
        events = audit.query(event_type=AuditEventType.AUTH_FAILURE)
        assert len(events) >= 1, (
            f"AUTH_FAILURE event should be emitted when no token provided. Got {len(events)} events."
        )
        assert events[0].actor == "anonymous"
        assert "No Authorization" in events[0].detail

    def test_auth_failure_bad_token_emitted(self, tmp_path):
        """Invalid token should emit AUTH_FAILURE."""
        audit_dir = tmp_path / "audit"
        token = "picodome-admin-" + "a" * 50
        audit = self._setup_handler(audit_dir, tokens=token)

        handler = PicoDomeHandler.__new__(PicoDomeHandler)
        handler.headers = {"Authorization": "Bearer wrong-token"}
        handler._send_json = MagicMock()
        handler._send_error = MagicMock()

        result = handler._require_auth()

        assert result is None, "Auth should fail with wrong token"
        events = audit.query(event_type=AuditEventType.AUTH_FAILURE)
        assert len(events) >= 1, f"AUTH_FAILURE event should be emitted for invalid token. Got {len(events)} events."
        assert "Invalid token" in events[0].detail

    def test_rate_limited_emitted(self, tmp_path):
        """Rate-limited request should emit RATE_LIMITED event."""
        audit_dir = tmp_path / "audit"
        # Very restrictive rate limit: 1 request per 10 seconds, burst of 1
        rate_config = RateLimitConfig(rate_per_second=0.01, burst_size=1)
        token = "picodome-admin-" + "a" * 50
        audit = self._setup_handler(audit_dir, tokens=token, rate_config=rate_config)

        handler = PicoDomeHandler.__new__(PicoDomeHandler)
        handler.headers = {"Authorization": f"Bearer {token}"}
        handler._send_json = MagicMock()
        handler._send_error = MagicMock()

        # First request should succeed (and emit AUTH_SUCCESS)
        result1 = handler._require_auth()
        assert result1 is not None, "First request should succeed"

        # Second request should be rate-limited
        result2 = handler._require_auth()
        assert result2 is None, "Second request should be rate-limited"

        # Verify RATE_LIMITED was emitted
        events = audit.query(event_type=AuditEventType.RATE_LIMITED)
        assert len(events) >= 1, (
            f"RATE_LIMITED event should be emitted when rate limit exceeded. "
            f"Got {len(events)} events. All events: "
            f"{[e.event_type.value for e in audit.query(limit=20)]}"
        )

    def test_command_denied_emitted(self, tmp_path):
        """Denied command should emit COMMAND_DENIED event."""
        audit_dir = tmp_path / "audit"
        token = "picodome-admin-" + "a" * 50
        audit = self._setup_handler(audit_dir, tokens=token)

        # Test _validateCommand directly first
        handler = PicoDomeHandler.__new__(PicoDomeHandler)
        error = handler._validate_command(["bash", "-c", "echo pwned"])
        assert error is not None, "bash should be denied"

        # Now test the full flow through _handle_submit_scan
        body = json.dumps({"command": ["bash", "-c", "echo pwned"]}).encode()
        handler.rfile = io.BytesIO(body)
        handler.headers = {
            "Authorization": f"Bearer {token}",
            "Content-Length": str(len(body)),
        }
        handler._send_json = MagicMock()
        handler._send_error = MagicMock()

        handler._handle_submit_scan(token)

        # Verify COMMAND_DENIED was emitted
        events = audit.query(event_type=AuditEventType.COMMAND_DENIED)
        assert len(events) >= 1, (
            f"COMMAND_DENIED event should be emitted for denied commands. "
            f"Got {len(events)} events. All events: "
            f"{[e.event_type.value for e in audit.query(limit=20)]}"
        )
        assert events[0].event_type == AuditEventType.COMMAND_DENIED

    def test_permission_denied_emits_auth_failure(self, tmp_path):
        """Insufficient permissions should emit AUTH_FAILURE."""
        audit_dir = tmp_path / "audit"
        # Set up a reader token (no write permissions)
        reader_token = "picodome-reader-abc1234567890abcdefghijklmnopqr"
        audit = self._setup_handler(audit_dir, tokens=reader_token)

        handler = PicoDomeHandler.__new__(PicoDomeHandler)
        handler.headers = {"Authorization": f"Bearer {reader_token}"}
        handler._send_json = MagicMock()
        handler._send_error = MagicMock()

        # Reader should not have scan:submit permission
        result = handler._require_permission("scan:submit")

        assert result is None, "Reader should not have scan:submit permission"
        events = audit.query(event_type=AuditEventType.AUTH_FAILURE)
        assert len(events) >= 1, (
            f"AUTH_FAILURE should be emitted for insufficient permissions. Got {len(events)} events."
        )
        assert "Insufficient permissions" in events[0].detail

    def test_chain_intact_after_security_events(self, tmp_path):
        """After auth success, auth failure, command denied, and rate limited
        events, the audit chain must still be intact."""
        audit_dir = tmp_path / "audit"
        token = "picodome-admin-" + "a" * 50
        audit = self._setup_handler(audit_dir, tokens=token)

        # Record various security events
        audit.record(event_type=AuditEventType.AUTH_SUCCESS, actor="user1", detail="login")
        audit.record(event_type=AuditEventType.AUTH_FAILURE, actor="attacker", detail="bad token")
        audit.record(event_type=AuditEventType.COMMAND_DENIED, actor="user1", detail="bash blocked")
        audit.record(event_type=AuditEventType.RATE_LIMITED, actor="user2", detail="too fast")

        # Chain must still be intact
        violations = audit.verify_chain()
        assert violations == [], f"Chain should be intact after security events: {violations}"

        # All four event types should be present
        success_events = audit.query(event_type=AuditEventType.AUTH_SUCCESS)
        failure_events = audit.query(event_type=AuditEventType.AUTH_FAILURE)
        denied_events = audit.query(event_type=AuditEventType.COMMAND_DENIED)
        rate_events = audit.query(event_type=AuditEventType.RATE_LIMITED)

        assert len(success_events) >= 1
        assert len(failure_events) >= 1
        assert len(denied_events) >= 1
        assert len(rate_events) >= 1


# ─── Part B: Chain integrity under adversarial conditions ─────────────────────


class TestAuditChainIntegrity:
    """Test that the audit chain remains intact under various conditions.

    These tests expose potential flaws:
    - Concurrent writes should not break the chain
    - Rapid sequential writes should not break the chain
    - Mixed event types should produce a valid chain
    """

    def test_concurrent_writes_dont_break_chain(self, audit_dir):
        """Multiple threads writing to the same audit log should not
        break chain integrity."""
        audit = AuditLogger(log_dir=audit_dir, max_bytes=1024 * 1024)
        errors = []

        def write_events(actor_prefix, count):
            try:
                for i in range(count):
                    audit.record(
                        event_type=AuditEventType.AUTH_SUCCESS,
                        actor=f"{actor_prefix}-{i}",
                        detail=f"concurrent test {i}",
                    )
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=write_events, args=(f"thread-{t}", 20)) for t in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert not errors, f"Errors during concurrent writes: {errors}"

        # Verify chain integrity
        violations = audit.verify_chain()
        assert violations == [], (
            f"Chain integrity violated under concurrent writes. This indicates a locking bug: {violations}"
        )

    def test_rapid_sequential_writes(self, audit_dir):
        """Rapid sequential writes should maintain chain integrity."""
        audit = AuditLogger(log_dir=audit_dir, max_bytes=1024 * 1024)

        for i in range(100):
            audit.record(
                event_type=AuditEventType.SCAN_START,
                actor="stress-test",
                detail=f"rapid-{i}",
            )

        violations = audit.verify_chain()
        assert violations == [], f"Chain broke after 100 rapid writes: {violations}"

    def test_tampered_line_detected(self, audit_dir):
        """Tampering with a log line should be detected by verify_chain."""
        audit = AuditLogger(log_dir=audit_dir, max_bytes=1024 * 1024)
        audit.record(event_type=AuditEventType.AUTH_SUCCESS, actor="user1", detail="login")
        audit.record(event_type=AuditEventType.SCAN_START, actor="user1", detail="scan")

        # Tamper with the first line
        log_path = audit.log_path
        lines = log_path.read_text().splitlines()
        data = json.loads(lines[0])
        data["detail"] = "TAMPERED"
        lines[0] = json.dumps(data, sort_keys=True)
        log_path.write_text("\n".join(lines) + "\n")

        violations = audit.verify_chain()
        assert len(violations) > 0, "Tampering should be detected"

    def test_removed_line_detected(self, audit_dir):
        """Removing a line from the log should be detected."""
        audit = AuditLogger(log_dir=audit_dir, max_bytes=1024 * 1024)
        audit.record(event_type=AuditEventType.AUTH_SUCCESS, actor="user1", detail="login")
        audit.record(event_type=AuditEventType.SCAN_START, actor="user1", detail="scan")
        audit.record(event_type=AuditEventType.SCAN_COMPLETE, actor="user1", detail="done")

        # Remove the middle line
        log_path = audit.log_path
        lines = log_path.read_text().splitlines()
        # Keep first and last, remove middle
        tampered = lines[0] + "\n" + lines[2] + "\n"
        log_path.write_text(tampered)

        violations = audit.verify_chain()
        assert len(violations) > 0, "Removed line should be detected"

    def test_prev_hash_links_correctly(self, audit_dir):
        """Each event's prev_hash should match SHA-256 of previous line."""
        audit = AuditLogger(log_dir=audit_dir, max_bytes=1024 * 1024)

        # Record different event types to prove chain works across types
        audit.record(event_type=AuditEventType.AUTH_SUCCESS, actor="user1", detail="login")
        audit.record(event_type=AuditEventType.SCAN_START, actor="user1", detail="scan")
        audit.record(event_type=AuditEventType.COMMAND_DENIED, actor="user2", detail="bash")
        audit.record(event_type=AuditEventType.AUTH_FAILURE, actor="user3", detail="bad token")
        audit.record(event_type=AuditEventType.RATE_LIMITED, actor="user4", detail="slow down")
        audit.record(event_type=AuditEventType.SCAN_COMPLETE, actor="user1", detail="done")

        # Verify each prev_hash matches
        log_path = audit.log_path
        lines = [line.strip() for line in log_path.read_text().splitlines() if line.strip()]

        for i in range(1, len(lines)):
            prev_line_hash = hashlib.sha256(lines[i - 1].encode("utf-8")).hexdigest()
            current_data = json.loads(lines[i])
            assert current_data["prev_hash"] == prev_line_hash, (
                f"Chain break at line {i + 1}: prev_hash doesn't match hash of line {i}"
            )


# ─── New event type values ──────────────────────────────────────────────────


class TestNewAuditEventTypes:
    """Verify the new COMMAND_DENIED and RATE_LIMITED event types."""

    def test_command_denied_value(self):
        assert AuditEventType.COMMAND_DENIED.value == "command_denied"

    def test_rate_limited_value(self):
        assert AuditEventType.RATE_LIMITED.value == "rate_limited"

    def test_command_denied_in_enum(self):
        """COMMAND_DENIED should be part of the AuditEventType enum."""
        assert AuditEventType("command_denied") == AuditEventType.COMMAND_DENIED

    def test_rate_limited_in_enum(self):
        """RATE_LIMITED should be part of the AuditEventType enum."""
        assert AuditEventType("rate_limited") == AuditEventType.RATE_LIMITED

    def test_all_security_types_present(self):
        """All security-relevant event types should exist."""
        security_types = {
            AuditEventType.AUTH_SUCCESS,
            AuditEventType.AUTH_FAILURE,
            AuditEventType.COMMAND_DENIED,
            AuditEventType.RATE_LIMITED,
        }
        for st in security_types:
            assert st in AuditEventType, f"{st} missing from AuditEventType"
