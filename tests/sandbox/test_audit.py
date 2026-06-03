"""Tests for the audit logging module."""

import json

import pytest

from picosentry.sandbox.audit import AuditEvent, AuditEventType, AuditLogger


@pytest.fixture
def audit_dir(tmp_path):
    return tmp_path / "audit"


@pytest.fixture
def audit(audit_dir):
    return AuditLogger(log_dir=audit_dir, max_bytes=1024 * 1024)


class TestAuditEvent:
    def test_create_event(self):
        event = AuditEvent(
            event_type=AuditEventType.SCAN_START,
            actor="test-user",
            detail="npm install test",
            target="test-pkg",
        )
        assert event.event_type == AuditEventType.SCAN_START
        assert event.actor == "test-user"

    def test_event_to_dict_sorted_keys(self):
        event = AuditEvent(
            event_type=AuditEventType.POLICY_CREATE,
            actor="admin",
            target="test-policy",
            event_id="abc123",
            timestamp="2025-01-01T00:00:00Z",
            prev_hash="hash000",
        )
        d = event.to_dict()
        keys = list(d.keys())
        assert keys == sorted(keys)

    def test_event_to_json_line(self):
        event = AuditEvent(
            event_type=AuditEventType.SCAN_COMPLETE,
            actor="ci",
            event_id="id1",
            timestamp="2025-01-01T00:00:00Z",
            prev_hash="",
        )
        line = event.to_json_line()
        data = json.loads(line)
        assert data["event_type"] == "scan_complete"


class TestAuditLogger:
    def test_record_creates_file(self, audit, audit_dir):
        audit.record(
            event_type=AuditEventType.SCAN_START,
            actor="test-user",
            detail="echo hello",
        )
        assert (audit_dir / "audit.jsonl").is_file()

    def test_record_appends_lines(self, audit):
        audit.record(event_type=AuditEventType.SCAN_START, actor="u1", detail="cmd1")
        audit.record(event_type=AuditEventType.SCAN_COMPLETE, actor="u1", detail="ok")
        audit.record(event_type=AuditEventType.SCAN_ALERT, actor="u1", detail="alert1")

        log_path = audit.log_path
        lines = [line.strip() for line in log_path.read_text().splitlines() if line.strip()]
        assert len(lines) == 3

    def test_chain_integrity(self, audit):
        _e1 = audit.record(event_type=AuditEventType.SCAN_START, actor="u1", detail="cmd1")  # noqa: F841
        _e2 = audit.record(event_type=AuditEventType.SCAN_COMPLETE, actor="u1", detail="ok")  # noqa: F841
        e3 = audit.record(event_type=AuditEventType.POLICY_UPDATE, actor="admin", detail="change")  # noqa: F841

        violations = audit.verify_chain()
        assert violations == []

    def test_chain_detects_tampering(self, audit):
        audit.record(event_type=AuditEventType.SCAN_START, actor="u1", detail="cmd1")
        audit.record(event_type=AuditEventType.SCAN_COMPLETE, actor="u1", detail="ok")

        # Tamper with the first line
        log_path = audit.log_path
        lines = log_path.read_text().splitlines()
        data = json.loads(lines[0])
        data["detail"] = "TAMPERED"
        lines[0] = json.dumps(data, sort_keys=True)
        log_path.write_text("\n".join(lines) + "\n")

        violations = audit.verify_chain()
        assert len(violations) > 0

    def test_query_by_event_type(self, audit):
        audit.record(event_type=AuditEventType.SCAN_START, actor="u1", detail="cmd1")
        audit.record(event_type=AuditEventType.SCAN_COMPLETE, actor="u1", detail="ok")
        audit.record(event_type=AuditEventType.POLICY_UPDATE, actor="admin", detail="change")

        results = audit.query(event_type=AuditEventType.SCAN_START)
        assert len(results) == 1
        assert results[0].event_type == AuditEventType.SCAN_START

    def test_query_by_actor(self, audit):
        audit.record(event_type=AuditEventType.SCAN_START, actor="alice", detail="cmd1")
        audit.record(event_type=AuditEventType.SCAN_START, actor="bob", detail="cmd2")
        audit.record(event_type=AuditEventType.SCAN_COMPLETE, actor="alice", detail="ok")

        results = audit.query(actor="alice")
        assert len(results) == 2

    def test_get_stats(self, audit):
        audit.record(event_type=AuditEventType.SCAN_START, actor="u1", detail="cmd1")
        stats = audit.get_stats()
        assert stats["exists"] is True
        assert stats["events"] == 1
        assert stats["chain_intact"] is True

    def test_rotation(self, audit_dir):
        # Small max_bytes to trigger rotation quickly
        small_audit = AuditLogger(log_dir=audit_dir, max_bytes=200, rotate_count=3)
        for i in range(50):
            small_audit.record(
                event_type=AuditEventType.SCAN_START,
                actor="load-test",
                detail=f"iteration-{i}" + "x" * 20,
            )
        # At least one rotated file should exist
        rotated = list(audit_dir.glob("*.jsonl.gz"))
        assert len(rotated) >= 1

    def test_prev_hash_chain(self, audit):
        import hashlib

        e1 = audit.record(event_type=AuditEventType.SCAN_START, actor="u1", detail="first")  # noqa: F841
        e2 = audit.record(event_type=AuditEventType.SCAN_COMPLETE, actor="u1", detail="second")  # noqa: F841

        # e2's prev_hash should be the SHA-256 of e1's JSON line
        log_path = audit.log_path
        lines = [line.strip() for line in log_path.read_text().splitlines() if line.strip()]
        line1_hash = hashlib.sha256(lines[0].encode("utf-8")).hexdigest()

        data2 = json.loads(lines[1])
        assert data2["prev_hash"] == line1_hash

    def test_empty_log_verify(self, audit_dir):
        audit = AuditLogger(log_dir=audit_dir)
        # No events yet — verify should pass
        violations = audit.verify_chain()
        assert violations == [] or any("not found" in v for v in violations)


class TestAuditEventTypes:
    def test_all_scan_types(self):
        assert AuditEventType.SCAN_START.value == "scan_start"
        assert AuditEventType.SCAN_COMPLETE.value == "scan_complete"
        assert AuditEventType.SCAN_ALERT.value == "scan_alert"

    def test_all_policy_types(self):
        assert AuditEventType.POLICY_CREATE.value == "policy_create"
        assert AuditEventType.POLICY_UPDATE.value == "policy_update"
        assert AuditEventType.POLICY_ROLLBACK.value == "policy_rollback"
        assert AuditEventType.POLICY_DELETE.value == "policy_delete"

    def test_daemon_types(self):
        assert AuditEventType.DAEMON_START.value == "daemon_start"
        assert AuditEventType.DAEMON_STOP.value == "daemon_stop"
        assert AuditEventType.AUTH_SUCCESS.value == "auth_success"
        assert AuditEventType.AUTH_FAILURE.value == "auth_failure"

    def test_security_enforcement_types(self):
        assert AuditEventType.COMMAND_DENIED.value == "command_denied"
        assert AuditEventType.RATE_LIMITED.value == "rate_limited"

    def test_data_governance_types(self):
        assert AuditEventType.DATA_RETENTION_CLEANUP.value == "data_retention_cleanup"
        assert AuditEventType.DATA_EXPORT.value == "data_export"
        assert AuditEventType.DATA_DELETE.value == "data_delete"
