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
        _e1 = audit.record(event_type=AuditEventType.SCAN_START, actor="u1", detail="cmd1")
        _e2 = audit.record(event_type=AuditEventType.SCAN_COMPLETE, actor="u1", detail="ok")
        _ = audit.record(event_type=AuditEventType.POLICY_UPDATE, actor="admin", detail="change")

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

    def test_query_returns_most_recent_window(self, audit):
        """WO5.0.0-018: query(limit=N) must return the N MOST RECENT events —
        the old forward-scan-and-break returned the N oldest in reversed dress."""
        for i in range(6):
            audit.record(event_type=AuditEventType.SCAN_START, actor=f"a{i}", detail=f"e{i}")

        results = audit.query(limit=3)
        assert [e.actor for e in results] == ["a5", "a4", "a3"]

    def test_query_limit_with_filter_returns_latest_matches(self, audit):
        audit.record(event_type=AuditEventType.SCAN_START, actor="a", detail="0")
        audit.record(event_type=AuditEventType.SCAN_COMPLETE, actor="a", detail="1")
        audit.record(event_type=AuditEventType.SCAN_START, actor="a", detail="2")
        audit.record(event_type=AuditEventType.SCAN_COMPLETE, actor="a", detail="3")
        audit.record(event_type=AuditEventType.SCAN_START, actor="a", detail="4")

        results = audit.query(event_type=AuditEventType.SCAN_START, limit=2)
        assert [e.detail for e in results] == ["4", "2"]

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

        _ = audit.record(event_type=AuditEventType.SCAN_START, actor="u1", detail="first")
        _ = audit.record(event_type=AuditEventType.SCAN_COMPLETE, actor="u1", detail="second")

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

    def test_crash_recovery_chain_reseed(self, audit_dir):
        # Simulate a crash: write entries, drop the logger (process restart),
        # re-open the file with a fresh logger, append, and verify the chain.
        first = AuditLogger(log_dir=audit_dir)
        first.record(event_type=AuditEventType.SCAN_START, actor="u1", detail="cmd1")
        first.record(event_type=AuditEventType.SCAN_COMPLETE, actor="u1", detail="ok")

        # "Crash" — new process, no in-memory prev_hash.
        restarted = AuditLogger(log_dir=audit_dir)
        restarted.record(event_type=AuditEventType.SCAN_ALERT, actor="u1", detail="alert1")

        violations = restarted.verify_chain()
        assert violations == []

    def test_verify_chain_walks_rotated_archives_clean(self, audit_dir):
        # Normal rotation yields correct cross-boundary links; verify_chain must
        # now walk the .gz archives + live log and report no violations.
        audit = AuditLogger(log_dir=audit_dir, max_bytes=200, rotate_count=3)
        for i in range(40):
            audit.record(
                event_type=AuditEventType.SCAN_START,
                actor="rot",
                detail=f"iter-{i}" + "y" * 20,
            )
        assert list(audit_dir.glob("*.1.jsonl.gz")), "rotation should have occurred"
        assert audit.verify_chain() == []

    def test_query_walks_rotated_archives(self, audit_dir):
        """WO6.0.0-018: query() used to read only the live file — after a
        rotation, query(limit=1000) returned just the live window (3 events)
        while verify_chain walked the archives (data existed). Must now return
        the full history across archives + live."""
        # max_bytes=400 (~2 events/file), rotate_count=20 retains all 40.
        audit = AuditLogger(log_dir=audit_dir, max_bytes=400, rotate_count=20)
        for i in range(40):
            audit.record(
                event_type=AuditEventType.SCAN_START,
                actor="rot",
                detail=f"iter-{i}" + "y" * 20,
            )
        assert list(audit_dir.glob("*.1.jsonl.gz")), "rotation should have occurred"

        events = audit.query(limit=1000)
        # Before the fix this returned ~2 (live-only). Must return all 40.
        assert len(events) == 40, f"archive-aware query returned {len(events)} events, expected 40"

    def test_get_stats_counts_archives(self, audit_dir):
        """WO6.0.0-018: get_stats() used to count only the live file — a
        freshly-rotated log reported events=0 while the data lived in archives."""
        audit = AuditLogger(log_dir=audit_dir, max_bytes=400, rotate_count=20)
        for i in range(40):
            audit.record(
                event_type=AuditEventType.SCAN_START,
                actor="rot",
                detail=f"iter-{i}" + "y" * 20,
            )
        assert list(audit_dir.glob("*.1.jsonl.gz")), "rotation should have occurred"

        stats = audit.get_stats()
        assert stats["events"] == 40, f"archive-aware stats counted {stats['events']} events, expected 40"
        assert stats["exists"] is True
        assert stats["size_bytes"] > 0

    def test_query_limit_bounds_across_archives(self, audit_dir):
        """The deque bound applies across archives + live — newest `limit`
        events, not `limit` per source."""
        audit = AuditLogger(log_dir=audit_dir, max_bytes=400, rotate_count=20)
        for i in range(40):
            audit.record(
                event_type=AuditEventType.SCAN_START,
                actor="rot",
                detail=f"iter-{i}" + "y" * 20,
            )
        events = audit.query(limit=5)
        assert len(events) == 5
        # Newest first — iter-39 at index 0 down to iter-35 at index 4.
        details = [e.detail for e in events]
        for offset, i in enumerate(range(39, 34, -1)):
            assert f"iter-{i}" in details[offset], details

    def test_verify_chain_detects_archive_tamper(self, audit_dir):
        import gzip

        audit = AuditLogger(log_dir=audit_dir, max_bytes=200, rotate_count=3)
        for i in range(40):
            audit.record(
                event_type=AuditEventType.SCAN_START,
                actor="rot",
                detail=f"iter-{i}" + "y" * 20,
            )
        archive = audit_dir / "audit.1.jsonl.gz"
        assert archive.is_file()
        # Inject a line whose prev_hash breaks the chain.
        with gzip.open(archive, "at", encoding="utf-8") as f:
            f.write('{"prev_hash": "deadbeef", "event_type": "scan_start"}\n')
        fresh = AuditLogger(log_dir=audit_dir, max_bytes=200, rotate_count=3)
        violations = fresh.verify_chain()
        assert violations, "tampered archive must be detected across the rotation boundary"
        assert any("prev_hash mismatch" in v for v in violations)

    def test_reseed_from_archive_when_live_truncated(self, audit_dir):
        import hashlib

        audit = AuditLogger(log_dir=audit_dir, max_bytes=200, rotate_count=3)
        for i in range(40):
            audit.record(
                event_type=AuditEventType.SCAN_START,
                actor="rot",
                detail=f"iter-{i}" + "y" * 20,
            )
        archive = audit_dir / "audit.1.jsonl.gz"
        assert archive.is_file()
        # Crash window: rotation truncated the live log to empty and the process
        # restarted before the next write completed.
        audit.log_path.write_text("", encoding="utf-8")

        restarted = AuditLogger(log_dir=audit_dir, max_bytes=200, rotate_count=3)
        evt = restarted.record(event_type=AuditEventType.SCAN_ALERT, actor="rot", detail="after-crash")
        # The new event must link to the archive's last line, not "".
        last_archive_line = AuditLogger._last_nonempty_line(archive, gzipped=True)
        assert evt.prev_hash == hashlib.sha256(last_archive_line.encode("utf-8")).hexdigest()
        assert restarted.verify_chain() == []

    def test_fsync_knob_default_on(self, audit_dir):
        audit = AuditLogger(log_dir=audit_dir)
        assert audit._fsync is True

    def test_fsync_knob_off(self, audit_dir):
        audit = AuditLogger(log_dir=audit_dir, fsync=False)
        assert audit._fsync is False


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
