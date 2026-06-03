"""Tests for schema versioning in audit logger and job store."""

import json
import tempfile
from pathlib import Path

from picosentry.sandbox.audit.logger import AUDIT_SCHEMA_VERSION, AuditEventType, AuditLogger
from picosentry.sandbox.daemon.store import JOB_STORE_SCHEMA_VERSION, PersistentScanJobStore


class TestAuditSchemaVersioning:
    """Test audit log schema versioning."""

    def test_schema_version_constant(self):
        assert AUDIT_SCHEMA_VERSION == 2

    def test_event_has_schema_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            logger = AuditLogger(log_dir=Path(tmp))
            event = logger.record(
                event_type=AuditEventType.SCAN_START,
                actor="test-user",
                detail="test event",
            )
            data = event.to_dict()
            assert "schema_version" in data
            assert data["schema_version"] == AUDIT_SCHEMA_VERSION

    def test_schema_version_in_log_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            logger = AuditLogger(log_dir=Path(tmp))
            logger.record(
                event_type=AuditEventType.SCAN_START,
                actor="test-user",
                detail="versioned event",
            )
            # Read the log file
            log_path = logger.log_path
            with open(log_path) as f:
                line = f.readline().strip()
                data = json.loads(line)
                assert "schema_version" in data
                assert data["schema_version"] == 2

    def test_query_reads_v2_events(self):
        with tempfile.TemporaryDirectory() as tmp:
            logger = AuditLogger(log_dir=Path(tmp))
            logger.record(
                event_type=AuditEventType.SCAN_COMPLETE,
                actor="ci",
                detail="scan done",
            )
            events = logger.query(event_type=AuditEventType.SCAN_COMPLETE)
            assert len(events) == 1

    def test_stats_includes_schema_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            logger = AuditLogger(log_dir=Path(tmp))
            logger.record(
                event_type=AuditEventType.SCAN_START,
                actor="test",
                detail="test",
            )
            stats = logger.get_stats()
            assert "schema_version" in stats
            assert stats["schema_version"] == AUDIT_SCHEMA_VERSION


class TestJobStoreSchemaVersioning:
    """Test job store schema versioning."""

    def test_schema_version_constant(self):
        assert JOB_STORE_SCHEMA_VERSION == 2

    def test_job_has_schema_version(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PersistentScanJobStore(store_dir=Path(tmp))
            job = store.add("test-1", ["echo", "hello"], "test-actor")
            assert "schema_version" in job
            assert job["schema_version"] == JOB_STORE_SCHEMA_VERSION

    def test_schema_version_in_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = PersistentScanJobStore(store_dir=Path(tmp))
            store.add("test-2", ["ls"], "actor")
            # Read the file
            store_file = Path(tmp) / "jobs.jsonl"
            with open(store_file) as f:
                line = f.readline().strip()
                data = json.loads(line)
                assert "schema_version" in data
                assert data["schema_version"] == 2
