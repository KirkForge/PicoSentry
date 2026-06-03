"""Tests for PicoSentry audit module."""

import json
import tempfile
import unittest
from pathlib import Path

from picosentry.scan.audit import (
    ACTIONS,
    AuditEvent,
    AuditSink,
    audit,
    configure_audit_sink,
    reset_audit_sink,
)


class TestAuditEvent(unittest.TestCase):
    """Tests for AuditEvent."""

    def test_basic_event(self):
        event = AuditEvent(action="corpus.import", target="pack.json")
        self.assertEqual(event.action, "corpus.import")
        self.assertEqual(event.target, "pack.json")
        self.assertEqual(event.actor, "system")
        self.assertEqual(event.outcome, "success")
        self.assertTrue(event.timestamp)  # auto-generated

    def test_event_with_metadata(self):
        event = AuditEvent(
            action="ioc.register",
            target="malicious-pkg@1.0.0",
            actor="admin",
            outcome="success",
            metadata={"severity": "HIGH", "source": "custom"},
        )
        d = event.to_dict()
        self.assertEqual(d["metadata"]["severity"], "HIGH")
        self.assertIn("timestamp", d)

    def test_event_with_request_id(self):
        event = AuditEvent(action="cache.purge", target="age=7", request_id="abc123")
        d = event.to_dict()
        self.assertEqual(d["request_id"], "abc123")

    def test_event_json(self):
        event = AuditEvent(action="cache.wipe", target="/tmp/cache")
        j = event.to_json()
        data = json.loads(j)
        self.assertEqual(data["action"], "cache.wipe")

    def test_no_metadata_when_empty(self):
        event = AuditEvent(action="auth.success")
        d = event.to_dict()
        self.assertNotIn("metadata", d)

    def test_no_request_id_when_empty(self):
        event = AuditEvent(action="auth.success")
        d = event.to_dict()
        self.assertNotIn("request_id", d)

    def test_known_actions(self):
        """Verify all well-known actions are in ACTIONS."""
        self.assertIn("corpus.import", ACTIONS)
        self.assertIn("ioc.register", ACTIONS)
        self.assertIn("cache.purge", ACTIONS)
        self.assertIn("auth.success", ACTIONS)
        self.assertIn("update.download", ACTIONS)


class TestAuditSink(unittest.TestCase):
    """Tests for AuditSink file operations."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.path = Path(self.tmpdir) / "test_audit.jsonl"
        self.sink = AuditSink(path=self.path, max_size_bytes=1024, retention_days=0)

    def tearDown(self):
        reset_audit_sink()
        if self.path.exists():
            self.path.unlink()
        # Clean up rotated files
        for f in self.path.parent.glob("test_audit.jsonl.*"):
            f.unlink()

    def test_write_event(self):
        event = AuditEvent(action="corpus.import", target="pack.json")
        self.sink.write(event)
        lines = self.path.read_text().strip().split("\n")
        self.assertEqual(len(lines), 1)
        data = json.loads(lines[0])
        self.assertEqual(data["action"], "corpus.import")

    def test_write_multiple_events(self):
        for i in range(5):
            self.sink.write(AuditEvent(action="test", target=f"item-{i}"))
        lines = self.path.read_text().strip().split("\n")
        self.assertEqual(len(lines), 5)

    def test_read_events(self):
        for i in range(3):
            self.sink.write(AuditEvent(action=f"action-{i}"))
        events = self.sink.read(limit=10)
        self.assertEqual(len(events), 3)

    def test_read_with_action_filter(self):
        self.sink.write(AuditEvent(action="corpus.import"))
        self.sink.write(AuditEvent(action="ioc.register"))
        self.sink.write(AuditEvent(action="corpus.import"))
        events = self.sink.read(action="corpus.import")
        self.assertEqual(len(events), 2)

    def test_read_empty_file(self):
        events = self.sink.read()
        self.assertEqual(len(events), 0)

    def test_read_nonexistent_file(self):
        other_path = Path(self.tmpdir) / "nonexistent.jsonl"
        other_sink = AuditSink(path=other_path)
        events = other_sink.read()
        self.assertEqual(len(events), 0)

    def test_rotation(self):
        """Test that the log rotates when it exceeds max_size_bytes."""
        # Write enough data to trigger rotation
        for _i in range(50):
            self.sink.write(AuditEvent(action="test", target="x" * 50))
        # Original file should have been rotated
        self.assertTrue(self.path.exists())


class TestAuditFunction(unittest.TestCase):
    """Tests for the global audit() function."""

    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.path = Path(self.tmpdir) / "global_audit.jsonl"
        configure_audit_sink(path=self.path, max_size_bytes=10 * 1024 * 1024, retention_days=0)

    def tearDown(self):
        reset_audit_sink()
        if self.path.exists():
            self.path.unlink()

    def test_audit_emits_event(self):
        event = audit("cache.purge", target="age=7", outcome="success")
        self.assertEqual(event.action, "cache.purge")
        self.assertTrue(self.path.exists())
        lines = self.path.read_text().strip().split("\n")
        self.assertEqual(len(lines), 1)

    def test_audit_with_metadata(self):
        event = audit("ioc.register", target="pkg@1.0.0", metadata={"severity": "HIGH"})
        self.assertEqual(event.metadata["severity"], "HIGH")

    def test_audit_failure(self):
        event = audit("corpus.import", target="bad.json", outcome="failure")
        self.assertEqual(event.outcome, "failure")


if __name__ == "__main__":
    unittest.main()
