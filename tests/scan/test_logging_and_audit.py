"""Tests for PicoSentry logging and request context."""

import json
import logging
import unittest

from picosentry.scan.logging import (
    AuditLogFormatter,
    JsonFormatter,
    clear_request_context,
    configure_audit_logging,
    configure_logging,
    get_actor,
    get_request_id,
    set_request_context,
)


class TestRequestContext(unittest.TestCase):
    """Tests for thread-local request context."""

    def test_set_and_get_request_id(self):
        set_request_context(request_id="abc-123")
        self.assertEqual(get_request_id(), "abc-123")
        clear_request_context()

    def test_set_and_get_actor(self):
        set_request_context(actor="admin@example.com")
        self.assertEqual(get_actor(), "admin@example.com")
        clear_request_context()

    def test_clear_context(self):
        set_request_context(request_id="test", actor="user")
        self.assertEqual(get_request_id(), "test")
        self.assertEqual(get_actor(), "user")
        clear_request_context()
        self.assertEqual(get_request_id(), "")
        self.assertEqual(get_actor(), "")

    def test_default_empty(self):
        clear_request_context()
        self.assertEqual(get_request_id(), "")
        self.assertEqual(get_actor(), "")


class TestJsonFormatter(unittest.TestCase):
    """Tests for JSON log formatter."""

    def test_basic_format(self):
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="picosentry.test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="test message",
            args=None,
            exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)
        self.assertEqual(data["message"], "test message")
        self.assertEqual(data["level"], "INFO")
        self.assertEqual(data["logger"], "picosentry.test")

    def test_format_with_request_context(self):
        set_request_context(request_id="req-456", actor="user@example.com")
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="picosentry.test",
            level=logging.WARNING,
            pathname="test.py",
            lineno=1,
            msg="auth failed",
            args=None,
            exc_info=None,
        )
        output = formatter.format(record)
        data = json.loads(output)
        self.assertEqual(data["request_id"], "req-456")
        self.assertEqual(data["actor"], "user@example.com")
        clear_request_context()

    def test_format_with_promoted_fields(self):
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="picosentry.scan",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="scan completed",
            args=None,
            exc_info=None,
        )
        record.scan_id = "abc123"
        record.duration_ms = 150
        output = formatter.format(record)
        data = json.loads(output)
        self.assertEqual(data["scan_id"], "abc123")
        self.assertEqual(data["duration_ms"], 150)

    def test_format_with_extra_fields(self):
        formatter = JsonFormatter()
        record = logging.LogRecord(
            name="picosentry.test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="test",
            args=None,
            exc_info=None,
        )
        record.extra_fields = {"custom_key": "custom_value"}
        output = formatter.format(record)
        data = json.loads(output)
        self.assertEqual(data["custom_key"], "custom_value")


class TestAuditLogFormatter(unittest.TestCase):
    """Tests for audit-specific log formatter."""

    def test_audit_format_includes_required_fields(self):
        formatter = AuditLogFormatter()
        record = logging.LogRecord(
            name="picosentry.audit",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="corpus imported",
            args=None,
            exc_info=None,
        )
        record.action = "corpus.import"
        record.target = "pack.json"
        record.outcome = "success"
        output = formatter.format(record)
        data = json.loads(output)
        self.assertTrue(data.get("audit"))
        self.assertEqual(data["action"], "corpus.import")
        self.assertEqual(data["target"], "pack.json")
        self.assertEqual(data["outcome"], "success")


class TestConfigureLogging(unittest.TestCase):
    """Tests for logging configuration."""

    def test_configure_text_logging(self):
        configure_logging(log_format="text")
        logger = logging.getLogger("picosentry")
        self.assertTrue(any(isinstance(h, logging.StreamHandler) for h in logger.handlers))

    def test_configure_json_logging(self):
        configure_logging(log_format="json")
        logger = logging.getLogger("picosentry")
        has_json = any(isinstance(h.formatter, JsonFormatter) for h in logger.handlers)
        self.assertTrue(has_json)

    def test_configure_audit_logging(self):
        import tempfile
        from pathlib import Path

        tmpdir = tempfile.mkdtemp()
        audit_path = str(Path(tmpdir) / "audit.log")
        handler = configure_audit_logging(path=audit_path)
        self.assertIsNotNone(handler)

        # Write an audit event
        audit_logger = logging.getLogger("picosentry.audit")
        audit_logger.info("test audit event")

        # Verify file was created
        self.assertTrue(Path(audit_path).exists())


if __name__ == "__main__":
    unittest.main()