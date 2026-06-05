"""Tests for picodome.logging — structured JSON/SIEM logging."""

from __future__ import annotations

import json
import logging

from picosentry.sandbox.logging import (
    PicoDomeJSONFormatter,
    PicoDomeTextFormatter,
    get_log_context,
    setup_logging,
)


class TestJSONFormatter:
    def test_basic_format(self):
        fmt = PicoDomeJSONFormatter()
        record = logging.LogRecord(
            name="picodome.test",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="test message",
            args=(),
            exc_info=None,
        )
        output = fmt.format(record)
        data = json.loads(output)
        assert data["message"] == "test message"
        assert data["level"] == "INFO"
        assert data["logger"] == "picodome.test"
        assert "timestamp" in data

    def test_includes_version(self):
        fmt = PicoDomeJSONFormatter(include_version=True)
        record = logging.LogRecord("picodome.test", logging.INFO, "", 0, "msg", (), None)
        data = json.loads(fmt.format(record))
        assert "picodome_version" in data

    def test_excludes_version(self):
        fmt = PicoDomeJSONFormatter(include_version=False)
        record = logging.LogRecord("picodome.test", logging.INFO, "", 0, "msg", (), None)
        data = json.loads(fmt.format(record))
        assert "picodome_version" not in data

    def test_extra_context(self):
        fmt = PicoDomeJSONFormatter()
        record = logging.LogRecord("picodome.test", logging.INFO, "", 0, "msg", (), None)
        record.picodome_context = {"command": ["echo"], "target": "pkg"}
        data = json.loads(fmt.format(record))
        assert data["command"] == ["echo"]
        assert data["target"] == "pkg"

    def test_exception_info(self):
        fmt = PicoDomeJSONFormatter()
        try:
            raise ValueError("test error")
        except ValueError:
            import sys

            exc_info = sys.exc_info()
        record = logging.LogRecord("picodome.test", logging.ERROR, "", 0, "msg", (), exc_info)
        data = json.loads(fmt.format(record))
        assert "exception" in data

    def test_deterministic_key_order(self):
        fmt = PicoDomeJSONFormatter()
        record = logging.LogRecord("picodome.test", logging.INFO, "", 0, "msg", (), None)
        output = fmt.format(record)
        # Keys should be sorted (deterministic)
        keys = list(json.loads(output).keys())
        assert keys == sorted(keys)


class TestTextFormatter:
    def test_basic_format(self):
        fmt = PicoDomeTextFormatter(use_color=False)
        record = logging.LogRecord("picodome.test", logging.INFO, "", 0, "msg", (), None)
        output = fmt.format(record)
        assert "msg" in output
        assert "INFO" in output

    def test_color_format(self):
        fmt = PicoDomeTextFormatter(use_color=True)
        record = logging.LogRecord("picodome.test", logging.WARNING, "", 0, "warning msg", (), None)
        output = fmt.format(record)
        assert "\033[" in output  # ANSI code present

    def test_no_color_format(self):
        fmt = PicoDomeTextFormatter(use_color=False)
        record = logging.LogRecord("picodome.test", logging.WARNING, "", 0, "msg", (), None)
        output = fmt.format(record)
        assert "\033[" not in output

    def test_verbose_format(self):
        fmt = PicoDomeTextFormatter(use_color=False, verbose=True)
        record = logging.LogRecord("picodome.test", logging.INFO, "", 0, "msg", (), None)
        output = fmt.format(record)
        assert "picodome.test" in output


class TestSetupLogging:
    def test_setup_text(self):
        setup_logging(level="DEBUG", log_format="text", use_color=False)
        logger = logging.getLogger("picodome")
        assert logger.level == logging.DEBUG

    def test_setup_json(self):
        setup_logging(level="INFO", log_format="json")
        logger = logging.getLogger("picodome")
        assert logger.level == logging.INFO
        assert len(logger.handlers) == 1
        assert isinstance(logger.handlers[0].formatter, PicoDomeJSONFormatter)

    def test_propagate_disabled(self):
        setup_logging(level="WARNING")
        logger = logging.getLogger("picodome")
        assert logger.propagate is False


class TestGetLogContext:
    def test_basic_context(self):
        ctx = get_log_context(command=["echo", "hello"])
        assert ctx["command"] == ["echo", "hello"]

    def test_all_fields(self):
        ctx = get_log_context(
            command=["echo"],
            run_id="test-run",
            policy="default",
            target="mypackage",
        )
        assert ctx["command"] == ["echo"]
        assert ctx["run_id"] == "test-run"
        assert ctx["policy"] == "default"
        assert ctx["target"] == "mypackage"

    def test_kwargs(self):
        ctx = get_log_context(custom_field="value")
        assert ctx["custom_field"] == "value"

    def test_none_fields_excluded(self):
        ctx = get_log_context(command=None, run_id=None)
        assert "command" not in ctx
        assert "run_id" not in ctx
