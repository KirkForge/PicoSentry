"""Unit tests for LogManager exception-narrowing paths."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from picosentry.serve.services.log_manager import LogManager


class TestLogManagerHardening:
    """Log query must tolerate expected file errors but surface programmer errors."""

    def test_oserror_while_reading_log_is_logged_and_skipped(self, tmp_path, caplog, monkeypatch):
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        (log_dir / "app.log").write_text("INFO hello\n", encoding="utf-8")

        manager = LogManager(log_dir=str(log_dir))

        def _boom(*args, **kwargs):
            raise OSError("permission denied")

        monkeypatch.setattr(Path, "open", _boom)

        with caplog.at_level(logging.WARNING, logger="picoshogun.LogManager"):
            entries = manager.query()

        assert entries == []
        assert any("Failed to read log file" in r.message for r in caplog.records)

    def test_unicode_decode_error_while_reading_log_is_logged_and_skipped(self, tmp_path, caplog):
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        (log_dir / "app.log").write_bytes(b"\xff\xfe\x00\x00")  # invalid UTF-8

        manager = LogManager(log_dir=str(log_dir))

        with caplog.at_level(logging.WARNING, logger="picoshogun.LogManager"):
            entries = manager.query()

        assert entries == []
        assert any("Failed to read log file" in r.message for r in caplog.records)

    def test_unexpected_error_while_reading_log_propagates(self, tmp_path, monkeypatch):
        log_dir = tmp_path / "logs"
        log_dir.mkdir()
        (log_dir / "app.log").write_text("INFO hello\n", encoding="utf-8")

        manager = LogManager(log_dir=str(log_dir))

        def _boom(*args, **kwargs):
            raise AttributeError("programmer mistake")

        monkeypatch.setattr(Path, "open", _boom)

        with pytest.raises(AttributeError, match="programmer mistake"):
            manager.query()
