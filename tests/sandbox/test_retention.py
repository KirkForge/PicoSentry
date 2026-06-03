"""Tests for the data retention module."""

import json
from pathlib import Path

import pytest

from picosentry.sandbox.retention import RetentionConfig, RetentionManager, RetentionPolicy


@pytest.fixture
def retention_dir(tmp_path):
    return tmp_path / "retention_data"


@pytest.fixture
def rm(retention_dir):
    config = RetentionConfig(
        scan_results=RetentionPolicy(data_type="scan_results", ttl_days=90, secure_delete=False, max_size_mb=1),
        audit_logs=RetentionPolicy(data_type="audit_logs", ttl_days=365, secure_delete=False, max_size_mb=1),
        baselines=RetentionPolicy(data_type="baselines", ttl_days=0, secure_delete=False, max_size_mb=1),
    )
    return RetentionManager(config=config, data_dir=retention_dir)


class TestRetentionPolicy:
    def test_default_config(self):
        cfg = RetentionConfig()
        assert cfg.scan_results.ttl_days == 90
        assert cfg.audit_logs.ttl_days == 365
        assert cfg.baselines.ttl_days == 0

    def test_from_dict(self):
        data = {
            "scan_results": {"data_type": "scan_results", "ttl_days": 30},
            "audit_logs": {"data_type": "audit_logs", "ttl_days": 180},
        }
        cfg = RetentionConfig.from_dict(data)
        assert cfg.scan_results.ttl_days == 30
        assert cfg.audit_logs.ttl_days == 180
        assert cfg.baselines.ttl_days == 0  # unchanged default


class TestRetentionManager:
    def test_save_scan_result(self, rm, retention_dir):
        path = rm.save_scan_result('{"verdict": "ALLOW"}', package_name="test-pkg")
        assert path.exists()
        assert "test-pkg" in path.name
        assert path.suffix == ".json"

    def test_storage_stats(self, rm):
        rm.save_scan_result('{"verdict": "ALLOW"}', package_name="pkg1")
        rm.save_scan_result('{"verdict": "DENY"}', package_name="pkg2")
        stats = rm.get_storage_stats()
        assert stats["scan_results"]["file_count"] == 2
        assert stats["total_bytes"] > 0

    def test_cleanup_does_not_remove_fresh_files(self, rm):
        rm.save_scan_result('{"verdict": "ALLOW"}', package_name="fresh")
        stats = rm.run_cleanup()
        assert stats["files_removed"] == 0

    def test_export_data(self, rm, tmp_path):
        rm.save_scan_result('{"verdict": "ALLOW"}', package_name="pkg1")
        output = tmp_path / "export.json"
        rm.export_data(output, data_type="scan_results")
        assert output.exists()
        data = json.loads(output.read_text())
        assert len(data["scan_results"]) == 1

    def test_secure_delete(self, rm, retention_dir):
        # Create a temp file
        test_file = retention_dir / "test_delete.txt"
        test_file.write_text("sensitive data" * 100)
        assert test_file.exists()
        result = rm.secure_delete(test_file)
        assert result is True
        assert not test_file.exists()

    def test_secure_delete_nonexistent(self, rm):
        result = rm.secure_delete(Path("/nonexistent/file.txt"))
        assert result is False
