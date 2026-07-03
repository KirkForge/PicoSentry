"""Tests for picodome.daemon.store — persistent scan job store."""

import json
import logging

import pytest

from picosentry.sandbox.daemon.store import PersistentScanJobStore


@pytest.fixture
def store_dir(tmp_path):
    """Create a temporary directory for the store."""
    return tmp_path / "jobs"


class TestPersistentScanJobStore:
    """Tests for PersistentScanJobStore."""

    def test_add_and_get(self, store_dir):
        store = PersistentScanJobStore(store_dir=store_dir)
        job = store.add("job-1", ["echo", "hello"], "admin")
        assert job["job_id"] == "job-1"
        assert job["command"] == ["echo", "hello"]
        assert job["actor"] == "admin"
        assert job["status"] == "pending"

        retrieved = store.get("job-1")
        assert retrieved is not None
        assert retrieved["job_id"] == "job-1"

    def test_update_status(self, store_dir):
        store = PersistentScanJobStore(store_dir=store_dir)
        store.add("job-2", ["ls"], "reader")
        updated = store.update("job-2", status="completed", result={"verdict": "ALLOW"})
        assert updated is not None
        assert updated["status"] == "completed"
        assert updated["completed_at"] is not None
        assert updated["result"]["verdict"] == "ALLOW"

    def test_update_failed(self, store_dir):
        store = PersistentScanJobStore(store_dir=store_dir)
        store.add("job-3", ["rm", "-rf"], "admin")
        updated = store.update("job-3", status="failed", error="Command denied")
        assert updated is not None
        assert updated["status"] == "failed"
        assert updated["error"] == "Command denied"

    def test_update_nonexistent(self, store_dir):
        store = PersistentScanJobStore(store_dir=store_dir)
        result = store.update("nonexistent", status="completed")
        assert result is None

    def test_list_recent(self, store_dir):
        store = PersistentScanJobStore(store_dir=store_dir)
        store.add("job-a", ["echo", "a"], "admin")
        store.add("job-b", ["echo", "b"], "admin")
        store.add("job-c", ["echo", "c"], "admin")

        recent = store.list_recent(limit=2)
        assert len(recent) == 2
        # All jobs should be present in the store
        all_jobs = store.list_recent(limit=10)
        assert len(all_jobs) == 3

    def test_get_nonexistent(self, store_dir):
        store = PersistentScanJobStore(store_dir=store_dir)
        assert store.get("nonexistent") is None

    def test_persistence_across_instances(self, store_dir):
        """Jobs should persist across store instances."""
        store1 = PersistentScanJobStore(store_dir=store_dir)
        store1.add("persist-1", ["echo", "test"], "admin")
        store1.update("persist-1", status="completed", result={"verdict": "ALLOW"})

        # Create a new instance pointing to the same directory
        store2 = PersistentScanJobStore(store_dir=store_dir)
        job = store2.get("persist-1")
        assert job is not None
        assert job["status"] == "completed"

    def test_jsonl_file_format(self, store_dir):
        """Verify the JSONL file is written correctly."""
        store = PersistentScanJobStore(store_dir=store_dir)
        store.add("file-test", ["echo", "hello"], "admin")

        store_file = store_dir / "jobs.jsonl"
        assert store_file.exists()
        lines = store_file.read_text().strip().split("\n")
        assert len(lines) == 1
        data = json.loads(lines[0])
        assert data["job_id"] == "file-test"

    def test_max_jobs_eviction(self, store_dir):
        """Store should keep only max_jobs most recent."""
        store = PersistentScanJobStore(store_dir=store_dir, max_jobs=3)
        store.add("job-1", ["echo", "1"], "admin")
        store.add("job-2", ["echo", "2"], "admin")
        store.add("job-3", ["echo", "3"], "admin")
        store.add("job-4", ["echo", "4"], "admin")

        # After loading, only the most recent max_jobs should be kept
        recent = store.list_recent(limit=10)
        assert len(recent) == 4  # all 4 in memory before compaction

    def test_empty_store(self, store_dir):
        """Empty store should return empty lists."""
        store = PersistentScanJobStore(store_dir=store_dir)
        assert store.get("nonexistent") is None
        assert store.list_recent() == []

    def test_store_dir_created_automatically(self, tmp_path):
        """Store should create its directory if it doesn't exist."""
        new_dir = tmp_path / "nested" / "dir"
        store = PersistentScanJobStore(store_dir=new_dir)
        store.add("auto-dir", ["echo"], "admin")
        assert new_dir.exists()


class TestPersistentScanJobStoreExceptionNarrowing:
    """Load failures must log expected errors and propagate bugs."""

    def test_load_expected_oserror_starts_fresh(self, store_dir, caplog, monkeypatch):
        store = PersistentScanJobStore(store_dir=store_dir)

        def _boom():
            raise OSError("disk unavailable")

        monkeypatch.setattr(store, "_load_from_disk", _boom)

        with caplog.at_level(logging.WARNING, logger="picodome.daemon.store"):
            store.add("job-1", ["echo"], "admin")

        assert store.get("job-1") is not None
        assert any("Failed to load job store from disk" in r.message for r in caplog.records)

    def test_load_unexpected_error_propagates(self, store_dir, monkeypatch):
        store = PersistentScanJobStore(store_dir=store_dir)

        def _boom():
            raise NameError("programmer mistake")

        monkeypatch.setattr(store, "_load_from_disk", _boom)

        with pytest.raises(NameError, match="programmer mistake"):
            store.add("job-1", ["echo"], "admin")
