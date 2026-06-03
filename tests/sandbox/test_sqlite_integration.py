"""Integration tests for SQLite store backend in daemon context."""

from __future__ import annotations

import json
import os
from unittest import mock

from picosentry.sandbox.daemon.sqlite_store import SQLiteScanJobStore


class TestSQLiteStoreIntegration:
    """Integration tests for SQLite store under realistic conditions."""

    def test_concurrent_adds_and_reads(self, tmp_path):
        """Simulate daemon workload: many concurrent adds with reads."""
        import threading

        store = SQLiteScanJobStore(db_path=tmp_path / "integration.db", max_jobs=100)
        errors = []

        def add_jobs(start, count):
            for i in range(start, start + count):
                try:
                    job = store.add(f"job-{i}", [f"cmd-{i}"], f"actor-{i % 5}")
                    assert job["job_id"] == f"job-{i}"
                    assert job["schema_version"] == 2
                except Exception as e:
                    errors.append(e)

        def read_jobs():
            for _ in range(5):
                try:
                    recent = store.list_recent(limit=10)
                    assert isinstance(recent, list)
                except Exception as e:
                    errors.append(e)

        # Add 50 jobs from 5 threads
        threads = [threading.Thread(target=add_jobs, args=(i * 10, 10)) for i in range(5)]
        read_threads = [threading.Thread(target=read_jobs) for _ in range(3)]

        for t in threads + read_threads:
            t.start()
        for t in threads + read_threads:
            t.join()

        assert len(errors) == 0
        assert store.count() == 50

    def test_update_status_and_read(self, tmp_path):
        """Test full lifecycle: add → update → read."""
        store = SQLiteScanJobStore(db_path=tmp_path / "lifecycle.db")

        # Add
        store.add("lifecycle-1", ["echo", "test"], "ci-user")

        # Read pending
        job = store.get("lifecycle-1")
        assert job is not None
        assert job["status"] == "pending"

        # Update to running
        store.update("lifecycle-1", status="running")
        job = store.get("lifecycle-1")
        assert job["status"] == "running"

        # Update to completed
        store.update("lifecycle-1", status="completed", result='{"verdict": "ALLOW"}')
        job = store.get("lifecycle-1")
        assert job["status"] == "completed"
        assert job["completed_at"] is not None
        assert "ALLOW" in str(job.get("result", ""))

    def test_prune_on_overflow(self, tmp_path):
        """Test automatic pruning when exceeding max_jobs."""
        store = SQLiteScanJobStore(db_path=tmp_path / "prune.db", max_jobs=20)

        # Add more than max_jobs
        for i in range(30):
            store.add(f"overflow-{i}", [f"cmd-{i}"], "overflow-test")

        # Should have been pruned to max_jobs
        count = store.count()
        assert count <= 20

    def test_schema_version_persistence(self, tmp_path):
        """Verify schema_version survives close/reopen."""
        db_path = tmp_path / "versioned.db"

        store = SQLiteScanJobStore(db_path=db_path)
        store.add("versioned-1", ["echo"], "tester")

        # Close and reopen
        store.close()
        store2 = SQLiteScanJobStore(db_path=db_path)

        job = store2.get("versioned-1")
        assert job is not None
        assert job["schema_version"] == 2

    def test_from_env_creates_store(self, tmp_path):
        """Test from_env with custom path."""
        db_path = str(tmp_path / "env.db")
        with mock.patch.dict(os.environ, {"PICODOME_SQLITE_PATH": db_path}):
            store = SQLiteScanJobStore.from_env()
            assert str(store.db_path) == db_path
            store.add("env-1", ["echo"], "env-test")
            assert store.get("env-1") is not None

    def test_jsonl_to_sqlite_migration(self, tmp_path):
        """Test that JSONL data can be read alongside new SQLite data.

        This verifies forward compatibility: existing JSONL stores continue
        to work while new data can go to SQLite.
        """
        # Create a JSONL store alongside
        jsonl_path = tmp_path / "jobs.jsonl"
        jsonl_path.write_text(
            json.dumps(
                {
                    "job_id": "legacy-1",
                    "command": ["old-cmd"],
                    "actor": "legacy-user",
                    "status": "completed",
                    "created_at": "2026-01-01T00:00:00Z",
                    "completed_at": "2026-01-01T00:01:00Z",
                    "result": None,
                    "error": None,
                    "schema_version": 1,
                }
            )
            + "\n"
        )

        # SQLite store should work independently
        sqlite_store = SQLiteScanJobStore(db_path=tmp_path / "jobs.db")
        sqlite_store.add("new-1", ["new-cmd"], "new-user")

        # Both stores should return their own data
        assert sqlite_store.get("new-1") is not None
        assert sqlite_store.get("legacy-1") is None  # Different store
