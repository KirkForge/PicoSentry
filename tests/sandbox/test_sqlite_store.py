"""Tests for SQLite-backed scan job store — production-grade storage."""

from __future__ import annotations

from pathlib import Path

import pytest

from picosentry.sandbox.daemon.sqlite_store import SQLiteScanJobStore


@pytest.fixture
def store(tmp_path):
    """Create a temporary SQLite store."""
    db_path = tmp_path / "test_jobs.db"
    return SQLiteScanJobStore(db_path=db_path, max_jobs=100)


class TestSQLiteStoreBasic:
    """Basic CRUD operations."""

    def test_add_and_get(self, store):
        job = store.add("job-1", ["echo", "hello"], "alice")
        assert job["job_id"] == "job-1"
        assert job["status"] == "pending"
        assert job["command"] == ["echo", "hello"]
        assert job["actor"] == "alice"
        assert job["schema_version"] == 2

        retrieved = store.get("job-1")
        assert retrieved is not None
        assert retrieved["job_id"] == "job-1"
        assert retrieved["command"] == ["echo", "hello"]

    def test_get_nonexistent(self, store):
        assert store.get("no-such-job") is None

    def test_update_status(self, store):
        store.add("job-2", ["ls"], "bob")
        updated = store.update("job-2", status="completed")
        assert updated is not None
        assert updated["status"] == "completed"
        assert updated["completed_at"] is not None

    def test_update_nonexistent(self, store):
        result = store.update("no-such-job", status="completed")
        assert result is None

    def test_list_recent(self, store):
        store.add("job-a", ["echo", "a"], "user1")
        store.add("job-b", ["echo", "b"], "user2")
        store.add("job-c", ["echo", "c"], "user3")

        recent = store.list_recent(limit=2)
        assert len(recent) == 2
        # Most recent first
        assert recent[0]["job_id"] == "job-c"

    def test_list_recent_empty(self, store):
        recent = store.list_recent()
        assert recent == []

    def test_schema_version_in_db(self, store):
        store.add("job-sv", ["echo"], "tester")
        job = store.get("job-sv")
        assert job is not None
        assert job["schema_version"] == 2

    def test_command_serialization(self, store):
        store.add("job-cmd", ["python3", "-m", "picodome", "sandbox", "npm", "install"], "ci")
        job = store.get("job-cmd")
        assert job is not None
        assert isinstance(job["command"], list)
        assert len(job["command"]) == 6


class TestSQLiteStoreConcurrency:
    """Thread safety and concurrent access."""

    def test_threaded_adds(self, store):
        import threading

        errors = []

        def add_job(i):
            try:
                store.add(f"thread-job-{i}", [f"cmd-{i}"], f"actor-{i}")
            except Exception as e:
                errors.append(e)

        threads = [threading.Thread(target=add_job, args=(i,)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        assert len(errors) == 0
        assert store.count() == 20


class TestSQLiteStorePruning:
    """Job pruning when exceeding max_jobs."""

    def test_prune_old_jobs(self, tmp_path):
        store = SQLiteScanJobStore(db_path=tmp_path / "prune.db", max_jobs=5)
        for i in range(10):
            store.add(f"prune-job-{i}", [f"cmd-{i}"], "pruner")

        # After pruning, should have at most max_jobs
        count = store.count()
        assert count <= 5

    def test_count(self, store):
        assert store.count() == 0
        store.add("c1", ["echo"], "a")
        store.add("c2", ["ls"], "b")
        assert store.count() == 2


class TestSQLiteStoreFromEnv:
    """Test environment-based configuration."""

    def test_from_env_default(self):
        store = SQLiteScanJobStore.from_env()
        assert store.db_path == Path.home() / ".picodome" / "jobs.db"

    def test_from_env_custom_path(self, tmp_path):
        import os

        db_path = tmp_path / "env_test.db"
        os.environ["PICODOME_SQLITE_PATH"] = str(db_path)
        try:
            store = SQLiteScanJobStore.from_env()
            assert store.db_path == db_path
        finally:
            del os.environ["PICODOME_SQLITE_PATH"]


class TestSQLiteStoreClose:
    """Test connection lifecycle."""

    def test_close_and_reopen(self, tmp_path):
        db_path = tmp_path / "lifecycle.db"
        store = SQLiteScanJobStore(db_path=db_path)
        store.add("lifecycle-1", ["echo"], "test")
        assert store.get("lifecycle-1") is not None

        store.close()
        # Re-open should still work
        store2 = SQLiteScanJobStore(db_path=db_path)
        job = store2.get("lifecycle-1")
        assert job is not None
        assert job["job_id"] == "lifecycle-1"
