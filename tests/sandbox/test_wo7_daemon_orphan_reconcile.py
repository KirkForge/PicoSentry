"""WO7.0.0-018: daemon startup reconciliation marks orphaned jobs as failed."""

from __future__ import annotations

from pathlib import Path

from picosentry.sandbox.daemon.store import PersistentScanJobStore


def test_jsonl_reconcile_marks_running_and_queued_failed(tmp_path: Path):
    store = PersistentScanJobStore(store_dir=tmp_path / "jobs")
    store.add("job-1", ["echo", "a"], "admin")
    store.add("job-2", ["echo", "b"], "admin")
    store.add("job-3", ["echo", "c"], "admin")
    store.add("job-4", ["echo", "d"], "admin")
    store.update("job-1", status="running")
    store.update("job-2", status="running")
    store.update("job-3", status="queued")
    store.update("job-4", status="completed")

    count = store.reconcile_on_start()
    assert count == 3

    assert store.get("job-1")["status"] == "failed"
    assert store.get("job-1")["error"] == "ORPHANED_ON_RESTART"
    assert store.get("job-2")["status"] == "failed"
    assert store.get("job-3")["status"] == "failed"
    assert store.get("job-4")["status"] == "completed"


def test_jsonl_reconcile_no_orphans(tmp_path: Path):
    store = PersistentScanJobStore(store_dir=tmp_path / "jobs")
    store.add("job-1", ["echo", "a"], "admin")
    store.update("job-1", status="completed")
    assert store.reconcile_on_start() == 0


def test_sqlite_reconcile_marks_running_and_queued_failed(tmp_path: Path):
    from picosentry.sandbox.daemon.sqlite_store import SQLiteScanJobStore

    db = tmp_path / "jobs.db"
    store = SQLiteScanJobStore(db_path=db)
    store.add("job-1", ["echo", "a"], "admin")
    store.add("job-2", ["echo", "b"], "admin")
    store.add("job-3", ["echo", "c"], "admin")
    store.add("job-4", ["echo", "d"], "admin")
    store.update("job-1", status="running")
    store.update("job-2", status="running")
    store.update("job-3", status="queued")
    store.update("job-4", status="completed")

    count = store.reconcile_on_start()
    assert count == 3

    assert store.get("job-1")["status"] == "failed"
    assert store.get("job-2")["status"] == "failed"
    assert store.get("job-3")["status"] == "failed"
    assert store.get("job-4")["status"] == "completed"
    store.close()


def test_sqlite_reconcile_no_orphans(tmp_path: Path):
    from picosentry.sandbox.daemon.sqlite_store import SQLiteScanJobStore

    store = SQLiteScanJobStore(db_path=tmp_path / "jobs.db")
    store.add("job-1", ["echo", "a"], "admin")
    store.update("job-1", status="completed")
    assert store.reconcile_on_start() == 0
    store.close()
