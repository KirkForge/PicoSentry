"""BackupManager exception-narrowing + basic contract tests."""

from __future__ import annotations

import tarfile
from pathlib import Path

import pytest

from picosentry.serve.services.backup import BackupManager


@pytest.fixture
def manager(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> BackupManager:
    """A BackupManager wired to a temp directory so tests are hermetic."""
    from picosentry.serve.config.settings import settings

    monkeypatch.setattr(settings.database, "path", tmp_path / "db.sqlite3")
    monkeypatch.setattr(settings.database, "backup_dir", tmp_path / "backups")
    monkeypatch.setattr(settings.database, "backup_retention_days", 30)
    (tmp_path / "db.sqlite3").write_text("test db")
    return BackupManager()


def test_create_backup_happy_path(manager: BackupManager, tmp_path: Path) -> None:
    result = manager.create_backup(name="manual_test", include_logs=False)
    assert result is not None
    assert Path(result["path"]).exists()
    assert result["name"] == "manual_test"
    assert result["size"] > 0
    assert result["metadata"]["include_logs"] is False


def test_create_backup_logs_and_returns_none_on_oserror(
    manager: BackupManager, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """OSError during backup is caught by the narrowed tuple and logged."""

    def _failing_copy2(*_a, **_kw) -> None:
        raise OSError("disk full")

    monkeypatch.setattr("shutil.copy2", _failing_copy2)

    with caplog.at_level("ERROR", logger="picoshogun.Backup"):
        result = manager.create_backup(name="fail_test", include_logs=False)

    assert result is None
    assert "Backup failed" in caplog.text


def test_create_backup_unexpected_error_propagates(manager: BackupManager, monkeypatch: pytest.MonkeyPatch) -> None:
    """A programmer error is NOT swallowed by the narrowed tuple."""

    def _buggy_copy2(*_a, **_kw) -> None:
        raise NameError("programmer bug")

    monkeypatch.setattr("shutil.copy2", _buggy_copy2)

    with pytest.raises(NameError, match="programmer bug"):
        manager.create_backup(name="bug_test", include_logs=False)


def _make_backup(manager: BackupManager, tmp_path: Path) -> Path:
    result = manager.create_backup(name="restore_test", include_logs=False)
    assert result is not None
    return Path(result["path"])


def test_restore_backup_happy_path(manager: BackupManager, tmp_path: Path) -> None:
    backup_path = _make_backup(manager, tmp_path)
    assert manager.restore_backup(str(backup_path), force=True) is True


def test_restore_backup_returns_false_on_corrupt_tar(
    manager: BackupManager, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """tarfile.TarError during restore is caught and logged."""
    corrupt = tmp_path / "backups" / "corrupt.tar.gz"
    corrupt.parent.mkdir(parents=True, exist_ok=True)
    corrupt.write_text("not a tar")

    with caplog.at_level("ERROR", logger="picoshogun.Backup"):
        result = manager.restore_backup(str(corrupt), force=True)

    assert result is False
    assert "Restore failed" in caplog.text


def test_restore_backup_unexpected_error_propagates(
    manager: BackupManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A programmer error during restore is NOT swallowed."""
    backup_path = _make_backup(manager, tmp_path)

    def _buggy_extract(*_a, **_kw) -> None:
        raise NameError("programmer bug")

    monkeypatch.setattr(tarfile.TarFile, "extract", _buggy_extract)

    with pytest.raises(NameError, match="programmer bug"):
        manager.restore_backup(str(backup_path), force=True)


def test_list_backups_and_cleanup(manager: BackupManager, tmp_path: Path) -> None:
    result = manager.create_backup(name="listed", include_logs=False)
    assert result is not None

    backups = manager.list_backups()
    assert len(backups) == 1
    assert backups[0]["name"] == "listed"

    removed = manager.cleanup_old_backups()
    assert removed == 0  # backup is fresh


def test_encrypted_round_trip(manager: BackupManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """create -> encrypt -> restore -> verify integrity round-trip."""
    from picosentry.serve.config.settings import settings

    monkeypatch.setattr(settings.backup, "encrypt_key", "test-secret-key")

    result = manager.create_backup(name="enc_roundtrip", include_logs=False)
    assert result is not None
    assert result["metadata"]["encrypted"] is True
    backup_path = Path(result["path"])
    assert backup_path.suffix == ".enc"
    assert b"PICOSHOGUN" in backup_path.read_bytes()[:16]

    assert manager.restore_backup(str(backup_path), force=True) is True
    assert (tmp_path / "db.sqlite3").read_text() == "test db"


def test_restore_wrong_key_fails_safely(
    manager: BackupManager, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Restore with the wrong key must fail before extraction."""
    from picosentry.serve.config.settings import settings

    monkeypatch.setattr(settings.backup, "encrypt_key", "correct-key")
    result = manager.create_backup(name="enc_wrongkey", include_logs=False)
    assert result is not None
    backup_path = Path(result["path"])

    monkeypatch.setattr(settings.backup, "encrypt_key", "wrong-key")
    with caplog.at_level("ERROR", logger="picoshogun.Backup"):
        assert manager.restore_backup(str(backup_path), force=True) is False
    assert "decryption/integrity" in caplog.text
    assert (tmp_path / "db.sqlite3").read_text() == "test db"  # untouched


def test_restore_under_live_pool_swaps_state(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """write -> backup -> mutate -> restore: the live pool must serve restored state.

    restore_backup closes the manager's pool (all threads), drops stale
    -wal/-shm side files, swaps the file, and the pool re-opens lazily on the
    next query.
    """
    from picosentry.serve.config.settings import settings
    from picosentry.serve.database import manager as db_manager_mod
    from picosentry.serve.database.manager import DatabaseManager

    db_file = tmp_path / "live.db"
    monkeypatch.setattr(settings.database, "path", db_file)
    monkeypatch.setattr(settings.database, "backup_dir", tmp_path / "backups")

    mgr = DatabaseManager(db_path=db_file, backend="sqlite")
    monkeypatch.setattr(db_manager_mod, "db", mgr)  # restore coordinates with this pool

    mgr.execute("CREATE TABLE state (k TEXT, v TEXT)")
    mgr.execute("INSERT INTO state (k, v) VALUES ('shape', 'original')")

    bm = BackupManager()
    backup = bm.create_backup(name="restore_pool", include_logs=False)
    assert backup is not None

    mgr.execute("UPDATE state SET v = 'mutated' WHERE k = 'shape'")
    assert mgr.execute_one("SELECT v FROM state WHERE k = 'shape'")["v"] == "mutated"

    assert bm.restore_backup(backup["path"], force=True) is True

    # Pool was closed by the restore; this read re-opens lazily and must see
    # the restored (pre-mutation) state.
    assert mgr.execute_one("SELECT v FROM state WHERE k = 'shape'")["v"] == "original"
    mgr.close()
