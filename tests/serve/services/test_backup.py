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
