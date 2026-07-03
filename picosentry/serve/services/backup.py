import json
import logging
import os
import shutil
import tarfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from picosentry.serve.config.settings import settings
from picosentry.serve.config.version import __version__

logger = logging.getLogger("picoshogun.Backup")


class BackupManager:
    def __init__(self):
        self.backup_dir = Path(settings.database.backup_dir)
        self.db_path = Path(settings.database.path)
        self.retention_days = getattr(settings.database, "backup_retention_days", 30)

    def create_backup(self, name: str | None = None, include_logs: bool = True) -> dict | None:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        name = name or f"picoshogun_{timestamp}"
        backup_path = self.backup_dir / f"{name}.tar.gz"

        self.backup_dir.mkdir(parents=True, exist_ok=True)

        temp_dir = self.backup_dir / f"temp_{timestamp}"
        temp_dir.mkdir(parents=True, exist_ok=True)

        try:
            db_backup = temp_dir / "database.sqlite3"
            shutil.copy2(str(self.db_path), str(db_backup))

            meta = {
                "version": __version__,
                "created": datetime.now(timezone.utc).isoformat(),
                "database_size": db_backup.stat().st_size,
                "include_logs": include_logs,
            }

            with (temp_dir / "metadata.json").open("w") as f:
                json.dump(meta, f, indent=2)

            if include_logs:
                logs_dir = self.backup_dir.parent / "logs"
                if logs_dir.exists():
                    shutil.copytree(str(logs_dir), str(temp_dir / "logs"), dirs_exist_ok=True)

            with tarfile.open(str(backup_path), "w:gz") as tar:
                for item in temp_dir.iterdir():
                    tar.add(str(item), arcname=item.name)

            backup_size = backup_path.stat().st_size

            logger.info("Backup created: %s (%s bytes)", backup_path, backup_size)

            return {"path": str(backup_path), "name": name, "size": backup_size, "metadata": meta}

        except (OSError, ValueError, TypeError, tarfile.TarError):
            logger.exception("Backup failed")
            return None

        finally:
            if temp_dir.exists():
                shutil.rmtree(str(temp_dir))

    def restore_backup(self, backup_path: str | Path, force: bool = False) -> bool:
        backup_path = Path(backup_path)

        if not backup_path.exists():
            logger.error("Backup not found: %s", backup_path)
            return False

        if not force:
            current_db_size = self.db_path.stat().st_size if self.db_path.exists() else 0
            logger.warning("About to restore over database (%s bytes). Use force=True to confirm.", current_db_size)
            return False

        temp_dir = self.backup_dir / f"restore_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"

        try:
            with tarfile.open(str(backup_path), "r:gz") as tar:
                for member in tar.getmembers():
                    member_path = os.path.normpath(member.name)
                    if member_path.startswith("..") or Path(member.name).is_absolute():
                        logger.warning("Skipping unsafe path in archive: %s", member.name)
                        continue
                    tar.extract(member, str(temp_dir))

            meta_path = temp_dir / "metadata.json"
            if meta_path.exists():
                with meta_path.open() as f:
                    meta = json.load(f)
                logger.info("Restoring backup from %s", meta["created"])

            db_backup = temp_dir / "database.sqlite3"
            if db_backup.exists():
                current_backup = f"{self.db_path}.pre_restore_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}"
                shutil.copy2(str(self.db_path), current_backup)

                shutil.copy2(str(db_backup), str(self.db_path))
                logger.info("Database restored")

            logs_backup = temp_dir / "logs"
            if logs_backup.exists():
                logs_dir = self.backup_dir.parent / "logs"
                if logs_dir.exists():
                    shutil.rmtree(str(logs_dir))
                shutil.copytree(str(logs_backup), str(logs_dir))
                logger.info("Logs restored")

            return True

        except (OSError, ValueError, TypeError, tarfile.TarError):
            logger.exception("Restore failed")
            return False

        finally:
            if temp_dir.exists():
                shutil.rmtree(str(temp_dir))

    def list_backups(self) -> list[dict[str, Any]]:
        backups: list[dict[str, Any]] = []

        if not self.backup_dir.exists():
            return backups

        for backup_file in self.backup_dir.glob("*.tar.gz"):
            stat = backup_file.stat()
            backups.append(
                {
                    "name": backup_file.stem.replace(".tar", ""),
                    "path": str(backup_file),
                    "size": stat.st_size,
                    "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                }
            )

        return sorted(backups, key=lambda x: x["created"], reverse=True)

    def cleanup_old_backups(self) -> int:
        if not self.backup_dir.exists() or self.retention_days <= 0:
            return 0

        cutoff = datetime.now(timezone.utc).timestamp() - (self.retention_days * 86400)
        removed = 0

        for backup_file in self.backup_dir.glob("*.tar.gz"):
            if backup_file.stat().st_ctime < cutoff:
                backup_file.unlink()
                removed += 1
                logger.info("Removed old backup: %s", backup_file.name)

        return removed

    def auto_backup(self) -> dict | None:
        result = self.create_backup(name=f"auto_{datetime.now(timezone.utc).strftime('%Y%m%d')}", include_logs=True)

        if result:
            self.cleanup_old_backups()

        return result
