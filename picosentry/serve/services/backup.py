import hashlib
import hmac
import json
import logging
import os
import shutil
import sqlite3
import tarfile
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from picosentry.serve.config.settings import settings
from picosentry.serve.config.version import __version__

logger = logging.getLogger("picoshogun.Backup")

# Envelope: magic(8) + version(1) + nonce(12) + ciphertext(GCM tag appended).
_ENC_MAGIC = b"PICOSHOGUN"
_ENC_VERSION = 1
_NONCE_LEN = 12


def _derive_key(key_material: str) -> bytes:
    return hashlib.sha256(key_material.encode("utf-8")).digest()


def _encrypt_bytes(plaintext: bytes, key_material: str) -> bytes:
    key = _derive_key(key_material)
    nonce = os.urandom(_NONCE_LEN)
    ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
    return _ENC_MAGIC + bytes([_ENC_VERSION]) + nonce + ciphertext


def _decrypt_bytes(envelope: bytes, key_material: str) -> bytes:
    if not envelope.startswith(_ENC_MAGIC) or len(envelope) < len(_ENC_MAGIC) + 1 + _NONCE_LEN:
        raise ValueError("Not a PicoSentry encrypted backup")
    version = envelope[len(_ENC_MAGIC)]
    if version != _ENC_VERSION:
        raise ValueError(f"Unsupported backup encryption version: {version}")
    nonce = envelope[len(_ENC_MAGIC) + 1 : len(_ENC_MAGIC) + 1 + _NONCE_LEN]
    ciphertext = envelope[len(_ENC_MAGIC) + 1 + _NONCE_LEN :]
    key = _derive_key(key_material)
    # GCM auth tag is verified here: wrong key or tampering raises InvalidTag.
    return AESGCM(key).decrypt(nonce, ciphertext, None)


def _s3_upload(path: Path, key: str) -> bool:
    """Best-effort SigV4 PUT to an S3/GCS-compatible endpoint. Returns False offline/unconfigured."""
    cfg = settings.backup
    if not cfg.s3_enabled:
        return False

    host = urllib.parse.urlparse(cfg.s3_endpoint)
    if not host.scheme or not host.netloc:
        logger.warning("S3 upload skipped: invalid endpoint %r", cfg.s3_endpoint)
        return False

    try:
        body = path.read_bytes()
        now = datetime.now(timezone.utc)
        amz_date = now.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = now.strftime("%Y%m%d")
        canonical_uri = "/" + urllib.parse.quote(key, safe="/")
        canonical_headers = (
            f"host:{host.netloc}\nx-amz-content-sha256:{hashlib.sha256(body).hexdigest()}\nx-amz-date:{amz_date}\n"
        )
        signed_headers = "host;x-amz-content-sha256;x-amz-date"
        payload_hash = hashlib.sha256(body).hexdigest()
        canonical_request = f"PUT\n{canonical_uri}\n\n{canonical_headers}\n{signed_headers}\n{payload_hash}"
        scope = f"{date_stamp}/{cfg.s3_region}/s3/aws4_request"
        string_to_sign = (
            f"AWS4-HMAC-SHA256\n{amz_date}\n{scope}\n{hashlib.sha256(canonical_request.encode()).hexdigest()}"
        )

        def _hmac(key: bytes, msg: str) -> bytes:
            return hmac.new(key, msg.encode("utf-8"), hashlib.sha256).digest()

        k_date = _hmac(("AWS4" + cfg.s3_secret_key).encode("utf-8"), date_stamp)
        k_region = _hmac(k_date, cfg.s3_region)
        k_service = _hmac(k_region, "s3")
        k_signing = _hmac(k_service, "aws4_request")
        signature = hmac.new(k_signing, string_to_sign.encode("utf-8"), hashlib.sha256).hexdigest()

        url = f"{cfg.s3_endpoint.rstrip('/')}/{urllib.parse.quote(key, safe='/')}"
        req = urllib.request.Request(
            url,
            data=body,
            method="PUT",
            headers={
                "Host": host.netloc,
                "x-amz-date": amz_date,
                "x-amz-content-sha256": payload_hash,
                "Authorization": (
                    f"AWS4-HMAC-SHA256 Credential={cfg.s3_access_key}/{scope}, "
                    f"SignedHeaders={signed_headers}, Signature={signature}"
                ),
            },
        )
        with urllib.request.urlopen(req, timeout=30) as resp:
            if resp.status not in (200, 201, 204):
                logger.warning("S3 upload returned status %s", resp.status)
                return False
        logger.info("Backup uploaded to S3: %s", key)
        return True
    except (OSError, ValueError, urllib.error.URLError):
        logger.warning("S3 upload failed (offline or misconfigured); keeping local copy")
        return False


class BackupManager:
    """Creates, restores, and manages compressed database and log backups."""

    def __init__(self):
        self.backup_dir = Path(settings.database.backup_dir)
        self.db_path = Path(settings.database.path)
        self.retention_days = getattr(settings.database, "backup_retention_days", 30)

    def create_backup(self, name: str | None = None, include_logs: bool = True) -> dict | None:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        name = name or f"picoshogun_{timestamp}"
        encrypt_key = settings.backup.encrypt_key
        suffix = ".tar.gz.enc" if encrypt_key else ".tar.gz"
        backup_path = self.backup_dir / f"{name}{suffix}"

        self.backup_dir.mkdir(parents=True, exist_ok=True)

        temp_dir = self.backup_dir / f"temp_{timestamp}"
        temp_dir.mkdir(parents=True, exist_ok=True)

        try:
            db_backup = temp_dir / "database.sqlite3"
            with self.db_path.open("rb") as probe:
                is_sqlite = probe.read(16) == b"SQLite format 3\x00"
            if is_sqlite:
                src = sqlite3.connect(str(self.db_path))
                dst = sqlite3.connect(str(db_backup))
                try:
                    src.backup(dst)
                finally:
                    dst.close()
                    src.close()
            else:
                shutil.copy2(str(self.db_path), str(db_backup))

            meta = {
                "version": __version__,
                "created": datetime.now(timezone.utc).isoformat(),
                "database_size": db_backup.stat().st_size,
                "include_logs": include_logs,
                "encrypted": bool(encrypt_key),
            }

            with (temp_dir / "metadata.json").open("w") as f:
                json.dump(meta, f, indent=2)

            if include_logs:
                logs_dir = self.backup_dir.parent / "logs"
                if logs_dir.exists():
                    shutil.copytree(str(logs_dir), str(temp_dir / "logs"), dirs_exist_ok=True)

            tar_path = temp_dir / "archive.tar.gz"
            with tarfile.open(str(tar_path), "w:gz") as tar:
                for item in temp_dir.iterdir():
                    if item.name == "archive.tar.gz":
                        continue
                    tar.add(str(item), arcname=item.name)

            if encrypt_key:
                backup_path.write_bytes(_encrypt_bytes(tar_path.read_bytes(), encrypt_key))
            else:
                shutil.copy2(str(tar_path), str(backup_path))

            backup_size = backup_path.stat().st_size

            uploaded = False
            if settings.backup.s3_enabled:
                uploaded = _s3_upload(backup_path, backup_path.name)

            logger.info("Backup created: %s (%s bytes)", backup_path, backup_size)

            return {
                "path": str(backup_path),
                "name": name,
                "size": backup_size,
                "metadata": meta,
                "uploaded": uploaded,
            }

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
            if backup_path.suffix == ".enc":
                encrypt_key = settings.backup.encrypt_key
                if not encrypt_key:
                    logger.error("Backup is encrypted but no PICOSHOGUN_BACKUP_ENCRYPT_KEY is set")
                    return False
                try:
                    tar_bytes = _decrypt_bytes(backup_path.read_bytes(), encrypt_key)
                except Exception as exc:  # InvalidTag on wrong key, ValueError on bad envelope
                    logger.error("Backup decryption/integrity check failed: %s", exc)
                    return False
                tar_path = temp_dir / "archive.tar.gz"
                tar_path.parent.mkdir(parents=True, exist_ok=True)
                tar_path.write_bytes(tar_bytes)
            else:
                tar_path = backup_path

            with tarfile.open(str(tar_path), "r:gz") as tar:
                for member in tar.getmembers():
                    member_path = os.path.normpath(member.name)
                    if member_path.startswith("..") or Path(member.name).is_absolute():
                        logger.warning("Skipping unsafe path in archive: %s", member.name)
                        continue
                    if member.issym() or member.islnk():
                        logger.warning("Skipping symlink in archive: %s", member.name)
                        continue
                    tar.extract(member, str(temp_dir), filter="data")

            meta_path = temp_dir / "metadata.json"
            if meta_path.exists():
                with meta_path.open() as f:
                    meta = json.load(f)
                logger.info("Restoring backup from %s", meta["created"])

            db_backup = temp_dir / "database.sqlite3"
            if db_backup.exists():
                # Coordinate with the live pool before swapping the file:
                # close every thread's connection (close_all), copy the safety
                # backup while the WAL is checkpointed, drop the -wal/-shm side
                # files (a stale -wal replayed onto the restored DB corrupts
                # it), then swap. Pools re-open lazily — acquire() probes
                # liveness and reconnects to the restored file. The write half
                # of the manager's statement lock drains in-flight statements
                # and blocks new ones for the swap; without it a thread could
                # acquire a connection to the half-swapped database mid-restore.
                from picosentry.serve.database.manager import db as live_db

                with live_db._lock.write():
                    live_db.close()
                    for suffix in ("-wal", "-shm"):
                        Path(f"{self.db_path}{suffix}").unlink(missing_ok=True)
                    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
                    current_backup = f"{self.db_path}.pre_restore_{stamp}"
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

        for backup_file in self.backup_dir.glob("*.tar.gz*"):
            stat = backup_file.stat()
            backups.append(
                {
                    "name": backup_file.stem.replace(".tar", ""),
                    "path": str(backup_file),
                    "size": stat.st_size,
                    "created": datetime.fromtimestamp(stat.st_ctime).isoformat(),
                    "encrypted": backup_file.suffix == ".enc",
                }
            )

        return sorted(backups, key=lambda x: x["created"], reverse=True)

    def cleanup_old_backups(self) -> int:
        if not self.backup_dir.exists() or self.retention_days <= 0:
            return 0

        cutoff = datetime.now(timezone.utc).timestamp() - (self.retention_days * 86400)
        removed = 0

        for backup_file in self.backup_dir.glob("*.tar.gz*"):
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
