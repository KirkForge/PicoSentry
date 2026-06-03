"""
Custom IoC (Indicator of Compromise) registry for enterprise users.

Allows organizations to register their own supply-chain indicators
without modifying the built-in corpus. Custom IoCs are merged at scan time.

Usage:
    picosentry ioc register ./my-ioc.json
    picosentry ioc list
    picosentry ioc remove <id>

Corpus priority: custom IoCs > user corpus > built-in corpus.
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from datetime import datetime, timezone
from pathlib import Path

from picosentry.scan.audit import audit
from picosentry.scan.engine import user_corpus_dir
from picosentry.scan.enterprise import is_enterprise_mode

logger = logging.getLogger("picosentry.ioc_registry")


class IoCRecord:
    """A single custom IoC entry."""

    def __init__(self, data: dict) -> None:
        self.id: str = data.get("id", "")
        self.name: str = data.get("name", "")
        self.package_name: str = data.get("package_name", "")
        self.version_range: str = data.get("version_range", "*")
        self.ioc_type: str = data.get("ioc_type", "custom")
        self.attack_vector: str = data.get("attack_vector", "")
        self.severity: str = data.get("severity", "HIGH")
        self.description: str = data.get("description", "")
        self.references: list[str] = data.get("references", [])
        self.added_at: str = data.get("added_at", "")
        self.source: str = data.get("source", "custom")
        self.expires_at: str | None = data.get("expires_at")

        # Auto-generate ID from content if missing
        if not self.id:
            content = json.dumps(
                {
                    "name": self.name,
                    "package_name": self.package_name,
                    "ioc_type": self.ioc_type,
                },
                sort_keys=True,
            )
            self.id = hashlib.sha256(content.encode()).hexdigest()[:12]

        if not self.added_at:
            self.added_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict:
        d = {
            "id": self.id,
            "name": self.name,
            "package_name": self.package_name,
            "version_range": self.version_range,
            "ioc_type": self.ioc_type,
            "attack_vector": self.attack_vector,
            "severity": self.severity,
            "description": self.description,
            "references": self.references,
            "added_at": self.added_at,
            "source": self.source,
        }
        if self.expires_at:
            d["expires_at"] = self.expires_at
        return d


def custom_ioc_dir() -> Path:
    """Return the custom IoC directory for user-registered IoCs."""
    d = user_corpus_dir() / "ioc" / "custom"
    d.mkdir(parents=True, exist_ok=True)
    return d


# Only allow safe characters in IoC IDs (prevent path traversal)
_SAFE_IOC_ID = re.compile(r"^[A-Za-z0-9_.-]{1,128}$")


def _validate_ioc_id(ioc_id: str) -> None:
    """Validate that an IoC ID is safe for use as a filename component.

    Rejects IDs containing path separators, directory traversal sequences,
    or characters that could escape the intended directory.
    """
    if not ioc_id:
        raise ValueError("IoC id must not be empty")
    if ".." in ioc_id:
        raise ValueError(f"IoC id contains directory traversal: {ioc_id!r}")
    if "/" in ioc_id or "\\" in ioc_id:
        raise ValueError(f"IoC id contains path separator: {ioc_id!r}")
    if not _SAFE_IOC_ID.fullmatch(ioc_id):
        raise ValueError(f"IoC id contains invalid characters: {ioc_id!r}")


def register_ioc(ioc_data: dict, allow_overwrite: bool = False) -> IoCRecord:
    """Register a new custom IoC entry.

    Args:
        ioc_data: IoC data dict (minimal: name, package_name, description).
        allow_overwrite: If True, overwrite existing entry with same ID.

    Returns:
        The registered IoCRecord.

    Raises:
        FileExistsError: If entry exists and allow_overwrite is False.
    """
    record = IoCRecord(ioc_data)
    _validate_ioc_id(record.id)
    ioc_path = custom_ioc_dir() / f"{record.id}.json"

    resolved_path = ioc_path.resolve()
    resolved_dir = custom_ioc_dir().resolve()
    if resolved_dir not in resolved_path.parents and resolved_path.parent != resolved_dir:
        raise ValueError(f"IoC path escapes custom directory: {record.id!r}")

    if resolved_path.exists() and not allow_overwrite:
        raise FileExistsError(f"IoC entry already exists: {record.id}")

    data = record.to_dict()
    resolved_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    logger.info("Registered custom IoC: %s (%s)", record.id, record.name)
    audit(
        "ioc.register",
        target=f"{record.id}:{record.package_name}",
        metadata={"name": record.name, "severity": record.severity},
        fail_closed=is_enterprise_mode(),
    )

    return record


def list_custom_iocs() -> list[IoCRecord]:
    """List all user-registered custom IoCs."""
    records = []
    ioc_dir = custom_ioc_dir()
    if not ioc_dir.exists():
        return []

    for f in sorted(ioc_dir.glob("*.json")):
        if f.is_symlink():
            continue  # Skip symlinks for security
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            records.append(IoCRecord(data))
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to read IoC file %s: %s", f.name, e)

    return records


def remove_ioc(ioc_id: str) -> bool:
    """Remove a custom IoC entry by ID.

    Returns:
        True if removed, False if not found.
    """
    _validate_ioc_id(ioc_id)
    resolved_path = (custom_ioc_dir() / f"{ioc_id}.json").resolve()
    resolved_dir = custom_ioc_dir().resolve()
    if resolved_dir not in resolved_path.parents and resolved_path.parent != resolved_dir:
        raise ValueError(f"IoC path escapes custom directory: {ioc_id!r}")
    if resolved_path.exists():
        resolved_path.unlink()
        logger.info("Removed custom IoC: %s", ioc_id)
        audit("ioc.remove", target=ioc_id, outcome="success", fail_closed=is_enterprise_mode())
        return True
    audit("ioc.remove", target=ioc_id, outcome="not_found", fail_closed=is_enterprise_mode())
    return False


def load_all_iocs() -> list[dict]:
    """Load all IoCs: built-in + custom (merged).

    Custom IoCs override built-in if they share the same package_name + version_range.
    Used by the scanner to check against known-bad packages.
    """
    all_iocs: dict[str, dict] = {}

    # Load built-in IoCs directly from corpus directory
    # (avoids creating a full ScanEngine just to find the corpus path)
    corpus_dir = Path(__file__).parent / "corpus"
    builtin_dir = corpus_dir / "ioc"
    if builtin_dir.exists():
        for f in sorted(builtin_dir.glob("*.json")):
            if f.is_symlink():
                continue  # Skip symlinks for security
            try:
                data = json.loads(f.read_text(encoding="utf-8"))
                key = f"{data.get('package_name', '')}@{data.get('version_range', '*')}"
                all_iocs[key] = data
            except (json.JSONDecodeError, OSError):
                pass

    # Load custom IoCs (override built-in on conflict)
    for record in list_custom_iocs():
        key = f"{record.package_name}@{record.version_range}"
        all_iocs[key] = record.to_dict()

    return list(all_iocs.values())
