"""Versioned policy store with provenance tracking.

Each policy version records:
- Who created/modified it (``author``)
- When (``timestamp``)
- Why (``change_description``)
- A SHA-256 content hash for integrity verification
- Optional Sigstore signature (future)

The store supports:
- Listing all versions of a policy
- Diffing two versions
- Rolling back to a previous version
- Verifying integrity of all stored versions

Storage: file-based, one JSON file per version under
``~/.picodome/policies/<name>/v<version>.json``
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import tempfile
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from picosentry.sandbox.l3.models import Policy
from picosentry.sandbox.l3.policy import _policy_from_dict

logger = logging.getLogger("picodome.policy_versioned")

_DEFAULT_STORE_DIR = Path.home() / ".picodome" / "policies"


@dataclass(frozen=True)
class PolicyVersion:
    """A versioned snapshot of a Policy with provenance metadata."""

    policy: Policy
    version: int
    author: str
    timestamp: str
    change_description: str = ""
    content_hash: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "author": self.author,
            "change_description": self.change_description,
            "content_hash": self.content_hash,
            "policy": self.policy.to_dict(),
            "timestamp": self.timestamp,
            "version": self.version,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyVersion:
        policy_data = data.get("policy", {})
        policy = _policy_from_dict(policy_data)
        return cls(
            policy=policy,
            version=data.get("version", 1),
            author=data.get("author", "unknown"),
            timestamp=data.get("timestamp", ""),
            change_description=data.get("change_description", ""),
            content_hash=data.get("content_hash", ""),
        )


class VersionedPolicyStore:
    """File-based versioned policy store.

    Directory structure::

        ~/.picodome/policies/
        ├── picodome-default/
        │   ├── v1.json
        │   ├── v2.json
        │   └── latest -> v2.json  (symlink or metadata)
        └── custom-policy/
            └── v1.json
    """

    def __init__(self, store_dir: Path | None = None) -> None:
        self._store_dir = store_dir or _DEFAULT_STORE_DIR
        self._store_dir.mkdir(parents=True, exist_ok=True)

    def save(
        self,
        policy: Policy,
        author: str,
        change_description: str = "",
    ) -> PolicyVersion:
        """Save a new version of a policy.

        Assigns the next version number and records provenance.
        Returns the created PolicyVersion.
        """
        name = policy.name
        policy_dir = self._store_dir / name
        policy_dir.mkdir(parents=True, exist_ok=True)

        # Determine next version number
        existing = self._list_versions(name)
        next_version = max(v.version for v in existing) + 1 if existing else 1

        timestamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        content_hash = self._hash_policy(policy)

        pv = PolicyVersion(
            policy=policy,
            version=next_version,
            author=author,
            timestamp=timestamp,
            change_description=change_description,
            content_hash=content_hash,
        )

        path = policy_dir / f"v{next_version}.json"
        tmp_fd, tmp_path = tempfile.mkstemp(suffix=".json", dir=policy_dir)
        try:
            with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
                f.write(json.dumps(pv.to_dict(), indent=2, sort_keys=True, default=str))
            os.replace(tmp_path, path)
        except Exception:
            os.unlink(tmp_path)
            raise

        # Update latest pointer atomically
        latest_path = policy_dir / "latest.json"
        tmp_fd2, tmp_path2 = tempfile.mkstemp(suffix=".json", dir=policy_dir)
        try:
            with os.fdopen(tmp_fd2, "w", encoding="utf-8") as f:
                f.write(json.dumps(pv.to_dict(), indent=2, sort_keys=True, default=str))
            os.replace(tmp_path2, latest_path)
        except Exception:
            os.unlink(tmp_path2)
            raise

        logger.info(
            "Policy '%s' v%d saved by %s: %s",
            name,
            next_version,
            author,
            change_description,
        )

        return pv

    def load(self, name: str, version: int | None = None) -> PolicyVersion | None:
        """Load a policy version. None = latest."""
        if version is None:
            # Read latest
            latest_path = self._store_dir / name / "latest.json"
            if latest_path.is_file():
                return self._read_version_file(latest_path)
            # Fallback: find highest version
            versions = self._list_versions(name)
            if versions:
                return max(versions, key=lambda v: v.version)
            return None

        path = self._store_dir / name / f"v{version}.json"
        if not path.is_file():
            return None
        return self._read_version_file(path)

    def rollback(self, name: str, version: int, author: str) -> PolicyVersion | None:
        """Roll back to a previous version by re-saving it as a new version.

        This creates a new version (not overwriting history) so the
        rollback itself is auditable.
        """
        target = self.load(name, version)
        if target is None:
            logger.warning("Rollback failed: policy '%s' v%d not found", name, version)
            return None

        return self.save(
            policy=target.policy,
            author=author,
            change_description=f"Rollback to v{version}",
        )

    def diff(self, name: str, version_a: int, version_b: int) -> dict[str, Any]:
        """Diff two versions of a policy.

        Returns a dict with added_rules, removed_rules, changed_rules.
        """
        pv_a = self.load(name, version_a)
        pv_b = self.load(name, version_b)

        if pv_a is None or pv_b is None:
            return {"error": f"One or both versions not found: v{version_a}, v{version_b}"}

        rules_a = {r.rule_id: r for r in pv_a.policy.rules}
        rules_b = {r.rule_id: r for r in pv_b.policy.rules}

        added = [rid for rid in rules_b if rid not in rules_a]
        removed = [rid for rid in rules_a if rid not in rules_b]
        changed = []

        for rid in rules_a:
            if rid in rules_b:
                ra, rb = rules_a[rid], rules_b[rid]
                if ra.to_dict() != rb.to_dict():
                    changed.append(rid)

        default_changed = pv_a.policy.default_action != pv_b.policy.default_action

        return {
            "policy_name": name,
            "version_a": version_a,
            "version_b": version_b,
            "default_action_changed": default_changed,
            "added_rules": added,
            "removed_rules": removed,
            "changed_rules": changed,
        }

    def list_policies(self) -> list[str]:
        """List all policy names in the store."""
        if not self._store_dir.exists():
            return []
        return sorted(
            d.name for d in self._store_dir.iterdir() if d.is_dir() and any(f.suffix == ".json" for f in d.iterdir())
        )

    def list_versions(self, name: str) -> list[PolicyVersion]:
        """List all versions of a policy."""
        return self._list_versions(name)

    def verify_integrity(self, name: str) -> list[str]:
        """Verify content hash integrity for all versions."""
        violations: list[str] = []
        versions = self._list_versions(name)

        for pv in versions:
            expected_hash = self._hash_policy(pv.policy)
            if pv.content_hash and pv.content_hash != expected_hash:
                violations.append(
                    f"v{pv.version}: content_hash mismatch — "
                    f"stored={pv.content_hash[:16]}... computed={expected_hash[:16]}..."
                )

        return violations

    # ── Internal ────────────────────────────────────────────────────────

    def _list_versions(self, name: str) -> list[PolicyVersion]:
        """Internal: list versions from disk."""
        policy_dir = self._store_dir / name
        if not policy_dir.is_dir():
            return []

        versions: list[PolicyVersion] = []
        for f in sorted(policy_dir.iterdir()):
            if f.name.startswith("v") and f.name.endswith(".json") and f.name != "latest.json":
                pv = self._read_version_file(f)
                if pv:
                    versions.append(pv)

        return versions

    def _read_version_file(self, path: Path) -> PolicyVersion | None:
        """Read a PolicyVersion from a JSON file."""
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            return PolicyVersion.from_dict(data)
        except (json.JSONDecodeError, OSError, KeyError) as e:
            logger.warning("Failed to read policy version from %s: %s", path, e)
            return None

    @staticmethod
    def _hash_policy(policy: Policy) -> str:
        """SHA-256 hash of the policy's deterministic JSON representation."""
        data = policy.to_dict()
        return hashlib.sha256(json.dumps(data, sort_keys=True).encode()).hexdigest()


# ─── Module-level singleton ────────────────────────────────────────────────


_policy_store_lock = threading.Lock()
_policy_store: VersionedPolicyStore | None = None


def get_policy_store() -> VersionedPolicyStore:
    """Get the global policy store (lazy init)."""
    global _policy_store
    if _policy_store is None:
        with _policy_store_lock:
            if _policy_store is None:
                _policy_store = VersionedPolicyStore()
    return _policy_store
