"""Shared policy primitives — vendored from pico-core.

Provides a base class and protocol for policy-as-code models.
Both PicoDome (sandbox execution policy) and PicoSentry (scan enforcement
policy) use policy objects with common patterns: versioning, content
hashing, serialization, and deterministic enforcement.

This module extracts the shared base so each codebase can subclass
while sharing the deterministic guarantees.
"""

from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PolicyVersion:
    """Version metadata for a policy object.

    Deterministic: same version string = same enforcement result.
    """

    version: int = 1
    schema_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        return {"version": self.version, "schema_version": self.schema_version}


class PolicyBase(ABC):
    """Abstract base for all PicoSeries policy objects.

    Enforces:
    - Content hashing (deterministic digest)
    - Version tracking
    - Deterministic serialization (sorted keys, no random content)
    - from_dict / to_dict for persistence
    """

    @property
    @abstractmethod
    def policy_version(self) -> PolicyVersion:
        """Return version metadata for this policy."""
        ...

    @property
    def digest(self) -> str:
        """Deterministic content digest (SHA-256) of the policy.

        Same policy content = same digest, regardless of when/where computed.
        """
        canonical = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()[:32]}"

    @abstractmethod
    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict. Must use sorted keys for deterministic output."""
        ...

    @classmethod
    @abstractmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyBase:
        """Deserialize from dict. Round-trips with to_dict()."""
        ...

    def to_json(self, indent: int = 2) -> str:
        """Deterministic JSON — sorted keys, no random content."""
        return json.dumps(self.to_dict(), sort_keys=True, indent=indent)


def content_hash(data: dict[str, Any]) -> str:
    """Compute a deterministic SHA-256 hash of any dict.

    Utility for policy versioning and cache keys.
    """
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


__all__ = [
    "PolicyBase",
    "PolicyVersion",
    "content_hash",
]
