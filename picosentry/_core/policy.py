
from __future__ import annotations

import hashlib
import json
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PolicyVersion:

    version: int = 1
    schema_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        return {"version": self.version, "schema_version": self.schema_version}


class PolicyBase(ABC):

    @property
    @abstractmethod
    def policy_version(self) -> PolicyVersion:
        ...

    @property
    def digest(self) -> str:
        canonical = json.dumps(self.to_dict(), sort_keys=True, separators=(",", ":"))
        return f"sha256:{hashlib.sha256(canonical.encode()).hexdigest()[:32]}"

    @abstractmethod
    def to_dict(self) -> dict[str, Any]:
        ...

    @classmethod
    @abstractmethod
    def from_dict(cls, data: dict[str, Any]) -> PolicyBase:
        ...

    def to_json(self, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=indent)


def content_hash(data: dict[str, Any]) -> str:
    canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


__all__ = [
    "PolicyBase",
    "PolicyVersion",
    "content_hash",
]
