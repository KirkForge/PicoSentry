from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class PolicyVersion:
    version: int = 1
    schema_version: str = "1.0"

    def to_dict(self) -> dict[str, Any]:
        return {"version": self.version, "schema_version": self.schema_version}


__all__ = [
    "PolicyVersion",
]
