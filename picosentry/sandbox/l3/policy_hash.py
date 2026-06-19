from __future__ import annotations

import hashlib
import json
from typing import Any

from picosentry.sandbox.l3.models import Policy


def canonical_policy_dict(policy: Policy) -> dict[str, Any]:

    d = policy.to_dict()
    rules = d.get("rules", [])

    def _norm_rule(r: dict[str, Any]) -> dict[str, Any]:
        return {
            "rule_id": r.get("rule_id", ""),
            "target": r.get("target", ""),
            "action": r.get("action", ""),
            "paths": sorted(r.get("paths", []) or []),
            "addresses": sorted(r.get("addresses", []) or []),
            "syscalls": sorted(r.get("syscalls", []) or []),
            "description": r.get("description", ""),
        }

    rules_norm = sorted([_norm_rule(r) for r in rules], key=lambda x: x["rule_id"])

    return {
        "name": d.get("name", ""),
        "version": d.get("version", ""),
        "default_action": d.get("default_action", ""),
        "rules": rules_norm,
    }


def policy_hash(policy: Policy) -> str:
    canon = canonical_policy_dict(policy)
    blob = json.dumps(canon, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(blob).hexdigest()
