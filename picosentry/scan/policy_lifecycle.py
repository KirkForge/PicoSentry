from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from picosentry.scan.audit import audit
from picosentry.scan.policy import Policy

logger = logging.getLogger("picosentry.policy_lifecycle")

POLICY_LIFECYCLE_VERSION = "1.0"


class PolicyLayer:
    GLOBAL = "global"  # Organization-wide defaults
    ORG = "org"  # Organization/team overrides
    REPO = "repo"  # Repository/project overrides
    PIPELINE = "pipeline"  # Pipeline/CI-specific overrides

    ORDER = (GLOBAL, ORG, REPO, PIPELINE)

    @staticmethod
    def precedence(layer: str) -> int:
        try:
            return PolicyLayer.ORDER.index(layer)
        except ValueError:
            return -1

    @staticmethod
    def validate(layer: str) -> bool:
        return layer in PolicyLayer.ORDER


@dataclass
class InheritedPolicy:
    policy: Policy
    layer: str = PolicyLayer.GLOBAL
    source: str = ""  # File path or URL where policy was loaded from
    description: str = ""
    last_modified: str = ""
    modified_by: str = ""

    def __post_init__(self) -> None:
        if not PolicyLayer.validate(self.layer):
            raise ValueError(f"Invalid policy layer: {self.layer}")
        if not self.last_modified:
            self.last_modified = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "layer": self.layer,
            "source": self.source,
            "description": self.description,
            "last_modified": self.last_modified,
            "modified_by": self.modified_by,
            "policy": self.policy.to_dict(),
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> InheritedPolicy:
        return InheritedPolicy(
            policy=Policy.from_dict(d.get("policy", {})),
            layer=d.get("layer", PolicyLayer.GLOBAL),
            source=d.get("source", ""),
            description=d.get("description", ""),
            last_modified=d.get("last_modified", ""),
            modified_by=d.get("modified_by", ""),
        )

    @staticmethod
    def from_file(path: Path, layer: str = PolicyLayer.REPO) -> InheritedPolicy:
        data = json.loads(path.read_text(encoding="utf-8"))

        policy_data = data.get("policy", data)

        policy = Policy.from_dict(policy_data)
        return InheritedPolicy(
            policy=policy,
            layer=layer,
            source=str(path),
            description=data.get("description", ""),
            last_modified=data.get("last_modified", datetime.now(timezone.utc).isoformat()),
            modified_by=data.get("modified_by", ""),
        )


class PolicyStack:
    def __init__(self) -> None:
        self._layers: dict[str, InheritedPolicy] = {}

    def add(self, inherited: InheritedPolicy) -> None:
        self._layers[inherited.layer] = inherited

        audit(
            "policy.stack_add",
            target=f"{inherited.layer}:{inherited.source}",
            metadata={
                "layer": inherited.layer,
                "source": inherited.source[:256],
                "fail_on_severity": inherited.policy.fail_on_severity,
                "waivers": len(inherited.policy.waivers),
            },
        )
        logger.info("Added policy layer: %s from %s", inherited.layer, inherited.source)

    def remove(self, layer: str) -> bool:
        if layer in self._layers:
            del self._layers[layer]
            audit("policy.stack_remove", target=layer)
            return True
        return False

    def effective_policy(self) -> Policy:
        sorted_layers = sorted(
            self._layers.values(),
            key=lambda ip: PolicyLayer.precedence(ip.layer),
        )

        if not sorted_layers:
            return Policy()

        base = sorted_layers[0].policy

        for inherited in sorted_layers[1:]:
            base = _merge_policies(base, inherited.policy)

        return base

    def layers(self) -> list[InheritedPolicy]:
        return sorted(
            self._layers.values(),
            key=lambda ip: PolicyLayer.precedence(ip.layer),
        )

    def drift_report(self) -> dict[str, Any]:
        sorted_layers = self.layers()
        if len(sorted_layers) < 2:
            return {"layers": len(sorted_layers), "drift": [], "warnings": []}

        drift = []
        warnings = []

        for i in range(1, len(sorted_layers)):
            lower = sorted_layers[i - 1]
            upper = sorted_layers[i]

            from picosentry.scan.models import SEVERITY_ORDER

            severity_order = dict(SEVERITY_ORDER)  # canonical from models
            lower_sev = severity_order.get(lower.policy.fail_on_severity or "low", 0)
            upper_sev = severity_order.get(upper.policy.fail_on_severity or "low", 0)

            if upper_sev > lower_sev:
                drift.append(
                    {
                        "type": "severity_relaxation",
                        "lower_layer": lower.layer,
                        "upper_layer": upper.layer,
                        "detail": (
                            f"{upper.layer} relaxes fail_on_severity from "
                            f"{lower.policy.fail_on_severity} to {upper.policy.fail_on_severity}"
                        ),
                    }
                )
                warnings.append(
                    f"Policy drift: {upper.layer} relaxes severity threshold from "
                    f"{lower.policy.fail_on_severity} to {upper.policy.fail_on_severity}"
                )

            if lower.policy.deny_licenses and upper.policy.allow_licenses:
                conflicts = set(upper.policy.allow_licenses) & set(lower.policy.deny_licenses)
                if conflicts:
                    drift.append(
                        {
                            "type": "license_conflict",
                            "lower_layer": lower.layer,
                            "upper_layer": upper.layer,
                            "detail": f"{upper.layer} allows licenses that {lower.layer} denies: {conflicts}",
                        }
                    )
                    warnings.append(f"Policy drift: {upper.layer} allows licenses denied by {lower.layer}: {conflicts}")

        return {
            "layers": len(sorted_layers),
            "drift": drift,
            "warnings": warnings,
        }

    def to_json(self, indent: int = 2) -> str:
        data = {
            "version": POLICY_LIFECYCLE_VERSION,
            "layers": {k: v.to_dict() for k, v in self._layers.items()},
            "effective": self.effective_policy().to_dict(),
        }
        return json.dumps(data, indent=indent, sort_keys=True)


def _merge_policies(base: Policy, override: Policy) -> Policy:

    from picosentry.scan.models import SEVERITY_ORDER

    severity_order = dict(SEVERITY_ORDER)  # canonical from models
    base_sev = severity_order.get(base.fail_on_severity or "low", 0)
    override_sev = severity_order.get(override.fail_on_severity or "low", 0)
    effective_severity = base.fail_on_severity
    if override_sev < base_sev:
        effective_severity = override.fail_on_severity

    effective_rules = list(set(base.fail_on_rules + override.fail_on_rules))

    if base.allow_licenses and override.allow_licenses:
        effective_allow = list(set(base.allow_licenses) & set(override.allow_licenses))
    elif base.allow_licenses:
        effective_allow = list(base.allow_licenses)
    elif override.allow_licenses:
        effective_allow = list(override.allow_licenses)
    else:
        effective_allow = []

    effective_deny = list(set(base.deny_licenses + override.deny_licenses))

    effective_require_lockfile = base.require_lockfile or override.require_lockfile
    effective_require_integrity = base.require_integrity or override.require_integrity
    effective_require_provenance = base.require_provenance or override.require_provenance

    effective_deny_packages = list(set(base.deny_packages + override.deny_packages))

    effective_waivers = list(base.waivers) + list(override.waivers)

    return Policy(
        fail_on_severity=effective_severity,
        fail_on_rules=effective_rules,
        allow_licenses=effective_allow,
        deny_licenses=effective_deny,
        deny_packages=effective_deny_packages,
        waivers=effective_waivers,
        require_lockfile=effective_require_lockfile,
        require_integrity=effective_require_integrity,
        require_provenance=effective_require_provenance,
    )


def migrate_policy(policy_data: dict[str, Any], from_version: int = 0) -> dict[str, Any]:
    if from_version == 0:
        from_version = policy_data.get("version", 0)

    if from_version < 1:
        policy_data.setdefault("version", 1)
        policy_data.setdefault("fail_on_severity", "medium")
        policy_data.setdefault("fail_on_rules", [])
        policy_data.setdefault("allow_licenses", [])
        policy_data.setdefault("deny_licenses", [])
        policy_data.setdefault("deny_packages", [])
        policy_data.setdefault("require", {})
        policy_data.setdefault("waivers", [])

        for flag in ("lockfile", "integrity", "provenance"):
            if flag in policy_data and flag not in policy_data.get("require", {}):
                policy_data.setdefault("require", {})[flag] = policy_data.pop(flag)

    policy_data["version"] = 1

    audit(
        "policy.migrate",
        target=f"v{from_version}->v1",
        metadata={"from_version": from_version, "fields": list(policy_data.keys())},
    )

    return policy_data


def detect_policy_drift(stack: PolicyStack) -> dict[str, Any]:
    return stack.drift_report()
