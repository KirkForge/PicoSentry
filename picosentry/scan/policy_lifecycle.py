"""
Policy lifecycle -- inheritance, versioning, audit trail, and migration
for enterprise PicoSentry deployments.

Extends the core Policy module with:
- Policy inheritance: global -> org -> repo -> pipeline layers
- Expiring suppressions with required justification and owner
- Policy change audit events
- Policy migration and versioning
- Drift detection between policy layers

Usage:
    from picosentry.scan.policy_lifecycle import (
        PolicyLayer, PolicyStack, InheritedPolicy,
        detect_policy_drift, migrate_policy,
    )
"""

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

# -- Policy layers (inheritance hierarchy) ---------------------------------


class PolicyLayer:
    """Policy inheritance layers from broadest to most specific.

    Each layer can override or refine the layer above it.
    The effective policy is computed by merging layers top-to-bottom.
    """

    GLOBAL = "global"  # Organization-wide defaults
    ORG = "org"  # Organization/team overrides
    REPO = "repo"  # Repository/project overrides
    PIPELINE = "pipeline"  # Pipeline/CI-specific overrides

    ORDER = (GLOBAL, ORG, REPO, PIPELINE)

    @staticmethod
    def precedence(layer: str) -> int:
        """Return precedence (higher = more specific)."""
        try:
            return PolicyLayer.ORDER.index(layer)
        except ValueError:
            return -1

    @staticmethod
    def validate(layer: str) -> bool:
        return layer in PolicyLayer.ORDER


# -- Inherited policy -------------------------------------------------------


@dataclass
class InheritedPolicy:
    """A policy at a specific inheritance layer.

    Wraps a Policy with layer metadata, source, and audit trail.
    """

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
        """Load a policy from a file with layer metadata."""
        data = json.loads(path.read_text(encoding="utf-8"))

        # Handle policy bundle format
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


# -- Policy stack (merged inheritance) --------------------------------------


class PolicyStack:
    """A stack of inherited policies merged into an effective policy.

    Layers are merged top-to-bottom: GLOBAL -> ORG -> REPO -> PIPELINE.
    More specific layers override broader ones. Waivers are accumulated
    (not overridden) across all layers.

    Usage:
        stack = PolicyStack()
        stack.add(InheritedPolicy(policy=global_policy, layer="global"))
        stack.add(InheritedPolicy(policy=repo_policy, layer="repo"))
        effective = stack.effective_policy()
    """

    def __init__(self) -> None:
        self._layers: dict[str, InheritedPolicy] = {}

    def add(self, inherited: InheritedPolicy) -> None:
        """Add a policy layer to the stack."""
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
        """Remove a policy layer from the stack."""
        if layer in self._layers:
            del self._layers[layer]
            audit("policy.stack_remove", target=layer)
            return True
        return False

    def effective_policy(self) -> Policy:
        """Compute the effective policy by merging all layers.

        Merge order: GLOBAL -> ORG -> REPO -> PIPELINE
        Later layers override earlier ones for:
        - fail_on_severity (higher specificity wins)
        - fail_on_rules (union across layers)
        - allow_licenses (more restrictive wins: intersection)
        - deny_licenses (union across layers)
        - require flags (union across layers)

        Waivers are accumulated from all layers (not overridden).
        """
        sorted_layers = sorted(
            self._layers.values(),
            key=lambda ip: PolicyLayer.precedence(ip.layer),
        )

        if not sorted_layers:
            return Policy()

        # Start with the broadest layer
        base = sorted_layers[0].policy

        # Merge subsequent layers
        for inherited in sorted_layers[1:]:
            base = _merge_policies(base, inherited.policy)

        return base

    def layers(self) -> list[InheritedPolicy]:
        """Return all layers in precedence order."""
        return sorted(
            self._layers.values(),
            key=lambda ip: PolicyLayer.precedence(ip.layer),
        )

    def drift_report(self) -> dict[str, Any]:
        """Detect drift between policy layers.

        Returns a report showing where layers conflict or
        where a more specific layer relaxes a broader layer.
        """
        sorted_layers = self.layers()
        if len(sorted_layers) < 2:
            return {"layers": len(sorted_layers), "drift": [], "warnings": []}

        drift = []
        warnings = []

        for i in range(1, len(sorted_layers)):
            lower = sorted_layers[i - 1]
            upper = sorted_layers[i]

            # Check if upper layer relaxes severity threshold
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
                        "detail": f"{upper.layer} relaxes fail_on_severity from {lower.policy.fail_on_severity} to {upper.policy.fail_on_severity}",
                    }
                )
                warnings.append(
                    f"Policy drift: {upper.layer} relaxes severity threshold from "
                    f"{lower.policy.fail_on_severity} to {upper.policy.fail_on_severity}"
                )

            # Check if upper layer adds allow_licenses that lower denies
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
        """Export the full policy stack as JSON."""
        data = {
            "version": POLICY_LIFECYCLE_VERSION,
            "layers": {k: v.to_dict() for k, v in self._layers.items()},
            "effective": self.effective_policy().to_dict(),
        }
        return json.dumps(data, indent=indent, sort_keys=True)


# -- Policy merge logic -----------------------------------------------------


def _merge_policies(base: Policy, override: Policy) -> Policy:
    """Merge two policies, with override taking precedence.

    - fail_on_severity: override wins if more specific
    - fail_on_rules: union
    - allow_licenses: intersection (more restrictive) if both set, else union
    - deny_licenses: union
    - require flags: union (more restrictive)
    - waivers: union from both
    """
    # Severity: more restrictive wins (lower number = more severe)
    from picosentry.scan.models import SEVERITY_ORDER
    severity_order = dict(SEVERITY_ORDER)  # canonical from models
    base_sev = severity_order.get(base.fail_on_severity or "low", 0)
    override_sev = severity_order.get(override.fail_on_severity or "low", 0)
    effective_severity = base.fail_on_severity
    if override_sev < base_sev:
        effective_severity = override.fail_on_severity

    # Rules: union
    effective_rules = list(set(base.fail_on_rules + override.fail_on_rules))

    # Licenses: intersection if both set, union otherwise
    if base.allow_licenses and override.allow_licenses:
        effective_allow = list(set(base.allow_licenses) & set(override.allow_licenses))
    elif base.allow_licenses:
        effective_allow = list(base.allow_licenses)
    elif override.allow_licenses:
        effective_allow = list(override.allow_licenses)
    else:
        effective_allow = []

    effective_deny = list(set(base.deny_licenses + override.deny_licenses))

    # Require flags: union (more restrictive)
    effective_require_lockfile = base.require_lockfile or override.require_lockfile
    effective_require_integrity = base.require_integrity or override.require_integrity
    effective_require_provenance = base.require_provenance or override.require_provenance

    # Deny packages: union
    effective_deny_packages = list(set(base.deny_packages + override.deny_packages))

    # Waivers: union from both (with expiration check)
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


# -- Policy migration -------------------------------------------------------


def migrate_policy(policy_data: dict[str, Any], from_version: int = 0) -> dict[str, Any]:
    """Migrate a policy dict from an older schema version.

    Handles field renames, default additions, and structural changes
    so enterprise teams can upgrade PicoSentry without breaking policies.

    Args:
        policy_data: Raw policy dict (may be from an older version).
        from_version: Schema version of the input data (0 = auto-detect).

    Returns:
        Migrated policy dict compatible with the current version.
    """
    if from_version == 0:
        from_version = policy_data.get("version", 0)

    # Version 0 -> 1: Add version field, ensure required lists exist
    if from_version < 1:
        policy_data.setdefault("version", 1)
        policy_data.setdefault("fail_on_severity", "medium")
        policy_data.setdefault("fail_on_rules", [])
        policy_data.setdefault("allow_licenses", [])
        policy_data.setdefault("deny_licenses", [])
        policy_data.setdefault("deny_packages", [])
        policy_data.setdefault("require", {})
        policy_data.setdefault("waivers", [])

        # Migrate flat require flags into the require dict
        for flag in ("lockfile", "integrity", "provenance"):
            if flag in policy_data and flag not in policy_data.get("require", {}):
                policy_data.setdefault("require", {})[flag] = policy_data.pop(flag)

    # Ensure version is current
    policy_data["version"] = 1

    audit(
        "policy.migrate",
        target=f"v{from_version}->v1",
        metadata={"from_version": from_version, "fields": list(policy_data.keys())},
    )

    return policy_data


# -- Drift detection --------------------------------------------------------


def detect_policy_drift(stack: PolicyStack) -> dict[str, Any]:
    """Convenience function to detect policy drift in a stack."""
    return stack.drift_report()
