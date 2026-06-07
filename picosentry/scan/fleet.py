
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from picosentry.scan.audit import audit
from picosentry.scan.policy import Policy

logger = logging.getLogger("picosentry.fleet")

FLEET_VERSION = "1.0"


class RolloutStage:

    CANARY = "canary"
    STAGING = "staging"
    PRODUCTION = "production"

    ORDER = (CANARY, STAGING, PRODUCTION)

    @staticmethod
    def precedence(stage: str) -> int:
        try:
            return RolloutStage.ORDER.index(stage)
        except ValueError:
            return -1

    @staticmethod
    def validate(stage: str) -> bool:
        return stage in RolloutStage.ORDER


@dataclass
class RolloutPolicy:

    name: str = ""
    policy_digest: str = ""
    policy_path: str = ""
    stages: list[str] = field(default_factory=lambda: list(RolloutStage.ORDER))
    canary_targets: list[str] = field(default_factory=list)  # repo or pipeline identifiers
    failure_action: str = "rollback"  # rollback, pause, notify
    created_at: str = ""
    created_by: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if not self.created_at:
            self.created_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "policy_digest": self.policy_digest,
            "policy_path": self.policy_path,
            "stages": self.stages,
            "canary_targets": self.canary_targets,
            "failure_action": self.failure_action,
            "created_at": self.created_at,
            "created_by": self.created_by,
            "metadata": self.metadata,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> RolloutPolicy:
        return RolloutPolicy(
            name=d.get("name", ""),
            policy_digest=d.get("policy_digest", ""),
            policy_path=d.get("policy_path", ""),
            stages=d.get("stages", list(RolloutStage.ORDER)),
            canary_targets=d.get("canary_targets", []),
            failure_action=d.get("failure_action", "rollback"),
            created_at=d.get("created_at", ""),
            created_by=d.get("created_by", ""),
            metadata=d.get("metadata", {}),
        )


@dataclass
class RolloutStatus:

    name: str = ""
    current_stage: str = ""
    started_at: str = ""
    promoted_at: str = ""
    completed_at: str = ""
    failed: bool = False
    failure_reason: str = ""
    targets_reached: int = 0
    targets_total: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "current_stage": self.current_stage,
            "started_at": self.started_at,
            "promoted_at": self.promoted_at,
            "completed_at": self.completed_at,
            "failed": self.failed,
            "failure_reason": self.failure_reason,
            "targets_reached": self.targets_reached,
            "targets_total": self.targets_total,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> RolloutStatus:
        return RolloutStatus(
            name=d.get("name", ""),
            current_stage=d.get("current_stage", ""),
            started_at=d.get("started_at", ""),
            promoted_at=d.get("promoted_at", ""),
            completed_at=d.get("completed_at", ""),
            failed=d.get("failed", False),
            failure_reason=d.get("failure_reason", ""),
            targets_reached=d.get("targets_reached", 0),
            targets_total=d.get("targets_total", 0),
        )


@dataclass
class FleetTarget:

    id: str = ""  # e.g., "repo:org/project" or "pipeline:ci/deploy"
    name: str = ""
    stage: str = RolloutStage.PRODUCTION
    policy_digest: str = ""
    last_scan_at: str = ""
    last_scan_verdict: str = ""
    compliant: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "stage": self.stage,
            "policy_digest": self.policy_digest,
            "last_scan_at": self.last_scan_at,
            "last_scan_verdict": self.last_scan_verdict,
            "compliant": self.compliant,
            "metadata": self.metadata,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> FleetTarget:
        return FleetTarget(
            id=d.get("id", ""),
            name=d.get("name", ""),
            stage=d.get("stage", RolloutStage.PRODUCTION),
            policy_digest=d.get("policy_digest", ""),
            last_scan_at=d.get("last_scan_at", ""),
            last_scan_verdict=d.get("last_scan_verdict", ""),
            compliant=d.get("compliant", True),
            metadata=d.get("metadata", {}),
        )


class FleetManager:

    def __init__(self, data_dir: Path | None = None) -> None:
        self.data_dir = data_dir or Path.home() / ".local" / "share" / "picosentry" / "fleet"
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self._targets: dict[str, FleetTarget] = {}
        self._rollouts: dict[str, RolloutPolicy] = {}
        self._statuses: dict[str, RolloutStatus] = {}
        self._previous_policies: dict[str, str] = {}  # target -> previous policy digest
        self._load_state()

    def _state_file(self) -> Path:
        return self.data_dir / "fleet-state.json"

    def _load_state(self) -> None:
        state_file = self._state_file()
        if not state_file.is_file():
            return
        try:
            data = json.loads(state_file.read_text(encoding="utf-8"))
            for tid, td in data.get("targets", {}).items():
                self._targets[tid] = FleetTarget.from_dict(td)
            for rn, rd in data.get("rollouts", {}).items():
                self._rollouts[rn] = RolloutPolicy.from_dict(rd)
            for sn, sd in data.get("statuses", {}).items():
                self._statuses[sn] = RolloutStatus.from_dict(sd)
            self._previous_policies = data.get("previous_policies", {})
        except (json.JSONDecodeError, OSError) as e:
            logger.warning("Failed to load fleet state: %s", e)

    def _save_state(self) -> None:
        state_file = self._state_file()
        data = {
            "targets": {tid: t.to_dict() for tid, t in self._targets.items()},
            "rollouts": {rn: r.to_dict() for rn, r in self._rollouts.items()},
            "statuses": {sn: s.to_dict() for sn, s in self._statuses.items()},
            "previous_policies": self._previous_policies,
        }
        state_file.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")


    def register_target(self, target: FleetTarget) -> None:
        self._targets[target.id] = target
        self._save_state()
        audit("fleet.register_target", target=target.id, metadata={"stage": target.stage})

    def unregister_target(self, target_id: str) -> bool:
        if target_id in self._targets:
            del self._targets[target_id]
            self._save_state()
            audit("fleet.unregister_target", target=target_id, outcome="success")
            return True
        audit("fleet.unregister_target", target=target_id, outcome="not_found")
        return False

    def list_targets(self, stage: str = "") -> list[FleetTarget]:
        targets = list(self._targets.values())
        if stage:
            targets = [t for t in targets if t.stage == stage]
        return sorted(targets, key=lambda t: t.id)

    def get_target(self, target_id: str) -> FleetTarget | None:
        return self._targets.get(target_id)

    def update_target_status(
        self, target_id: str, verdict: str = "", compliant: bool = True, policy_digest: str = ""
    ) -> None:
        target = self._targets.get(target_id)
        if not target:
            logger.warning("Unknown target: %s", target_id)
            return

        if policy_digest and policy_digest != target.policy_digest:
            self._previous_policies[target_id] = target.policy_digest
            target.policy_digest = policy_digest

        if verdict:
            target.last_scan_verdict = verdict
        target.last_scan_at = datetime.now(timezone.utc).isoformat()
        target.compliant = compliant
        self._save_state()
        audit(
            "fleet.update_target",
            target=target_id,
            metadata={"verdict": verdict, "compliant": compliant},
        )


    def create_rollout(
        self,
        name: str,
        policy_path: Path | str = "",
        policy: Policy | None = None,
        stages: list[str] | None = None,
        canary_targets: list[str] | None = None,
        failure_action: str = "rollback",
        created_by: str = "",
    ) -> RolloutStatus:
        if name in self._rollouts:
            raise ValueError(f"Rollout '{name}' already exists")

        stages = stages or list(RolloutStage.ORDER)
        canary_targets = canary_targets or []


        policy_digest = ""
        if policy:
            policy_digest = f"sha256:{policy.digest}" if hasattr(policy, "digest") and policy.digest else ""
        elif policy_path:
            policy_path = Path(policy_path)
            if policy_path.is_file():
                try:
                    policy = Policy.from_file(policy_path)
                    policy_digest = f"sha256:{policy.digest}" if hasattr(policy, "digest") and policy.digest else ""
                except Exception as e:
                    logger.warning("Failed to load policy from %s: %s", policy_path, e)

        rollout = RolloutPolicy(
            name=name,
            policy_digest=policy_digest,
            policy_path=str(policy_path),
            stages=stages,
            canary_targets=canary_targets,
            failure_action=failure_action,
            created_by=created_by,
        )
        self._rollouts[name] = rollout


        initial_stage = stages[0] if stages else RolloutStage.CANARY
        status = RolloutStatus(
            name=name,
            current_stage=initial_stage,
            started_at=datetime.now(timezone.utc).isoformat(),
            targets_total=len(self._targets),
            targets_reached=0,
        )
        self._statuses[name] = status
        self._save_state()

        audit(
            "fleet.create_rollout",
            target=name,
            metadata={
                "stages": stages,
                "canary_targets": canary_targets,
                "policy_digest": policy_digest,
                "failure_action": failure_action,
            },
        )

        return status

    def promote_rollout(self, name: str) -> RolloutStatus:
        if name not in self._rollouts:
            raise ValueError(f"Rollout '{name}' not found")

        rollout = self._rollouts[name]
        status = self._statuses.get(name)
        if not status:
            raise ValueError(f"Status for rollout '{name}' not found")

        current_idx = RolloutStage.precedence(status.current_stage)
        if current_idx < 0:
            raise ValueError(f"Invalid current stage: {status.current_stage}")

        next_idx = current_idx + 1
        if next_idx >= len(rollout.stages):
            raise ValueError(f"Rollout '{name}' is already at the last stage")


        old_stage = status.current_stage
        new_stage = rollout.stages[next_idx]

        status.current_stage = new_stage
        status.promoted_at = datetime.now(timezone.utc).isoformat()
        self._save_state()

        audit(
            "fleet.promote_rollout",
            target=name,
            metadata={"from": old_stage, "to": new_stage},
        )

        return status

    def complete_rollout(self, name: str) -> RolloutStatus:
        if name not in self._statuses:
            raise ValueError(f"Rollout '{name}' not found")

        status = self._statuses[name]
        status.completed_at = datetime.now(timezone.utc).isoformat()
        status.targets_reached = len(self._targets)
        self._save_state()

        audit("fleet.complete_rollout", target=name, metadata={"targets_reached": status.targets_reached})
        return status

    def fail_rollout(self, name: str, reason: str = "") -> RolloutStatus:
        if name not in self._rollouts:
            raise ValueError(f"Rollout '{name}' not found")

        rollout = self._rollouts[name]
        status = self._statuses.get(name)
        if not status:
            raise ValueError(f"Status for rollout '{name}' not found")

        status.failed = True
        status.failure_reason = reason
        self._save_state()

        if rollout.failure_action == "rollback":
            self._rollback_targets(name)

        audit(
            "fleet.fail_rollout",
            target=name,
            outcome="failure",
            metadata={"reason": reason, "action": rollout.failure_action},
        )

        return status

    def _rollback_targets(self, name: str) -> None:
        for target_id, prev_digest in self._previous_policies.items():
            target = self._targets.get(target_id)
            if target and prev_digest:
                target.policy_digest = prev_digest
                logger.info("Rolled back target %s to policy %s", target_id, prev_digest[:16])

        self._save_state()

    def get_rollout_status(self, name: str) -> RolloutStatus | None:
        return self._statuses.get(name)

    def list_rollouts(self, active_only: bool = False) -> list[RolloutPolicy]:
        rollouts = list(self._rollouts.values())
        if active_only:
            rollouts = [
                r
                for r in rollouts
                if r.name in self._statuses
                and not self._statuses[r.name].completed_at
                and not self._statuses[r.name].failed
            ]
        return sorted(rollouts, key=lambda r: r.created_at, reverse=True)


    def fleet_health(self) -> dict[str, Any]:
        total = len(self._targets)
        compliant = sum(1 for t in self._targets.values() if t.compliant)
        with_policy = sum(1 for t in self._targets.values() if t.policy_digest)
        active_rollouts = sum(
            1 for s in self._statuses.values() if s.started_at and not s.completed_at and not s.failed
        )
        failed_rollouts = sum(1 for s in self._statuses.values() if s.failed)


        stage_counts: dict[str, int] = {}
        for t in self._targets.values():
            stage_counts[t.stage] = stage_counts.get(t.stage, 0) + 1

        return {
            "total_targets": total,
            "compliant_targets": compliant,
            "non_compliant_targets": total - compliant,
            "compliance_pct": round(compliant / total * 100, 1) if total else 100.0,
            "policy_coverage": with_policy,
            "policy_coverage_pct": round(with_policy / total * 100, 1) if total else 0.0,
            "active_rollouts": active_rollouts,
            "failed_rollouts": failed_rollouts,
            "stage_distribution": stage_counts,
        }

    def compliance_report(self) -> dict[str, Any]:
        targets_report = []
        for target in self._targets.values():
            targets_report.append(
                {
                    "id": target.id,
                    "name": target.name,
                    "stage": target.stage,
                    "compliant": target.compliant,
                    "policy_digest": target.policy_digest[:16] if target.policy_digest else "none",
                    "last_scan_at": target.last_scan_at,
                    "last_scan_verdict": target.last_scan_verdict,
                }
            )

        health = self.fleet_health()
        return {
            "fleet_health": health,
            "targets": sorted(targets_report, key=lambda t: t["id"]),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
