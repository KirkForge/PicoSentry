from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from picosentry.sandbox.models import Verdict


class SyscallAction(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    KILL = "kill"
    TRACE = "trace"


class RuleTarget(str, Enum):
    FILE_READ = "file_read"
    FILE_WRITE = "file_write"
    FILE_EXEC = "file_exec"
    NETWORK_OUT = "network_out"
    NETWORK_IN = "network_in"
    NETWORK_BIND = "network_bind"
    PROCESS_SPAWN = "process_spawn"
    PROCESS_KILL = "process_kill"
    DNS_QUERY = "dns_query"
    SIGNAL_SEND = "signal_send"
    SYSCALL_GENERIC = "syscall_generic"


@dataclass(frozen=True)
class PolicyRule:
    rule_id: str
    target: RuleTarget
    action: SyscallAction
    paths: list[str] = field(default_factory=list)
    addresses: list[str] = field(default_factory=list)
    syscalls: list[str] = field(default_factory=list)
    description: str = ""

    def to_dict(self) -> dict:
        return {
            "action": self.action.value,
            "addresses": list(self.addresses),
            "description": self.description,
            "paths": list(self.paths),
            "rule_id": self.rule_id,
            "syscalls": list(self.syscalls),
            "target": self.target.value,
        }


@dataclass(frozen=True)
class Policy:
    name: str
    version: str = "1.0"
    default_action: SyscallAction = SyscallAction.DENY
    rules: list[PolicyRule] = field(default_factory=list)
    fail_closed: bool = True

    def to_dict(self) -> dict:
        return {
            "default_action": self.default_action.value,
            "fail_closed": self.fail_closed,
            "name": self.name,
            "rules": [
                {
                    "action": r.action.value,
                    "addresses": list(r.addresses),
                    "description": r.description,
                    "paths": list(r.paths),
                    "rule_id": r.rule_id,
                    "syscalls": list(r.syscalls),
                    "target": r.target.value,
                }
                for r in self.rules
            ],
            "version": self.version,
        }


@dataclass(frozen=True)
class SandboxEvent:
    rule_id: str
    verdict: Verdict
    operation: str
    detail: str
    path: str = ""
    address: str = ""
    timestamp_ms: int = 0

    def to_dict(self, deterministic: bool = False) -> dict:
        d: dict = {
            "detail": self.detail,
            "operation": self.operation,
            "path": self.path,
            "rule_id": self.rule_id,
            "verdict": self.verdict.value,
        }
        if self.address:
            d["address"] = self.address
        if not deterministic and self.timestamp_ms:
            d["timestamp_ms"] = self.timestamp_ms
        return dict(sorted(d.items()))


@dataclass(frozen=True)
class SandboxResult:
    run_id: str = ""
    timestamp: str = ""

    backend: str = ""
    policy_hash: str = ""
    policy_version: str = ""

    command: list[str] = field(default_factory=list)
    overall_verdict: Verdict = Verdict.ALLOW
    exit_code: int = 0
    duration_ms: int = 0
    events: list[SandboxEvent] = field(default_factory=list)
    policy_name: str = ""
    backend_name: str = ""
    isolation_level: str = ""
    enforcement_guarantee: str = ""
    degraded: bool = False
    stdout: str = ""
    stderr: str = ""

    def to_dict(self, deterministic: bool = False) -> dict:
        d: dict = {
            "backend": self.backend_name,
            "command": list(self.command),
            "degraded": self.degraded,
            "enforcement_guarantee": self.enforcement_guarantee,
            "events": [e.to_dict(deterministic=deterministic) for e in self.events],
            "exit_code": self.exit_code,
            "isolation_level": self.isolation_level,
            "overall_verdict": self.overall_verdict.value,
            "policy_name": self.policy_name,
            "policy_version": self.policy_version,
            "policy_hash": self.policy_hash,
        }
        if not deterministic:
            d["duration_ms"] = self.duration_ms
            if self.run_id:
                d["run_id"] = self.run_id
            if self.timestamp:
                d["timestamp"] = self.timestamp
        return dict(sorted(d.items()))
