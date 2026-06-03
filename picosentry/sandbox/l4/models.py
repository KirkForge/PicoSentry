"""L4 Behavioral Analysis — data models.

Deterministic by default: AnalysisResult.to_dict() omits timing fields
when deterministic=True. Finding.finding_id defaults to "".
"""

from __future__ import annotations

from dataclasses import dataclass, field

from picosentry.sandbox.models import (
    BehavioralVerdict,
    Finding,
)
from picosentry.sandbox.models import ScanStats  # noqa: F401 — re-exported for l4/engine convenience


@dataclass(frozen=True)
class NetworkCall:
    """A single network call observed during execution."""

    address: str
    port: int = 0
    protocol: str = "tcp"
    bytes_sent: int = 0
    bytes_received: int = 0
    timestamp_ms: int = 0

    def to_dict(self, deterministic: bool = False) -> dict:
        d: dict = {
            "address": self.address,
            "bytes_received": self.bytes_received,
            "bytes_sent": self.bytes_sent,
            "port": self.port,
            "protocol": self.protocol,
        }
        if not deterministic and self.timestamp_ms:
            d["timestamp_ms"] = self.timestamp_ms
        return {k: v for k, v in sorted(d.items())}


@dataclass(frozen=True)
class DnsQuery:
    """A DNS query observed during execution."""

    hostname: str
    resolved_ips: list[str] = field(default_factory=list)
    timestamp_ms: int = 0

    def to_dict(self, deterministic: bool = False) -> dict:
        d: dict = {
            "hostname": self.hostname,
            "resolved_ips": list(self.resolved_ips),
        }
        if not deterministic and self.timestamp_ms:
            d["timestamp_ms"] = self.timestamp_ms
        return {k: v for k, v in sorted(d.items())}


@dataclass(frozen=True)
class FileOperation:
    """A filesystem operation observed during execution."""

    path: str
    operation: str  # read, write, delete, create, chmod, chown
    success: bool = True
    bytes_transferred: int = 0
    timestamp_ms: int = 0

    def to_dict(self, deterministic: bool = False) -> dict:
        d: dict = {
            "bytes_transferred": self.bytes_transferred,
            "operation": self.operation,
            "path": self.path,
            "success": self.success,
        }
        if not deterministic and self.timestamp_ms:
            d["timestamp_ms"] = self.timestamp_ms
        return {k: v for k, v in sorted(d.items())}


@dataclass(frozen=True)
class ProcessSpawn:
    """A child process spawned during execution."""

    executable: str
    args: list[str] = field(default_factory=list)
    pid: int = 0
    exit_code: int | None = None
    timestamp_ms: int = 0

    def to_dict(self, deterministic: bool = False) -> dict:
        d: dict = {
            "args": list(self.args),
            "executable": self.executable,
            "exit_code": self.exit_code,
            "pid": self.pid,
        }
        if not deterministic and self.timestamp_ms:
            d["timestamp_ms"] = self.timestamp_ms
        return {k: v for k, v in sorted(d.items())}


@dataclass(frozen=True)
class TimingPoint:
    """A timing measurement during execution."""

    label: str
    elapsed_ms: int
    timestamp_ms: int = 0

    def to_dict(self, deterministic: bool = False) -> dict:
        d: dict = {
            "elapsed_ms": self.elapsed_ms,
            "label": self.label,
        }
        if not deterministic and self.timestamp_ms:
            d["timestamp_ms"] = self.timestamp_ms
        return {k: v for k, v in sorted(d.items())}


@dataclass(frozen=True)
class BehavioralProfile:
    """Full behavioral profile of a sandbox execution."""

    package: str
    timing_points: list[TimingPoint] = field(default_factory=list)
    network_calls: list[NetworkCall] = field(default_factory=list)
    dns_queries: list[DnsQuery] = field(default_factory=list)
    fs_ops: list[FileOperation] = field(default_factory=list)
    spawns: list[ProcessSpawn] = field(default_factory=list)
    entrypoint: str = ""
    total_runtime_ms: int = 0
    exit_code: int = 0
    stdout_len: int = 0
    stderr_len: int = 0

    def to_dict(self, deterministic: bool = False) -> dict:
        d: dict = {
            "dns_queries_count": len(self.dns_queries),
            "entrypoint": self.entrypoint,
            "exit_code": self.exit_code,
            "fs_ops_count": len(self.fs_ops),
            "network_calls_count": len(self.network_calls),
            "package": self.package,
            "spawns_count": len(self.spawns),
            "stderr_len": self.stderr_len,
            "stdout_len": self.stdout_len,
            "timing_points_count": len(self.timing_points),
        }
        if not deterministic:
            d["total_runtime_ms"] = self.total_runtime_ms
        return {k: v for k, v in sorted(d.items())}


@dataclass(frozen=True)
class Baseline:
    """A known-good behavioral baseline for a package."""

    name: str
    package: str
    version: str = ""
    expected_network_calls: int = 0
    expected_dns_queries: int = 0
    expected_fs_ops: int = 0
    expected_spawns: int = 0
    expected_runtime_ms_range: tuple = (0, 0)
    allowed_domains: list[str] = field(default_factory=list)
    allowed_paths: list[str] = field(default_factory=list)
    notes: str = ""

    def to_dict(self) -> dict:
        return {
            "allowed_domains": list(self.allowed_domains),
            "allowed_paths": list(self.allowed_paths),
            "expected_dns_queries": self.expected_dns_queries,
            "expected_fs_ops": self.expected_fs_ops,
            "expected_network_calls": self.expected_network_calls,
            "expected_runtime_ms_range": list(self.expected_runtime_ms_range),
            "expected_spawns": self.expected_spawns,
            "name": self.name,
            "notes": self.notes,
            "package": self.package,
            "version": self.version,
        }


@dataclass(frozen=True)
class DriftResult:
    """Result of comparing a profile against a baseline."""

    baseline_name: str
    score: float  # 0.0 = identical, 1.0 = completely different
    network_drift: bool = False
    dns_drift: bool = False
    fs_drift: bool = False
    spawn_drift: bool = False
    timing_drift: bool = False
    details: str = ""

    def to_dict(self) -> dict:
        return {
            "baseline_name": self.baseline_name,
            "details": self.details,
            "dns_drift": self.dns_drift,
            "fs_drift": self.fs_drift,
            "network_drift": self.network_drift,
            "score": self.score,
            "spawn_drift": self.spawn_drift,
            "timing_drift": self.timing_drift,
        }


@dataclass(frozen=True)
class AnalysisResult:
    """Complete L4 behavioral analysis result."""

    target: str
    findings: list[Finding] = field(default_factory=list)
    profile: BehavioralProfile | None = None
    drift_results: list[DriftResult] = field(default_factory=list)
    overall_verdict: BehavioralVerdict = BehavioralVerdict.CLEAN
    stats: ScanStats = field(default_factory=ScanStats)

    def to_dict(self, deterministic: bool = False) -> dict:
        """Serialize to dict with sorted keys.

        In deterministic mode, omit timing fields from stats and finding IDs.
        """
        return {
            "drift_results": [d.to_dict() for d in self.drift_results],
            "findings": [f.to_dict(deterministic=deterministic) for f in self.findings],
            "overall_verdict": self.overall_verdict.value,
            "profile": self.profile.to_dict(deterministic=deterministic) if self.profile else None,
            "stats": self.stats.to_dict(deterministic=deterministic),
            "target": self.target,
        }
