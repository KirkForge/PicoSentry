"""Shared fixtures for PicoDome tests."""

import json
import tempfile
from pathlib import Path

import pytest

from picosentry.sandbox.l3.models import (
    Policy,
    PolicyRule,
    RuleTarget,
    SandboxEvent,
    SandboxResult,
    SyscallAction,
)
from picosentry.sandbox.l4.models import (
    Baseline,
    BehavioralProfile,
    DnsQuery,
    FileOperation,
    NetworkCall,
    ProcessSpawn,
    TimingPoint,
)
from picosentry.sandbox.models import (
    Finding,
    Severity,
    Verdict,
)

# ─── Shared model fixtures ──────────────────────────────────────────────────


@pytest.fixture
def clean_finding():
    """A finding with no uuid4 or timestamp — fully deterministic."""
    return Finding(
        rule_id="TEST-001",
        severity=Severity.HIGH,
        message="Test finding",
        location="/tmp/test",
        evidence={"key": "value"},
    )


@pytest.fixture
def critical_finding():
    return Finding(
        rule_id="TEST-CRIT",
        severity=Severity.CRITICAL,
        message="Critical test finding",
        location="/etc/passwd",
        evidence={},
    )


@pytest.fixture
def medium_finding():
    return Finding(
        rule_id="TEST-MED",
        severity=Severity.MEDIUM,
        message="Medium test finding",
        location="/tmp/medium",
        evidence={},
    )


@pytest.fixture
def info_finding():
    return Finding(
        rule_id="TEST-INFO",
        severity=Severity.INFO,
        message="Info test finding",
        location="/tmp/info",
        evidence={},
    )


@pytest.fixture
def clean_sandbox_result():
    """A SandboxResult for a clean run — no events."""
    return SandboxResult(
        run_id="deterministic-run-001",
        timestamp="2025-01-01T00:00:00Z",
        command=["echo", "hello"],
        overall_verdict=Verdict.ALLOW,
        exit_code=0,
        duration_ms=42,
        events=[],
        policy_name="test-policy",
        stdout="hello",
        stderr="",
    )


@pytest.fixture
def suspicious_sandbox_result():
    """A SandboxResult with DENY events."""
    return SandboxResult(
        run_id="deterministic-run-002",
        timestamp="2025-01-01T00:00:00Z",
        command=["python3", "-c", "print('evil')"],
        overall_verdict=Verdict.DENY,
        exit_code=0,
        duration_ms=100,
        events=[
            SandboxEvent(
                rule_id="L3-SUS-001",
                verdict=Verdict.DENY,
                operation="dynamic_code_exec",
                detail="eval() detected",
            ),
        ],
        policy_name="test-policy",
        stdout="evil",
        stderr="",
    )


@pytest.fixture
def clean_profile():
    """A behavioral profile for a clean package run."""
    return BehavioralProfile(
        package="python",
        entrypoint="python",
        total_runtime_ms=100,
        exit_code=0,
        stdout_len=10,
        stderr_len=0,
    )


@pytest.fixture
def suspicious_profile():
    """A behavioral profile with suspicious behaviors."""
    return BehavioralProfile(
        package="evil-pkg",
        entrypoint="node",
        timing_points=[TimingPoint(label="init", elapsed_ms=1)],
        network_calls=[
            NetworkCall(address="evil.xyz", port=4444),
        ],
        dns_queries=[
            DnsQuery(hostname="c2.evil.xyz"),
        ],
        fs_ops=[
            FileOperation(path="/etc/passwd", operation="read"),
            FileOperation(path="/home/user/.env", operation="read"),
        ],
        spawns=[
            ProcessSpawn(executable="/usr/bin/sudo", args=["sudo", "whoami"]),
        ],
        total_runtime_ms=500,
        exit_code=0,
    )


@pytest.fixture
def python_baseline():
    """The shipped python-script baseline."""
    return Baseline(
        name="python-script",
        package="python",
        version="*",
        expected_network_calls=0,
        expected_dns_queries=0,
        expected_fs_ops=100,
        expected_spawns=0,
        expected_runtime_ms_range=(10, 30000),
        allowed_domains=[],
        allowed_paths=["**"],
    )


@pytest.fixture
def npm_baseline():
    return Baseline(
        name="npm-install",
        package="npm",
        version="*",
        expected_network_calls=10,
        expected_dns_queries=5,
        expected_fs_ops=500,
        expected_spawns=0,
        expected_runtime_ms_range=(1000, 120000),
        allowed_domains=["registry.npmjs.org", "registry.yarnpkg.com"],
        allowed_paths=["node_modules/**", "package.json", "package-lock.json"],
    )


@pytest.fixture
def default_policy():
    """The built-in default policy."""
    from picosentry.sandbox.l3.policy import default_policy

    return default_policy()


@pytest.fixture
def restrictive_policy():
    """A very restrictive policy — deny everything."""
    return Policy(
        name="test-restrictive",
        version="1.0",
        default_action=SyscallAction.DENY,
        rules=[
            PolicyRule(
                rule_id="TEST-NET-001",
                target=RuleTarget.NETWORK_OUT,
                action=SyscallAction.DENY,
                description="Deny all network",
            ),
            PolicyRule(
                rule_id="TEST-PROC-001",
                target=RuleTarget.PROCESS_SPAWN,
                action=SyscallAction.DENY,
                description="Deny all spawns",
            ),
        ],
    )


@pytest.fixture
def tmp_json_policy_file():
    """Write a JSON policy file to a temp location and return the path."""
    policy_data = {
        "name": "test-policy-from-file",
        "version": "2.0",
        "default_action": "deny",
        "rules": [
            {
                "rule_id": "FILE-001",
                "target": "file_read",
                "action": "allow",
                "paths": ["/tmp/**"],
                "description": "Allow reads from /tmp",
            },
        ],
    }
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(policy_data, f)
        return Path(f.name)


@pytest.fixture
def tmp_baselines_json_file():
    """Write a baselines JSON file to a temp location and return the path."""
    baselines_data = [
        {
            "name": "test-custom-baseline",
            "package": "myapp",
            "version": "1.0",
            "expected_network_calls": 2,
            "expected_dns_queries": 1,
            "expected_fs_ops": 50,
            "expected_spawns": 0,
            "expected_runtime_ms_range": [100, 5000],
            "allowed_domains": ["api.example.com"],
            "allowed_paths": ["/tmp/**"],
            "notes": "Custom baseline for myapp",
        },
    ]
    with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as f:
        json.dump(baselines_data, f)
        return Path(f.name)
