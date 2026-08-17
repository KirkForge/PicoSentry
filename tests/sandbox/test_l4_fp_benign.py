"""L4 FP-rate + policy tests — WO4.0.0-018.

Gate: a benign postinstall corpus must produce 0 CRITICAL findings, and the
reclassified rules must keep their true-positive teeth.
"""

from __future__ import annotations

import pytest

from picosentry.sandbox.l4.differ import _host_of, compare_profile_to_baseline
from picosentry.sandbox.l4.engine import create_default_engine
from picosentry.sandbox.l4.models import (
    Baseline,
    BehavioralProfile,
    DnsQuery,
    FileOperation,
    NetworkCall,
    ProcessSpawn,
)
from picosentry.sandbox.models import Severity


def _benign_postinstall_profile(package: str = "left-pad") -> BehavioralProfile:
    """Composite of behaviors every benign npm postinstall exhibits — the
    exact catalog that used to fire CRITICAL/MEDIUM (WO4.0.0-018 evidence 3):
    chmod of bin shims, .sh written into the package tree, a handful of
    helper spawns, a mirror registry flag, sub-second runtime."""
    return BehavioralProfile(
        package=package,
        entrypoint="npm",
        fs_ops=[
            FileOperation(path="node_modules/.bin/tsc", operation="chmod"),
            FileOperation(path="node_modules/pkg/install.sh", operation="write"),
            FileOperation(path="node_modules/pkg/index.js", operation="write"),
        ],
        spawns=[
            ProcessSpawn(executable="/usr/bin/chmod", args=["+x", "node_modules/.bin/tsc"]),
            ProcessSpawn(executable="/usr/bin/node", args=["postinstall.js"]),
            ProcessSpawn(executable="/usr/bin/npm", args=["config", "get", "prefix"]),
        ]
        + [ProcessSpawn(executable="/usr/bin/node", args=[f"worker{i}.js"]) for i in range(6)],
        network_calls=[],
        dns_queries=[DnsQuery(hostname="registry.npmjs.org")],
        total_runtime_ms=2,  # trivial fast package
        exit_code=0,
    )


class TestBenignCorpusZeroCritical:
    @pytest.mark.parametrize(
        "profile",
        [
            _benign_postinstall_profile(),
            _benign_postinstall_profile("tiny-is-even-ok"),
            BehavioralProfile(package="echo-pkg", entrypoint="echo", total_runtime_ms=1, exit_code=0),
        ],
        ids=["npm-postinstall", "fast-npm", "sub-ms-cli"],
    )
    def test_no_critical_findings_on_benign_corpus(self, profile):
        result = create_default_engine().analyze(profile, deterministic=True)
        critical = [f for f in result.findings if f.severity == Severity.CRITICAL]
        assert critical == [], f"Benign corpus produced CRITICAL: {[(f.rule_id, f.message) for f in critical]}"


class TestReclassifiedRulesKeepTeeth:
    def test_privilege_broker_spawn_still_critical(self):
        from picosentry.sandbox.l4.rules.honeypot import detect_honeypot_touches

        profile = BehavioralProfile(
            package="evil",
            spawns=[ProcessSpawn(executable="/usr/bin/sudo", args=["bash"])],
            total_runtime_ms=100,
        )
        findings = detect_honeypot_touches(profile)
        assert any(f.rule_id == "L4-HONEY-002" and f.severity == Severity.CRITICAL for f in findings)

    def test_chmod_spawn_is_low_not_critical(self):
        from picosentry.sandbox.l4.rules.honeypot import detect_honeypot_touches

        profile = BehavioralProfile(
            package="benign",
            spawns=[ProcessSpawn(executable="/usr/bin/chmod", args=["+x", "bin/tool"])],
            total_runtime_ms=100,
        )
        findings = detect_honeypot_touches(profile)
        honeypot = [f for f in findings if f.rule_id.startswith("L4-HONEY")]
        assert any(f.rule_id == "L4-HONEY-003" and f.severity == Severity.LOW for f in honeypot)
        assert not any(f.severity == Severity.CRITICAL for f in honeypot)

    def test_sh_write_outside_tmp_and_workspace_still_medium(self):
        from picosentry.sandbox.l4.rules.filesystem import detect_filesystem_anomalies

        profile = BehavioralProfile(
            package="evil",
            fs_ops=[FileOperation(path="/usr/local/bin/payload.sh", operation="write")],
            total_runtime_ms=100,
        )
        findings = detect_filesystem_anomalies(profile)
        assert any(f.rule_id == "L4-FS-002" and f.severity == Severity.MEDIUM for f in findings)

    def test_registry_override_internal_value_still_high(self):
        from picosentry.sandbox.l4.rules.dependency_confusion import detect_dependency_confusion

        profile = BehavioralProfile(
            package="evil",
            spawns=[
                ProcessSpawn(
                    executable="/usr/bin/pip",
                    args=["install", "--index-url=http://npm.company.internal/simple", "pkg"],
                )
            ],
            total_runtime_ms=100,
        )
        findings = detect_dependency_confusion(profile)
        assert any(f.rule_id == "L4-DEP-004" and f.severity == Severity.HIGH for f in findings)

    def test_public_mirror_registry_override_is_medium(self):
        from picosentry.sandbox.l4.rules.dependency_confusion import detect_dependency_confusion

        profile = BehavioralProfile(
            package="benign-ci",
            spawns=[
                ProcessSpawn(
                    executable="/usr/bin/pip",
                    args=["install", "--index-url=https://mirror.example.org/simple", "pkg"],
                )
            ],
            total_runtime_ms=100,
        )
        findings = detect_dependency_confusion(profile)
        dep004 = [f for f in findings if f.rule_id == "L4-DEP-004"]
        assert dep004 and all(f.severity == Severity.MEDIUM for f in dep004)

    def test_persistence_tail_path_no_longer_matches_project_dirs(self):
        from picosentry.sandbox.l4.rules.persistence import detect_persistence

        profile = BehavioralProfile(
            package="benign",
            fs_ops=[FileOperation(path="myproject/etc/rc.local.example", operation="write")],
            total_runtime_ms=100,
        )
        findings = detect_persistence(profile)
        assert not any(f.rule_id == "L4-PERSIST-001" for f in findings)

    def test_persistence_real_paths_still_fire(self):
        from picosentry.sandbox.l4.rules.persistence import detect_persistence

        profile = BehavioralProfile(
            package="evil",
            fs_ops=[
                FileOperation(path="/etc/rc.local", operation="write"),
                FileOperation(path="/home/u/.ssh/authorized_keys", operation="write"),
            ],
            total_runtime_ms=100,
        )
        findings = detect_persistence(profile)
        paths = {f.location for f in findings if f.rule_id == "L4-PERSIST-001"}
        assert "/etc/rc.local" in paths
        assert "/home/u/.ssh/authorized_keys" in paths


class TestDifferUrlDomainMatching:
    def test_host_of_variants(self):
        assert _host_of("https://registry.npmjs.org/pkg/-/pkg-1.0.0.tgz") == "registry.npmjs.org"
        assert _host_of("registry.npmjs.org:443") == "registry.npmjs.org"
        assert _host_of("Registry.NPMJS.org") == "registry.npmjs.org"
        assert _host_of("1.2.3.4") == "1.2.3.4"

    def test_url_against_domain_allowlist_no_drift(self):
        """The old code compared raw URLs to domains — never equal, so every
        benign npm fetch drifted (WO4.0.0-018 evidence 2)."""
        profile = BehavioralProfile(
            package="npm",
            network_calls=[NetworkCall(address="https://registry.npmjs.org/left-pad", port=443)],
            dns_queries=[],
            fs_ops=[],
            spawns=[],
            total_runtime_ms=5000,
        )
        baseline = Baseline(
            name="npm-install",
            package="npm",
            expected_network_calls=10,
            expected_dns_queries=5,
            expected_fs_ops=500,
            expected_spawns=0,
            expected_runtime_ms_range=(1000, 120000),
            allowed_domains=["registry.npmjs.org", "registry.yarnpkg.com"],
            allowed_paths=["node_modules/**", "package.json", "package-lock.json"],
        )
        drift = compare_profile_to_baseline(profile, baseline)
        assert not drift.network_drift, drift.details

    def test_foreign_domain_still_drifts(self):
        profile = BehavioralProfile(
            package="npm",
            network_calls=[NetworkCall(address="https://evil.tld/exfil", port=443)],
            dns_queries=[],
            fs_ops=[],
            spawns=[],
            total_runtime_ms=5000,
        )
        baseline = Baseline(
            name="npm-install",
            package="npm",
            allowed_domains=["registry.npmjs.org"],
            allowed_paths=["**"],
        )
        drift = compare_profile_to_baseline(profile, baseline)
        assert drift.network_drift


class TestSeccompTraceDefaultActionParity:
    """A permissive policy with one deny rule must NOT flip the trace
    backend's default to KILL_PROCESS (seccomp would ALLOW those syscalls —
    same policy, opposite verdicts per backend; WO4.0.0-018 evidence 5)."""

    def test_permissive_policy_with_deny_rule_uses_log_default(self):
        from unittest.mock import MagicMock

        from picosentry.sandbox.l3.backends._seccomp_common import SCMP_ACT_LOG, SCMP_ACT_KILL_PROCESS
        from picosentry.sandbox.l3.backends.seccomp_trace.filter_builder import build_filter
        from picosentry.sandbox.l3.models import Policy, PolicyRule, RuleTarget, SyscallAction

        lib = MagicMock()
        ctx = MagicMock()
        ctx.__bool__ = lambda self: True
        lib.seccomp_init.return_value = ctx
        lib.seccomp_syscall_resolve_name.return_value = 1

        policy = Policy(
            name="permissive-with-one-deny",
            default_action=SyscallAction.ALLOW,
            rules=[
                PolicyRule(
                    rule_id="DENY-NET",
                    target=RuleTarget.NETWORK_OUT,
                    action=SyscallAction.DENY,
                ),
            ],
        )
        build_filter(lib, policy, {})
        first_call = lib.seccomp_init.call_args_list[0]
        assert first_call.args[0] == SCMP_ACT_LOG  # NOT KILL_PROCESS
        assert first_call.args[0] != SCMP_ACT_KILL_PROCESS

    def test_deny_default_policy_uses_kill_default(self):
        from unittest.mock import MagicMock

        from picosentry.sandbox.l3.backends._seccomp_common import SCMP_ACT_KILL_PROCESS
        from picosentry.sandbox.l3.backends.seccomp_trace.filter_builder import build_filter
        from picosentry.sandbox.l3.policy import default_policy

        lib = MagicMock()
        ctx = MagicMock()
        ctx.__bool__ = lambda self: True
        lib.seccomp_init.return_value = ctx
        lib.seccomp_syscall_resolve_name.return_value = 1

        build_filter(lib, default_policy(), {})
        assert lib.seccomp_init.call_args_list[0].args[0] == SCMP_ACT_KILL_PROCESS


class TestDeniedCommandWrappers:
    def test_env_wrapper_cannot_bypass_denylist(self):
        from picosentry.sandbox.daemon.constants import validate_command

        assert validate_command(["env", "bash", "-c", "echo pwned"]) is not None
        assert validate_command(["xargs", "bash"]) is not None
        assert validate_command(["timeout", "5", "sh"]) is not None
        assert validate_command(["nohup", "python3", "-c", "x"]) is not None

    def test_package_managers_still_allowed(self):
        from picosentry.sandbox.daemon.constants import validate_command

        assert validate_command(["npm", "install"]) is None
        assert validate_command(["pip", "install", "requests"]) is None
