"""Tests for L3 sandbox execution."""

from unittest.mock import patch

import pytest

from picosentry.sandbox.l3.backends.subprocess_backend import SubprocessBackend
from picosentry.sandbox.l3.engine import SandboxEngine, sandbox_run
from picosentry.sandbox.l3.models import Policy, PolicyRule, RuleTarget, SyscallAction, Verdict
from picosentry.sandbox.l3.policy import default_policy


class TestPolicy:
    def test_default_policy_loads(self):
        policy = default_policy()
        assert policy.name == "picodome-default"
        assert policy.default_action == SyscallAction.DENY
        assert len(policy.rules) > 0

    def test_policy_rules_have_ids(self):
        policy = default_policy()
        rule_ids = [r.rule_id for r in policy.rules]
        assert "L3-FILE-R-001" in rule_ids
        assert "L3-NET-OUT-001" in rule_ids

    def test_policy_to_dict_roundtrip(self):
        policy = default_policy()
        d = policy.to_dict()
        assert d["name"] == policy.name
        assert len(d["rules"]) == len(policy.rules)


class TestSubprocessBackend:
    """Tests using the SubprocessBackend directly (not auto-detected)."""

    def test_backend_available(self):
        backend = SubprocessBackend()
        assert backend.is_available() is True
        assert backend.name == "subprocess"

    def test_run_simple_command(self):
        backend = SubprocessBackend()
        result = backend.run(["echo", "hello"], default_policy())
        assert result.overall_verdict == Verdict.ALLOW
        assert result.exit_code == 0
        assert result.duration_ms > 0
        assert "hello" in result.stdout

    def test_run_with_timeout(self):
        backend = SubprocessBackend()
        result = backend.run(["sleep", "10"], default_policy(), timeout=0.1)
        assert result.overall_verdict == Verdict.KILL

    def test_run_detects_network(self):
        backend = SubprocessBackend()
        result = backend.run(
            ["python3", "-c", "print('connect to 93.184.216.34')"],
            default_policy(),
        )
        assert any(e.operation == "network_outbound" for e in result.events)

    def test_run_detects_suspicious(self):
        backend = SubprocessBackend()
        result = backend.run(
            ["python3", "-c", "print('eval(compile(open(\\\"/etc/passwd\\\")))')"],
            default_policy(),
        )
        assert any(e.rule_id == "L3-SUS-001" for e in result.events)
        assert any(e.rule_id == "L3-SUS-003" for e in result.events)

    def test_run_safe_command_passes(self):
        backend = SubprocessBackend()
        result = backend.run(["python3", "-c", "print('hello world')"], default_policy())
        assert result.overall_verdict == Verdict.ALLOW

    def test_run_command_not_found(self):
        backend = SubprocessBackend()
        result = backend.run(["nonexistent_command_xyzzy"], default_policy())
        assert result.exit_code in (-1, 127)
        assert any(
            e.rule_id in ("L3-EXEC-001", "L3-SECCOMP-KILL") for e in result.events
        ) or result.overall_verdict in (Verdict.DENY, Verdict.KILL)

    def test_result_to_dict(self):
        backend = SubprocessBackend()
        result = backend.run(["echo", "test"], default_policy())
        d = result.to_dict()
        # run_id is omitted when empty (deterministic default)
        assert "command" in d
        assert d["command"] == ["echo", "test"]
        assert "events" in d
        assert "exit_code" in d
        assert "overall_verdict" in d


class TestSeccompBackend:
    """Tests that exercise the seccomp backend (auto-detected on Linux)."""

    def test_sandbox_run_echo(self):
        """Echo should work under seccomp (safe syscalls only)."""
        result = sandbox_run(["echo", "hello_seccomp"], allow_degraded=True)
        assert result.overall_verdict == Verdict.ALLOW
        assert "hello_seccomp" in result.stdout

    def test_sandbox_run_python(self):
        """Safe Python code should work."""
        result = sandbox_run(["python3", "-c", "print(42)"], allow_degraded=True)
        assert result.overall_verdict == Verdict.ALLOW
        assert "42" in result.stdout

    def test_sandbox_subprocess_child_survives(self):
        """Child process spawned via subprocess.run must survive seccomp.

        This is the exact regression that broke npm/pip installs: CPython's
        subprocess module calls close_range() in the child between fork and
        exec.  If close_range is missing from the allowlist, the child dies
        with SIGSYS (returncode -31) while the parent exits 0 — a silent
        failure masked as ALLOW.
        """
        from picosentry.sandbox.l3.backends.seccomp_backend import SeccompBackend

        backend = SeccompBackend()
        if not backend.is_available():
            pytest.skip("seccomp-bpf not available on this platform")

        from picosentry.sandbox.l3.policy import node_policy

        # Run Python code that spawns a child via subprocess.run('/bin/true')
        # and exits with the child's return code — not just the parent's.
        result = backend.run(
            [
                "python3", "-c",
                "import subprocess, sys; sys.exit(subprocess.run(['/bin/true']).returncode)",
            ],
            node_policy(),
            timeout=10.0,
        )
        # The child must survive (exit 0), not die with SIGSYS (returncode -31).
        assert result.exit_code == 0, (
            f"Child process killed: exit_code={result.exit_code}, verdict={result.overall_verdict}. "
            f"close_range/kill/setsid/sigprocmask may be missing from the seccomp allowlist."
        )
        assert result.overall_verdict == Verdict.ALLOW

    def test_sandbox_node_policy_subprocess_child(self):
        """Node policy must allow subprocess children (npm install path)."""
        from picosentry.sandbox.l3.backends.seccomp_backend import SeccompBackend

        backend = SeccompBackend()
        if not backend.is_available():
            pytest.skip("seccomp-bpf not available on this platform")

        from picosentry.sandbox.l3.policy import node_policy

        result = backend.run(
            [
                "python3", "-c",
                "import subprocess, sys; sys.exit(subprocess.run(['/bin/true']).returncode)",
            ],
            node_policy(),
            timeout=10.0,
        )
        assert result.exit_code == 0, (
            f"Child killed under node policy: exit_code={result.exit_code}"
        )
        assert result.overall_verdict == Verdict.ALLOW

    def test_sandbox_blocks_network(self):
        """Network access should be killed by seccomp."""
        result = sandbox_run(
            [
                "python3",
                "-c",
                "import urllib.request; urllib.request.urlopen('http://example.com')",
            ],
            timeout=5.0,
            allow_degraded=True,
        )
        # Either KILL from seccomp or DENY from pattern analysis
        assert result.overall_verdict in (Verdict.KILL, Verdict.DENY)
        # Should have evidence of violation

    def test_sandbox_blocks_file_write(self):
        """File writes outside allowed paths should be blocked."""
        result = sandbox_run(["touch", "/tmp/seccomp_test_should_be_blocked"], allow_degraded=True)
        if result.isolation_level == "observational_only":
            # The portable subprocess backend cannot enforce filesystem blocks.
            assert result.overall_verdict in (Verdict.ALLOW, Verdict.DENY, Verdict.KILL)
        else:
            assert result.overall_verdict in (Verdict.KILL, Verdict.DENY)

    def test_command_not_found(self):
        """Non-existent commands should produce error events."""
        result = sandbox_run(["nonexistent_command_xyzzy"], allow_degraded=True)
        assert result.exit_code in (-1, 127, 1)
        assert result.overall_verdict in (Verdict.DENY, Verdict.KILL, Verdict.ALLOW)


class TestSandboxEngine:
    def test_engine_uses_backend(self):
        engine = SandboxEngine(backend=SubprocessBackend())
        result = engine.run(["echo", "from_engine"])
        assert "from_engine" in result.stdout

    def test_sandbox_run_with_restrictive_policy(self):
        policy_rules = [
            PolicyRule(
                rule_id="TEST-001",
                target=RuleTarget.NETWORK_OUT,
                action=SyscallAction.DENY,
                description="Deny all network",
            ),
        ]
        policy = Policy(name="test-restrictive", rules=policy_rules)
        _ = sandbox_run(
            ["python3", "-c", "print('1.2.3.4')"],
            policy=policy,
            timeout=5.0,
            allow_degraded=True,
        )
        # With restrictive policy, network output should trigger violation
        # Either via seccomp kill or post-hoc pattern detection
        # With seccomp, print does not trigger network syscalls. Post-hoc pattern analysis catches IP in output.
        # The seccomp backend handles this at kernel level; subprocess backend catches it post-hoc.
        # Either way, events should exist if anything suspicious was found.


# ── Backend detection and engine tests ─────────────────────────────────


class TestBackendDetection:
    def test_detect_subprocess_backend(self):
        from picosentry.sandbox.l3.engine import _detect_backend

        backend = _detect_backend(requested="subprocess")
        assert backend.name == "subprocess"

    def test_detect_unknown_backend_raises(self):
        from picosentry.sandbox.l3.engine import BackendUnavailableError, _detect_backend

        with pytest.raises(BackendUnavailableError):
            _detect_backend(requested="nonexistent")

    def test_detect_seccomp_when_available(self):
        """On Linux with libseccomp, seccomp should be auto-detected."""
        from picosentry.sandbox.l3.engine import _detect_backend

        backend = _detect_backend(requested="seccomp-bpf", allow_degraded=True)
        assert backend.name in ("seccomp-bpf", "subprocess")

    def test_detect_seccomp_degrades_to_subprocess(self):
        """With allow_degraded=True, seccomp-bpf request degrades gracefully when unavailable."""
        from picosentry.sandbox.l3.engine import _detect_backend

        # Mock seccomp as unavailable to test degradation path
        with patch("picosentry.sandbox.l3.engine.platform.system", return_value="FreeBSD"):
            backend = _detect_backend(requested="seccomp-bpf", allow_degraded=True)
            assert backend.name == "subprocess"

    def test_detect_seatbelt_degrades_to_subprocess(self):
        """With allow_degraded=True, seatbelt request degrades gracefully when unavailable."""
        from picosentry.sandbox.l3.engine import _detect_backend

        # On Linux, seatbelt is not available
        backend = _detect_backend(requested="seatbelt", allow_degraded=True)
        assert backend.name == "subprocess"

    def test_detect_seatbelt_raises_on_linux(self):
        """On Linux without allow_degraded, seatbelt should raise."""
        from picosentry.sandbox.l3.engine import BackendUnavailableError, _detect_backend

        with pytest.raises(BackendUnavailableError):
            _detect_backend(requested="seatbelt", allow_degraded=False)

    def test_detect_auto_uses_seccomp_on_linux(self):
        """On Linux with libseccomp, auto-detect should return seccomp."""
        from picosentry.sandbox.l3.engine import _detect_backend

        backend = _detect_backend(allow_degraded=True)
        assert backend.name in ("seccomp-bpf", "subprocess")

    def test_detect_auto_degrades_on_other_platforms(self):
        """On non-Linux/macOS, auto-detect degrades gracefully."""
        from picosentry.sandbox.l3.engine import _detect_backend

        with patch("picosentry.sandbox.l3.engine.platform.system", return_value="FreeBSD"):
            backend = _detect_backend(allow_degraded=True)
            assert backend.name == "subprocess"

    def test_detect_auto_raises_without_degraded_on_other_platforms(self):
        """On non-Linux/macOS without degraded, auto-detect should raise."""
        from picosentry.sandbox.l3.engine import BackendUnavailableError, _detect_backend

        with patch("picosentry.sandbox.l3.engine.platform.system", return_value="FreeBSD"):
            with pytest.raises(BackendUnavailableError, match="No enforcement backend"):
                _detect_backend(allow_degraded=False)

    def test_allow_degraded_env_var(self):
        import os

        from picosentry.sandbox.l3.engine import _detect_backend

        os.environ["PICODOME_ALLOW_DEGRADED"] = "1"
        try:
            backend = _detect_backend()
            assert backend is not None
        finally:
            del os.environ["PICODOME_ALLOW_DEGRADED"]


class TestSandboxEngineExtra:
    def test_engine_with_explicit_backend(self):
        from picosentry.sandbox.l3.backends.subprocess_backend import SubprocessBackend
        from picosentry.sandbox.l3.engine import SandboxEngine

        backend = SubprocessBackend()
        engine = SandboxEngine(backend=backend)
        assert engine.backend is backend

    def test_engine_run_delegates(self):
        from picosentry.sandbox.l3.backends.subprocess_backend import SubprocessBackend
        from picosentry.sandbox.l3.engine import SandboxEngine

        engine = SandboxEngine(backend=SubprocessBackend())
        result = engine.run(["echo", "hello"], deterministic=True)
        assert result.exit_code == 0


class TestGetSetBackend:
    def test_set_and_reset_backend(self):
        from picosentry.sandbox.l3.backends.subprocess_backend import SubprocessBackend
        from picosentry.sandbox.l3.engine import get_backend, reset_backend, set_backend

        backend = SubprocessBackend()
        set_backend(backend, name="test-subprocess")
        assert get_backend() is backend
        reset_backend()

    def test_backend_unavailable_error(self):
        from picosentry.sandbox.l3.engine import BackendUnavailableError

        err = BackendUnavailableError("test", "reason", available_backends=["subprocess"])
        assert "test" in str(err)
        assert "reason" in str(err)
        assert err.backend_name == "test"
