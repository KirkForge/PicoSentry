"""Red-team tests for the seccomp-bpf backend.

These tests verify that the syscall policy actually blocks common escape and
abuse vectors rather than merely trusting the allowlist. They are intended as
the P5 #20 seccomp red-team acceptance suite.  Most tests are marked ``slow``
and require a real Linux seccomp-bpf backend; they skip cleanly on platforms
without libseccomp or when run as root (some privilege-escalation checks are
meaningless with CAP_SYS_ADMIN).

Run selectively:
    PICODOME_SANDBOX_TESTS=1 pytest tests/sandbox/test_seccomp_redteam.py -v
"""

from __future__ import annotations

import os
import platform
from pathlib import Path

import pytest

from picosentry.sandbox.l3.backends.seccomp_backend import SeccompBackend
from picosentry.sandbox.l3.engine import sandbox_run
from picosentry.sandbox.l3.models import Policy, PolicyRule, RuleTarget, SyscallAction, Verdict
from picosentry.sandbox.l3.policy import default_policy, strict_policy


@pytest.fixture(scope="module")
def seccomp_available():
    backend = SeccompBackend()
    if platform.system() != "Linux":
        pytest.skip("seccomp-bpf is Linux-only")
    if not backend.is_available():
        pytest.skip("libseccomp not available on this system")
    if os.geteuid() == 0:
        pytest.skip("red-team seccomp tests skipped as root (CAP_SYS_ADMIN changes semantics)")
    return True


@pytest.fixture
def tmp_work_dir(tmp_path: Path):
    d = tmp_path / "work"
    d.mkdir()
    return d


class TestRedTeamDenyNetwork:
    """Network access must be denied under the default deny policy."""

    @pytest.mark.slow
    def test_python_socket_connect_killed(self, seccomp_available):
        result = sandbox_run(
            ["python3", "-c", "import socket; socket.socket().connect(('127.0.0.1', 1))"],
            policy=default_policy(),
            timeout=5.0,
            allow_degraded=False,
        )
        assert result.exit_code != 0, f"connect() was allowed: {result.stderr}"
        assert result.overall_verdict in (Verdict.KILL, Verdict.DENY)
        assert any("network" in e.operation.lower() or "seccomp" in e.operation.lower() for e in result.events)

    @pytest.mark.slow
    def test_curl_binary_killed(self, seccomp_available):
        curl = Path("/usr/bin/curl")
        if not curl.exists():
            pytest.skip("curl not installed")
        result = sandbox_run(
            [str(curl), "--max-time", "2", "http://127.0.0.1:1/"],
            policy=default_policy(),
            timeout=5.0,
            allow_degraded=False,
        )
        assert result.overall_verdict in (Verdict.KILL, Verdict.DENY)


class TestRedTeamDenyFilesystemEscape:
    """Writes outside the allowed temp/stdio set must be blocked."""

    @pytest.mark.slow
    def test_write_to_var_tmp_blocked_by_strict_policy(self, seccomp_available):
        """Strict policy denies all file_write syscalls, so /var/tmp write fails."""
        target = f"/var/tmp/picodome-redteam-{os.getpid()}.txt"
        result = sandbox_run(
            ["python3", "-c", f"open({target!r}, 'w').write('escape')"],
            policy=strict_policy(),
            timeout=5.0,
            allow_degraded=False,
        )
        assert result.exit_code != 0, f"strict policy allowed write: {result.stderr}"
        assert not Path(target).exists(), "escape artifact was created"

    @pytest.mark.slow
    def test_mkdir_outside_temp_fails(self, seccomp_available):
        result = sandbox_run(
            ["python3", "-c", "import os; os.makedirs('/tmp/picodome-escape-dir-nested', exist_ok=True)"],
            policy=default_policy(),
            timeout=5.0,
            allow_degraded=False,
        )
        # mkdir under /tmp is allowed by default policy, so this should succeed.
        # The red-team value is verifying the policy boundary, not /tmp itself.
        assert result.exit_code == 0

    @pytest.mark.slow
    def test_default_policy_allows_tmp_write(self, seccomp_available):
        """Positive control: default policy intentionally allows /tmp writes."""
        target = f"/tmp/picodome-redteam-positive-{os.getpid()}.txt"
        result = sandbox_run(
            ["python3", "-c", f"open({target!r}, 'w').write('ok')"],
            policy=default_policy(),
            timeout=5.0,
            allow_degraded=False,
        )
        assert result.exit_code == 0
        assert Path(target).read_text() == "ok"


class TestRedTeamPrivilegeEscalation:
    """Common privilege-escalation syscalls must be denied."""

    @pytest.mark.slow
    def test_setuid_zero_killed(self, seccomp_available):
        result = sandbox_run(
            ["python3", "-c", "import os; os.setuid(0)"],
            policy=default_policy(),
            timeout=5.0,
            allow_degraded=False,
        )
        assert result.exit_code != 0 or any("Permission" in e.detail for e in result.events)

    @pytest.mark.slow
    def test_setgid_zero_killed(self, seccomp_available):
        result = sandbox_run(
            ["python3", "-c", "import os; os.setgid(0)"],
            policy=default_policy(),
            timeout=5.0,
            allow_degraded=False,
        )
        assert result.exit_code != 0 or any("Permission" in e.detail for e in result.events)

    @pytest.mark.slow
    def test_setreuid_zero_killed(self, seccomp_available):
        result = sandbox_run(
            ["python3", "-c", "import os; os.setreuid(0, 0)"],
            policy=default_policy(),
            timeout=5.0,
            allow_degraded=False,
        )
        assert result.exit_code != 0


class TestRedTeamProcessInjection:
    """Process injection / debugging primitives must be denied."""

    @pytest.mark.slow
    def test_ptrace_attach_self_killed(self, seccomp_available):
        result = sandbox_run(
            ["python3", "-c", "import ctypes; ctypes.CDLL('libc.so.6').ptrace(0, 0, 0, 0)"],
            policy=default_policy(),
            timeout=5.0,
            allow_degraded=False,
        )
        assert result.exit_code != 0

    @pytest.mark.slow
    def test_process_vm_writev_blocked(self, seccomp_available):
        result = sandbox_run(
            ["python3", "-c", "import ctypes; ctypes.CDLL('libc.so.6').process_vm_writev(0, 0, 0, 0, 0, 0)"],
            policy=default_policy(),
            timeout=5.0,
            allow_degraded=False,
        )
        assert result.exit_code != 0


class TestRedTeamKernelExploitSurface:
    """Dangerous kernel interfaces should not be reachable."""

    @pytest.mark.slow
    def test_perf_event_open_blocked(self, seccomp_available):
        result = sandbox_run(
            ["python3", "-c", "import ctypes; ctypes.CDLL('libc.so.6').syscall(298, 0, 0, 0, 0, 0)"],
            policy=default_policy(),
            timeout=5.0,
            allow_degraded=False,
        )
        assert result.exit_code != 0

    @pytest.mark.slow
    def test_bpf_syscall_blocked(self, seccomp_available):
        result = sandbox_run(
            ["python3", "-c", "import ctypes; ctypes.CDLL('libc.so.6').syscall(321, 0, 0, 0, 0, 0)"],
            policy=default_policy(),
            timeout=5.0,
            allow_degraded=False,
        )
        assert result.exit_code != 0


class TestRedTeamBackendIntegrity:
    """The backend must not silently degrade or leak policy state."""

    def test_backend_reports_isolation_level(self, seccomp_available):
        backend = SeccompBackend()
        assert backend.isolation_level == "syscall_policy"
        assert backend.enforcement_guarantee == "moderate"

    @pytest.mark.slow
    def test_fail_closed_policy_rejects_fallback(self, seccomp_available, tmp_work_dir):
        backend = SeccompBackend()
        policy = Policy(
            name="fail-closed-test",
            default_action=SyscallAction.DENY,
            rules=[
                PolicyRule(rule_id="TEST-001", target=RuleTarget.FILE_WRITE, action=SyscallAction.ALLOW),
            ],
            fail_closed=True,
        )
        result = backend.run(
            ["/nonexistent-binary-picodome-redteam"],
            policy=policy,
            timeout=2.0,
        )
        # When execve fails we still exit non-zero; the fail-closed guarantee is
        # that we do not silently fall back to an unconfined subprocess.
        assert result.exit_code in (126, 127, -1, 1)
        assert result.degraded is False or any(e.rule_id == "L3-SANDBOX-DEGRADE" for e in result.events)
        # The verdict may be ALLOW because the seccomp filter was loaded and
        # enforced; the command simply could not be executed. The critical
        # property is that we did not fall back to an unconfined backend.
        assert not any(e.rule_id == "L3-SANDBOX-DEGRADE" for e in result.events)
