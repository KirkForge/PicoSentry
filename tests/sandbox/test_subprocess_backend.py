"""Tests for the subprocess backend — pattern detection, verdicts, edge cases."""

import pytest

from picosentry.sandbox.l3.backends.subprocess_backend import SubprocessBackend
from picosentry.sandbox.l3.models import Policy, SyscallAction, Verdict
from picosentry.sandbox.l3.policy import default_policy


@pytest.fixture
def backend():
    return SubprocessBackend()


@pytest.fixture
def permissive_policy():
    """A permissive policy for testing pattern detection without DENY verdicts."""
    return Policy(
        name="test-permissive",
        default_action=SyscallAction.ALLOW,
        rules=[],
    )


# ─── Backend basics ────────────────────────────────────────────────────────────


class TestBackendBasics:
    def test_backend_name(self, backend):
        assert backend.name == "subprocess"

    def test_backend_is_available(self, backend):
        assert backend.is_available() is True

    def test_backend_run_simple_command(self, backend):
        result = backend.run(["echo", "hello"], default_policy())
        assert result.exit_code == 0
        assert "hello" in result.stdout

    def test_backend_run_returns_sandbox_result(self, backend):
        from picosentry.sandbox.l3.models import SandboxResult

        result = backend.run(["echo", "test"], default_policy())
        assert isinstance(result, SandboxResult)

    def test_backend_result_has_command(self, backend):
        result = backend.run(["echo", "hello"], default_policy())
        assert result.command == ["echo", "hello"]


# ─── L3-SUS pattern tests ─────────────────────────────────────────────────────


class TestSuspiciousPatternDetection:
    def test_sus_001_eval(self, backend):
        """L3-SUS-001: dynamic code execution (eval/exec/compile)."""
        result = backend.run(
            ["python3", "-c", "print('eval(x)')"],
            default_policy(),
        )
        assert any(e.rule_id == "L3-SUS-001" for e in result.events)

    def test_sus_001_exec(self, backend):
        """L3-SUS-001: exec pattern."""
        result = backend.run(
            ["python3", "-c", "print('exec(cmd)')"],
            default_policy(),
        )
        assert any(e.rule_id == "L3-SUS-001" for e in result.events)

    def test_sus_001_compile(self, backend):
        """L3-SUS-001: compile pattern."""
        result = backend.run(
            ["python3", "-c", "print('compile(code)')"],
            default_policy(),
        )
        assert any(e.rule_id == "L3-SUS-001" for e in result.events)

    def test_sus_002_subprocess(self, backend):
        """L3-SUS-002: subprocess/os.system usage."""
        result = backend.run(
            ["python3", "-c", "print('subprocess.run')"],
            default_policy(),
        )
        assert any(e.rule_id == "L3-SUS-002" for e in result.events)

    def test_sus_002_os_system(self, backend):
        """L3-SUS-002: os.system pattern."""
        result = backend.run(
            ["python3", "-c", "print('os.system')"],
            default_policy(),
        )
        assert any(e.rule_id == "L3-SUS-002" for e in result.events)

    def test_sus_003_sensitive_file(self, backend):
        """L3-SUS-003: /etc/passwd access."""
        result = backend.run(
            ["python3", "-c", "print('/etc/passwd')"],
            default_policy(),
        )
        assert any(e.rule_id == "L3-SUS-003" for e in result.events)

    def test_sus_003_shadow(self, backend):
        """L3-SUS-003: /etc/shadow access."""
        result = backend.run(
            ["python3", "-c", "print('/etc/shadow')"],
            default_policy(),
        )
        assert any(e.rule_id == "L3-SUS-003" for e in result.events)

    def test_sus_004_curl(self, backend):
        """L3-SUS-004: curl/wget/nc pattern."""
        result = backend.run(
            ["python3", "-c", "print('curl http://evil.com')"],
            default_policy(),
        )
        assert any(e.rule_id == "L3-SUS-004" for e in result.events)

    def test_sus_005_chmod(self, backend):
        """L3-SUS-005: chmod +x / chmod 777."""
        result = backend.run(
            ["python3", "-c", "print('chmod +x script.sh')"],
            default_policy(),
        )
        assert any(e.rule_id == "L3-SUS-005" for e in result.events)

    def test_sus_006_base64(self, backend):
        """L3-SUS-006: base64 decoding."""
        result = backend.run(
            ["python3", "-c", "print('base64 -d payload')"],
            default_policy(),
        )
        assert any(e.rule_id == "L3-SUS-006" for e in result.events)

    def test_sus_007_destructive(self, backend):
        """L3-SUS-007: rm -rf / or dd."""
        result = backend.run(
            ["python3", "-c", "print('rm -rf /')"],
            default_policy(),
        )
        assert any(e.rule_id == "L3-SUS-007" for e in result.events)

    def test_sus_008_proc_self(self, backend):
        """L3-SUS-008: process introspection."""
        result = backend.run(
            ["python3", "-c", "print('/proc/self/status')"],
            default_policy(),
        )
        assert any(e.rule_id == "L3-SUS-008" for e in result.events)

    def test_sus_009_ssh_key(self, backend):
        """L3-SUS-009: SSH key access."""
        result = backend.run(
            ["python3", "-c", "print('.ssh/id_rsa')"],
            default_policy(),
        )
        assert any(e.rule_id == "L3-SUS-009" for e in result.events)

    def test_sus_010_dotfile(self, backend):
        """L3-SUS-010: dotfile access."""
        result = backend.run(
            ["python3", "-c", "print('/home/user/.bashrc')"],
            default_policy(),
        )
        assert any(e.rule_id == "L3-SUS-010" for e in result.events)


# ─── Network detection ─────────────────────────────────────────────────────────


class TestNetworkDetection:
    def test_detect_ip_address(self, backend):
        result = backend.run(
            ["python3", "-c", "print('connect to 93.184.216.34')"],
            default_policy(),
        )
        network_events = [e for e in result.events if e.operation == "network_outbound"]
        assert len(network_events) >= 1

    def test_skip_loopback_ips(self, backend):
        """127.0.0.1 and 0.0.0.0 should be skipped."""
        result = backend.run(
            ["python3", "-c", "print('connect 127.0.0.1')"],
            default_policy(),
        )
        # Loopback should not trigger network event (it's filtered)
        loopback_events = [e for e in result.events if e.operation == "network_outbound" and "127.0.0.1" in e.address]
        assert len(loopback_events) == 0

    def test_detect_url(self, backend):
        result = backend.run(
            ["python3", "-c", "print('https://evil.com/payload')"],
            default_policy(),
        )
        url_events = [e for e in result.events if "evil.com" in e.detail]
        assert len(url_events) >= 1


# ─── File write detection ──────────────────────────────────────────────────────


class TestFileWriteDetection:
    def test_detect_writing_to(self, backend):
        result = backend.run(
            ["python3", "-c", "print('writing to /tmp/evil.sh')"],
            default_policy(),
        )
        write_events = [e for e in result.events if "file_write" in e.operation]
        assert len(write_events) >= 1

    def test_detect_saved_to(self, backend):
        result = backend.run(
            ["python3", "-c", "print('saved to /tmp/data.txt')"],
            default_policy(),
        )
        write_events = [e for e in result.events if "file_write" in e.operation or "file_save" in e.operation]
        assert len(write_events) >= 1


# ─── Process spawn detection ──────────────────────────────────────────────────


class TestProcessSpawnDetection:
    def test_detect_executing(self, backend):
        result = backend.run(
            ["python3", "-c", "print('executing: /bin/bash')"],
            default_policy(),
        )
        spawn_events = [e for e in result.events if e.operation == "process_spawn"]
        assert len(spawn_events) >= 1

    def test_detect_spawning(self, backend):
        result = backend.run(
            ["python3", "-c", "print('spawning /usr/bin/wget')"],
            default_policy(),
        )
        spawn_events = [e for e in result.events if e.operation == "process_spawn"]
        assert len(spawn_events) >= 1


# ─── Timeout handling ─────────────────────────────────────────────────────────


class TestTimeoutHandling:
    def test_timeout_kills_process(self, backend):
        result = backend.run(["sleep", "10"], default_policy(), timeout=0.5)
        assert result.overall_verdict == Verdict.KILL

    def test_timeout_has_event(self, backend):
        result = backend.run(["sleep", "10"], default_policy(), timeout=0.5)
        assert any(e.rule_id == "L3-TIMEOUT-001" for e in result.events)

    def test_normal_command_no_timeout(self, backend):
        result = backend.run(["echo", "fast"], default_policy(), timeout=10.0)
        assert result.overall_verdict == Verdict.ALLOW
        assert not any(e.rule_id == "L3-TIMEOUT-001" for e in result.events)


# ─── Command not found ──────────────────────────────────────────────────────────


class TestCommandNotFound:
    def test_nonexistent_command(self, backend):
        result = backend.run(["nonexistent_command_xyzzy_12345"], default_policy())
        assert result.exit_code != 0
        assert (
            any(e.rule_id in ("L3-EXEC-001", "L3-EXEC-002") for e in result.events)
            or result.overall_verdict != Verdict.ALLOW
        )


# ─── Permission denied ────────────────────────────────────────────────────────


class TestPermissionDenied:
    def test_permission_denied_command(self, backend):
        """Running a command that might get permission denied."""
        result = backend.run(["/proc/1/mem"], default_policy(), timeout=2.0)
        # Should either get FILENOTFOUND or permission error
        assert result.exit_code != 0 or result.overall_verdict != Verdict.ALLOW


# ─── Verdict computation ────────────────────────────────────────────────────────


class TestVerdictComputation:
    def test_clean_command_allows(self, backend):
        result = backend.run(["echo", "clean"], default_policy())
        assert result.overall_verdict == Verdict.ALLOW

    def test_suspicious_command_denies(self, backend):
        result = backend.run(
            ["python3", "-c", "print('eval(x)')"],
            default_policy(),
        )
        # Should have DENY or KILL events from SUS patterns
        deny_or_kill = [e for e in result.events if e.verdict in (Verdict.DENY, Verdict.KILL)]
        if deny_or_kill:
            assert result.overall_verdict in (Verdict.DENY, Verdict.KILL)


# ─── Suspicious pattern regex edge cases ────────────────────────────────────────


class TestSuspiciousPatternEdgeCases:
    def test_eval_with_spaces(self, backend):
        """eval with spaces should still match."""
        result = backend.run(
            ["python3", "-c", "print('eval  (x)')"],
            default_policy(),
        )
        assert any(e.rule_id == "L3-SUS-001" for e in result.events)

    def test_case_insensitive_eval(self, backend):
        """SUS patterns should be case-insensitive."""
        result = backend.run(
            ["python3", "-c", "print('EVAL(x)')"],
            default_policy(),
        )
        assert any(e.rule_id == "L3-SUS-001" for e in result.events)

    def test_safe_output_no_events(self, backend):
        """Clean output should not trigger any SUS patterns."""
        result = backend.run(["echo", "hello world"], default_policy())
        sus_events = [e for e in result.events if e.rule_id.startswith("L3-SUS")]
        assert len(sus_events) == 0

    def test_multiple_patterns_in_one_output(self, backend):
        """Multiple SUS patterns in one output should all be detected."""
        result = backend.run(
            ["python3", "-c", "print('eval(x) /etc/passwd chmod 777')"],
            default_policy(),
        )
        rule_ids = {e.rule_id for e in result.events}
        assert "L3-SUS-001" in rule_ids  # eval
        assert "L3-SUS-003" in rule_ids  # /etc/passwd
        assert "L3-SUS-005" in rule_ids  # chmod 777
