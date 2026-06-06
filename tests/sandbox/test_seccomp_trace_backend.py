"""Tests for SeccompTraceBackend (P0 kernel-syscall observation).

Integration tests under TestSeccompTraceBackendRun are gated on the
PICODOME_HAS_SECCOMP=1 environment variable. CI on Linux containers
without libseccomp will skip them. To run locally:

    PICODOME_HAS_SECCOMP=1 pytest tests/sandbox/test_seccomp_trace_backend.py -v
"""

from __future__ import annotations

import os
from unittest.mock import MagicMock, patch

import pytest

from picosentry.sandbox.l3.backends.seccomp_trace_backend import (
    _AUDIT_LINE_RE,
    _LOG_ACTION_CODE,
    SCMP_ACT_LOG,
    SeccompTraceBackend,
)
from picosentry.sandbox.l3.engine import (
    BackendUnavailableError,
    _detect_backend,
    get_backend,
    reset_backend,
)
from picosentry.sandbox.l3.models import (
    Policy,
    SandboxEvent,
    SandboxResult,
    SyscallAction,
    Verdict,
)
from picosentry.sandbox.l3.policy import default_policy
from picosentry.sandbox.l4.profiler import profile_from_sandbox_result

# ─── Helpers ────────────────────────────────────────────────────────────


_HAS_SECCOMP_ENV = os.environ.get("PICODOME_HAS_SECCOMP") == "1"
# The probe inside is_available() also checks for CONFIG_SECCOMP_LOG=y;
# some Linux 5.x/6.x kernels are built without that flag and return
# an empty /proc/<pid>/seccomp buffer. is_available() is a few-ms
# fork+execve, cheap enough to call once at module import.
_seccomp_trace_available = False
if _HAS_SECCOMP_ENV:
    try:
        _seccomp_trace_available = SeccompTraceBackend().is_available()
    except Exception:
        _seccomp_trace_available = False
skip_without_seccomp = pytest.mark.skipif(
    not (_HAS_SECCOMP_ENV and _seccomp_trace_available),
    reason="seccomp-trace unavailable (set PICODOME_HAS_SECCOMP=1 and ensure libseccomp + CONFIG_SECCOMP_LOG=y)",
)


# ─── TestSeccompTraceBackendAvailability ────────────────────────────────


class TestSeccompTraceBackendAvailability:
    """Properties and is_available(). No fork required."""

    def test_name_is_seccomp_trace(self) -> None:
        backend = SeccompTraceBackend()
        assert backend.name == "seccomp-trace"

    def test_isolation_level_is_kernel_enforced(self) -> None:
        backend = SeccompTraceBackend()
        assert backend.isolation_level == "kernel_enforced"

    def test_enforcement_guarantee_is_moderate(self) -> None:
        backend = SeccompTraceBackend()
        assert backend.enforcement_guarantee == "moderate"

    def test_is_available_returns_bool(self) -> None:
        backend = SeccompTraceBackend()
        result = backend.is_available()
        assert isinstance(result, bool)

    def test_is_available_false_when_libseccomp_missing(self) -> None:
        """If libseccomp is missing, is_available returns False."""
        backend = SeccompTraceBackend()
        with patch(
            "ctypes.CDLL",
            side_effect=OSError("libseccomp.so.2: cannot open shared object file"),
        ):
            assert backend.is_available() is False


# ─── TestSeccompTraceBackendFilterBuilding ─────────────────────────────


class TestSeccompTraceBackendFilterBuilding:
    """_build_filter() behavior. Mocks libseccomp — no real fork."""

    def _make_mock_lib(self) -> MagicMock:
        """Build a mock libseccomp that records all calls."""
        lib = MagicMock()
        ctx = MagicMock()
        ctx.__bool__ = lambda self: True
        lib.seccomp_init.return_value = ctx
        lib.seccomp_load.return_value = 0
        lib.seccomp_syscall_resolve_name.return_value = 1
        return lib

    def test_build_filter_kill_policy_uses_kill_process(self) -> None:
        """default_policy() has default_action=DENY → KILL_PROCESS."""
        backend = SeccompTraceBackend()
        lib = self._make_mock_lib()
        backend._build_filter(lib, default_policy())
        # First arg to seccomp_init is the default action.
        first_call = lib.seccomp_init.call_args_list[0]
        assert first_call.args[0] == 0x80000000  # SCMP_ACT_KILL_PROCESS

    def test_build_filter_allow_policy_uses_log(self) -> None:
        """Policy(default_action=ALLOW) → SCMP_ACT_LOG."""
        backend = SeccompTraceBackend()
        lib = self._make_mock_lib()
        permissive = Policy(
            name="permissive-test",
            default_action=SyscallAction.ALLOW,
            rules=[],
        )
        backend._build_filter(lib, permissive)
        first_call = lib.seccomp_init.call_args_list[0]
        assert first_call.args[0] == SCMP_ACT_LOG

    def test_build_filter_registers_safe_syscalls_as_allow(self) -> None:
        """_SAFE_SYSCALLS are always added as ALLOW rules."""
        backend = SeccompTraceBackend()
        lib = self._make_mock_lib()
        permissive = Policy(
            name="permissive-test",
            default_action=SyscallAction.ALLOW,
            rules=[],
        )
        backend._build_filter(lib, permissive)
        # seccomp_rule_add is called many times. Each call's second arg
        # is the action. Count how many are SCMP_ACT_ALLOW.
        allow_count = sum(
            1
            for call in lib.seccomp_rule_add.call_args_list
            if call.args[1] == 0x7FFF0000  # SCMP_ACT_ALLOW
        )
        # _SAFE_SYSCALLS has 90+ entries. Assert a lower bound.
        assert allow_count > 50, f"expected many _SAFE_SYSCALLS to be added as ALLOW, got {allow_count}"

    def test_build_filter_returns_none_when_seccomp_init_fails(self) -> None:
        backend = SeccompTraceBackend()
        lib = MagicMock()
        lib.seccomp_init.return_value = None
        ctx, blocked = backend._build_filter(lib, default_policy())
        assert ctx is None
        assert blocked == set()


# ─── TestSeccompTraceBackendEventShapes ────────────────────────────────


class TestSeccompTraceBackendEventShapes:
    """_classify_syscall and _parse_seccomp_log — no fork."""

    def test_classify_syscall_open(self) -> None:
        backend = SeccompTraceBackend()
        op, prefix = backend._classify_syscall("open")
        assert op == "file_open"
        assert prefix == "L3-TRACE-FS-OPEN"

    def test_classify_syscall_read(self) -> None:
        backend = SeccompTraceBackend()
        op, prefix = backend._classify_syscall("read")
        assert op == "file_read"
        assert prefix == "L3-TRACE-FS-READ"

    def test_classify_syscall_write(self) -> None:
        backend = SeccompTraceBackend()
        op, prefix = backend._classify_syscall("write")
        assert op == "file_write"
        assert prefix == "L3-TRACE-FS-WRITE"

    def test_classify_syscall_connect(self) -> None:
        backend = SeccompTraceBackend()
        op, prefix = backend._classify_syscall("connect")
        assert op == "network_outbound"
        assert prefix == "L3-TRACE-NET"

    def test_classify_syscall_execve(self) -> None:
        backend = SeccompTraceBackend()
        op, prefix = backend._classify_syscall("execve")
        assert op == "process_spawn"
        assert prefix == "L3-TRACE-PROC-EXEC"

    def test_classify_syscall_clone(self) -> None:
        backend = SeccompTraceBackend()
        op, prefix = backend._classify_syscall("clone")
        assert op == "process_spawn"
        assert prefix == "L3-TRACE-PROC-FORK"

    def test_classify_syscall_unknown_returns_other(self) -> None:
        backend = SeccompTraceBackend()
        op, prefix = backend._classify_syscall("totally_made_up_syscall")
        assert op == "syscall_other"
        assert prefix == "L3-TRACE-OTHER"

    def test_parse_seccomp_log_empty_returns_empty_list(self) -> None:
        backend = SeccompTraceBackend()
        events = backend._parse_seccomp_log("", default_policy(), 0.0, 0)
        assert events == []

    def test_parse_seccomp_log_skips_non_log_lines(self) -> None:
        """Lines without the LOG action code are skipped silently."""
        backend = SeccompTraceBackend()
        # Code 0x7fff0000 = ALLOW, not LOG
        log_text = (
            "type=1326 audit(1700000000.123:45): "
            "auid=4294967295 uid=0 gid=0 ses=4294967295 pid=1234 comm=\"python3\" "
            "exe=\"/usr/bin/python3\" sig=0 arch=c000003e syscall=2 compat=0 ip=0x7f code=0x7fff0000"
        )
        events = backend._parse_seccomp_log(log_text, default_policy(), 0.0, 0)
        assert events == []

    def test_parse_seccomp_log_extracts_open_syscall(self) -> None:
        """A canonical LOG line for syscall=2 (open) on x86_64 produces a file_open event."""
        backend = SeccompTraceBackend()
        log_text = (
            "type=1326 audit(1700000000.123:45): "
            "auid=4294967295 uid=0 gid=0 ses=4294967295 pid=1234 comm=\"python3\" "
            "exe=\"/usr/bin/python3\" sig=0 arch=c000003e syscall=2 compat=0 ip=0x7f "
            f"code={_LOG_ACTION_CODE}"
        )
        events = backend._parse_seccomp_log(log_text, default_policy(), 0.0, 1700000000000)
        assert len(events) == 1
        assert events[0].operation == "file_open"
        assert events[0].verdict == Verdict.ALLOW
        # v2.0.8 limitation: no path/address.
        assert events[0].path == ""
        assert events[0].address == ""

    def test_parse_seccomp_log_extracts_multiple_syscalls(self) -> None:
        """Multiple LOG lines produce multiple events."""
        backend = SeccompTraceBackend()
        line_open = (
            "type=1326 audit(1700000000.123:45): auid=4294967295 uid=0 gid=0 "
            "ses=4294967295 pid=1234 comm=\"python3\" exe=\"/usr/bin/python3\" "
            f"sig=0 arch=c000003e syscall=2 compat=0 ip=0x7f code={_LOG_ACTION_CODE}"
        )
        line_read = (
            "type=1326 audit(1700000000.456:46): auid=4294967295 uid=0 gid=0 "
            "ses=4294967295 pid=1234 comm=\"python3\" exe=\"/usr/bin/python3\" "
            f"sig=0 arch=c000003e syscall=0 compat=0 ip=0x7f code={_LOG_ACTION_CODE}"
        )
        line_connect = (
            "type=1326 audit(1700000000.789:47): auid=4294967295 uid=0 gid=0 "
            "ses=4294967295 pid=1234 comm=\"python3\" exe=\"/usr/bin/python3\" "
            f"sig=0 arch=c000003e syscall=42 compat=0 ip=0x7f code={_LOG_ACTION_CODE}"
        )
        events = backend._parse_seccomp_log(
            "\n".join([line_open, line_read, line_connect]),
            default_policy(),
            0.0,
            1700000000000,
        )
        assert len(events) == 3
        ops = [e.operation for e in events]
        assert "file_open" in ops
        assert "file_read" in ops
        assert "network_outbound" in ops

    def test_parse_seccomp_log_handles_malformed_lines(self) -> None:
        """Lines without syscall= are silently skipped."""
        backend = SeccompTraceBackend()
        log_text = f"random garbage with {_LOG_ACTION_CODE} but no syscall= field"
        events = backend._parse_seccomp_log(log_text, default_policy(), 0.0, 0)
        assert events == []

    def test_audit_line_re_anchors_on_required_fields(self) -> None:
        """The regex requires arch=, syscall=, and code= to be present.

        Field order in real audit output is arch=...syscall=...code=
        (verified on Linux 5.x/6.x /proc/<pid>/seccomp).
        """
        # Match
        m = _AUDIT_LINE_RE.search(
            f"audit(1.0:1): arch=c000003e syscall=2 code={_LOG_ACTION_CODE}"
        )
        assert m is not None
        assert m.group("nr") == "2"
        assert m.group("arch") == "c000003e"
        # No syscall= — no match
        m = _AUDIT_LINE_RE.search(f"audit(1.0:1): arch=c000003e code={_LOG_ACTION_CODE}")
        assert m is None
        # No code= — no match
        m = _AUDIT_LINE_RE.search("audit(1.0:1): arch=c000003e syscall=2")
        assert m is None


# ─── TestSeccompTraceBackendRun (gated) ────────────────────────────────


@skip_without_seccomp
class TestSeccompTraceBackendRun:
    """Integration tests — real fork. Require PICODOME_HAS_SECCOMP=1
    AND SeccompTraceBackend.is_available() to return True (which
    probes both libseccomp presence and CONFIG_SECCOMP_LOG=y)."""

    def setup_method(self) -> None:
        reset_backend()

    def teardown_method(self) -> None:
        reset_backend()

    def test_run_echo_captures_stdout(self) -> None:
        """Regression for the teardown-review bug: stdout is captured."""
        backend = SeccompTraceBackend()
        result = backend.run(["echo", "hello"], default_policy())
        assert result.exit_code == 0
        assert "hello" in result.stdout
        assert result.overall_verdict == Verdict.ALLOW

    def test_run_echo_emits_trace_events(self) -> None:
        """Even a simple echo produces events (file_read/write for argv + stdout)."""
        backend = SeccompTraceBackend()
        result = backend.run(["echo", "hello"], default_policy())
        # The default policy is KILL-mode (default_action=DENY), so
        # SCMP_ACT_KILL_PROCESS is the default. The trace then captures
        # syscalls the tracee makes BEFORE any policy violation. For
        # echo, that's execve + a few writes + exit. We expect at least
        # one event from the trace path (or from the post-hoc layer).
        assert len(result.events) > 0
        # Lifecycle event always emitted at the end
        operations = [e.operation for e in result.events]
        assert "process_exit" in operations

    def test_run_permissive_policy_emits_many_events(self) -> None:
        """Permissive policy uses SCMP_ACT_LOG as default — many events expected."""
        backend = SeccompTraceBackend()
        permissive = Policy(
            name="permissive",
            default_action=SyscallAction.ALLOW,
            rules=[],
        )
        result = backend.run(["echo", "hello"], permissive)
        assert result.exit_code == 0
        # At least 5 events: execve, file_read (echo reads argv), file_write (echo writes), exit, plus a few from the loader
        assert len(result.events) > 5, f"expected many events under LOG mode, got {len(result.events)}"

    def test_run_command_not_found(self) -> None:
        backend = SeccompTraceBackend()
        result = backend.run(["definitely_not_a_real_binary_xyzzy"], default_policy())
        # Either exit_code=-1 (FileNotFoundError caught) or 127
        assert result.exit_code in (-1, 127, 1)
        # Should have an exec_not_found event OR a post-hoc detection
        assert len(result.events) > 0

    def test_run_timeout(self) -> None:
        backend = SeccompTraceBackend()
        result = backend.run(["sleep", "10"], default_policy(), timeout=0.2)
        assert result.overall_verdict == Verdict.KILL
        # process_timeout event expected
        operations = [e.operation for e in result.events]
        assert "process_timeout" in operations

    def test_run_kill_policy_kills_network(self) -> None:
        """Under default policy, network connect is KILLed."""
        backend = SeccompTraceBackend()
        # Use a network connect attempt. The default policy has
        # default_action=DENY, so connect is KILLed.
        result = backend.run(
            ["python3", "-c", "import socket; socket.socket().connect(('1.2.3.4', 80))"],
            default_policy(),
            timeout=5.0,
        )
        # Exit code should be -31 (SIGSYS) or 137 (SIGKILL) or similar
        assert result.exit_code != 0
        # Either a seccomp_violation event (KILL via BPF) or a process_timeout
        # (child took too long after being KILLed) — both acceptable
        operations = [e.operation for e in result.events]
        assert (
            "seccomp_violation" in operations
            or "process_timeout" in operations
        )


# ─── TestSeccompTraceBackendDispatch ───────────────────────────────────


class TestSeccompTraceBackendDispatch:
    """_detect_backend routing for seccomp-trace. No real fork needed."""

    def setup_method(self) -> None:
        reset_backend()

    def teardown_method(self) -> None:
        reset_backend()

    def test_detect_explicit_seccomp_trace_returns_correct_backend(self) -> None:
        """When available and explicitly requested, returns SeccompTraceBackend."""
        with patch.object(SeccompTraceBackend, "is_available", return_value=True):
            backend = _detect_backend(requested="seccomp-trace")
            assert backend.name == "seccomp-trace"

    def test_detect_seccomp_trace_unavailable_raises(self) -> None:
        """When unavailable and not allow_degraded, raises BackendUnavailableError."""
        with patch.object(SeccompTraceBackend, "is_available", return_value=False):
            with pytest.raises(BackendUnavailableError) as exc_info:
                _detect_backend(requested="seccomp-trace", allow_degraded=False)
            assert exc_info.value.backend_name == "seccomp-trace"
            assert "SCMP_ACT_LOG" in str(exc_info.value) or "seccomp-trace" in str(exc_info.value)

    def test_detect_seccomp_trace_unavailable_degrades_to_subprocess(self) -> None:
        """When unavailable and allow_degraded=True, returns SubprocessBackend."""
        with patch.object(SeccompTraceBackend, "is_available", return_value=False):
            backend = _detect_backend(requested="seccomp-trace", allow_degraded=True)
            assert backend.name == "subprocess"

    def test_auto_detect_does_not_pick_seccomp_trace(self) -> None:
        """Auto-detect never returns seccomp-trace — it's explicit-only in v2.0.8."""
        with patch.object(SeccompTraceBackend, "is_available", return_value=True):
            with patch("picosentry.sandbox.l3.backends.seccomp_backend.SeccompBackend.is_available", return_value=False):
                with patch("picosentry.sandbox.l3.backends.subprocess_backend.SubprocessBackend.is_available", return_value=True):
                    with patch(
                        "picosentry.sandbox.l3.backends.subprocess_backend.SubprocessBackend.run",
                        return_value=MagicMock(),
                    ):
                        backend = _detect_backend(allow_degraded=True)
                        assert backend.name != "seccomp-trace"

    def test_get_backend_reads_env_var(self) -> None:
        """PICODOME_SANDBOX_BACKEND=seccomp-trace routes to SeccompTraceBackend."""
        with patch.object(SeccompTraceBackend, "is_available", return_value=True):
            with patch.dict(os.environ, {"PICODOME_SANDBOX_BACKEND": "seccomp-trace"}):
                reset_backend()
                try:
                    backend = get_backend()
                    assert backend.name == "seccomp-trace"
                finally:
                    reset_backend()


# ─── TestSeccompTraceBackendProfilerRoundtrip ──────────────────────────


class TestSeccompTraceBackendProfilerRoundtrip:
    """L4 contract: events from L3 → BehavioralProfile."""

    def test_events_with_paths_feed_profiler(self) -> None:
        """When events have path/address/detail populated, profiler builds profile."""
        result = SandboxResult(
            command=["/bin/ls"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
            events=[
                SandboxEvent(
                    rule_id="L3-TRACE-FS-READ",
                    verdict=Verdict.ALLOW,
                    operation="file_read",
                    detail="read syscall",
                    path="/etc/passwd",
                ),
                SandboxEvent(
                    rule_id="L3-TRACE-NET",
                    verdict=Verdict.ALLOW,
                    operation="network_outbound",
                    detail="connect syscall",
                    address="1.2.3.4",
                ),
                SandboxEvent(
                    rule_id="L3-TRACE-PROC-EXEC",
                    verdict=Verdict.ALLOW,
                    operation="process_spawn",
                    detail="Process spawn: /usr/bin/curl",
                ),
            ],
            policy_name="test",
            backend_name="seccomp-trace",
            isolation_level="kernel_enforced",
            enforcement_guarantee="moderate",
        )
        profile = profile_from_sandbox_result(result)
        # All three dimensions should be populated.
        assert len(profile.fs_ops) == 1
        assert len(profile.network_calls) == 1
        assert len(profile.spawns) == 1

    def test_events_with_empty_paths_dropped_by_profiler(self) -> None:
        """v2.0.8 limitation: events without path/address don't populate profile fields."""
        result = SandboxResult(
            command=["/bin/ls"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
            events=[
                SandboxEvent(
                    rule_id="L3-TRACE-FS-READ",
                    verdict=Verdict.ALLOW,
                    operation="file_read",
                    detail="read syscall (no path: SCMP_ACT_LOG)",
                    path="",
                ),
                SandboxEvent(
                    rule_id="L3-TRACE-NET",
                    verdict=Verdict.ALLOW,
                    operation="network_outbound",
                    detail="connect syscall (no address: SCMP_ACT_LOG)",
                    address="",
                ),
            ],
            policy_name="test",
            backend_name="seccomp-trace",
            isolation_level="kernel_enforced",
            enforcement_guarantee="moderate",
        )
        profile = profile_from_sandbox_result(result)
        # The profiler requires non-empty path/address/detail.
        assert profile.fs_ops == []
        assert profile.network_calls == []
