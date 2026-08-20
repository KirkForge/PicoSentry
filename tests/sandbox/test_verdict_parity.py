"""Cross-backend verdict parity (WO5.0.0-019).

The same command + policy must yield the same l3_verdict regardless of the
host backend, and landlock's FS-ceiling gaps must be visible as degraded
rather than silently absent. Real-execution legs: subprocess always,
seccomp when libseccomp is present, landlock opt-in via
PICODOME_HAS_LANDLOCK=1 (kernel >= 5.13 with the landlock LSM).
"""

from __future__ import annotations

import os
from typing import Any

import pytest

from picosentry.sandbox.l3.backends.base import compute_verdict
from picosentry.sandbox.l3.models import (
    Policy,
    PolicyRule,
    RuleTarget,
    SandboxEvent,
    SyscallAction,
    Verdict,
)

_HAS_LANDLOCK_ENV = os.environ.get("PICODOME_HAS_LANDLOCK") == "1"
_skip_landlock = pytest.mark.skipif(
    not _HAS_LANDLOCK_ENV,
    reason="landlock real-exec is opt-in (set PICODOME_HAS_LANDLOCK=1 on Linux >= 5.13 with landlock LSM)",
)

# WO6.0.0-005: seccomp-trace is gated on libseccomp + CONFIG_SECCOMP_LOG=y,
# same opt-in env (PICODOME_HAS_SECCOMP=1) the trace-backend suite uses.
_HAS_SECCOMP_TRACE_ENV = os.environ.get("PICODOME_HAS_SECCOMP") == "1"
_seccomp_trace_available = False
if _HAS_SECCOMP_TRACE_ENV:
    try:
        from picosentry.sandbox.l3.backends.seccomp_trace_backend import SeccompTraceBackend

        _seccomp_trace_available = SeccompTraceBackend().is_available()
    except Exception:
        _seccomp_trace_available = False
_skip_seccomp_trace = pytest.mark.skipif(
    not (_HAS_SECCOMP_TRACE_ENV and _seccomp_trace_available),
    reason="seccomp-trace unavailable (set PICODOME_HAS_SECCOMP=1 and ensure libseccomp + CONFIG_SECCOMP_LOG=y)",
)


def _allow_all_policy() -> Policy:
    return Policy(name="parity-allow-all", version="1.0", default_action=SyscallAction.ALLOW, rules=[])


def _deny_write_policy() -> Policy:
    return Policy(
        name="parity-deny-write",
        version="1.0",
        default_action=SyscallAction.ALLOW,
        rules=[
            PolicyRule(
                rule_id="PARITY-W-001",
                target=RuleTarget.FILE_WRITE,
                action=SyscallAction.DENY,
                description="deny writes",
            )
        ],
    )


PARITY_CASES: list[tuple[str, list[str], Verdict]] = [
    ("exit0", ["python3", "-c", "raise SystemExit(0)"], Verdict.ALLOW),
    ("exit1", ["python3", "-c", "raise SystemExit(1)"], Verdict.ALLOW),
    ("exit2", ["python3", "-c", "raise SystemExit(2)"], Verdict.ALLOW),
    ("signal-death", ["python3", "-c", "import os, signal; os.kill(os.getpid(), signal.SIGKILL)"], Verdict.KILL),
    ("exec-not-found", ["/nonexistent/binary-for-parity", "--flag"], Verdict.DENY),
]


class TestComputeVerdictUnit:
    """The shared decision function (mocked — no execution)."""

    def test_events_decide_first(self):
        kill = SandboxEvent(rule_id="X", verdict=Verdict.KILL, operation="op", detail="d")
        deny = SandboxEvent(rule_id="Y", verdict=Verdict.DENY, operation="op", detail="d")
        assert compute_verdict([kill, deny], 0) is Verdict.KILL
        assert compute_verdict([deny, kill], 0) is Verdict.DENY  # first deciding event wins
        assert compute_verdict([deny], 0) is Verdict.DENY
        assert compute_verdict([kill], 2) is Verdict.KILL

    def test_signal_death_without_events_is_kill(self):
        # WO5.0.0-018 item 8: subprocess used to ALLOW exit -11 with no events.
        assert compute_verdict([], -11) is Verdict.KILL
        assert compute_verdict([], -9) is Verdict.KILL

    def test_plain_nonzero_exit_is_allow(self):
        # WO5.0.0-019 item 1: landlock used to DENY grep-exit-2/npm-audit-1.
        assert compute_verdict([], 1) is Verdict.ALLOW
        assert compute_verdict([], 2) is Verdict.ALLOW

    def test_none_exit_is_allow(self):
        assert compute_verdict([], None) is Verdict.ALLOW

    def test_all_backends_delegate_to_shared_helper(self):
        from picosentry.sandbox.l3.backends.seccomp_backend import SeccompBackend
        from picosentry.sandbox.l3.backends.seatbelt_backend import SeatbeltBackend
        from picosentry.sandbox.l3.backends.subprocess_backend import SubprocessBackend

        events: list[SandboxEvent] = []
        for backend in (SubprocessBackend(), SeccompBackend(), SeatbeltBackend()):
            assert backend._compute_verdict(events, -11) is Verdict.KILL
            assert backend._compute_verdict(events, 2) is Verdict.ALLOW

    def test_seccomp_trace_uses_shared_helper_for_benign_nonzero_exit(self):
        # WO6.0.0-005: seccomp-trace used to KILL any nonzero exit; the
        # private compute_verdict is gone and the orchestrator now imports
        # the shared helper. A stub event list + benign exit must ALLOW.
        from picosentry.sandbox.l3.backends.base import compute_verdict as shared_compute_verdict

        assert shared_compute_verdict([], 3) is Verdict.ALLOW
        assert shared_compute_verdict([], 2) is Verdict.ALLOW
        assert shared_compute_verdict([], -9) is Verdict.KILL


class TestFsCeilings:
    """ABI<2/3 gaps must be surfaced (degraded + logged), not silent."""

    def test_abi1_flags_refer_and_truncate(self):
        from picosentry.sandbox.l3.backends.landlock_backend import _fs_ceilings

        ceilings = _fs_ceilings(_deny_write_policy(), abi=1)
        assert any("refer" in c for c in ceilings)
        assert any("truncate" in c for c in ceilings)

    def test_abi2_flags_truncate_only(self):
        from picosentry.sandbox.l3.backends.landlock_backend import _fs_ceilings

        ceilings = _fs_ceilings(_deny_write_policy(), abi=2)
        assert not any("refer" in c for c in ceilings)
        assert any("truncate" in c for c in ceilings)

    def test_abi3_has_no_fs_ceilings(self):
        from picosentry.sandbox.l3.backends.landlock_backend import _fs_ceilings

        assert _fs_ceilings(_deny_write_policy(), abi=3) == []

    def test_allow_all_policy_has_no_fs_ceilings(self):
        from picosentry.sandbox.l3.backends.landlock_backend import _fs_ceilings

        assert _fs_ceilings(_allow_all_policy(), abi=1) == []


class TestCrossBackendParity:
    """Identical command + policy → identical verdict on real execution.

    Fast tier: subprocess + seccomp (when libseccomp exists). The landlock
    leg runs the same matrix under PICODOME_HAS_LANDLOCK=1 below.
    """

    @pytest.fixture(params=["subprocess", "seccomp"])
    def backend(self, request) -> Any:
        if request.param == "subprocess":
            from picosentry.sandbox.l3.backends.subprocess_backend import SubprocessBackend

            return SubprocessBackend()
        from picosentry.sandbox.l3.backends.seccomp_backend import SeccompBackend

        b = SeccompBackend()
        if not b.is_available():
            pytest.skip("seccomp-bpf not available on this platform")
        return b

    @pytest.mark.parametrize("label,command,expected", PARITY_CASES, ids=[c[0] for c in PARITY_CASES])
    def test_verdict_matches_across_backends(self, backend, label, command, expected):
        result = backend.run(command, _allow_all_policy(), timeout=15.0)
        assert result.overall_verdict is expected, (
            f"{backend.name}: exit={result.exit_code} events={[e.rule_id for e in result.events]}"
        )

    @_skip_landlock
    @pytest.mark.parametrize("label,command,expected", PARITY_CASES, ids=[c[0] for c in PARITY_CASES])
    def test_verdict_matches_on_landlock(self, label, command, expected):
        from picosentry.sandbox.l3.backends.landlock_backend import LandlockBackend

        backend = LandlockBackend(fallback_to_seccomp=False)
        if not backend.is_available():
            pytest.skip("landlock unavailable on this platform")
        result = backend.run(command, _allow_all_policy(), timeout=15.0)
        assert result.overall_verdict is expected, (
            f"{backend.name}: exit={result.exit_code} events={[e.rule_id for e in result.events]}"
        )

    def test_subprocess_signal_death_is_kill(self):
        """WO5.0.0-018 item 8 regression: subprocess ALLOWed signal-killed
        children (exit -11, no events)."""
        from picosentry.sandbox.l3.backends.subprocess_backend import SubprocessBackend

        result = SubprocessBackend().run(
            ["python3", "-c", "import os, signal; os.kill(os.getpid(), signal.SIGKILL)"],
            _allow_all_policy(),
            timeout=15.0,
        )
        assert result.exit_code == -9
        assert result.overall_verdict is Verdict.KILL


class TestLandlockDegradedHonesty:
    """Infra failures and ABI ceilings must surface as degraded."""

    def test_infra_failure_is_degraded_not_clean_deny(self):
        """A child-stub exit (126/127) is degraded=True with an infra event —
        the old code reported a clean policy DENY (WO5.0.0-019 item 2)."""
        from picosentry.sandbox.l3.backends.landlock_backend import LandlockBackend

        backend = LandlockBackend(fallback_to_seccomp=False)
        if not backend.is_available():
            pytest.skip("landlock unavailable on this platform")
        result = backend.run(["/nonexistent/binary-for-parity"], _allow_all_policy(), timeout=15.0)
        assert result.exit_code in (126, 127)
        assert result.overall_verdict is Verdict.DENY
        assert result.degraded is True
        assert any(e.rule_id.startswith("L3-EXEC") for e in result.events)

    @_skip_landlock
    def test_real_landlock_exit2_is_allow(self):
        """Real round-trip on a live kernel: exit 2 must NOT be a DENY."""
        from picosentry.sandbox.l3.backends.landlock_backend import LandlockBackend

        backend = LandlockBackend(fallback_to_seccomp=False)
        if not backend.is_available():
            pytest.skip("landlock unavailable on this platform")
        result = backend.run(["python3", "-c", "raise SystemExit(2)"], _allow_all_policy(), timeout=15.0)
        assert result.overall_verdict is Verdict.ALLOW
        assert result.degraded is False

    @_skip_landlock
    def test_real_landlock_restriction_still_enforces(self):
        """Sanity: the verdict change did not disable enforcement — a denied
        read outside the grants still fails (EACCES-driven nonzero exit or
        kill), never a silent clean run."""
        from picosentry.sandbox.l3.backends.landlock_backend import LandlockBackend

        backend = LandlockBackend(fallback_to_seccomp=False)
        if not backend.is_available():
            pytest.skip("landlock unavailable on this platform")
        deny_read = Policy(
            name="parity-deny-read",
            version="1.0",
            default_action=SyscallAction.ALLOW,
            rules=[
                PolicyRule(
                    rule_id="PARITY-R-001",
                    target=RuleTarget.FILE_READ,
                    action=SyscallAction.DENY,
                )
            ],
        )
        result = backend.run(["python3", "-c", "print(open('/etc/hostname').read())"], deny_read, timeout=15.0)
        assert result.exit_code != 0  # the read was blocked; python errors out


class TestSeccompTraceParity:
    """WO6.0.0-005: seccomp-trace real-exec parity seat.

    The same PARITY_CASES matrix the other backends run, plus the degraded
    honesty check that infra failures (125/126/127) surface as DENY+degraded
    rather than a clean policy KILL.
    """

    @_skip_seccomp_trace
    @pytest.mark.parametrize("label,command,expected", PARITY_CASES, ids=[c[0] for c in PARITY_CASES])
    def test_verdict_matches_on_seccomp_trace(self, label, command, expected):
        from picosentry.sandbox.l3.backends.seccomp_trace_backend import SeccompTraceBackend

        backend = SeccompTraceBackend()
        if not backend.is_available():
            pytest.skip("seccomp-trace unavailable on this platform")
        result = backend.run(command, _allow_all_policy(), timeout=15.0)
        assert result.overall_verdict is expected, (
            f"{backend.name}: exit={result.exit_code} events={[e.rule_id for e in result.events]}"
        )

    @_skip_seccomp_trace
    def test_seccomp_trace_infra_failure_is_degraded_deny(self):
        """WO6.0.0-005 item 2: a missing command (exit 127) was reported as a
        clean policy KILL with degraded=False. Must be DENY+degraded now,
        matching the landlock contract (test_infra_failure_is_degraded_not_clean_deny)."""
        from picosentry.sandbox.l3.backends.seccomp_trace_backend import SeccompTraceBackend

        backend = SeccompTraceBackend()
        if not backend.is_available():
            pytest.skip("seccomp-trace unavailable on this platform")
        result = backend.run(["/nonexistent/binary-for-parity"], _allow_all_policy(), timeout=15.0)
        assert result.exit_code == 127, f"unexpected exit code: {result.exit_code}"
        assert result.overall_verdict is Verdict.DENY
        assert result.degraded is True
        assert any(e.rule_id.startswith("L3-EXEC") for e in result.events)
