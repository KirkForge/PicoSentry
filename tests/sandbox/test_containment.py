"""Containment hardening tests — WO4.0.0-011.

Covers:
- RLIMIT_CPU / RLIMIT_NPROC knobs in the shared rlimit helper (0 = off)
- kill_process_group group kill semantics
- Timeout kills the whole process GROUP: grandchildren holding the stdout
  pipe must die with the direct child (the old bare-kill left them alive and
  subprocess-backend communicate() hung forever on the open write end).
- Fork-bomb bounded by RLIMIT_NPROC (env-gated malicious-workload round)
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path
from typing import ClassVar

import pytest

from picosentry.sandbox.l3.backends import _rlimits
from picosentry.sandbox.l3.backends._rlimits import (
    compute_rlimits,
    kill_process_group,
    sandbox_preexec,
)
from picosentry.sandbox.l3.engine import sandbox_run
from picosentry.sandbox.l3.policy import default_policy

posix_only = pytest.mark.skipif(not hasattr(os, "setsid"), reason="POSIX process groups required")


def _proc_count_with_marker(marker: str) -> int:
    """Live (non-zombie) processes whose cmdline contains the marker.

    Zombies have an empty cmdline, so a killed-but-unreaped child does not
    match — no sleep is needed to await reaping.
    """
    if not Path("/proc").is_dir():
        pytest.skip("/proc not available")
    count = 0
    for entry in Path("/proc").iterdir():
        if not entry.name.isdigit():
            continue
        try:
            cmdline = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        if marker.encode() in cmdline:
            count += 1
    return count


class TestComputeRlimits:
    def test_defaults_cpu_on_nproc_off(self, monkeypatch):
        """CPU ceiling defaults on; NPROC defaults OFF (RLIMIT_NPROC is
        per-UID host-wide while /proc sees only the PID namespace — a default
        bound breaks every fork on shared-UID hosts, verified empirically)."""
        for name in (
            "PICODOME_MEMORY_LIMIT_MB",
            "PICODOME_FILE_SIZE_LIMIT_MB",
            "PICODOME_CPU_LIMIT_SECONDS",
            "PICODOME_PROCESS_LIMIT",
        ):
            monkeypatch.delenv(name, raising=False)
        limits = compute_rlimits()
        assert limits["RLIMIT_CPU"] == (3600, 3601)
        assert "RLIMIT_NPROC" not in limits
        assert limits["RLIMIT_NOFILE"] == (256, 256)

    def test_cpu_zero_disables_cpu_limit(self, monkeypatch):
        monkeypatch.setenv("PICODOME_CPU_LIMIT_SECONDS", "0")
        assert "RLIMIT_CPU" not in compute_rlimits()

    def test_nproc_opt_in_bound_is_count_plus_headroom(self, monkeypatch):
        monkeypatch.setenv("PICODOME_PROCESS_LIMIT", "512")
        monkeypatch.setattr(_rlimits, "_user_process_count", lambda: 100)
        assert compute_rlimits()["RLIMIT_NPROC"] == (612, 612)

    def test_no_user_proc_count_disables_nproc(self, monkeypatch):
        """Non-Linux (no /proc): computed bound unavailable, no NPROC limit."""
        monkeypatch.setenv("PICODOME_PROCESS_LIMIT", "512")
        monkeypatch.setattr(_rlimits, "_user_process_count", lambda: 0)
        assert "RLIMIT_NPROC" not in compute_rlimits()


class TestRlimitsAppliedToChildren:
    @posix_only
    def test_child_sees_cpu_and_nproc_limits(self, monkeypatch):
        import ast

        monkeypatch.setenv("PICODOME_CPU_LIMIT_SECONDS", "17")
        monkeypatch.setenv("PICODOME_PROCESS_LIMIT", "8")
        monkeypatch.setattr(_rlimits, "_user_process_count", lambda: 100)
        out = subprocess.run(
            [
                sys.executable,
                "-c",
                "import resource\n"
                "print(resource.getrlimit(resource.RLIMIT_CPU))\n"
                "print(resource.getrlimit(resource.RLIMIT_NPROC))",
            ],
            capture_output=True,
            text=True,
            preexec_fn=sandbox_preexec,
            timeout=10,
        ).stdout
        cpu_line, nproc_line = out.splitlines()
        assert ast.literal_eval(cpu_line) == (17, 18)
        assert ast.literal_eval(nproc_line) == (108, 108)

    @posix_only
    def test_preexec_creates_new_session(self):
        out = subprocess.run(
            [sys.executable, "-c", "import os; print(os.getsid(0) == os.getpid())"],
            capture_output=True,
            text=True,
            preexec_fn=sandbox_preexec,
            timeout=10,
        ).stdout
        assert out.strip() == "True"


class TestKillProcessGroup:
    @posix_only
    def test_kills_whole_group(self):
        proc = subprocess.Popen(
            ["sh", "-c", "sleep 30 & sleep 30"],
            start_new_session=True,
        )
        try:
            kill_process_group(proc.pid)
            proc.wait(timeout=5)
        finally:
            kill_process_group(proc.pid)  # idempotent cleanup
        assert proc.poll() is not None

    def test_missing_group_is_not_an_error(self):
        kill_process_group(2**24)  # no such pgid — must not raise


class TestTimeoutKillsProcessGroup:
    @posix_only
    def test_grandchildren_die_on_timeout(self):
        """Regression: bare proc.kill() left grandchildren holding the stdout
        pipe — communicate() then hung forever. The group kill must take the
        whole tree and the run must return promptly.

        Backend pinned to subprocess: the hang was in its communicate() path,
        and auto-detect picks seccomp here which (correctly) kills the shell
        on its first fork under the default policy.
        """
        from picosentry.sandbox.l3.backends.subprocess_backend import SubprocessBackend

        marker = "picodome-gc-regression-4f2a"
        result = sandbox_run(
            ["sh", "-c", f"sh -c 'sleep 30 # {marker}' & sleep 30 # {marker}"],
            default_policy(),
            timeout=1.0,
            backend=SubprocessBackend(),
        )
        assert result.overall_verdict.value == "KILL"
        assert any(e.rule_id == "L3-TIMEOUT-001" for e in result.events)
        # The whole group is gone: no live process still carries the marker.
        assert _proc_count_with_marker(marker) == 0

    @posix_only
    def test_backend_run_also_kills_group(self):
        """Direct backend.run timeout path (no engine) kills the group too."""
        from picosentry.sandbox.l3.backends.subprocess_backend import SubprocessBackend

        marker = "picodome-gc-backend-9c1d"
        result = SubprocessBackend().run(
            ["sh", "-c", f"sh -c 'sleep 30 # {marker}' & sleep 30 # {marker}"],
            default_policy(),
            timeout=1.0,
        )
        assert result.exit_code == -1
        assert _proc_count_with_marker(marker) == 0


class TestForkBombBounded:
    """Env-gated malicious-workload round (PICODOME_SANDBOX_TESTS=1)."""

    pytestmark: ClassVar[list] = [
        pytest.mark.skipif(
            os.environ.get("PICODOME_SANDBOX_TESTS", "").lower() not in ("1", "true", "yes"),
            reason="Set PICODOME_SANDBOX_TESTS=1 to run sandbox-dependent malicious workload tests",
        ),
        pytest.mark.malicious_workload,
    ]

    @posix_only
    def test_spawn_flood_bounded_by_nproc_and_killed_on_timeout(self, monkeypatch):
        from picosentry.sandbox.l3.backends.subprocess_backend import SubprocessBackend

        marker = "picodome-forkbomb-77aa"
        monkeypatch.setenv("PICODOME_PROCESS_LIMIT", "512")
        result = sandbox_run(
            ["sh", "-c", f"while :; do sleep 5 # {marker} & done"],
            default_policy(),
            timeout=3.0,
            backend=SubprocessBackend(),
        )
        # The flood is bounded (forks fail under RLIMIT_NPROC once the
        # headroom is spent) and the timeout group-kill removes whatever
        # did spawn.
        assert result.overall_verdict.value == "KILL"
        assert result.duration_ms < 30_000, "sandbox_run must not hang on a fork flood"
        assert _proc_count_with_marker(marker) == 0


class TestHelperNoopWithoutResource:
    def test_noop_without_resource_module(self, monkeypatch):
        monkeypatch.setattr(_rlimits, "HAS_RESOURCE", False)
        _rlimits.set_resource_limits()

    def test_killpg_missing_on_platform(self, monkeypatch):
        monkeypatch.delattr(os, "killpg", raising=False)
        kill_process_group(1)  # must not raise AttributeError
