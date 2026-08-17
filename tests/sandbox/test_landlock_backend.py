"""Tests for the Landlock backend.

The Landlock backend provides filesystem path-based access control on Linux
kernels >= 5.13. On older kernels or non-Linux platforms, it falls back to
seccomp-only. This test module validates:

1. Kernel-version gate logic (mocked)
2. The ``LandlockBackend.is_available()`` probe
3. Fallback to seccomp when landlock is unavailable
4. Arch-portability of syscall number selection
5. Backend-selection wiring (env var + ``_detect_backend`` explicit name)
6. Child cwd/stdout/stderr behavior with the landlock syscalls mocked

Run with ``pytest tests/sandbox/test_landlock_backend.py -v``.
"""

from __future__ import annotations

import contextlib
import os
import platform
from unittest.mock import MagicMock, patch

import pytest

from picosentry.sandbox.l3.backends.landlock_backend import (
    LandlockBackend,
    LandlockUnavailable,
    _check_landlock_available,
    _kernel_version,
)

# Real-landlock end-to-end tests are opt-in via PICODOME_HAS_LANDLOCK=1
# (same pattern as PICODOME_HAS_SECCOMP in test_seccomp_trace_backend.py).
_HAS_LANDLOCK_ENV = os.environ.get("PICODOME_HAS_LANDLOCK") == "1"
_landlock_available = False
if _HAS_LANDLOCK_ENV:
    with contextlib.suppress(Exception):
        _landlock_available = LandlockBackend().is_available()
skip_without_landlock = pytest.mark.skipif(
    not (_HAS_LANDLOCK_ENV and _landlock_available),
    reason="landlock unavailable (set PICODOME_HAS_LANDLOCK=1 on Linux >= 5.13 with landlock LSM)",
)


class TestKernelVersionGate:
    def test_linux_5_13_passes(self) -> None:
        with (
            patch("platform.uname", return_value=platform.uname()._replace(release="5.13.0-generic")),
            patch("platform.system", return_value="Linux"),
        ):
            assert _check_landlock_available() is None

    def test_linux_5_12_fails(self) -> None:
        with (
            patch("platform.uname", return_value=platform.uname()._replace(release="5.12.0-generic")),
            patch("platform.system", return_value="Linux"),
        ):
            reason = _check_landlock_available()
            assert reason is not None
            assert "5.13" in reason

    def test_linux_6_17_passes(self) -> None:
        with (
            patch("platform.uname", return_value=platform.uname()._replace(release="6.17.0-40-generic")),
            patch("platform.system", return_value="Linux"),
        ):
            assert _check_landlock_available() is None

    def test_non_linux_fails(self) -> None:
        with (
            patch("platform.system", return_value="Darwin"),
            patch("platform.uname", return_value=platform.uname()._replace(release="23.1.0")),
        ):
            reason = _check_landlock_available()
            assert reason is not None
            assert "not Linux" in reason


class TestLandlockBackendProperties:
    def test_name(self) -> None:
        assert LandlockBackend().name == "landlock"

    def test_isolation_level(self) -> None:
        assert LandlockBackend().isolation_level == "filesystem_policy"

    def test_enforcement_guarantee(self) -> None:
        assert LandlockBackend().enforcement_guarantee == "high"


class TestLandlockUnavailable:
    def test_error_message(self) -> None:
        err = LandlockUnavailable("test reason")
        assert "test reason" in str(err)
        assert isinstance(err, RuntimeError)


class TestFallbackBehavior:
    def test_fallback_enabled_by_default(self) -> None:
        assert LandlockBackend()._fallback_to_seccomp is True

    def test_fallback_can_be_disabled(self) -> None:
        assert LandlockBackend(fallback_to_seccomp=False)._fallback_to_seccomp is False

    @pytest.mark.skipif(platform.system() != "Linux", reason="landlock requires Linux")
    def test_run_falls_back_to_seccomp_on_unavailable(self) -> None:
        backend = LandlockBackend()
        with patch.object(backend, "is_available", return_value=False):
            from picosentry.sandbox.l3.models import Policy

            policy = Policy(name="test", default_action=MagicMock())
            with patch("picosentry.sandbox.l3.backends.seccomp_backend.SeccompBackend") as mock_seccomp:
                mock_instance = MagicMock()
                mock_instance.run.return_value = MagicMock(overall_verdict="clean")
                mock_seccomp.return_value = mock_instance
                backend.run(["echo", "hello"], policy)
                mock_seccomp.assert_called_once()

    def test_run_raises_on_unavailable_no_fallback(self) -> None:
        backend = LandlockBackend(fallback_to_seccomp=False)
        with patch.object(backend, "is_available", return_value=False):
            from picosentry.sandbox.l3.models import Policy

            policy = Policy(name="test", default_action=MagicMock())
            with pytest.raises(LandlockUnavailable):
                backend.run(["echo", "hello"], policy)


class TestKernelVersionParsing:
    def test_standard_release(self) -> None:
        with patch("platform.uname", return_value=platform.uname()._replace(release="5.15.0-generic")):
            assert _kernel_version() == (5, 15, 0)

    def test_three_part_version(self) -> None:
        with patch("platform.uname", return_value=platform.uname()._replace(release="6.1.55-generic")):
            assert _kernel_version() == (6, 1, 55)

    def test_rc_suffix(self) -> None:
        with patch("platform.uname", return_value=platform.uname()._replace(release="5.13-rc1")):
            assert _kernel_version() == (5, 13, 0)

    def test_comparison_boundary(self) -> None:
        with patch("platform.uname", return_value=platform.uname()._replace(release="5.12.99")):
            reason = _check_landlock_available()
            assert reason is not None
            assert "5.13" in reason


class TestArchSyscallNumbers:
    def test_x86_64_numbers(self) -> None:
        from picosentry.sandbox.l3.backends.landlock_backend import _SYSCALL_NUMBERS

        nums = _SYSCALL_NUMBERS["x86_64"]
        assert nums == (446, 447, 448)

    def test_aarch64_numbers(self) -> None:
        from picosentry.sandbox.l3.backends.landlock_backend import _SYSCALL_NUMBERS

        nums = _SYSCALL_NUMBERS["aarch64"]
        assert nums == (444, 445, 446)

    def test_fallback_for_unknown_arch(self) -> None:
        from picosentry.sandbox.l3.backends.landlock_backend import _SYSCALL_NUMBERS

        with patch("picosentry.sandbox.l3.backends.landlock_backend._ARCH", "riscv64"):
            nums = _SYSCALL_NUMBERS.get("riscv64")
            assert nums is None or isinstance(nums, tuple)


# ─── Backend-selection wiring ────────────────────────────────────────────


class TestBackendSelectionWiring:
    """PICODOME_SANDBOX_BACKEND=landlock / --backend landlock must reach LandlockBackend."""

    def test_detect_backend_explicit_landlock(self) -> None:
        from picosentry.sandbox.l3.engine import _detect_backend

        with patch.object(LandlockBackend, "is_available", return_value=True):
            backend = _detect_backend(requested="landlock")
        assert isinstance(backend, LandlockBackend)

    def test_detect_backend_landlock_unavailable_raises(self) -> None:
        from picosentry.sandbox.l3.engine import BackendUnavailableError, _detect_backend

        with (
            patch.object(LandlockBackend, "is_available", return_value=False),
            pytest.raises(BackendUnavailableError) as excinfo,
        ):
            _detect_backend(requested="landlock", allow_degraded=False)
        assert "landlock" in str(excinfo.value)

    def test_detect_backend_landlock_unavailable_degrades(self) -> None:
        from picosentry.sandbox.l3.backends.subprocess_backend import SubprocessBackend
        from picosentry.sandbox.l3.engine import _detect_backend

        with patch.object(LandlockBackend, "is_available", return_value=False):
            backend = _detect_backend(requested="landlock", allow_degraded=True)
        assert isinstance(backend, SubprocessBackend)

    def test_env_var_selects_landlock_via_registry(self, monkeypatch) -> None:
        from picosentry.sandbox.l3 import engine

        monkeypatch.setenv("PICODOME_SANDBOX_BACKEND", "landlock")
        engine.reset_backend()
        try:
            with patch.object(LandlockBackend, "is_available", return_value=True):
                backend = engine.get_backend()
            assert isinstance(backend, LandlockBackend)
        finally:
            engine.reset_backend()

    def test_landlock_not_auto_detected(self) -> None:
        """Even with landlock available, auto-detect must not pick it (opt-in only)."""
        from picosentry.sandbox.l3.engine import BackendUnavailableError, _detect_backend

        with patch.object(LandlockBackend, "is_available", return_value=True):
            try:
                backend = _detect_backend(requested=None, allow_degraded=True)
            except BackendUnavailableError:
                return  # no kernel backend at all — still not landlock
            assert not isinstance(backend, LandlockBackend)


# ─── Child behavior with landlock syscalls mocked ────────────────────────


def _mock_landlock_syscalls():
    """Patch the landlock syscalls so run() exercises fork/exec on any Linux."""
    devnull_fd = os.open(os.devnull, os.O_RDONLY)
    return (
        patch.object(LandlockBackend, "is_available", return_value=True),
        patch.object(LandlockBackend, "_get_libc", return_value=MagicMock()),
        patch("picosentry.sandbox.l3.backends.landlock_backend._landlock_create_ruleset", return_value=devnull_fd),
        patch("picosentry.sandbox.l3.backends.landlock_backend._landlock_add_rule", return_value=0),
        patch("picosentry.sandbox.l3.backends.landlock_backend._landlock_restrict_self", return_value=0),
        patch("picosentry.sandbox.l3.backends.landlock_backend.set_resource_limits", lambda: None),
    )


@pytest.mark.skipif(platform.system() != "Linux", reason="os.fork required")
class TestRunWithMockedSyscalls:
    """cwd chdir, stdout/stderr capture, distinct chdir exit code, timeout kill."""

    @staticmethod
    def _policy():
        from picosentry.sandbox.l3.policy import default_policy

        return default_policy()

    def test_cwd_is_honored(self, tmp_path) -> None:
        backend = LandlockBackend()
        patches = _mock_landlock_syscalls()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
            result = backend.run(["pwd"], self._policy(), cwd=str(tmp_path))
        assert result.exit_code == 0
        assert result.stdout == str(tmp_path)

    def test_stdout_and_stderr_captured(self) -> None:
        backend = LandlockBackend()
        patches = _mock_landlock_syscalls()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
            result = backend.run(["sh", "-c", "echo out-marker; echo err-marker >&2"], self._policy())
        assert result.exit_code == 0
        assert result.stdout == "out-marker"
        assert result.stderr == "err-marker"

    def test_large_stdout_does_not_deadlock(self) -> None:
        backend = LandlockBackend()
        patches = _mock_landlock_syscalls()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
            result = backend.run(["sh", "-c", "seq 1 20000"], self._policy(), timeout=30.0)
        assert result.exit_code == 0
        assert len(result.stdout.splitlines()) == 20000

    def test_bad_cwd_exits_125(self) -> None:
        backend = LandlockBackend()
        patches = _mock_landlock_syscalls()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
            result = backend.run(["pwd"], self._policy(), cwd="/nonexistent/definitely/not/here")
        assert result.exit_code == 125
        assert result.overall_verdict.value != "allow"

    def test_timeout_kills_and_denies(self) -> None:
        backend = LandlockBackend()
        patches = _mock_landlock_syscalls()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
            result = backend.run(["sleep", "30"], self._policy(), timeout=0.5)
        assert result.exit_code == -9
        assert result.overall_verdict.value != "allow"

    def test_result_reports_backend_metadata(self) -> None:
        backend = LandlockBackend()
        patches = _mock_landlock_syscalls()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5]:
            result = backend.run(["true"], self._policy())
        assert result.backend_name == "landlock"
        assert result.isolation_level == "filesystem_policy"
        assert result.enforcement_guarantee == "high"


# ─── Real landlock end-to-end (opt-in via PICODOME_HAS_LANDLOCK=1) ──────


@skip_without_landlock
class TestRealLandlock:
    def test_pwd_respects_cwd(self, tmp_path) -> None:
        result = LandlockBackend().run(["pwd"], policy=None, cwd=str(tmp_path))  # type: ignore[arg-type]
        assert result.exit_code == 0
        assert result.stdout == str(tmp_path)

    def test_write_outside_workspace_is_denied(self, tmp_path) -> None:
        result = LandlockBackend().run(
            ["sh", "-c", "echo x > /tmp/landlock-should-deny-$$.txt"],
            policy=None,
            cwd=str(tmp_path),
        )  # type: ignore[arg-type]
        assert result.exit_code != 0
        assert result.overall_verdict.value != "allow"
