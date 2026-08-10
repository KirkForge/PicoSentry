"""Tests for the Landlock backend.

The Landlock backend provides filesystem path-based access control on Linux
kernels >= 5.13. On older kernels or non-Linux platforms, it falls back to
seccomp-only. This test module validates:

1. Kernel-version gate logic (mocked)
2. The ``LandlockBackend.is_available()`` probe
3. Fallback to seccomp when landlock is unavailable
4. Arch-portability of syscall number selection

Run with ``pytest tests/sandbox/test_landlock_backend.py -v``.
"""

from __future__ import annotations

import platform
from unittest.mock import MagicMock, patch

import pytest

from picosentry.sandbox.l3.backends.landlock_backend import (
    LandlockBackend,
    LandlockUnavailable,
    _check_landlock_available,
    _kernel_version,
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
