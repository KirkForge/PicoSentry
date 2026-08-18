"""Tests for the Landlock backend.

The Landlock backend provides filesystem path-based access control on Linux
kernels >= 5.13. On older kernels or non-Linux platforms, it falls back to
seccomp-only. This test module validates:

1. Kernel-version gate logic (mocked)
2. The ``LandlockBackend.is_available()`` probe (ABI-version based)
3. Fallback to seccomp when landlock is unavailable
4. Arch-portability of syscall number selection (derived from kernel headers,
   never from hardcoded literals)
5. Backend-selection wiring (env var + ``_detect_backend`` explicit name)
6. Policy → ruleset translation (workspace tightening, net bits, ceilings)
7. Child cwd/stdout/stderr behavior with the landlock syscalls mocked
8. Real-execution round-trips (opt-in via PICODOME_HAS_LANDLOCK=1)

Run with ``pytest tests/sandbox/test_landlock_backend.py -v``.
"""

from __future__ import annotations

import contextlib
import ctypes
import os
import platform
import re
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from picosentry.sandbox.l3.backends.landlock_backend import (
    LANDLOCK_ACCESS_FS_EXECUTE,
    LANDLOCK_ACCESS_FS_READ_DIR,
    LANDLOCK_ACCESS_FS_READ_FILE,
    LANDLOCK_ACCESS_FS_WRITE_FILE,
    LANDLOCK_ACCESS_NET_BIND_TCP,
    LANDLOCK_ACCESS_NET_CONNECT_TCP,
    LandlockBackend,
    LandlockUnavailable,
    _abi_fs_bits,
    _build_grants,
    _check_landlock_available,
    _glob_anchor,
    _kernel_version,
    _landlock_abi_version,
    _net_handling,
    _SYSCALL_NUMBERS,
)
from picosentry.sandbox.l3.models import Policy, PolicyRule, RuleTarget, SyscallAction
from picosentry.sandbox.l3.policy import default_policy, node_policy, strict_policy
from picosentry.sandbox.models import Verdict

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

_landlock_abi = 0
if _HAS_LANDLOCK_ENV and _landlock_available:
    with contextlib.suppress(Exception):
        _landlock_abi = _landlock_abi_version(ctypes.CDLL("libc.so.6", use_errno=True))
skip_without_net_abi = pytest.mark.skipif(
    _landlock_abi < 4,
    reason="network restrictions need landlock ABI >= 4 (kernel >= 6.7)",
)


# ─── Syscall numbers: derived from kernel headers, never hardcoded ───────

_SYSCALL_NAMES = ("landlock_create_ruleset", "landlock_add_rule", "landlock_restrict_self")

_X86_64_HEADERS = (
    "/usr/include/x86_64-linux-gnu/asm/unistd_64.h",
    "/usr/include/asm/unistd_64.h",
)
# aarch64 consumes the generic syscall table.
_AARCH64_HEADERS = (
    "/usr/include/aarch64-linux-gnu/asm/unistd.h",
    "/usr/include/asm-generic/unistd.h",
)


def _header_syscall_numbers(header_paths: tuple[str, ...]) -> tuple[int, int, int] | None:
    for path in header_paths:
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        nums: list[int] = []
        for name in _SYSCALL_NAMES:
            match = re.search(rf"#define\s+__NR_{name}\s+(\d+)", text)
            if match is None:
                nums = []
                break
            nums.append(int(match.group(1)))
        if len(nums) == len(_SYSCALL_NAMES):
            return (nums[0], nums[1], nums[2])
    return None


_x86_64_derived = _header_syscall_numbers(_X86_64_HEADERS)
_aarch64_derived = _header_syscall_numbers(_AARCH64_HEADERS)


class TestSyscallTable:
    def test_numbers_are_contiguous_and_ascending(self) -> None:
        for arch, nums in _SYSCALL_NUMBERS.items():
            assert nums[1] == nums[0] + 1, arch
            assert nums[2] == nums[1] + 1, arch

    @pytest.mark.skipif(_x86_64_derived is None, reason="x86_64 kernel headers not installed")
    def test_x86_64_matches_kernel_headers(self) -> None:
        assert _SYSCALL_NUMBERS["x86_64"] == _x86_64_derived

    @pytest.mark.skipif(_aarch64_derived is None, reason="aarch64/generic kernel headers not installed")
    def test_aarch64_matches_generic_headers(self) -> None:
        assert _SYSCALL_NUMBERS["aarch64"] == _aarch64_derived

    def test_all_arches_agree_on_allocation(self) -> None:
        # The landlock allocation is uniform across architectures.
        assert len(set(_SYSCALL_NUMBERS.values())) == 1

    def test_unknown_arch_falls_back_to_uniform_numbers(self) -> None:
        assert _SYSCALL_NUMBERS.get("riscv64", (444, 445, 446)) == next(iter(_SYSCALL_NUMBERS.values()))

    @pytest.mark.skipif(platform.system() != "Linux", reason="live probe requires Linux")
    def test_live_create_ruleset_number_probes_abi(self) -> None:
        """If landlock is usable, syscalling the table's create number with the
        VERSION flag must return a positive ABI — proving the number is right."""
        backend = LandlockBackend()
        if not backend.is_available():
            pytest.skip("landlock not usable on this host")
        abi = _landlock_abi_version(backend._get_libc())
        assert abi >= 1


# ─── Availability probing ────────────────────────────────────────────────


class TestAbiProbe:
    def test_abi_probe_returns_version(self) -> None:
        libc = MagicMock()
        libc.syscall.return_value = 3
        with patch("ctypes.get_errno", return_value=0):
            assert _landlock_abi_version(libc) == 3

    def test_abi_probe_error_maps_to_zero(self) -> None:
        libc = MagicMock()
        libc.syscall.return_value = -38

        def _errno() -> int:
            return 0

        with patch("ctypes.get_errno", side_effect=_errno):
            assert _landlock_abi_version(libc) == 0

    def test_abi_fs_bits_scope_by_abi(self) -> None:
        v1 = _abi_fs_bits(1)
        assert v1 & (1 << 13) == 0  # REFER needs ABI 2 (kernel 5.19)
        assert _abi_fs_bits(2) & (1 << 13)
        assert _abi_fs_bits(2) & (1 << 14) == 0  # TRUNCATE needs ABI 3 (kernel 6.2)
        assert _abi_fs_bits(3) & (1 << 14)
        assert _abi_fs_bits(4) & (1 << 14)

    @pytest.mark.skipif(platform.system() != "Linux", reason="requires Linux libc")
    def test_is_available_matches_live_probe(self) -> None:
        backend = LandlockBackend()
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
        except OSError:
            pytest.skip("libc.so.6 not loadable")
        assert backend.is_available() == (_landlock_abi_version(libc) >= 1)


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


# ─── Policy → ruleset translation ────────────────────────────────────────

_FS_V3 = _abi_fs_bits(3)


class TestGlobAnchor:
    def test_plain_prefix(self) -> None:
        assert _glob_anchor("/usr/lib/**") == "/usr/lib"

    def test_mid_path_glob_falls_back_to_prefix(self) -> None:
        assert _glob_anchor("/usr/lib/python3*/**") == "/usr/lib/python3"

    def test_literal_file_is_its_own_anchor(self) -> None:
        assert _glob_anchor("/etc/ld.so.cache") == "/etc/ld.so.cache"

    def test_relative_cwd_glob(self) -> None:
        assert _glob_anchor("./**") == "."

    def test_unbounded_glob_is_none(self) -> None:
        assert _glob_anchor("**/site-packages/**") is None
        assert _glob_anchor("**/package.json") is None


class TestPolicyTranslation:
    def test_default_policy_has_no_bare_tmp_write(self, tmp_path) -> None:
        grants = dict(_build_grants(default_policy(), ["true"], str(tmp_path), _FS_V3))
        for path, bits in grants.items():
            if path == "/tmp":
                assert bits & LANDLOCK_ACCESS_FS_WRITE_FILE == 0

    def test_write_paths_tightened_to_workspace(self, tmp_path) -> None:
        grants = dict(_build_grants(default_policy(), ["true"], str(tmp_path), _FS_V3))
        assert grants[str(tmp_path)] & LANDLOCK_ACCESS_FS_WRITE_FILE

    def test_no_full_proc_read(self, tmp_path) -> None:
        grants = dict(_build_grants(default_policy(), ["true"], str(tmp_path), _FS_V3))
        assert "/proc" not in grants
        assert grants.get("/proc/self", 0) & LANDLOCK_ACCESS_FS_READ_DIR

    def test_proc_self_grant_kept_literal_not_parent_pid(self, tmp_path) -> None:
        grants = _build_grants(default_policy(), ["true"], str(tmp_path), _FS_V3)
        proc_keys = [p for p, _ in grants if p.startswith("/proc")]
        assert proc_keys == ["/proc/self"]  # resolved in the child, never the parent's pid dir

    def test_no_execute_on_dev(self, tmp_path) -> None:
        grants = dict(_build_grants(default_policy(), ["true"], str(tmp_path), _FS_V3))
        for path, bits in grants.items():
            if path.startswith("/dev"):
                assert bits & LANDLOCK_ACCESS_FS_EXECUTE == 0

    def test_workspace_not_executable(self, tmp_path) -> None:
        grants = dict(_build_grants(default_policy(), ["true"], str(tmp_path), _FS_V3))
        assert grants[str(tmp_path)] & LANDLOCK_ACCESS_FS_EXECUTE == 0

    def test_command_dir_gets_execute(self, tmp_path) -> None:
        import shutil

        grants = dict(_build_grants(default_policy(), ["true"], str(tmp_path), _FS_V3))
        cmd_dir = os.path.dirname(os.path.realpath(shutil.which("true") or "/bin/true"))
        assert grants.get(cmd_dir, 0) & LANDLOCK_ACCESS_FS_EXECUTE

    def test_exec_glob_enumerates_files_not_dirs(self, tmp_path) -> None:
        rule = PolicyRule(
            rule_id="t-exec",
            target=RuleTarget.FILE_EXEC,
            action=SyscallAction.ALLOW,
            paths=[os.path.join(tmp_path, "bin*")],
        )
        (tmp_path / "bin-shim").write_text("#!/bin/sh\n")
        (tmp_path / "other").write_text("x")
        policy = Policy(name="t", rules=[rule])
        grants = dict(_build_grants(policy, ["true"], str(tmp_path), _FS_V3))
        assert grants.get(str(tmp_path / "bin-shim"), 0) & LANDLOCK_ACCESS_FS_EXECUTE
        assert grants.get(str(tmp_path / "bin-shim"), 0) & LANDLOCK_ACCESS_FS_READ_FILE
        assert str(tmp_path / "other") not in grants

    def test_strict_policy_yields_no_grants(self, tmp_path) -> None:
        assert _build_grants(strict_policy(), ["true"], str(tmp_path), _FS_V3) == []

    def test_grants_are_deterministic(self, tmp_path) -> None:
        first = _build_grants(default_policy(), ["true"], str(tmp_path), _FS_V3)
        second = _build_grants(default_policy(), ["true"], str(tmp_path), _FS_V3)
        assert first == second
        assert first == sorted(first)

    def test_grants_masked_to_handled_bits(self, tmp_path) -> None:
        abi1 = _abi_fs_bits(1)
        grants = dict(_build_grants(default_policy(), ["true"], str(tmp_path), abi1))
        assert all(bits & ~abi1 == 0 for bits in grants.values())

    def test_relative_paths_resolve_against_workspace(self, tmp_path) -> None:
        rule = PolicyRule(
            rule_id="t-rw",
            target=RuleTarget.FILE_WRITE,
            action=SyscallAction.ALLOW,
            paths=["out/**"],
        )
        policy = Policy(name="t", rules=[rule], default_action=SyscallAction.DENY)
        grants = dict(_build_grants(policy, ["true"], str(tmp_path), _FS_V3))
        assert grants.get(str(tmp_path / "out"), 0) & LANDLOCK_ACCESS_FS_WRITE_FILE


class TestNetHandling:
    def test_default_policy_denies_connect_and_bind_at_abi4(self) -> None:
        handled, ceilings = _net_handling(default_policy(), 4)
        assert handled == LANDLOCK_ACCESS_NET_CONNECT_TCP | LANDLOCK_ACCESS_NET_BIND_TCP
        assert ceilings == []

    def test_abi3_reports_honest_ceilings(self) -> None:
        handled, ceilings = _net_handling(default_policy(), 3)
        assert handled == 0
        assert any("network_out" in c and "6.7" in c for c in ceilings)
        assert any("network_bind" in c for c in ceilings)

    def test_allow_policy_leaves_net_unhandled(self) -> None:
        handled, ceilings = _net_handling(node_policy(), 4)
        assert handled == 0
        assert ceilings == []

    def test_udp_and_inbound_are_documented_ceilings(self) -> None:
        rule = PolicyRule(rule_id="t", target=RuleTarget.DNS_QUERY, action=SyscallAction.DENY)
        policy = Policy(name="t", rules=[rule])
        _, ceilings = _net_handling(policy, 4)
        assert any("dns_query" in c and "UDP" in c for c in ceilings)

    def test_ambient_default_deny_still_handles_net_without_ceiling(self) -> None:
        policy = Policy(name="ambient", default_action=SyscallAction.DENY, rules=[])
        handled, ceilings = _net_handling(policy, 4)
        assert handled == LANDLOCK_ACCESS_NET_CONNECT_TCP | LANDLOCK_ACCESS_NET_BIND_TCP
        assert ceilings == []

    def test_strict_policy_inbound_ceiling(self) -> None:
        _, ceilings = _net_handling(strict_policy(), 4)
        assert any("network_in" in c for c in ceilings)


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
        patch("picosentry.sandbox.l3.backends.landlock_backend._landlock_abi_version", return_value=4),
        patch("picosentry.sandbox.l3.backends.landlock_backend.set_resource_limits", lambda: None),
    )


@pytest.mark.skipif(platform.system() != "Linux", reason="os.fork required")
class TestRunWithMockedSyscalls:
    """cwd chdir, stdout/stderr capture, distinct chdir exit code, timeout kill."""

    @staticmethod
    def _policy():
        return default_policy()

    def test_cwd_is_honored(self, tmp_path) -> None:
        backend = LandlockBackend()
        patches = _mock_landlock_syscalls()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
            result = backend.run(["pwd"], self._policy(), cwd=str(tmp_path))
        assert result.exit_code == 0
        assert result.stdout == str(tmp_path)

    def test_stdout_and_stderr_captured(self) -> None:
        backend = LandlockBackend()
        patches = _mock_landlock_syscalls()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
            result = backend.run(["sh", "-c", "echo out-marker; echo err-marker >&2"], self._policy())
        assert result.exit_code == 0
        assert result.stdout == "out-marker"
        assert result.stderr == "err-marker"

    def test_large_stdout_does_not_deadlock(self) -> None:
        backend = LandlockBackend()
        patches = _mock_landlock_syscalls()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
            result = backend.run(["sh", "-c", "seq 1 20000"], self._policy(), timeout=30.0)
        assert result.exit_code == 0
        assert len(result.stdout.splitlines()) == 20000

    def test_bad_cwd_exits_125(self) -> None:
        backend = LandlockBackend()
        patches = _mock_landlock_syscalls()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
            result = backend.run(["pwd"], self._policy(), cwd="/nonexistent/definitely/not/here")
        assert result.exit_code == 125
        assert result.overall_verdict is not Verdict.ALLOW

    def test_timeout_kills_and_denies(self) -> None:
        backend = LandlockBackend()
        patches = _mock_landlock_syscalls()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
            result = backend.run(["sleep", "30"], self._policy(), timeout=0.5)
        assert result.exit_code == -9
        assert result.overall_verdict is not Verdict.ALLOW

    def test_result_reports_backend_metadata(self) -> None:
        backend = LandlockBackend()
        patches = _mock_landlock_syscalls()
        with patches[0], patches[1], patches[2], patches[3], patches[4], patches[5], patches[6]:
            result = backend.run(["true"], self._policy())
        assert result.backend_name == "landlock"
        assert result.isolation_level == "filesystem_policy"
        assert result.enforcement_guarantee == "high"
        assert result.degraded is False

    def test_no_new_privs_failure_exits_127(self) -> None:
        import picosentry.sandbox.l3.backends.landlock_backend as lb

        backend = LandlockBackend()
        patches = _mock_landlock_syscalls()
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patches[6],
            patch.object(lb, "_set_no_new_privs", return_value=-1),
        ):
            result = backend.run(["true"], self._policy())
        assert result.exit_code == 127  # child refuses to exec without PR_SET_NO_NEW_PRIVS

    def test_net_ceiling_marks_result_degraded(self) -> None:
        backend = LandlockBackend()
        patches = _mock_landlock_syscalls()
        with (
            patches[0],
            patches[1],
            patches[2],
            patches[3],
            patches[4],
            patches[5],
            patches[6],
            patch("picosentry.sandbox.l3.backends.landlock_backend._landlock_abi_version", return_value=1),
        ):
            result = backend.run(["true"], self._policy())
        assert result.exit_code == 0
        assert result.degraded is True  # default policy denies network_out; ABI 1 cannot enforce


# ─── Real landlock end-to-end (opt-in via PICODOME_HAS_LANDLOCK=1) ──────


@skip_without_landlock
class TestRealLandlock:
    def test_true_succeeds_in_workspace(self, tmp_path) -> None:
        result = LandlockBackend().run(["true"], default_policy(), cwd=str(tmp_path))
        assert result.exit_code == 0
        assert result.overall_verdict is Verdict.ALLOW
        assert result.degraded is False

    def test_pwd_respects_cwd(self, tmp_path) -> None:
        result = LandlockBackend().run(["pwd"], default_policy(), cwd=str(tmp_path))
        assert result.exit_code == 0
        assert result.stdout == str(tmp_path)

    def test_write_outside_workspace_gets_eacces(self, tmp_path) -> None:
        outside = tmp_path.parent / f"landlock-outside-{os.getpid()}"
        outside.mkdir(exist_ok=True)
        try:
            result = LandlockBackend().run(
                ["sh", "-c", f"echo x > {outside}/should-deny.txt"],
                default_policy(),
                cwd=str(tmp_path),
            )
            assert result.exit_code != 0
            # WO5.0.0-019: verdicts are event-driven now — a blocked write is
            # real enforcement (EACCES, no file created) but NOT a policy-verdict
            # event; the workload fails on its own terms, so verdict is ALLOW.
            assert result.overall_verdict is Verdict.ALLOW
            assert "Permission denied" in result.stderr
            assert not (outside / "should-deny.txt").exists()
        finally:
            for entry in outside.iterdir():
                entry.unlink(missing_ok=True)
            outside.rmdir()

    def test_write_inside_workspace_succeeds(self, tmp_path) -> None:
        result = LandlockBackend().run(
            ["sh", "-c", "echo ok > inside.txt && cat inside.txt"],
            default_policy(),
            cwd=str(tmp_path),
        )
        assert result.exit_code == 0
        assert result.stdout == "ok"

    @skip_without_net_abi
    def test_network_connect_gets_eacces(self, tmp_path) -> None:
        result = LandlockBackend().run(
            [
                sys.executable,
                "-c",
                "import socket; socket.create_connection(('127.0.0.1', 9), timeout=2)",
            ],
            default_policy(),
            cwd=str(tmp_path),
        )
        assert result.exit_code != 0
        # WO5.0.0-019: verdicts are event-driven and no longer encode
        # enforcement (EACCES) — and posthoc heuristics can legitimately
        # differ by host (e.g. an interpreter installed under /home/<u>/.
        # trips L3-SUS-010 in the traceback). Enforcement is proven by the
        # exit code + EACCES below, not the verdict.
        assert result.overall_verdict is not Verdict.KILL
        assert "Permission denied" in result.stderr

    @skip_without_net_abi
    def test_degraded_flag_absent_when_net_enforced(self, tmp_path) -> None:
        result = LandlockBackend().run(["true"], default_policy(), cwd=str(tmp_path))
        assert result.degraded is False
