"""Tests for SeccompBackend (enforcement-only seccomp-bpf).

These tests target v2.0.11 fixes:

- ``TestSeccompBackendForkOrdering`` — regression net for Bug #1 (env-dict
  construction under the active seccomp filter). Uses
  ``unittest.mock.patch`` to assert that ``os.environ.copy()`` /
  ``dict.update()`` happen in the parent **before** ``os.fork()``.
  Strict ordering: no real libseccomp needed.

- ``TestSeccompBackendRuleAddReturn`` — regression net for Bug #2
  (silent ``seccomp_rule_add`` failures). Mocks libseccomp to return
  ``-EACCES`` (rule's action matches filter default) and ``-EINVAL``
  (unknown syscall) and asserts the ``add_rule_safely`` wrapper
  behaves as documented: DEBUG-and-skip for EACCES, WARNING-and-
  continue for EINVAL.

No real fork required. No libseccomp required. Run with
``pytest tests/sandbox/test_seccomp_backend.py -v``.
"""

from __future__ import annotations

import logging
import os
from unittest.mock import MagicMock, patch

import pytest

from picosentry.sandbox.l3.backends._seccomp_common import (
    FS_READ_SYSCALLS,
    FS_WRITE_SYSCALLS,
    NETWORK_SYSCALLS,
    PROCESS_SYSCALLS,
    SAFE_SYSCALLS,
    SCMP_ACT_ALLOW,
    SCMP_ACT_KILL_PROCESS,
    add_rule_safely,
)
from picosentry.sandbox.l3.backends.seccomp_backend import SeccompBackend
from picosentry.sandbox.l3.models import (
    Policy,
    PolicyRule,
    RuleTarget,
    SyscallAction,
)


# ─── TestSeccompBackendForkOrdering (Bug #1) ─────────────────────────────


class TestSeccompBackendForkOrdering:
    """Regression net for Bug #1: env-dict construction must run in the parent,
    before ``os.fork()``, so the child never allocates under the active filter.
    """

    def _stub_lib_and_build_filter(self) -> MagicMock:
        """Return a mock lib that allows _build_filter to run to completion."""
        lib = MagicMock()
        lib.seccomp_init.return_value = MagicMock()  # non-None ctx
        lib.seccomp_syscall_resolve_name.return_value = 1  # any positive
        lib.seccomp_rule_add.return_value = 0
        lib.seccomp_load.return_value = 0
        return lib

    def test_env_built_before_fork_in_kill_default(self) -> None:
        """Under a KILL-default policy, ``os.environ.copy()`` and the user-env
        ``update()`` must complete before ``os.fork()`` is called.

        Implementation: spy on ``os.environ.copy``, ``os.fork``, and
        ``os.execve`` via ``unittest.mock.patch`` (in
        ``picosentry.sandbox.l3.backends.seccomp_backend``). Assert the
        recorded call order. If a future change moves env construction
        back into the child branch, this test fails.
        """
        backend = SeccompBackend()
        policy = Policy(
            name="kill-default-test",
            default_action=SyscallAction.KILL,
            rules=[
                PolicyRule(
                    rule_id="L3-TEST-001",
                    target=RuleTarget.FILE_READ,
                    action=SyscallAction.ALLOW,
                ),
            ],
            fail_closed=True,
        )
        lib = self._stub_lib_and_build_filter()

        # Patch all the os.* and lib calls used by run(), plus the
        # import shim used for select. We never want the real fork+exec
        # to run; short-circuit by having os.fork return a non-zero pid
        # (parent branch).
        call_order: list[str] = []

        def fake_fork():
            call_order.append("fork")
            return 42  # parent branch

        def fake_environ_copy():
            call_order.append("environ_copy")
            return {"PATH": "/usr/bin"}

        def fake_wait_with_timeout(self, pid, out_r, err_r, timeout):
            call_order.append("wait")
            return (b"hi\n", b"", 0)

        # Patch os.environ.copy on the actual os.environ object so the
        # backend's call to ``os.environ.copy()`` is intercepted. Other
        # os.environ operations (if any) use the real mapping.
        with patch(
            "picosentry.sandbox.l3.backends.seccomp_backend.os.fork",
            side_effect=fake_fork,
        ), patch.object(
            os.environ, "copy", side_effect=fake_environ_copy
        ), patch(
            "picosentry.sandbox.l3.backends.seccomp_backend.os.pipe",
            return_value=(0, 1),
        ), patch(
            "picosentry.sandbox.l3.backends.seccomp_backend.ctypes.CDLL",
            return_value=lib,
        ), patch.object(
            SeccompBackend, "_wait_with_timeout", fake_wait_with_timeout
        ), patch(
            "picosentry.sandbox.l3.backends.seccomp_backend.os.read",
            return_value=b"hi\n",
        ), patch(
            "picosentry.sandbox.l3.backends.seccomp_backend.os.close",
            return_value=None,
        ):
            result = backend.run(["/bin/echo", "hi"], policy=policy, timeout=5.0)

        # The env-copy must happen before the fork.
        assert "environ_copy" in call_order, (
            f"expected environ_copy in call_order, got {call_order!r}"
        )
        assert "fork" in call_order
        assert call_order.index("environ_copy") < call_order.index("fork"), (
            f"env-dict construction must run in parent before fork; "
            f"got call_order={call_order!r}. This regressed Bug #1."
        )
        # And the run completed.
        assert result is not None

    def test_env_built_before_fork_in_allow_default(self) -> None:
        """Same assertion under an ALLOW default (non-KILL), where the
        failure mode is less catastrophic but still wrong: dict ops
        under an active filter can still SIGSYS a child on a strict
        kernel even when the default is ALLOW, if the BPF program
        rejects any of the allocator's internal syscalls.
        """
        backend = SeccompBackend()
        policy = Policy(
            name="allow-default-test",
            default_action=SyscallAction.ALLOW,
            rules=[],
            fail_closed=True,
        )
        lib = self._stub_lib_and_build_filter()

        call_order: list[str] = []

        def fake_fork():
            call_order.append("fork")
            return 42

        def fake_environ_copy():
            call_order.append("environ_copy")
            return {"PATH": "/usr/bin"}

        def fake_wait_with_timeout(self, pid, out_r, err_r, timeout):
            return (b"hi\n", b"", 0)

        with patch(
            "picosentry.sandbox.l3.backends.seccomp_backend.os.fork",
            side_effect=fake_fork,
        ), patch.object(
            os.environ, "copy", side_effect=fake_environ_copy
        ), patch(
            "picosentry.sandbox.l3.backends.seccomp_backend.os.pipe",
            return_value=(0, 1),
        ), patch(
            "picosentry.sandbox.l3.backends.seccomp_backend.ctypes.CDLL",
            return_value=lib,
        ), patch.object(
            SeccompBackend, "_wait_with_timeout", fake_wait_with_timeout
        ), patch(
            "picosentry.sandbox.l3.backends.seccomp_backend.os.read",
            return_value=b"hi\n",
        ), patch(
            "picosentry.sandbox.l3.backends.seccomp_backend.os.close",
            return_value=None,
        ):
            backend.run(["/bin/echo", "hi"], policy=policy, timeout=5.0)

        assert "environ_copy" in call_order
        assert "fork" in call_order
        assert call_order.index("environ_copy") < call_order.index("fork")


# ─── TestSeccompBackendRuleAddReturn (Bug #2) ───────────────────────────


class TestSeccompBackendRuleAddReturn:
    """Regression net for Bug #2: ``seccomp_rule_add`` return values are
    now checked via the ``add_rule_safely`` wrapper.
    """

    @pytest.fixture(autouse=True)
    def _restore_picodome_propagation(self) -> None:
        """Defensive: ``test_logging_extra.py::test_propagate_disabled``
        sets ``picodome.propagate=False`` and never restores it. Pytest's
        caplog handler is attached to the root logger, so records from
        ``picodome.l3.seccomp_common`` (a child of ``picodome``) would
        stop propagating to caplog after that test runs. Re-enable
        propagation on the ``picodome`` parent before each test in this
        class so the caplog-using tests below see their own records.
        """
        logging.getLogger("picodome").propagate = True

    def test_rule_add_eacces_logged_and_skipped(self, caplog: pytest.LogCaptureFixture) -> None:
        """``-EACCES`` means the rule's action matches the filter's default
        action (libseccomp refuses to add a redundant rule). The wrapper
        logs at DEBUG and returns False; it does not raise and does not
        prevent the filter from loading.
        """
        lib = MagicMock()
        lib.seccomp_rule_add.return_value = -13  # -EACCES

        with caplog.at_level(logging.DEBUG, logger="picodome.l3.seccomp_common"):
            result = add_rule_safely(lib, MagicMock(), SCMP_ACT_KILL_PROCESS, 1, "open")

        assert result is False
        # The DEBUG log line should mention the syscall and the action.
        debug_messages = [r.message for r in caplog.records if r.levelno == logging.DEBUG]
        assert any("open" in m for m in debug_messages), (
            f"expected DEBUG log mentioning 'open', got {debug_messages!r}"
        )
        assert any("seccomp_rule_add skipped" in m for m in debug_messages), (
            f"expected 'seccomp_rule_add skipped' in DEBUG, got {debug_messages!r}"
        )

    def test_rule_add_einval_logged_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """``-EINVAL`` means libseccomp rejected the syscall (usually
        unknown on this arch). The wrapper logs at WARNING and returns
        True (we don't fail the filter — the KILL default catches it).
        """
        lib = MagicMock()
        lib.seccomp_rule_add.return_value = -22  # -EINVAL

        with caplog.at_level(logging.WARNING, logger="picodome.l3.seccomp_common"):
            result = add_rule_safely(lib, MagicMock(), SCMP_ACT_ALLOW, 999, "future_syscall")

        assert result is True
        warning_messages = [r.message for r in caplog.records if r.levelno == logging.WARNING]
        assert any("future_syscall" in m for m in warning_messages), (
            f"expected WARNING log mentioning 'future_syscall', got {warning_messages!r}"
        )

    def test_rule_add_other_error_logged_warning(self, caplog: pytest.LogCaptureFixture) -> None:
        """An unexpected negative return (-7, E2BIG) still logs WARNING.
        The filter is not failed (returns True) — defensive: one bad
        rule shouldn't fail the whole load.
        """
        lib = MagicMock()
        lib.seccomp_rule_add.return_value = -7  # -E2BIG

        with caplog.at_level(logging.WARNING, logger="picodome.l3.seccomp_common"):
            result = add_rule_safely(lib, MagicMock(), SCMP_ACT_ALLOW, 5, "fstat")

        assert result is True
        warning_messages = [r.message for r in caplog.records if r.levelno == logging.WARNING]
        assert any("fstat" in m for m in warning_messages), (
            f"expected WARNING log mentioning 'fstat', got {warning_messages!r}"
        )

    def test_rule_add_success_returns_true(self) -> None:
        """Zero return (success) returns True and emits no log."""
        lib = MagicMock()
        lib.seccomp_rule_add.return_value = 0
        result = add_rule_safely(lib, MagicMock(), SCMP_ACT_ALLOW, 1, "write")
        assert result is True
        lib.seccomp_rule_add.assert_called_once()

    def test_build_filter_uses_add_rule_safely(self) -> None:
        """``SeccompBackend._build_filter`` must go through
        ``add_rule_safely`` for every rule add, not call libseccomp
        directly. Catches a future regression where someone reverts to
        raw ``lib.seccomp_rule_add`` calls.
        """
        backend = SeccompBackend()
        lib = MagicMock()
        lib.seccomp_init.return_value = MagicMock()
        lib.seccomp_syscall_resolve_name.return_value = 1
        lib.seccomp_rule_add.return_value = 0

        policy = Policy(
            name="test",
            default_action=SyscallAction.KILL,
            rules=[
                PolicyRule(
                    rule_id="L3-TEST-001",
                    target=RuleTarget.FILE_READ,
                    action=SyscallAction.ALLOW,
                ),
            ],
        )
        with patch(
            "picosentry.sandbox.l3.backends.seccomp_backend.add_rule_safely"
        ) as mock_add:
            _ctx, _blocked = backend._build_filter(lib, policy)

        # add_rule_safely must have been called for at least the
        # FS_READ_SYSCALLS syscalls + the SAFE_SYSCALLS syscalls.
        assert mock_add.called, "SeccompBackend._build_filter must use add_rule_safely"
        assert mock_add.call_count >= len(FS_READ_SYSCALLS), (
            f"expected add_rule_safely called at least {len(FS_READ_SYSCALLS)} times "
            f"(one per FS_READ_SYSCALL), got {mock_add.call_count}"
        )


# ─── TestSeccompBackendSharedConstants ───────────────────────────────────


class TestSeccompBackendSharedConstants:
    """The seccomp backend must use the constants from ``_seccomp_common``,
    not local duplicates. This is the refactor-regression net for the
    v2.0.11 extraction: if a future change re-introduces a local
    ``_SAFE_SYSCALLS`` block, the test catches the duplication at
    behavior time (the backend reads from the same source of truth).
    """

    def test_backend_safe_syscalls_is_shared_set(self) -> None:
        """The constants in the seccomp common module are the same
        Python object the backend references. (Reference equality, not
        value equality — catches a silent copy-paste.)
        """
        from picosentry.sandbox.l3.backends import seccomp_backend
        # The backend no longer carries a local _SAFE_SYSCALLS attribute.
        assert not hasattr(seccomp_backend, "_SAFE_SYSCALLS"), (
            "seccomp_backend.py should import SAFE_SYSCALLS from "
            "_seccomp_common, not redefine it locally"
        )
        # And the imported name is the same object as in common.
        assert seccomp_backend.SAFE_SYSCALLS is SAFE_SYSCALLS
        assert seccomp_backend.NETWORK_SYSCALLS is NETWORK_SYSCALLS
        assert seccomp_backend.FS_WRITE_SYSCALLS is FS_WRITE_SYSCALLS
        assert seccomp_backend.FS_READ_SYSCALLS is FS_READ_SYSCALLS
        assert seccomp_backend.PROCESS_SYSCALLS is PROCESS_SYSCALLS

    def test_setup_lib_delegates_to_common(self) -> None:
        """``SeccompBackend._setup_lib`` is a one-line delegate to
        ``_seccomp_common.setup_lib``. Verify by patching
        ``_seccomp_common.setup_lib`` and asserting the backend's call
        propagates.
        """
        backend = SeccompBackend()
        lib = MagicMock()
        with patch("picosentry.sandbox.l3.backends.seccomp_backend.setup_lib") as mock_setup:
            backend._setup_lib(lib)
        mock_setup.assert_called_once_with(lib)

    def test_resolve_delegates_to_common(self) -> None:
        """``SeccompBackend._resolve`` is a one-line delegate to
        ``_seccomp_common.resolve_syscall``.
        """
        backend = SeccompBackend()
        lib = MagicMock()
        with patch(
            "picosentry.sandbox.l3.backends.seccomp_backend.resolve_syscall"
        ) as mock_resolve:
            backend._resolve(lib, "open")
        mock_resolve.assert_called_once_with(lib, "open", backend._syscall_cache)

    def test_target_to_syscalls_delegates_to_common(self) -> None:
        """``SeccompBackend._target_to_syscalls`` is a one-line delegate
        to ``_seccomp_common.target_to_syscalls``.
        """
        backend = SeccompBackend()
        with patch(
            "picosentry.sandbox.l3.backends.seccomp_backend.target_to_syscalls"
        ) as mock_tts:
            backend._target_to_syscalls(RuleTarget.FILE_READ)
        mock_tts.assert_called_once_with(RuleTarget.FILE_READ)
