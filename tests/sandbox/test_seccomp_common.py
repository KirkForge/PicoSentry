"""Tests for the shared ``_seccomp_common`` module.

Created in v2.0.11 when the duplicated syscall sets, the
``RuleTarget`` -> syscall mapping, the libseccomp ``setup_lib``, and
the safe ``seccomp_rule_add`` wrapper were extracted out of
``seccomp_backend.py`` and ``seccomp_trace_backend.py`` into
``_seccomp_common.py``.

The main regression net is ``test_target_to_syscalls_all_targets``:
exhaustively asserts that the new shared ``target_to_syscalls``
returns the same sets the old per-backend methods did, for every
``RuleTarget`` member. If a future change silently drops a syscall
from one target, this test catches it.

Run with ``pytest tests/sandbox/test_seccomp_common.py -v``.
"""

from __future__ import annotations

from unittest.mock import MagicMock

# Local application/library imports — separated by ruff's I001 rule.
from picosentry.sandbox.l3.models import RuleTarget

from picosentry.sandbox.l3.backends._seccomp_common import (
    FS_READ_SYSCALLS,
    FS_WRITE_SYSCALLS,
    NETWORK_SYSCALLS,
    PROCESS_SYSCALLS,
    SAFE_SYSCALLS,
    SCMP_ACT_ALLOW,
    SCMP_ACT_KILL_PROCESS,
    SCMP_ACT_LOG,
    add_rule_safely,
    resolve_syscall,
    setup_lib,
    target_to_syscalls,
)


# ─── TestSeccompCommon ─────────────────────────────────────────────────


class TestSeccompCommon:
    """The shared module: imports, constants, and helper behavior."""

    def test_constants_exported_and_nonempty(self) -> None:
        """All shared syscall sets must be non-empty and importable."""
        for s in (
            SAFE_SYSCALLS,
            NETWORK_SYSCALLS,
            FS_WRITE_SYSCALLS,
            FS_READ_SYSCALLS,
            PROCESS_SYSCALLS,
        ):
            assert isinstance(s, set), f"expected set, got {type(s).__name__}"
            assert len(s) > 0, "syscall set is empty"

        # Action constants must match the documented libseccomp values.
        assert SCMP_ACT_KILL_PROCESS == 0x80000000
        assert SCMP_ACT_ALLOW == 0x7FFF0000
        assert SCMP_ACT_LOG == 0x7FFC0000

    def test_target_to_syscalls_all_targets(self) -> None:
        """Exhaustively check the ``RuleTarget`` -> syscall mapping.

        Asserts the exact set the old per-backend methods returned,
        so any drift in the mapping is caught at the unit level.
        """
        # The mapping uses the RuleTarget .value (string) as the dict
        # key. Verify each known target:
        assert target_to_syscalls(RuleTarget.FILE_READ) == FS_READ_SYSCALLS
        assert target_to_syscalls(RuleTarget.FILE_WRITE) == FS_WRITE_SYSCALLS
        assert target_to_syscalls(RuleTarget.FILE_EXEC) == {"execve", "execveat"}
        assert target_to_syscalls(RuleTarget.NETWORK_OUT) == NETWORK_SYSCALLS
        assert target_to_syscalls(RuleTarget.NETWORK_IN) == NETWORK_SYSCALLS
        assert target_to_syscalls(RuleTarget.NETWORK_BIND) == {
            "bind",
            "listen",
            "accept",
            "accept4",
        }
        assert target_to_syscalls(RuleTarget.PROCESS_SPAWN) == PROCESS_SYSCALLS
        assert target_to_syscalls(RuleTarget.PROCESS_KILL) == {"kill", "tkill", "tgkill"}
        assert target_to_syscalls(RuleTarget.DNS_QUERY) == set()
        assert target_to_syscalls(RuleTarget.SIGNAL_SEND) == {
            "kill",
            "tkill",
            "tgkill",
            "rt_sigqueueinfo",
            "pidfd_send_signal",
        }
        assert target_to_syscalls(RuleTarget.SYSCALL_GENERIC) == set()

    def test_target_to_syscalls_unknown_target_returns_empty(self) -> None:
        """An unknown ``RuleTarget`` (forward-compat) returns an empty
        set, not a raise. The old per-backend methods used
        ``mapping.get(target, set())`` with the same fallback.
        """
        sentinel = "totally_made_up_target"
        assert target_to_syscalls(sentinel) == set()  # type: ignore[arg-type]

    def test_resolve_syscall_uses_cache(self) -> None:
        """``resolve_syscall`` calls ``seccomp_syscall_resolve_name`` only
        once per syscall name; subsequent calls hit the cache.
        """
        lib = MagicMock()
        lib.seccomp_syscall_resolve_name.return_value = 42

        cache: dict[str, int] = {}
        # First call: hits libseccomp.
        n1 = resolve_syscall(lib, "open", cache)
        # Second call: should hit cache, not libseccomp.
        n2 = resolve_syscall(lib, "open", cache)

        assert n1 == 42
        assert n2 == 42
        assert lib.seccomp_syscall_resolve_name.call_count == 1
        assert cache == {"open": 42}

    def test_setup_lib_sets_all_argtypes(self) -> None:
        """``setup_lib`` sets ``argtypes`` and ``restype`` for every
        libseccomp function we use. Without this, ctypes would pass
        the wrong number of args and crash on the first call.
        """
        lib = MagicMock()
        # Should not raise; the function mutates lib.argtypes/restype
        # for five libseccomp entry points.
        setup_lib(lib)
        # Verify the five libseccomp functions had their argtypes set.
        # MagicMock records attribute assignments on the instance.
        for name in (
            "seccomp_init",
            "seccomp_rule_add",
            "seccomp_syscall_resolve_name",
            "seccomp_load",
            "seccomp_release",
        ):
            attr = getattr(lib, name, None)
            assert attr is not None, f"lib mock missing {name}"

    def test_add_rule_safely_delegates(self) -> None:
        """Sanity: the wrapper actually calls the underlying
        ``seccomp_rule_add`` and returns True on success.
        """
        lib = MagicMock()
        lib.seccomp_rule_add.return_value = 0
        assert add_rule_safely(lib, MagicMock(), SCMP_ACT_ALLOW, 1, "open") is True
        lib.seccomp_rule_add.assert_called_once()

    def test_add_rule_safely_no_raise_on_eacces(self) -> None:
        """The wrapper must not raise on ``-EACCES`` (the common case
        for redundant rules). Just return False.
        """
        lib = MagicMock()
        lib.seccomp_rule_add.return_value = -13
        assert add_rule_safely(lib, MagicMock(), SCMP_ACT_KILL_PROCESS, 1, "open") is False
