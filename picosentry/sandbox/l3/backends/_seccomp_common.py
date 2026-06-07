"""Shared seccomp constants and helpers for the seccomp-bpf backends.

This module is the single source of truth for the syscall sets, the
``RuleTarget`` -> syscall mapping, the libseccomp argtypes setup, and
the safe rule-adding helper. Both ``SeccompBackend`` (enforcement-only)
and ``SeccompTraceBackend`` (SCMP_ACT_LOG observation) import from
here, so the two backends cannot drift.

Extracted in v2.0.11 from duplicated copies in the two backends; the
old code had a "Keep in sync with seccomp_backend.py" comment as a
maintenance hazard. Now they share a real source of truth.
"""

from __future__ import annotations

import ctypes
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from picosentry.sandbox.l3.models import RuleTarget

logger = logging.getLogger("picodome.l3.seccomp_common")

# ─── libseccomp action constants ────────────────────────────────────────────
# These are the canonical libseccomp action codes. They are also defined
# in each backend (with the same values) because some call sites need
# them before this module is imported. Kept here so the backends can
# `from _seccomp_common import SCMP_ACT_*` if they prefer.

SCMP_ACT_KILL_PROCESS = 0x80000000
SCMP_ACT_KILL_THREAD = 0x00000000
SCMP_ACT_TRAP = 0x00030000
SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_ACT_LOG = 0x7FFC0000  # used by the trace backend only

# errno(EPERM) action for non-fatal denials — returns EPERM instead of SIGSYS,
# so the calling process learns which syscall was denied instead of being killed silently.
SCMP_ACT_ERRNO_EPERM = 0x00050001  # seccomp ACT_ERRNO with errno=EPERM (1)

# ─── Syscall name → number mappings ─────────────────────────────────────────

NETWORK_SYSCALLS = {
    "connect",
    "accept",
    "accept4",
    "bind",
    "listen",
    "sendto",
    "sendmsg",
    "sendmmsg",
    "recvfrom",
    "recvmsg",
    "recvmmsg",
    "socket",
    "socketpair",
    "getsockname",
    "getpeername",
    "setsockopt",
    "getsockopt",
    "shutdown",
}

FS_WRITE_SYSCALLS = {
    "write",
    "writev",
    "pwrite64",
    "pwritev",
    "pwritev2",
    "open",
    "openat",
    "creat",
    "mkdir",
    "mkdirat",
    "rmdir",
    "unlink",
    "unlinkat",
    "rename",
    "renameat",
    "renameat2",
    "link",
    "linkat",
    "symlink",
    "symlinkat",
    "chmod",
    "fchmod",
    "fchmodat",
    "chown",
    "fchown",
    "lchown",
    "fchownat",
    "truncate",
    "ftruncate",
    "fallocate",
    "mknod",
    "mknodat",
    "mount",
    "umount",
    "umount2",
}

FS_READ_SYSCALLS = {
    "read",
    "readv",
    "pread64",
    "preadv",
    "preadv2",
    "stat",
    "lstat",
    "fstat",
    "newfstatat",
    "getdents",
    "getdents64",
    "readlink",
    "readlinkat",
    "access",
    "faccessat",
    "faccessat2",
}

PROCESS_SYSCALLS = {
    "execve",
    "execveat",
    "fork",
    "vfork",
    "clone",
    "clone3",
    # Child reaping — inseparable from spawning
    "wait4",
    "waitid",
    "waitpid",
    # Process management — needed by npm, pip, yarn
    "kill",
    "setsid",
    "sigprocmask",
    "close_range",
}

# Comprehensive safe syscalls needed for basic binary execution
SAFE_SYSCALLS = {
    "read",
    "readv",
    "pread64",
    "preadv",
    "preadv2",
    "write",
    "writev",
    "pwrite64",
    "open",
    "openat",
    "close",
    "stat",
    "lstat",
    "fstat",
    "newfstatat",
    "statfs",
    "fstatfs",
    "access",
    "faccessat",
    "faccessat2",
    "readlink",
    "readlinkat",
    "getcwd",
    "getdents64",
    "mmap",
    "mprotect",
    "munmap",
    "brk",
    "mremap",
    "madvise",
    "execve",
    "execveat",
    "exit",
    "exit_group",
    "getpid",
    "gettid",
    "getuid",
    "getgid",
    "geteuid",
    "getegid",
    "getgroups",
    "rt_sigaction",
    "rt_sigprocmask",
    "rt_sigreturn",
    "sigaltstack",
    "tgkill",
    "tkill",
    "restart_syscall",
    "futex",
    "set_robust_list",
    "get_robust_list",
    "set_tid_address",
    "rseq",
    "membarrier",
    "fcntl",
    "ioctl",
    "dup",
    "dup2",
    "dup3",
    "pipe2",
    "lseek",
    "clock_gettime",
    "clock_nanosleep",
    "nanosleep",
    "gettimeofday",
    "time",
    "setitimer",
    "getitimer",
    "poll",
    "ppoll",
    "select",
    "pselect6",
    "epoll_create1",
    "epoll_ctl",
    "epoll_pwait",
    "eventfd2",
    "arch_prctl",
    "prctl",
    "prlimit64",
    "getrandom",
    "getrusage",
    "getrlimit",
    "uname",
    "sysinfo",
    "sched_yield",
    "sched_getaffinity",
    "memfd_create",
    "capget",
    "capset",
    # Child process reaping (inseparable from process management)
    "wait4",
    "waitid",
    "waitpid",
    # CPython subprocess fork/exec path (close_range kills children without this)
    "close_range",
    # Process management — signal dispatch, session creation, signal mask
    "kill",
    "setsid",
    "sigprocmask",
    # Modern binary runtime requirements
    "statx",
    "getppid",
    "umask",
    # io_uring — used by libuv/node.js for async I/O (Linux 5.1+)
    "io_uring_setup",
    "io_uring_enter",
    # Thread scheduling — used by node.js/libuv
    "sched_getparam",
    "sched_getscheduler",
    # File advisory — used by pip and other package managers
    "fadvise64",
    # File sync — used by pip for atomic file writes
    "fsync",
}


def target_to_syscalls(target: RuleTarget) -> set[str]:
    """Map a ``RuleTarget`` to the set of Linux syscall names that realize it.

    Note: there is no argument filtering. A ``RuleTarget.FILE_WRITE`` rule
    blocks every syscall in ``FS_WRITE_SYSCALLS`` (including ``write``/``writev``/
    ``pwrite*``), so a deny on file writes also blocks writes to redirected
    stdout/stderr pipes the runner sets up. Path-scoped FS rules are a job
    for landlock (future backend), not seccomp.
    """
    mapping = {
        "file_read": FS_READ_SYSCALLS,
        "file_write": FS_WRITE_SYSCALLS,
        "file_exec": {"execve", "execveat"},
        "network_out": NETWORK_SYSCALLS,
        "network_in": NETWORK_SYSCALLS,
        "network_bind": {"bind", "listen", "accept", "accept4"},
        "process_spawn": PROCESS_SYSCALLS,
        "process_kill": {"kill", "tkill", "tgkill"},
        "dns_query": set(),
        "signal_send": {"kill", "tkill", "tgkill", "rt_sigqueueinfo", "pidfd_send_signal"},
        "syscall_generic": set(),
    }
    # RuleTarget is a str Enum, so dict key is the .value string.
    return mapping.get(target.value if hasattr(target, "value") else str(target), set())


def resolve_syscall(lib: ctypes.CDLL, name: str, cache: dict[str, int]) -> int:
    """Resolve a syscall name to its number on the running arch, with caching.

    Returns the syscall number (>= 0 on success) or -1 if libseccomp does
    not know the syscall on this arch. The cache is per-backend-instance
    so the backends keep their existing lifecycle.
    """
    if name not in cache:
        cache[name] = lib.seccomp_syscall_resolve_name(name.encode())
    return cache[name]


def setup_lib(lib: ctypes.CDLL) -> None:
    """Set up libseccomp function signatures for ctypes.

    Note: ``seccomp_rule_add`` is variadic in C:
    ``seccomp_rule_add(ctx, action, syscall, arg_count, ...)``. We always
    pass ``arg_count=0`` (no argument filtering), so no varargs are read.
    This works on the x86-64 SysV ABI but will silently break if arg
    filtering is ever added without switching to the proper variadic
    call interface (``lib.seccomp_rule_add(ctx, ..., 0)`` with arg
    structs passed as additional ctypes args). Do NOT add arg filtering
    without refactoring this call to pass variadic arguments correctly.
    """
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
    lib.seccomp_rule_add.restype = ctypes.c_int
    lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
    lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_load.restype = ctypes.c_int
    lib.seccomp_release.argtypes = [ctypes.c_void_p]


def add_rule_safely(
    lib: ctypes.CDLL,
    ctx: ctypes.c_void_p,
    action: int,
    syscall_num: int,
    syscall_name: str,
) -> bool:
    """Wrap ``seccomp_rule_add`` with return-value checking.

    libseccomp can return non-zero from ``seccomp_rule_add`` for several
    reasons. The two that matter here:

    - ``-EACCES`` (13): the rule's action equals the filter's default
      action. libseccomp refuses to add a redundant rule. This is
      expected and benign — for a KILL-default filter, the KILL rules
      we try to add are no-ops (the default already kills). We log at
      DEBUG and skip.

    - ``-EINVAL`` (22) or other: unknown syscall on this arch (shouldn't
      happen because ``resolve_syscall`` already returns -1 for those,
      but defensive) or some other libseccomp rejection. We log at
      WARNING and continue.

    Returns True if the rule was added, False if it was skipped due to
    EACCES. Other failures log and return True (we don't raise — a
    failed rule add for one syscall shouldn't fail the whole filter
    load; the KILL default will catch the syscall anyway).
    """
    ret = lib.seccomp_rule_add(ctx, action, syscall_num, 0)
    if ret == 0:
        return True
    if ret == -13:  # -EACCES
        logger.debug(
            "seccomp_rule_add skipped (action matches filter default): syscall=%s action=0x%x",
            syscall_name,
            action,
        )
        return False
    if ret == -22:  # -EINVAL
        logger.warning(
            "seccomp_rule_add rejected syscall=%s (EINVAL — likely unknown on this arch)",
            syscall_name,
        )
        return True
    logger.warning(
        "seccomp_rule_add failed for syscall=%s action=0x%x ret=%d",
        syscall_name,
        action,
        ret,
    )
    return True


__all__ = [
    "FS_READ_SYSCALLS",
    "FS_WRITE_SYSCALLS",
    "NETWORK_SYSCALLS",
    "PROCESS_SYSCALLS",
    "SAFE_SYSCALLS",
    "SCMP_ACT_ALLOW",
    "SCMP_ACT_ERRNO_EPERM",
    "SCMP_ACT_KILL_PROCESS",
    "SCMP_ACT_KILL_THREAD",
    "SCMP_ACT_LOG",
    "SCMP_ACT_TRAP",
    "add_rule_safely",
    "resolve_syscall",
    "setup_lib",
    "target_to_syscalls",
]
