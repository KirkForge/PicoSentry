
from __future__ import annotations

import ctypes
import logging
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from picosentry.sandbox.l3.models import RuleTarget

logger = logging.getLogger("picodome.l3.seccomp_common")


SCMP_ACT_KILL_PROCESS = 0x80000000
SCMP_ACT_KILL_THREAD = 0x00000000
SCMP_ACT_TRAP = 0x00030000
SCMP_ACT_ALLOW = 0x7FFF0000
SCMP_ACT_LOG = 0x7FFC0000  # used by the trace backend only


SCMP_ACT_ERRNO_EPERM = 0x00050001  # seccomp ACT_ERRNO with errno=EPERM (1)


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

    "wait4",
    "waitid",
    "waitpid",

    "kill",
    "setsid",
    "sigprocmask",
    "close_range",
}


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

    "wait4",
    "waitid",
    "waitpid",

    "close_range",

    "kill",
    "setsid",
    "sigprocmask",

    "statx",
    "getppid",
    "umask",

    "io_uring_setup",
    "io_uring_enter",

    "sched_getparam",
    "sched_getscheduler",

    "fadvise64",

    "fsync",
}


def target_to_syscalls(target: RuleTarget) -> set[str]:
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

    return mapping.get(target.value if hasattr(target, "value") else str(target), set())


def resolve_syscall(lib: ctypes.CDLL, name: str, cache: dict[str, int]) -> int:
    if name not in cache:
        cache[name] = lib.seccomp_syscall_resolve_name(name.encode())
    return cache[name]


def setup_lib(lib: ctypes.CDLL) -> None:
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
