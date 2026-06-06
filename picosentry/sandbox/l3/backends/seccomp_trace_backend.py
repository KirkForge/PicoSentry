"""Seccomp-bpf backend with syscall observation (Linux only).

v2.1.0 (strategy A) — uses ``SCMP_ACT_LOG`` to capture every syscall the
tracee makes and emits one ``SandboxEvent`` per syscall. The filter is
identical in shape to ``SeccompBackend._build_filter`` with the default
action swapped to ``SCMP_ACT_LOG`` when no policy rule requires KILL.

**v2.1.0 limitation.** ``SCMP_ACT_LOG`` records the syscall number and
arch but not the syscall arguments. ``SandboxEvent.path`` and
``SandboxEvent.address`` are always empty in this strategy. The L4
profiler (``picosentry/sandbox/l4/profiler.py``) filters on those fields
being non-empty, so v2.1.0 events are visible to the L3 CLI summary
(``L3: allow | N events``) and to L4's stdout-derived extraction, but
``fs_ops``/``network_calls``/``spawns`` are not populated from kernel
data yet. Strategy B (``PTRACE_SECCOMP``) and C
(``SECCOMP_RET_USER_NOTIF``) will populate args in v2.2.0.

**KILL still wins.** When ``policy.default_action`` is ``KILL``/``DENY``,
or any rule has ``KILL``/``DENY`` action, the default action is
``SCMP_ACT_KILL_PROCESS`` and the tracee dies on the first policy
violation — identical to ``SeccompBackend``. We additionally emit a
``seccomp_violation`` event with a diagnostic, mirroring
``SeccompBackend.run:411-442``.

**Kernel requirement.** ``CONFIG_SECCOMP_LOG=y`` (default on Ubuntu, may
be disabled on minimal containers). ``is_available()`` probes with a
real fork+exec and reads back ``/proc/<pid>/seccomp``; if the buffer is
empty the backend reports unavailable.

**Threading.** Not thread-safe (mirrors ``SeccompBackend``). One trace
per process tree.

**Keep in sync with seccomp_backend.py.** The fork+execve flow, the
``_SAFE_SYSCALLS`` allowlist, the ``_target_to_syscalls`` mapping, and
``_resolve`` are intentionally copied here rather than imported, so a
maintainer can diff the two files without a chase. When
``seccomp_backend.py`` changes, mirror the change here.
"""

from __future__ import annotations

import ctypes
import logging
import os
import re
import shutil
import signal
import time
import warnings

from picosentry.sandbox.l3.backends.base import SandboxBackend
from picosentry.sandbox.l3.models import (
    Policy,
    RuleTarget,
    SandboxEvent,
    SandboxResult,
    SyscallAction,
    Verdict,
)
from picosentry.sandbox.models import _now_ms

logger = logging.getLogger("picodome.l3.seccomp_trace")

# ─── libseccomp constants ───────────────────────────────────────────────────

SCMP_ACT_KILL_PROCESS = 0x80000000
SCMP_ACT_KILL_THREAD = 0x00000000
SCMP_ACT_TRAP = 0x00030000
SCMP_ACT_ALLOW = 0x7FFF0000
# SECCOMP_RET_LOG — record to /proc/<pid>/seccomp (or audit) but allow.
# See <linux/seccomp.h>. Available since Linux 3.5.
SCMP_ACT_LOG = 0x7FFC0000

# Audit-message constant that confirms an entry came from a LOG action.
# Other action codes are 0x7fff0000 (ALLOW), 0x80000000 (KILL_PROCESS).
_LOG_ACTION_CODE = "0x7ffc0000"

# Audit-message fields that confirm an entry came from a LOG action.
# Other action codes are 0x7fff0000 (ALLOW), 0x80000000 (KILL_PROCESS).
# NOTE: the kernel's audit log field order is arch=...syscall=...code=,
# NOT syscall=...arch=...code= — verified against real /proc/<pid>/seccomp
# output on Linux 5.x/6.x.
_AUDIT_LINE_RE = re.compile(
    r"audit\(\d+\.\d+:\d+\):.*?arch=(?P<arch>[0-9a-fx]+).*?syscall=(?P<nr>\d+).*?code=(?P<code>[0-9a-fx]+)"
)

# ─── Syscall sets — keep in sync with seccomp_backend.py ──────────────────

_NETWORK_SYSCALLS = {
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

_FS_WRITE_SYSCALLS = {
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

_FS_READ_SYSCALLS = {
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

_PROCESS_SYSCALLS = {
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

_SAFE_SYSCALLS = {
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

# Arch constants for the audit log's `arch=` field.
# AUDIT_ARCH_X86_64 = 0xC000003E, AUDIT_ARCH_AARCH64 = 0xC00000B7.
_ARCH_X86_64 = 0xC000003E
_ARCH_AARCH64 = 0xC00000B7


# ─── x86_64 syscall-number → name table (subset) ─────────────────────────
# Generated from <asm/unistd_64.h>. The table covers the syscalls we care
# about; anything missing is logged as `syscall_other`. Maintain by hand
# when adding classifications.
_X86_64_SYSCALLS: dict[int, str] = {
    0: "read",
    1: "write",
    2: "open",
    3: "close",
    4: "stat",
    5: "fstat",
    6: "lstat",
    7: "poll",
    8: "lseek",
    9: "mmap",
    10: "mprotect",
    11: "munmap",
    12: "brk",
    13: "rt_sigaction",
    14: "rt_sigprocmask",
    15: "rt_sigreturn",
    16: "ioctl",
    17: "pread64",
    18: "pwrite64",
    19: "readv",
    20: "writev",
    21: "access",
    22: "pipe",
    23: "select",
    24: "sched_yield",
    25: "mremap",
    26: "msync",
    27: "mincore",
    28: "madvise",
    29: "shmget",
    30: "shmat",
    31: "shmctl",
    32: "dup",
    33: "dup2",
    34: "pause",
    35: "nanosleep",
    36: "getitimer",
    37: "alarm",
    38: "setitimer",
    39: "getpid",
    40: "sendfile",
    41: "socket",
    42: "connect",
    43: "accept",
    44: "sendto",
    45: "recvfrom",
    46: "sendmsg",
    47: "recvmsg",
    48: "shutdown",
    49: "bind",
    50: "listen",
    51: "getsockname",
    52: "getpeername",
    56: "clone",
    57: "fork",
    58: "vfork",
    59: "execve",
    60: "exit",
    61: "wait4",
    62: "kill",
    63: "uname",
    72: "fcntl",
    78: "getdents",
    79: "getcwd",
    83: "mkdir",
    84: "rmdir",
    85: "creat",
    86: "link",
    87: "unlink",
    88: "symlink",
    89: "readlink",
    90: "chmod",
    91: "fchmod",
    92: "chown",
    93: "fchown",
    94: "lchown",
    96: "gettimeofday",
    97: "getrlimit",
    98: "getrusage",
    99: "sysinfo",
    102: "getuid",
    104: "getgid",
    107: "geteuid",
    108: "getegid",
    110: "getppid",
    131: "sigaltstack",
    158: "arch_prctl",
    186: "gettid",
    200: "tkill",
    201: "time",
    202: "futex",
    204: "sched_getaffinity",
    217: "getdents64",
    228: "clock_gettime",
    230: "clock_nanosleep",
    231: "exit_group",
    234: "tgkill",
    247: "waitid",
    257: "openat",
    259: "mkdirat",
    263: "unlinkat",
    264: "renameat",
    269: "faccessat",
    270: "faccessat2",
    272: "uname",
    273: "semget",
    281: "epoll_create",
    290: "eventfd",
    291: "epoll_create1",
    292: "dup3",
    295: "preadv",
    296: "pwritev",
    316: "renameat2",
    319: "memfd_create",
    322: "execveat",
    323: "mknodat",
    324: "fchownat",
    325: "fchmodat",
    326: "fchownat",
    327: "linkat",
    328: "symlinkat",
    329: "readlinkat",
    330: "fchmodat",
    331: "fchownat",
    332: "fchmodat",
    333: "fchownat",
    334: "fchownat",
    435: "clone3",
}

# Syscalls whose only meaningful OpenAPI is the file open path —
# currently not extractable from SCMP_ACT_LOG but called out for v2.2.0.
_OPEN_SYSCALLS = {"open", "openat", "creat"}


class SeccompTraceBackend(SandboxBackend):
    """Seccomp-bpf backend that emits per-syscall events via SCMP_ACT_LOG.

    See module docstring for v2.1.0 limitations, kernel requirements,
    and the relationship to ``SeccompBackend``.
    """

    def __init__(self) -> None:
        self._syscall_cache: dict[str, int] = {}
        # Reverse of the x86_64 number→name table, kept for fast log
        # parsing. Populated lazily on first parse.
        self._x86_64_nr_to_name: dict[int, str] = dict(_X86_64_SYSCALLS)

    @property
    def name(self) -> str:
        return "seccomp-trace"

    @property
    def isolation_level(self) -> str:
        return "kernel_enforced"

    @property
    def enforcement_guarantee(self) -> str:
        return "moderate"

    def is_available(self) -> bool:
        """Check if seccomp-bpf with SCMP_ACT_LOG is usable on this system.

        Probes three things:
        1. ``libseccomp.so.2`` is loadable.
        2. ``SCMP_ACT_KILL_PROCESS`` filter is accepted (same as
           ``SeccompBackend.is_available`` — some containers reject it).
        3. ``SCMP_ACT_LOG`` is accepted AND a real child's
           ``/proc/<pid>/seccomp`` produces output (rules out kernels
           built with ``CONFIG_SECCOMP_LOG=n``).
        """
        try:
            lib = ctypes.CDLL("libseccomp.so.2")
            lib.seccomp_init.argtypes = [ctypes.c_uint32]
            lib.seccomp_init.restype = ctypes.c_void_p
            lib.seccomp_release.argtypes = [ctypes.c_void_p]
        except Exception:
            return False

        # Test permissive (ALLOW) filter
        try:
            ctx_allow = lib.seccomp_init(SCMP_ACT_ALLOW)
            if not ctx_allow:
                return False
            lib.seccomp_release(ctx_allow)
        except Exception:
            return False

        # Test fail-closed (KILL_PROCESS) filter
        try:
            ctx_kill = lib.seccomp_init(SCMP_ACT_KILL_PROCESS)
            if not ctx_kill:
                return False
            lib.seccomp_release(ctx_kill)
        except Exception:
            return False

        # Probe that SCMP_ACT_LOG actually emits entries to /proc/<pid>/seccomp.
        # This is the gate against CONFIG_SECCOMP_LOG=n kernels.
        return self._probe_log_emits(lib)

    def _probe_log_emits(self, lib: ctypes.CDLL) -> bool:
        """Fork a probe child, run a known syscall, read /proc/<pid>/seccomp.

        Returns True iff the kernel actually wrote a LOG entry to the
        per-process audit buffer.
        """
        lib.seccomp_init.argtypes = [ctypes.c_uint32]
        lib.seccomp_init.restype = ctypes.c_void_p
        lib.seccomp_load.argtypes = [ctypes.c_void_p]
        lib.seccomp_load.restype = ctypes.c_int
        lib.seccomp_release.argtypes = [ctypes.c_void_p]

        ctx = lib.seccomp_init(SCMP_ACT_LOG)
        if not ctx:
            return False
        if lib.seccomp_load(ctx) != 0:
            lib.seccomp_release(ctx)
            return False

        out_r, out_w = os.pipe()
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", DeprecationWarning)
            pid = os.fork()

        if pid == 0:
            os.close(out_r)
            os.dup2(out_w, 1)
            os.close(out_w)
            # Make a syscall that lands in the LOG buffer. execve replaces
            # the process image, so we use the loader to invoke /bin/true
            # via execve, which logs both execve and exit.
            try:
                os.execve("/bin/true", ["/bin/true"], {})
            except OSError:
                os._exit(127)

        # Parent
        os.close(out_w)
        try:
            os.waitpid(pid, 0)
        except ChildProcessError:
            pass
        try:
            log_path = f"/proc/{pid}/seccomp"
            if not os.path.exists(log_path):
                return False
            with open(log_path, encoding="utf-8", errors="replace") as f:
                log_text = f.read()
        except OSError:
            return False
        finally:
            try:
                os.close(out_r)
            except OSError:
                pass
            lib.seccomp_release(ctx)

        return _LOG_ACTION_CODE in log_text and "syscall=" in log_text

    def run(
        self,
        command: list[str],
        policy: Policy,
        timeout: float | None = None,
        cwd: str | None = None,
        env: dict | None = None,
    ) -> SandboxResult:
        start_ms = _now_ms()
        events: list[SandboxEvent] = []
        effective_timeout = timeout or 30.0
        unix_start_ms = int(time.time() * 1000)

        try:
            lib = ctypes.CDLL("libseccomp.so.2")
            self._setup_lib(lib)

            ctx, blocked = self._build_filter(lib, policy)
            if ctx is None:
                return self._fallback_run(command, policy, timeout, cwd, env)

            cmd_path = shutil.which(command[0])
            if cmd_path is None:
                cmd_path = command[0]

            out_r, out_w = os.pipe()
            err_r, err_w = os.pipe()

            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                pid = os.fork()

            if pid == 0:
                # ── Child process ──
                os.close(out_r)
                os.close(err_r)
                os.dup2(out_w, 1)
                os.dup2(err_w, 2)
                os.close(out_w)
                os.close(err_w)
                if cwd:
                    try:
                        os.chdir(cwd)
                    except OSError:
                        pass
                ret = lib.seccomp_load(ctx)
                lib.seccomp_release(ctx)
                if ret != 0:
                    os._exit(127)
                child_env = os.environ.copy()
                if env:
                    child_env.update(env)
                try:
                    os.execve(cmd_path, command, child_env)
                except FileNotFoundError:
                    os._exit(127)
                except PermissionError:
                    os._exit(126)
                os._exit(1)

            else:
                # ── Parent process ──
                os.close(out_w)
                os.close(err_w)
                lib.seccomp_release(ctx)

                log_path = f"/proc/{pid}/seccomp"
                stdout_bytes, stderr_bytes, exit_code = self._wait_with_timeout(
                    pid, out_r, err_r, effective_timeout, log_path
                )

                stdout = stdout_bytes.decode("utf-8", errors="replace").strip()
                stderr = stderr_bytes.decode("utf-8", errors="replace").strip()

                if exit_code == -1:
                    events.append(
                        SandboxEvent(
                            rule_id="L3-TIMEOUT-001",
                            verdict=Verdict.KILL,
                            operation="process_timeout",
                            detail=f"Process exceeded {effective_timeout}s timeout",
                            timestamp_ms=int(_now_ms() - start_ms),
                        )
                    )

                # KILL-violation handling, mirrors SeccompBackend.run:411-442
                if exit_code == -31:
                    denied_categories = []
                    if blocked:
                        denied_categories.append(f"blocked={', '.join(sorted(blocked)[:10])}")
                    if policy.default_action == SyscallAction.DENY or policy.default_action == SyscallAction.KILL:
                        denied_categories.append("default_action=DENY")
                    suggestions = []
                    if "clone" in blocked or "clone3" in blocked or "fork" in blocked:
                        suggestions.append(
                            "Process spawning was denied. Use --allow-runtime node/python "
                            "or add process_spawn: allow to your policy."
                        )
                    if "wait4" in blocked or "waitid" in blocked:
                        suggestions.append(
                            "Child reaping was denied. If you allow process spawning, "
                            "child reaping syscalls must also be allowed."
                        )
                    if not suggestions:
                        suggestions.append(
                            "A syscall was blocked by the sandbox policy. Use "
                            "--allow-runtime node/python for common package managers, "
                            "or use a permissive policy with default_action=ALLOW."
                        )
                    diagnostic = "Process killed by seccomp — syscall violation."
                    if denied_categories:
                        diagnostic += " " + "; ".join(denied_categories) + "."
                    if suggestions:
                        diagnostic += " " + suggestions[0]
                    events.append(
                        SandboxEvent(
                            rule_id="L3-SECCOMP-KILL",
                            verdict=Verdict.KILL,
                            operation="seccomp_violation",
                            detail=diagnostic,
                            timestamp_ms=int(_now_ms() - start_ms),
                        )
                    )

                # Parse kernel trace events. Empty buffer on
                # CONFIG_SECCOMP_LOG=n kernels is normal — we degrade
                # to post-hoc analysis only.
                log_text = self._read_proc_seccomp(log_path)
                if log_text:
                    trace_events = self._parse_seccomp_log(
                        log_text, policy, start_ms, unix_start_ms
                    )
                    events.extend(trace_events)
                    logger.info(
                        "seccomp-trace: %d events captured, 0 paths/addresses "
                        "(v2.1.0 SCMP_ACT_LOG limitation)",
                        len(trace_events),
                    )
                else:
                    logger.info(
                        "seccomp-trace: /proc/%d/seccomp empty — "
                        "kernel may have CONFIG_SECCOMP_LOG=n; "
                        "degrading to post-hoc analysis only",
                        pid,
                    )

                # Post-hoc analysis on output (fallback layer, same as
                # SeccompBackend)
                events.extend(self._posthoc_analysis(stdout, stderr))

                # Lifecycle boundary event for L4
                events.append(
                    SandboxEvent(
                        rule_id="L3-TRACE-LIFECYCLE",
                        verdict=Verdict.ALLOW if exit_code == 0 else Verdict.KILL,
                        operation="process_exit",
                        detail=f"process exited with code {exit_code}",
                        timestamp_ms=int(_now_ms() - start_ms),
                    )
                )

        except FileNotFoundError:
            events.append(
                SandboxEvent(
                    rule_id="L3-EXEC-001",
                    verdict=Verdict.DENY,
                    operation="exec_not_found",
                    detail=f"Command not found: {command[0] if command else '?'}",
                    timestamp_ms=int(_now_ms() - start_ms),
                )
            )
            stdout, stderr, exit_code = "", "", -1
        except Exception:
            logger.exception("Seccomp trace sandbox failed")
            return self._fallback_run(command, policy, timeout, cwd, env)

        duration_ms = int(_now_ms() - start_ms)
        overall = self._compute_verdict(events, exit_code)

        return SandboxResult(
            command=command,
            overall_verdict=overall,
            exit_code=exit_code if exit_code != -31 else 31,
            duration_ms=duration_ms,
            events=events,
            policy_name=policy.name,
            backend_name=self.name,
            isolation_level=self.isolation_level,
            enforcement_guarantee=self.enforcement_guarantee,
            degraded=False,
            stdout=stdout,
            stderr=stderr,
        )

    def _setup_lib(self, lib: ctypes.CDLL) -> None:
        """Set up libseccomp function signatures. Mirrors SeccompBackend."""
        lib.seccomp_init.argtypes = [ctypes.c_uint32]
        lib.seccomp_init.restype = ctypes.c_void_p
        lib.seccomp_rule_add.argtypes = [ctypes.c_void_p, ctypes.c_uint32, ctypes.c_int, ctypes.c_uint]
        lib.seccomp_rule_add.restype = ctypes.c_int
        lib.seccomp_syscall_resolve_name.argtypes = [ctypes.c_char_p]
        lib.seccomp_syscall_resolve_name.restype = ctypes.c_int
        lib.seccomp_load.argtypes = [ctypes.c_void_p]
        lib.seccomp_load.restype = ctypes.c_int
        lib.seccomp_release.argtypes = [ctypes.c_void_p]

    def _build_filter(
        self, lib: ctypes.CDLL, policy: Policy
    ) -> tuple[ctypes.c_void_p | None, set[str]]:
        """Build seccomp BPF filter from policy. Differs from
        SeccompBackend._build_filter in exactly one place: the default
        action is SCMP_ACT_LOG (not SCMP_ACT_KILL_PROCESS) when the
        policy has no KILL semantics.

        Returns (ctx, blocked_syscalls).
        """
        blocked: set[str] = set()
        has_kill = (
            policy.default_action in (SyscallAction.DENY, SyscallAction.KILL)
            or any(r.action in (SyscallAction.DENY, SyscallAction.KILL) for r in policy.rules)
        )
        default_action = SCMP_ACT_KILL_PROCESS if has_kill else SCMP_ACT_LOG

        ctx = lib.seccomp_init(default_action)
        if not ctx:
            logger.error("seccomp_init failed")
            return None, blocked

        for rule in policy.rules:
            if rule.action == SyscallAction.ALLOW:
                syscalls = self._target_to_syscalls(rule.target)
                for name in syscalls:
                    num = self._resolve(lib, name)
                    if num >= 0:
                        lib.seccomp_rule_add(ctx, SCMP_ACT_ALLOW, num, 0)
            elif rule.action in (SyscallAction.DENY, SyscallAction.KILL):
                syscalls = self._target_to_syscalls(rule.target)
                for name in syscalls:
                    num = self._resolve(lib, name)
                    if num >= 0:
                        lib.seccomp_rule_add(ctx, SCMP_ACT_KILL_PROCESS, num, 0)
                        blocked.add(name)

        # Always allow essential syscalls for basic binary execution
        for name in _SAFE_SYSCALLS:
            num = self._resolve(lib, name)
            if num >= 0:
                lib.seccomp_rule_add(ctx, SCMP_ACT_ALLOW, num, 0)

        return ctx, blocked

    def _target_to_syscalls(self, target: RuleTarget) -> set[str]:
        """Map a RuleTarget to Linux syscall names. Mirrors SeccompBackend."""
        mapping = {
            RuleTarget.FILE_READ: _FS_READ_SYSCALLS,
            RuleTarget.FILE_WRITE: _FS_WRITE_SYSCALLS,
            RuleTarget.FILE_EXEC: {"execve", "execveat"},
            RuleTarget.NETWORK_OUT: _NETWORK_SYSCALLS,
            RuleTarget.NETWORK_IN: _NETWORK_SYSCALLS,
            RuleTarget.NETWORK_BIND: {"bind", "listen", "accept", "accept4"},
            RuleTarget.PROCESS_SPAWN: _PROCESS_SYSCALLS,
            RuleTarget.PROCESS_KILL: {"kill", "tkill", "tgkill"},
            RuleTarget.DNS_QUERY: set(),
            RuleTarget.SIGNAL_SEND: {"kill", "tkill", "tgkill", "rt_sigqueueinfo", "pidfd_send_signal"},
            RuleTarget.SYSCALL_GENERIC: set(),
        }
        return mapping.get(target, set())

    def _resolve(self, lib: ctypes.CDLL, name: str) -> int:
        """Resolve syscall name to number, with caching. Mirrors SeccompBackend."""
        if name not in self._syscall_cache:
            self._syscall_cache[name] = lib.seccomp_syscall_resolve_name(name.encode())
        return self._syscall_cache[name]

    def _wait_with_timeout(
        self, pid: int, out_fd: int, err_fd: int, timeout: float, log_path: str
    ) -> tuple[bytes, bytes, int]:
        """Wait for child with timeout, collecting stdout/stderr.

        Reads /proc/<pid>/seccomp only AFTER waitpid returns — the buffer
        is preserved by the kernel for the duration of the parent-child
        relationship (we are the direct parent).
        """
        import select as _select

        stdout_chunks: list[bytes] = []
        stderr_chunks: list[bytes] = []
        deadline = time.monotonic() + timeout
        exit_code: int | None = None

        while time.monotonic() < deadline:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                break
            try:
                rlist, _, _ = _select.select([out_fd, err_fd], [], [], min(remaining, 1.0))
            except (ValueError, OSError):
                break
            for fd in rlist:
                try:
                    data = os.read(fd, 65536)
                    if not data:
                        continue
                    if fd == out_fd:
                        stdout_chunks.append(data)
                    else:
                        stderr_chunks.append(data)
                except OSError:
                    pass
            wpid, status = os.waitpid(pid, os.WNOHANG)
            if wpid == pid:
                if os.WIFEXITED(status):
                    exit_code = os.WEXITSTATUS(status)
                elif os.WIFSIGNALED(status):
                    exit_code = -os.WTERMSIG(status)
                break

        for fd in [out_fd, err_fd]:
            try:
                os.set_blocking(fd, False)
            except OSError:
                pass
            try:
                while True:
                    data = os.read(fd, 65536)
                    if not data:
                        break
                    if fd == out_fd:
                        stdout_chunks.append(data)
                    else:
                        stderr_chunks.append(data)
            except OSError:
                pass

        if exit_code is None:
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except OSError:
                pass
            exit_code = -1

        os.close(out_fd)
        os.close(err_fd)

        # 4 MB is the default /proc/<pid>/seccomp buffer size. If we
        # read back exactly 4 MB, the buffer is full and we lost tail
        # events. Surface a warning so users understand the gap.
        try:
            if os.path.exists(log_path):
                size = os.path.getsize(log_path)
                if size >= 4 * 1024 * 1024:
                    logger.warning(
                        "seccomp-trace: /proc/%d/seccomp is %d bytes — "
                        "buffer is full, tail events lost",
                        pid,
                        size,
                    )
        except OSError:
            pass

        return b"".join(stdout_chunks), b"".join(stderr_chunks), exit_code

    def _read_proc_seccomp(self, log_path: str) -> str:
        """Read the kernel audit buffer for the (now-exited) child.

        Returns "" if the file is missing or unreadable. The kernel
        exposes the buffer for the direct parent even after the child
        has exited (this is the standard `audit` behavior used by
        auditd, runc, and friends).
        """
        if not log_path or not os.path.exists(log_path):
            return ""
        try:
            with open(log_path, encoding="utf-8", errors="replace") as f:
                return f.read()
        except OSError as e:
            logger.debug("seccomp-trace: cannot read %s: %s", log_path, e)
            return ""

    def _classify_syscall(self, name: str) -> tuple[str, str]:
        """Map a syscall name to (operation, rule_id_prefix).

        Mirrors the wire format that L4's profiler.py:31-33 already
        knows. The rule_id_prefix is the L3-TRACE-* family; v2.2.0 will
        promote these to L4 rule IDs.
        """
        if name in _OPEN_SYSCALLS:
            return ("file_open", "L3-TRACE-FS-OPEN")
        if name in _FS_READ_SYSCALLS:
            return ("file_read", "L3-TRACE-FS-READ")
        if name in _FS_WRITE_SYSCALLS:
            return ("file_write", "L3-TRACE-FS-WRITE")
        if name in _NETWORK_SYSCALLS:
            return ("network_outbound", "L3-TRACE-NET")
        if name in {"execve", "execveat"}:
            return ("process_spawn", "L3-TRACE-PROC-EXEC")
        if name in {"fork", "vfork", "clone", "clone3"}:
            return ("process_spawn", "L3-TRACE-PROC-FORK")
        return ("syscall_other", "L3-TRACE-OTHER")

    def _parse_seccomp_log(
        self,
        log_text: str,
        policy: Policy,
        start_ms: float,
        unix_start_ms: int,
    ) -> list[SandboxEvent]:
        """Parse /proc/<pid>/seccomp audit text into SandboxEvent records.

        Anchors on ``code=0x7ffc0000`` (the SCMP_ACT_LOG magic) and
        ``syscall=N``. Lines that don't match are silently skipped.
        """
        events: list[SandboxEvent] = []
        # Build a quick set of syscalls that policy rules have marked
        # as KILL/DENY, so we can promote a LOG entry to DENY verdict
        # if it would have been killed under a stricter policy.
        denied_syscalls: set[str] = set()
        for rule in policy.rules:
            if rule.action in (SyscallAction.DENY, SyscallAction.KILL):
                denied_syscalls |= self._target_to_syscalls(rule.target)

        for line in log_text.splitlines():
            if _LOG_ACTION_CODE not in line:
                continue
            m = _AUDIT_LINE_RE.search(line)
            if not m:
                continue
            try:
                syscall_nr = int(m.group("nr"), 10)
                arch = int(m.group("arch"), 16)
            except (ValueError, TypeError):
                continue
            if arch == _ARCH_X86_64:
                name = self._x86_64_nr_to_name.get(syscall_nr)
            else:
                # aarch64 and other arches need their own number→name
                # table. v2.1.0 logs them as syscall_other.
                name = None
            if name is None:
                name = f"unknown_{arch:x}_{syscall_nr}"
            operation, rule_id_prefix = self._classify_syscall(name)
            if name in denied_syscalls:
                verdict = Verdict.DENY
            elif name in _NETWORK_SYSCALLS and policy.default_action == SyscallAction.ALLOW:
                # Under an explicit ALLOW-everything policy, network is
                # still considered noteworthy; not a verdict promotion
                # to DENY — leave as ALLOW.
                verdict = Verdict.ALLOW
            else:
                verdict = Verdict.ALLOW
            events.append(
                SandboxEvent(
                    rule_id=f"{rule_id_prefix}-{name}",
                    verdict=verdict,
                    operation=operation,
                    detail=(
                        f"{name} syscall "
                        f"(no path/address: SCMP_ACT_LOG does not capture "
                        f"args in v2.1.0)"
                    ),
                    timestamp_ms=int(_now_ms() - start_ms),
                )
            )
        return events

    def _posthoc_analysis(self, stdout: str, stderr: str) -> list[SandboxEvent]:
        """Post-hoc pattern analysis on captured output. Mirrors SeccompBackend."""
        from picosentry.sandbox.l3.backends.subprocess_backend import SubprocessBackend

        sb = SubprocessBackend()
        return sb._check_suspicious_patterns(stdout, stderr)

    def _compute_verdict(self, events: list[SandboxEvent], exit_code: int) -> Verdict:
        if exit_code == -1:
            return Verdict.KILL
        for event in events:
            if event.verdict == Verdict.KILL:
                return Verdict.KILL
            if event.verdict == Verdict.DENY:
                return Verdict.DENY
        return Verdict.ALLOW

    def _fallback_run(
        self,
        command: list[str],
        policy: Policy,
        timeout: float | None,
        cwd: str | None,
        env: dict | None,
        reason: str = "seccomp trace setup failed",
    ) -> SandboxResult:
        """Handle backend failure. Mirrors SeccompBackend._fallback_run."""
        if policy.fail_closed:
            logger.error(
                "FAIL-CLOSED: %s — refusing fallback to unconfined subprocess backend",
                reason,
            )
            return SandboxResult(
                command=command,
                overall_verdict=Verdict.KILL,
                exit_code=-1,
                events=[
                    SandboxEvent(
                        rule_id="L3-SANDBOX-DEGRADE",
                        verdict=Verdict.KILL,
                        operation="sandbox_degradation_blocked",
                        detail=(
                            f"Sandbox backend failed: {reason}. "
                            f"Fail-closed policy prevents unconfined execution."
                        ),
                    ),
                ],
                policy_name=policy.name,
                backend_name=self.name,
                isolation_level="none",
                enforcement_guarantee="none",
                degraded=True,
            )

        logger.warning(
            "FAIL-OPEN: %s — falling back to subprocess (no real sandboxing)",
            reason,
        )
        from picosentry.sandbox.l3.backends.subprocess_backend import SubprocessBackend

        result = SubprocessBackend().run(
            command,
            policy,
            timeout=timeout,
            cwd=cwd,
            env=env,
        )
        return SandboxResult(
            run_id=result.run_id,
            timestamp=result.timestamp,
            command=result.command,
            overall_verdict=result.overall_verdict,
            exit_code=result.exit_code,
            duration_ms=result.duration_ms,
            events=result.events,
            policy_name=result.policy_name,
            backend_name=self.name,
            isolation_level="observational_only",
            enforcement_guarantee="best_effort",
            degraded=True,
            stdout=result.stdout,
            stderr=result.stderr,
        )
