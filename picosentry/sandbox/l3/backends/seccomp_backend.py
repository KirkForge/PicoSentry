"""Seccomp-bpf sandbox backend (Linux only).

Uses libseccomp via ctypes for real kernel-level syscall filtering.
Provides deterministic allow/deny/kill enforcement via BPF.
"""

from __future__ import annotations

import ctypes
import logging
import os
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

logger = logging.getLogger("picodome.l3.seccomp")

# ─── libseccomp constants ───────────────────────────────────────────────────

SCMP_ACT_KILL_PROCESS = 0x80000000
SCMP_ACT_KILL_THREAD = 0x00000000
SCMP_ACT_TRAP = 0x00030000
SCMP_ACT_ALLOW = 0x7FFF0000

# errno(EPERM) action for non-fatal denials — returns EPERM instead of SIGSYS,
# so the calling process learns which syscall was denied instead of being killed silently.
SCMP_ACT_ERRNO_EPERM = 0x00050001  # seccomp ACT_ERRNO with errno=EPERM (1)

# ─── Syscall name → number mappings ─────────────────────────────────────────

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


class SeccompBackend(SandboxBackend):
    """Real seccomp-bpf backend using libseccomp via ctypes.

    Uses os.fork() + os.execve() directly to avoid subprocess.Popen's
    child-process setup syscalls conflicting with the seccomp filter.
    """

    def __init__(self):
        self._syscall_cache: dict[str, int] = {}

    @property
    def name(self) -> str:
        return "seccomp-bpf"

    @property
    def isolation_level(self) -> str:
        return "syscall_policy"

    @property
    def enforcement_guarantee(self) -> str:
        return "moderate"

    def is_available(self) -> bool:
        """Check if seccomp-bpf is available and both permissive and fail-closed
        filters can be created.

        Some containers allow SCMP_ACT_ALLOW (permissive) but reject
        SCMP_ACT_KILL_PROCESS (fail-closed), which means default-deny
        policies would fail silently. Verify both.
        """
        try:
            lib = ctypes.CDLL("libseccomp.so.2")
            lib.seccomp_init.argtypes = [ctypes.c_uint32]
            lib.seccomp_init.restype = ctypes.c_void_p
            lib.seccomp_release.argtypes = [ctypes.c_void_p]

            # Test permissive (ALLOW) filter
            ctx_allow = lib.seccomp_init(SCMP_ACT_ALLOW)
            if not ctx_allow:
                return False
            lib.seccomp_release(ctx_allow)

            # Test fail-closed (KILL_PROCESS) filter — this is what default-deny uses
            ctx_kill = lib.seccomp_init(SCMP_ACT_KILL_PROCESS)
            if not ctx_kill:
                return False
            lib.seccomp_release(ctx_kill)

            return True
        except Exception:
            return False

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

        try:
            lib = ctypes.CDLL("libseccomp.so.2")
            self._setup_lib(lib)

            # Build seccomp filter
            ctx, blocked = self._build_filter(lib, policy)
            if ctx is None:
                return self._fallback_run(command, policy, timeout, cwd, env)

            # Resolve full command path
            cmd_path = shutil.which(command[0])
            if cmd_path is None:
                cmd_path = command[0]  # Try as-is

            # Setup pipes for stdout/stderr capture
            out_r, out_w = os.pipe()
            err_r, err_w = os.pipe()

            # fork+exec is required for seccomp: the child must apply the BPF filter before exec.
            # Suppress the Python 3.12+ deprecation warning about fork in multi-threaded processes —
            # the seccomp backend is always called from a single-threaded scan context.
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                pid = os.fork()

            if pid == 0:
                # ── Child process ──
                os.close(out_r)
                os.close(err_r)

                # Redirect stdout/stderr
                os.dup2(out_w, 1)
                os.dup2(err_w, 2)
                os.close(out_w)
                os.close(err_w)

                # Change directory
                if cwd:
                    try:
                        os.chdir(cwd)
                    except OSError:
                        pass

                # Load seccomp filter
                ret = lib.seccomp_load(ctx)
                lib.seccomp_release(ctx)
                if ret != 0:
                    os._exit(127)  # seccomp filter failed — exit child immediately

                # Prepare env
                child_env = os.environ.copy()
                if env:
                    child_env.update(env)
                # Convert to dict for execve
                env_list = child_env

                # Exec
                try:
                    os.execve(cmd_path, command, env_list)
                except FileNotFoundError:
                    os._exit(127)
                except PermissionError:
                    os._exit(126)
                os._exit(1)

            else:
                # ── Parent process ──
                os.close(out_w)
                os.close(err_w)

                # Release seccomp context in parent
                lib.seccomp_release(ctx)

                # Wait with timeout
                stdout_bytes, stderr_bytes, exit_code = self._wait_with_timeout(pid, out_r, err_r, effective_timeout)

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

                # Check for seccomp kill (SIGSYS = 31)
                if exit_code == -31:
                    # Build a helpful diagnostic: which syscall categories were denied
                    denied_categories = []
                    if blocked:
                        denied_categories.append(f"blocked={', '.join(sorted(blocked)[:10])}")
                    if policy.default_action == SyscallAction.DENY or policy.default_action == SyscallAction.KILL:
                        denied_categories.append("default_action=DENY")
                    # Suggest remediation
                    suggestions = []
                    if "clone" in blocked or "clone3" in blocked or "fork" in blocked:
                        suggestions.append("Process spawning was denied. Use --allow-runtime node/python or add process_spawn: allow to your policy.")
                    if "wait4" in blocked or "waitid" in blocked:
                        suggestions.append("Child reaping was denied. If you allow process spawning, child reaping syscalls must also be allowed.")
                    if not suggestions:
                        suggestions.append("A syscall was blocked by the sandbox policy. Use --allow-runtime node/python for common package managers, or use a permissive policy with default_action=ALLOW.")

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

                # Post-hoc analysis on output
                events.extend(self._posthoc_analysis(stdout, stderr))

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
            logger.exception("Seccomp sandbox failed")
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

    def _setup_lib(self, lib: ctypes.CDLL):
        """Set up libseccomp function signatures.

        Note: seccomp_rule_add is variadic in C: seccomp_rule_add(ctx, action, syscall, arg_count, ...).
        We always pass arg_count=0 (no argument filtering), so no varargs are read.
        This works on x86-64 SysV ABI but will silently break if arg filtering is ever added
        without switching to the proper variadic call interface (lib.seccomp_rule_add(ctx, ..., 0)
        with arg structs passed as additional ctypes args). Do NOT add arg filtering without
        refactoring this call to pass variadic arguments correctly.
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

    def _build_filter(self, lib: ctypes.CDLL, policy: Policy) -> tuple:
        """Build seccomp BPF filter from policy. Returns (ctx, blocked_syscalls)."""
        blocked: set[str] = set()

        if policy.default_action == SyscallAction.DENY or policy.default_action == SyscallAction.KILL:
            default_action = SCMP_ACT_KILL_PROCESS
        else:
            default_action = SCMP_ACT_ALLOW

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
        """Map a RuleTarget to Linux syscall names."""
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
        """Resolve syscall name to number, with caching."""
        if name not in self._syscall_cache:
            self._syscall_cache[name] = lib.seccomp_syscall_resolve_name(name.encode())
        return self._syscall_cache[name]

    def _wait_with_timeout(self, pid: int, out_fd: int, err_fd: int, timeout: float) -> tuple:
        """Wait for child process with timeout, collecting stdout/stderr."""
        import select as _select

        stdout_chunks = []
        stderr_chunks = []
        deadline = time.monotonic() + timeout
        exit_code = None

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

            # Check if child exited
            wpid, status = os.waitpid(pid, os.WNOHANG)
            if wpid == pid:
                if os.WIFEXITED(status):
                    exit_code = os.WEXITSTATUS(status)
                elif os.WIFSIGNALED(status):
                    exit_code = -os.WTERMSIG(status)
                break

        # Collect remaining output
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

        # If still running after timeout, kill it
        if exit_code is None:
            try:
                os.kill(pid, signal.SIGKILL)
                os.waitpid(pid, 0)
            except OSError:
                pass
            exit_code = -1

        os.close(out_fd)
        os.close(err_fd)

        return b"".join(stdout_chunks), b"".join(stderr_chunks), exit_code

    def _posthoc_analysis(self, stdout: str, stderr: str) -> list[SandboxEvent]:
        """Post-hoc pattern analysis on captured output."""
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
        reason: str = "seccomp setup failed",
    ) -> SandboxResult:
        """Handle backend failure.

        If policy.fail_closed is True (default), return a KILL verdict
        instead of degrading to the unconfined subprocess backend.
        Only falls back to subprocess when fail_closed=False.
        """
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
                        detail=(f"Sandbox backend failed: {reason}. Fail-closed policy prevents unconfined execution."),
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
        # Mark as degraded — observational when kernel was expected
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
