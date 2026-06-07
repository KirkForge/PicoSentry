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

from picosentry.sandbox.l3.backends._seccomp_common import (
    FS_READ_SYSCALLS,
    FS_WRITE_SYSCALLS,
    NETWORK_SYSCALLS,
    PROCESS_SYSCALLS,
    SAFE_SYSCALLS,
    SCMP_ACT_ALLOW,
    SCMP_ACT_ERRNO_EPERM,
    SCMP_ACT_KILL_PROCESS,
    SCMP_ACT_KILL_THREAD,
    SCMP_ACT_TRAP,
    add_rule_safely,
    resolve_syscall,
    setup_lib,
    target_to_syscalls,
)
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

# Re-export the shared syscall sets and helpers so the backend's
# public namespace agrees with `_seccomp_common` (and tests can
# assert reference equality). The enforcement backend itself only
# uses SAFE_SYSCALLS and the SCMP_ACT_* constants, but the rest are
# part of the public surface for any caller that wants to inspect
# the policy model without reaching into _seccomp_common.
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
    "SCMP_ACT_TRAP",
    "SeccompBackend",
    "add_rule_safely",
    "resolve_syscall",
    "setup_lib",
    "target_to_syscalls",
]


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

            # Build the env dict in the parent BEFORE fork.
            # Any dict operations inside the child would run CPython allocators
            # (mmap/brk/futex) under the active seccomp filter, which under a
            # KILL default would SIGSYS the child before it ever execs. By
            # doing the .copy() + update() here, the child only needs to
            # call execve — no Python-side allocation under the filter.
            child_env = os.environ.copy()
            if env:
                child_env.update(env)
            env_list = child_env

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

                # No Python allocation after this point — env_list was built
                # in the parent. execve is a single syscall that reads the
                # already-merged dict.
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
        """Set up libseccomp function signatures. Delegates to the shared helper.

        See ``_seccomp_common.setup_lib`` for the variadic-args caveat
        (do NOT add arg filtering without refactoring the ctypes call).
        """
        setup_lib(lib)

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
                        add_rule_safely(lib, ctx, SCMP_ACT_ALLOW, num, name)
            elif rule.action in (SyscallAction.DENY, SyscallAction.KILL):
                syscalls = self._target_to_syscalls(rule.target)
                for name in syscalls:
                    num = self._resolve(lib, name)
                    if num >= 0:
                        add_rule_safely(lib, ctx, SCMP_ACT_KILL_PROCESS, num, name)
                        blocked.add(name)

        # Always allow essential syscalls for basic binary execution
        for name in SAFE_SYSCALLS:
            num = self._resolve(lib, name)
            if num >= 0:
                add_rule_safely(lib, ctx, SCMP_ACT_ALLOW, num, name)

        return ctx, blocked

    def _target_to_syscalls(self, target: RuleTarget) -> set[str]:
        """Map a RuleTarget to Linux syscall names. Delegates to the shared helper."""
        return target_to_syscalls(target)

    def _resolve(self, lib: ctypes.CDLL, name: str) -> int:
        """Resolve syscall name to number, with caching. Delegates to the shared helper."""
        return resolve_syscall(lib, name, self._syscall_cache)

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
