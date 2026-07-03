from __future__ import annotations

import contextlib
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
        try:
            lib = ctypes.CDLL("libseccomp.so.2")
            lib.seccomp_init.argtypes = [ctypes.c_uint32]
            lib.seccomp_init.restype = ctypes.c_void_p
            lib.seccomp_release.argtypes = [ctypes.c_void_p]

            ctx_allow = lib.seccomp_init(SCMP_ACT_ALLOW)
            if not ctx_allow:
                return False
            lib.seccomp_release(ctx_allow)

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

            ctx, blocked = self._build_filter(lib, policy)
            if ctx is None:
                return self._fallback_run(command, policy, timeout, cwd, env)

            cmd_path = shutil.which(command[0])
            if cmd_path is None:
                cmd_path = command[0]  # Try as-is

            out_r, out_w = os.pipe()
            err_r, err_w = os.pipe()

            child_env = os.environ.copy()
            if env:
                child_env.update(env)
            env_list = child_env

            with warnings.catch_warnings():
                warnings.simplefilter("ignore", DeprecationWarning)
                pid = os.fork()

            if pid == 0:
                os.close(out_r)
                os.close(err_r)

                os.dup2(out_w, 1)
                os.dup2(err_w, 2)
                os.close(out_w)
                os.close(err_w)

                if cwd:
                    with contextlib.suppress(OSError):
                        os.chdir(cwd)

                ret = lib.seccomp_load(ctx)
                lib.seccomp_release(ctx)
                if ret != 0:
                    os._exit(127)  # seccomp filter failed — exit child immediately

                try:
                    os.execve(cmd_path, command, env_list)
                except FileNotFoundError:
                    os._exit(127)
                except PermissionError:
                    os._exit(126)
                os._exit(1)

            else:
                os.close(out_w)
                os.close(err_w)

                lib.seccomp_release(ctx)

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

                if exit_code == -31:
                    denied_categories = []
                    if blocked:
                        denied_categories.append(f"blocked={', '.join(sorted(blocked)[:10])}")
                    if policy.default_action in (SyscallAction.DENY, SyscallAction.KILL):
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
                            "A syscall was blocked by the sandbox policy. "
                            "Use --allow-runtime node/python for common package managers, "
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
        setup_lib(lib)

    def _build_filter(self, lib: ctypes.CDLL, policy: Policy) -> tuple:
        blocked: set[str] = set()

        if policy.default_action in (SyscallAction.DENY, SyscallAction.KILL):
            default_action = SCMP_ACT_KILL_PROCESS
        else:
            default_action = SCMP_ACT_ALLOW

        ctx = lib.seccomp_init(default_action)
        if not ctx:
            logger.error("seccomp_init failed")
            return None, blocked

        # The backend loads the seccomp filter and then execve's the target
        # command, so execve/execveat must remain allowed regardless of policy.
        launch_syscalls: set[str] = {"execve", "execveat"}

        # Collect every syscall that the policy explicitly denies. We must not
        # blindly add these to the safe allowlist, or libseccomp would reject
        # the later DENY rule as redundant.
        explicitly_blocked: set[str] = set()
        for rule in policy.rules:
            if rule.action in (SyscallAction.DENY, SyscallAction.KILL):
                explicitly_blocked.update(self._target_to_syscalls(rule.target))

        # Never block the syscalls required to launch the child.
        explicitly_blocked -= launch_syscalls

        # Baseline safe allowlist, minus anything the policy wants to block.
        for name in SAFE_SYSCALLS - explicitly_blocked:
            num = self._resolve(lib, name)
            if num >= 0:
                add_rule_safely(lib, ctx, SCMP_ACT_ALLOW, num, name)

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
                    if name in launch_syscalls:
                        continue
                    num = self._resolve(lib, name)
                    if num >= 0:
                        added = add_rule_safely(lib, ctx, SCMP_ACT_KILL_PROCESS, num, name)
                        if added or default_action == SCMP_ACT_KILL_PROCESS:
                            blocked.add(name)

        return ctx, blocked

    def _target_to_syscalls(self, target: RuleTarget) -> set[str]:
        return target_to_syscalls(target)

    def _resolve(self, lib: ctypes.CDLL, name: str) -> int:
        return resolve_syscall(lib, name, self._syscall_cache)

    def _wait_with_timeout(self, pid: int, out_fd: int, err_fd: int, timeout: float) -> tuple:
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

            wpid, status = os.waitpid(pid, os.WNOHANG)
            if wpid == pid:
                if os.WIFEXITED(status):
                    exit_code = os.WEXITSTATUS(status)
                elif os.WIFSIGNALED(status):
                    exit_code = -os.WTERMSIG(status)
                break

        for fd in [out_fd, err_fd]:
            with contextlib.suppress(OSError):
                os.set_blocking(fd, False)
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

        return b"".join(stdout_chunks), b"".join(stderr_chunks), exit_code

    def _posthoc_analysis(self, stdout: str, stderr: str) -> list[SandboxEvent]:
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
