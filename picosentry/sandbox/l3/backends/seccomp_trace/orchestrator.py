from __future__ import annotations

import ctypes
import logging
import os
import shutil
import warnings

from picosentry.sandbox.l3.backends.base import SandboxBackend
from picosentry.sandbox.l3.models import (
    Policy,
    SandboxEvent,
    SandboxResult,
    SyscallAction,
    Verdict,
)
from picosentry.sandbox.models import _now_ms

from . import event_parser, filter_builder, process_manager
from ._audit import _X86_64_SYSCALLS

logger = logging.getLogger("picodome.l3.seccomp_trace")


class SeccompTraceBackend(SandboxBackend):

    def __init__(self) -> None:
        self._syscall_cache: dict[str, int] = {}


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
        try:
            lib = ctypes.CDLL("libseccomp.so.2")
            lib.seccomp_init.argtypes = [ctypes.c_uint32]
            lib.seccomp_init.restype = ctypes.c_void_p
            lib.seccomp_release.argtypes = [ctypes.c_void_p]
        except Exception:
            return False

        from picosentry.sandbox.l3.backends._seccomp_common import (
            SCMP_ACT_ALLOW,
            SCMP_ACT_KILL_PROCESS,
        )


        try:
            ctx_allow = lib.seccomp_init(SCMP_ACT_ALLOW)
            if not ctx_allow:
                return False
            lib.seccomp_release(ctx_allow)
        except Exception:
            return False


        try:
            ctx_kill = lib.seccomp_init(SCMP_ACT_KILL_PROCESS)
            if not ctx_kill:
                return False
            lib.seccomp_release(ctx_kill)
        except Exception:
            return False


        return process_manager.probe_log_emits(lib)

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
            filter_builder.setup(lib)

            ctx, blocked = filter_builder.build_filter(lib, policy, self._syscall_cache)
            if ctx is None:
                return self._fallback_run(command, policy, timeout, cwd, env)

            cmd_path = shutil.which(command[0])
            if cmd_path is None:
                cmd_path = command[0]

            out_r, out_w = os.pipe()
            err_r, err_w = os.pipe()


            child_env = os.environ.copy()
            if env:
                child_env.update(env)

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
                    try:
                        os.chdir(cwd)
                    except OSError:
                        pass
                ret = lib.seccomp_load(ctx)
                lib.seccomp_release(ctx)
                if ret != 0:
                    os._exit(127)


                try:
                    os.execve(cmd_path, command, child_env)
                except FileNotFoundError:
                    os._exit(127)
                except PermissionError:
                    os._exit(126)
                os._exit(1)

            else:

                os.close(out_w)
                os.close(err_w)
                lib.seccomp_release(ctx)

                log_path = f"/proc/{pid}/seccomp"
                stdout_bytes, stderr_bytes, exit_code, log_text = process_manager.wait_with_timeout(
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


                if log_text:
                    trace_events = event_parser.parse_seccomp_log(
                        log_text, policy, start_ms, self._x86_64_nr_to_name
                    )
                    events.extend(trace_events)
                    logger.info(
                        "seccomp-trace: %d events captured, 0 paths/addresses "
                        "(v2.0.8 SCMP_ACT_LOG limitation)",
                        len(trace_events),
                    )
                else:
                    logger.info(
                        "seccomp-trace: /proc/%d/seccomp empty — "
                        "kernel may have CONFIG_SECCOMP_LOG=n; "
                        "degrading to post-hoc analysis only",
                        pid,
                    )


                events.extend(self._posthoc_analysis(stdout, stderr))


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
        overall = event_parser.compute_verdict(events, exit_code)

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


    def _posthoc_analysis(self, stdout: str, stderr: str) -> list[SandboxEvent]:
        from picosentry.sandbox.l3.backends.subprocess_backend import SubprocessBackend

        sb = SubprocessBackend()
        return sb._check_suspicious_patterns(stdout, stderr)


    def _build_filter(
        self, lib: ctypes.CDLL, policy: Policy
    ) -> tuple[ctypes.c_void_p | None, set[str]]:
        return filter_builder.build_filter(lib, policy, self._syscall_cache)

    def _classify_syscall(self, name: str) -> tuple[str, str]:
        return event_parser.classify_syscall(name)

    def _parse_seccomp_log(
        self,
        log_text: str,
        policy: Policy,
        start_ms: float,
        x86_64_nr_to_name: dict[int, str] | None = None,
    ) -> list[SandboxEvent]:
        if x86_64_nr_to_name is None:
            x86_64_nr_to_name = self._x86_64_nr_to_name
        return event_parser.parse_seccomp_log(
            log_text, policy, start_ms, x86_64_nr_to_name
        )

    def _wait_with_timeout(
        self, pid: int, out_fd: int, err_fd: int, timeout: float, log_path: str
    ) -> tuple[bytes, bytes, int, str]:
        return process_manager.wait_with_timeout(pid, out_fd, err_fd, timeout, log_path)

    def _read_proc_seccomp(self, log_path: str) -> str:
        return process_manager.read_proc_seccomp(log_path)

    def _probe_log_emits(self, lib: ctypes.CDLL) -> bool:
        return process_manager.probe_log_emits(lib)

    def _setup_lib(self, lib: ctypes.CDLL) -> None:
        filter_builder.setup(lib)

    def _resolve(self, lib: ctypes.CDLL, name: str) -> int:
        return filter_builder.resolve(lib, name, self._syscall_cache)

    def _target_to_syscalls(self, target) -> set[str]:
        from picosentry.sandbox.l3.backends._seccomp_common import target_to_syscalls

        return target_to_syscalls(target)

    def _compute_verdict(
        self, events: list[SandboxEvent], exit_code: int
    ) -> Verdict:
        return event_parser.compute_verdict(events, exit_code)

    def _fallback_run(
        self,
        command: list[str],
        policy: Policy,
        timeout: float | None,
        cwd: str | None,
        env: dict | None,
        reason: str = "seccomp trace setup failed",
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


__all__ = ["SeccompTraceBackend"]
