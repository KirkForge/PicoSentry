
from __future__ import annotations

import logging
import os
import platform
import subprocess
import tempfile

from picosentry.sandbox.l3.backends.base import SandboxBackend
from picosentry.sandbox.l3.models import (
    Policy,
    PolicyRule,
    RuleTarget,
    SandboxEvent,
    SandboxResult,
    SyscallAction,
    Verdict,
)
from picosentry.sandbox.models import _now_ms

logger = logging.getLogger("picodome.l3.seatbelt")


def _escape_seatbelt_path(path: str) -> str:
    path = path.replace(chr(92), chr(92) + chr(92))  # backslash -> double-backslash
    return path.replace(chr(34), chr(92) + chr(34))  # double-quote -> escaped double-quote


class SeatbeltBackend(SandboxBackend):

    @property
    def name(self) -> str:
        return "seatbelt"

    @property
    def isolation_level(self) -> str:
        return "os_policy_enforced"

    @property
    def enforcement_guarantee(self) -> str:
        return "hard"

    def is_available(self) -> bool:
        if platform.system() != "Darwin":
            return False
        try:
            subprocess.run(
                ["sandbox-exec", "-h"],
                capture_output=True,
                timeout=2,
            )
            return True
        except (FileNotFoundError, subprocess.TimeoutExpired):
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

        if not self.is_available():
            return self._fallback_run(command, policy, timeout, cwd, env)

        try:

            profile = self._generate_profile(policy, command, cwd)

            with tempfile.NamedTemporaryFile(mode="w", suffix=".sb", delete=False, prefix="picodome_") as f:
                f.write(profile)
                profile_path = f.name

            try:

                sandbox_cmd = ["sandbox-exec", "-f", profile_path, "--", *command]

                run_env = os.environ.copy()
                if env:
                    run_env.update(env)

                proc = subprocess.Popen(
                    sandbox_cmd,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    cwd=cwd,
                    env=run_env,
                )

                try:
                    stdout_bytes, stderr_bytes = proc.communicate(timeout=effective_timeout)
                    exit_code = proc.returncode
                    stdout = stdout_bytes.decode("utf-8", errors="replace").strip()
                    stderr = stderr_bytes.decode("utf-8", errors="replace").strip()
                except subprocess.TimeoutExpired:
                    proc.kill()
                    stdout_bytes, stderr_bytes = proc.communicate()
                    stdout = stdout_bytes.decode("utf-8", errors="replace").strip()
                    stderr = stderr_bytes.decode("utf-8", errors="replace").strip()
                    exit_code = -1
                    events.append(
                        SandboxEvent(
                            rule_id="L3-TIMEOUT-001",
                            verdict=Verdict.KILL,
                            operation="process_timeout",
                            detail=f"Process exceeded {effective_timeout}s timeout",
                            timestamp_ms=int(_now_ms() - start_ms),
                        )
                    )


                if "deny" in stderr.lower() or "violation" in stderr.lower():
                    events.append(
                        SandboxEvent(
                            rule_id="L3-SEATBELT-DENY",
                            verdict=Verdict.DENY,
                            operation="seatbelt_violation",
                            detail=f"macOS sandbox violation: {stderr[:200]}",
                            timestamp_ms=int(_now_ms() - start_ms),
                        )
                    )


                from picosentry.sandbox.l3.backends.subprocess_backend import SubprocessBackend

                sb = SubprocessBackend()
                events.extend(sb._check_suspicious_patterns(stdout, stderr))

            finally:
                os.unlink(profile_path)

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
        except Exception as e:
            logger.exception("Seatbelt run failed")
            events.append(
                SandboxEvent(
                    rule_id="L3-SEATBELT-ERR",
                    verdict=Verdict.KILL,
                    operation="seatbelt_error",
                    detail=str(e),
                    timestamp_ms=int(_now_ms() - start_ms),
                )
            )
            stdout, stderr, exit_code = "", "", -1

        duration_ms = int(_now_ms() - start_ms)
        overall = self._compute_verdict(events, exit_code)

        return SandboxResult(
            command=command,
            overall_verdict=overall,
            exit_code=exit_code,
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

    def _generate_profile(
        self,
        policy: Policy,
        command: list[str],
        cwd: str | None = None,
    ) -> str:
        lines = ["(version 1)"]


        if policy.default_action == SyscallAction.DENY:
            lines.append("(deny default)")
        else:
            lines.append("(allow default)")

        for rule in policy.rules:
            if rule.action == SyscallAction.ALLOW:
                clause = self._rule_to_allow_clause(rule, cwd)
                if clause:
                    lines.append(clause)
            elif rule.action in (SyscallAction.DENY, SyscallAction.KILL):
                clause = self._rule_to_deny_clause(rule)
                if clause:
                    lines.append(clause)

        return "\n".join(lines)

    def _rule_to_allow_clause(self, rule: PolicyRule, cwd: str | None) -> str | None:
        parts = ["(allow"]

        if rule.target in (RuleTarget.FILE_READ, RuleTarget.FILE_WRITE):
            if rule.paths:
                for path in rule.paths:
                    literal = _escape_seatbelt_path(self._normalize_path(path, cwd))
                    if "*" in literal:
                        parts.append(f'(subpath "{literal.replace("*", "")}")')
                    else:
                        parts.append(f'(literal "{literal}")')
            else:
                parts.append("file-read*")
                if rule.target == RuleTarget.FILE_WRITE:
                    parts.append("file-write*")
                return f"({' '.join(parts)})" if len(parts) > 1 else None

            _op = "file-read*" if rule.target == RuleTarget.FILE_READ else "file-write*"

            if rule.target == RuleTarget.FILE_READ:
                parts.append("file-read-data")
                parts.append("file-read-metadata")

        elif rule.target == RuleTarget.NETWORK_OUT:
            parts.append("network-outbound")
            if rule.addresses:
                parts.extend(f'(remote ip "{_escape_seatbelt_path(addr)}")' for addr in rule.addresses)

        elif rule.target == RuleTarget.NETWORK_IN:
            parts.append("network-inbound")

        elif rule.target == RuleTarget.NETWORK_BIND:
            parts.append("network-bind")

        elif rule.target == RuleTarget.PROCESS_SPAWN:
            parts.append("process-exec")
            parts.append("process-fork")

        elif rule.target == RuleTarget.DNS_QUERY:
            parts.append("network-outbound")
            parts.append('(remote port "53")')

        if len(parts) == 1:
            return None  # Just "(allow)" with no ops is meaningless

        return f"({' '.join(parts)})"

    def _rule_to_deny_clause(self, rule: PolicyRule) -> str | None:
        parts = ["(deny"]

        if rule.target in (RuleTarget.NETWORK_OUT, RuleTarget.NETWORK_IN):
            parts.append("network*")
        elif rule.target == RuleTarget.NETWORK_BIND:
            parts.append("network-bind")
            parts.append("network-inbound")
        elif rule.target == RuleTarget.PROCESS_SPAWN:
            parts.append("process-exec")
            parts.append("process-fork")
        elif rule.target == RuleTarget.FILE_WRITE:
            parts.append("file-write*")
            if rule.paths:
                parts.extend(f'(subpath "{_escape_seatbelt_path(path)}")' for path in rule.paths)
        elif rule.target == RuleTarget.FILE_READ:
            if rule.paths:
                parts.extend(f'(literal "{_escape_seatbelt_path(path)}")' for path in rule.paths)
            else:
                parts.append("file-read*")

        if len(parts) == 1:
            return None

        return f"({' '.join(parts)})"

    def _normalize_path(self, path: str, cwd: str | None) -> str:
        if path == "**":
            return "/"
        if path.startswith("/"):
            return path
        if cwd:
            return os.path.join(cwd, path)
        return os.path.abspath(path)

    def _compute_verdict(self, events: list[SandboxEvent], exit_code: int) -> Verdict:
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
        reason: str = "seatbelt not available",
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
