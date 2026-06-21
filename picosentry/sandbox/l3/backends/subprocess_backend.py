from __future__ import annotations

import logging
import os
import re
import subprocess

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

logger = logging.getLogger("picodome.l3.subprocess")


class SubprocessBackend(SandboxBackend):
    @property
    def name(self) -> str:
        return "subprocess"

    @property
    def isolation_level(self) -> str:
        return "observational_only"

    @property
    def enforcement_guarantee(self) -> str:
        return "best_effort"

    def is_available(self) -> bool:
        return True

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
        exit_code = -1
        stdout = ""
        stderr = ""

        effective_timeout = timeout or 30.0

        try:
            if env is not None:
                run_env = dict(env)
            else:
                run_env = {
                    k: v
                    for k, v in os.environ.items()
                    if k
                    in (
                        "PATH",
                        "HOME",
                        "USER",
                        "LANG",
                        "LC_ALL",
                        "LC_CTYPE",
                        "TERM",
                        "TMPDIR",
                        "TEMP",
                        "TMP",
                        "LD_LIBRARY_PATH",
                        "DYLD_LIBRARY_PATH",
                        "PYTHONPATH",
                        "PYTHONHOME",
                        "PYTHONIOENCODING",
                        "NODE_PATH",
                        "NPM_CONFIG_PREFIX",
                        "PICODOME_SANDBOX_BACKEND",
                        "PICODOME_ALLOW_DEGRADED",
                    )
                }

            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=cwd,
                env=run_env,
            )

            try:
                stdout_bytes, stderr_bytes = proc.communicate(timeout=effective_timeout)
                exit_code = proc.returncode
            except subprocess.TimeoutExpired:
                proc.kill()
                stdout_bytes, stderr_bytes = proc.communicate()
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

            stdout = stdout_bytes.decode("utf-8", errors="replace").strip()
            stderr = stderr_bytes.decode("utf-8", errors="replace").strip()

            events.extend(self._analyze_output(stdout, stderr, policy, command))

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
        except PermissionError as e:
            events.append(
                SandboxEvent(
                    rule_id="L3-EXEC-002",
                    verdict=Verdict.DENY,
                    operation="exec_permission_denied",
                    detail=str(e),
                    timestamp_ms=int(_now_ms() - start_ms),
                )
            )

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

    def _analyze_output(
        self,
        stdout: str,
        stderr: str,
        policy: Policy,
        command: list[str],
    ) -> list[SandboxEvent]:
        events: list[SandboxEvent] = []
        combined = stdout + "\n" + stderr

        for rule in policy.rules:
            if rule.target in (RuleTarget.NETWORK_OUT, RuleTarget.NETWORK_IN):
                events.extend(self._check_network(combined, rule, command))
            elif rule.target == RuleTarget.FILE_WRITE:
                events.extend(self._check_file_write(combined, rule))
            elif rule.target == RuleTarget.PROCESS_SPAWN:
                events.extend(self._check_process_spawn(combined, rule))

        events.extend(self._check_suspicious_patterns(stdout, stderr))

        return events

    def _check_network(self, output: str, rule: PolicyRule, command: list[str]) -> list[SandboxEvent]:
        events: list[SandboxEvent] = []
        ip_pattern = re.compile(
            r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|\d{1,2})\.){3}"
            r"(?:25[0-5]|2[0-4]\d|1\d\d|\d{1,2})"
        )
        url_pattern = re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+')

        for match in ip_pattern.finditer(output):
            ip = match.group(0)
            if ip in ("0.0.0.0", "127.0.0.1", "255.255.255.255"):
                continue
            events.append(
                SandboxEvent(
                    rule_id=rule.rule_id,
                    verdict=Verdict.DENY if rule.action == SyscallAction.DENY else Verdict.ALLOW,
                    operation="network_outbound",
                    detail=f"IP address found: {ip}",
                    address=ip,
                )
            )

        for match in url_pattern.finditer(output):
            url = match.group(0)
            events.append(
                SandboxEvent(
                    rule_id=rule.rule_id,
                    verdict=Verdict.DENY if rule.action == SyscallAction.DENY else Verdict.ALLOW,
                    operation="network_outbound",
                    detail=f"URL found: {url[:100]}",
                    address=url[:100],
                )
            )

        return events

    def _check_file_write(self, output: str, rule: PolicyRule) -> list[SandboxEvent]:
        events: list[SandboxEvent] = []
        write_indicators = [
            (r"writing to ([^\s]+)", "file_write_indicator"),
            (r"wrote (\d+) bytes to ([^\s]+)", "file_write_bytes"),
            (r"saved to ([^\s]+)", "file_save"),
            (r"exported to ([^\s]+)", "file_export"),
        ]

        for pattern, op in write_indicators:
            for match in re.finditer(pattern, output):
                path = match.group(1) if match.lastindex else match.group(0)
                events.append(
                    SandboxEvent(
                        rule_id=rule.rule_id,
                        verdict=Verdict.DENY if rule.action == SyscallAction.DENY else Verdict.ALLOW,
                        operation=op,
                        detail=f"Write detected: {path}",
                        path=path,
                    )
                )

        return events

    def _check_process_spawn(self, output: str, rule: PolicyRule) -> list[SandboxEvent]:
        events: list[SandboxEvent] = []
        spawn_patterns = [
            r"executing: ([^\s]+)",
            r"spawning ([^\s]+)",
            r"subprocess\.(?:run|Popen|call|check_call|check_output)",
        ]

        for pattern in spawn_patterns:
            for match in re.finditer(pattern, output):
                detail = match.group(1) if match.lastindex else match.group(0)
                events.append(
                    SandboxEvent(
                        rule_id=rule.rule_id,
                        verdict=Verdict.DENY if rule.action == SyscallAction.DENY else Verdict.ALLOW,
                        operation="process_spawn",
                        detail=f"Process spawn detected: {detail}",
                    )
                )

        return events

    def _check_suspicious_patterns(self, stdout: str, stderr: str) -> list[SandboxEvent]:
        events: list[SandboxEvent] = []
        combined = stdout + stderr

        patterns = [
            (r"(?i)(eval\s*\(|exec\s*\(|compile\s*\()", "L3-SUS-001", "dynamic_code_exec", Verdict.DENY),
            (
                r"(?i)(subprocess\.(?:call|run|Popen|check_output|check_call)|os\.system|os\.popen|commands\.getoutput)",
                "L3-SUS-002",
                "shell_execution",
                Verdict.DENY,
            ),
            (r"(?i)(/etc/passwd|/etc/shadow|/etc/sudoers)", "L3-SUS-003", "sensitive_file_access", Verdict.DENY),
            (r"(?i)(curl|wget|nc\s|netcat|telnet)", "L3-SUS-004", "network_tool_usage", Verdict.DENY),
            (r"(?i)(chmod\s\+x|chmod\s777)", "L3-SUS-005", "permission_escalation", Verdict.DENY),
            (
                r"(?i)(base64\.(?:b64decode|b64encode|decode|encode)\s*\(|base64\s+-d\b)",
                "L3-SUS-006",
                "base64_decoding",
                Verdict.DENY,
            ),
            (r"(?i)(rm\s+-rf\s+/|dd\s+if=/dev)", "L3-SUS-007", "destructive_command", Verdict.KILL),
            (r"(?i)(/proc/self|ptrace|process_vm_readv)", "L3-SUS-008", "process_introspection", Verdict.DENY),
            (r"(?i)(\.ssh/|id_rsa|id_ed25519|authorized_keys)", "L3-SUS-009", "ssh_key_access", Verdict.DENY),
            (r"(?i)(/root/\.\w+|/home/\w+/\.)", "L3-SUS-010", "dotfile_access", Verdict.DENY),
        ]

        for pattern, rule_id, operation, verdict in patterns:
            if re.search(pattern, combined):
                events.append(
                    SandboxEvent(
                        rule_id=rule_id,
                        verdict=verdict,
                        operation=operation,
                        detail=f"Pattern matched: {pattern}",
                    )
                )

        return events

    def _compute_verdict(self, events: list[SandboxEvent], exit_code: int) -> Verdict:
        if exit_code == -1 and any(e.rule_id == "L3-TIMEOUT-001" for e in events):
            return Verdict.KILL

        for event in events:
            if event.verdict == Verdict.KILL:
                return Verdict.KILL
            if event.verdict == Verdict.DENY:
                return Verdict.DENY

        return Verdict.ALLOW
