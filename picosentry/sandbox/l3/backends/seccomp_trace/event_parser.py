from __future__ import annotations

from typing import TYPE_CHECKING

from picosentry.sandbox.l3.backends._seccomp_common import (
    FS_READ_SYSCALLS,
    FS_WRITE_SYSCALLS,
    NETWORK_SYSCALLS,
    target_to_syscalls,
)
from picosentry.sandbox.l3.models import (
    SandboxEvent,
    SyscallAction,
    Verdict,
)
from picosentry.sandbox.models import _now_ms

from ._audit import (
    _ARCH_X86_64,
    _AUDIT_LINE_RE,
    _LOG_ACTION_CODE,
    _OPEN_SYSCALLS,
    _X86_64_SYSCALLS,
)

if TYPE_CHECKING:
    from picosentry.sandbox.l3.models import Policy


def classify_syscall(name: str) -> tuple[str, str]:
    if name in _OPEN_SYSCALLS:
        return ("file_open", "L3-TRACE-FS-OPEN")
    if name in FS_READ_SYSCALLS:
        return ("file_read", "L3-TRACE-FS-READ")
    if name in FS_WRITE_SYSCALLS:
        return ("file_write", "L3-TRACE-FS-WRITE")
    if name in NETWORK_SYSCALLS:
        return ("network_outbound", "L3-TRACE-NET")
    if name in {"execve", "execveat"}:
        return ("process_spawn", "L3-TRACE-PROC-EXEC")
    if name in {"fork", "vfork", "clone", "clone3"}:
        return ("process_spawn", "L3-TRACE-PROC-FORK")
    return ("syscall_other", "L3-TRACE-OTHER")


def parse_seccomp_log(
    log_text: str,
    policy: "Policy",
    start_ms: float,
    x86_64_nr_to_name: dict[int, str] | None = None,
) -> list[SandboxEvent]:
    if x86_64_nr_to_name is None:
        x86_64_nr_to_name = _X86_64_SYSCALLS

    events: list[SandboxEvent] = []


    denied_syscalls: set[str] = set()
    for rule in policy.rules:
        if rule.action in (SyscallAction.DENY, SyscallAction.KILL):
            denied_syscalls |= target_to_syscalls(rule.target)

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
            name = x86_64_nr_to_name.get(syscall_nr)
        else:


            name = None
        if name is None:
            name = f"unknown_{arch:x}_{syscall_nr}"
        operation, rule_id_prefix = classify_syscall(name)
        if name in denied_syscalls:
            verdict = Verdict.DENY
        elif name in NETWORK_SYSCALLS and policy.default_action == SyscallAction.ALLOW:


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
                    f"args in v2.0.8)"
                ),
                timestamp_ms=int(_now_ms() - start_ms),
            )
        )
    return events


def compute_verdict(events: list[SandboxEvent], exit_code: int) -> Verdict:
    if exit_code == -1:
        return Verdict.KILL
    for event in events:
        if event.verdict == Verdict.KILL:
            return Verdict.KILL
        if event.verdict == Verdict.DENY:
            return Verdict.DENY
    return Verdict.ALLOW


__all__ = ["classify_syscall", "compute_verdict", "parse_seccomp_log"]
