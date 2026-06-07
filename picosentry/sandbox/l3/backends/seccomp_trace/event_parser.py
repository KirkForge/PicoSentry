"""Event parsing and classification for the seccomp-trace backend.

Extracted in v2.1.0 (refactor) from ``seccomp_trace_backend.py``. Pure
functions: classify a syscall name into an operation+rule prefix, parse
the audit log text into ``SandboxEvent`` records, and compute the
overall verdict from the event list.
"""
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
    """Map a syscall name to ``(operation, rule_id_prefix)``.

    Mirrors the wire format that L4's profiler.py:31-33 already knows.
    The ``rule_id_prefix`` is the L3-TRACE-* family; v2.0.9+ will promote
    these to L4 rule IDs.
    """
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
    """Parse audit text (from any source) into ``SandboxEvent`` records.

    Anchors on ``code=0x7ffc0000`` (the SCMP_ACT_LOG magic) and
    ``syscall=N``. Lines that don't match are silently skipped.
    In v2.0.8 this is only exercised by unit tests with mock data;
    production audit-log integration is the v2.0.9 target.

    The optional ``x86_64_nr_to_name`` dict is the reverse syscall-number
    table. Pass ``None`` to use the default (``_X86_64_SYSCALLS``).
    """
    if x86_64_nr_to_name is None:
        x86_64_nr_to_name = _X86_64_SYSCALLS

    events: list[SandboxEvent] = []
    # Build a quick set of syscalls that policy rules have marked
    # as KILL/DENY, so we can promote a LOG entry to DENY verdict
    # if it would have been killed under a stricter policy.
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
            # aarch64 and other arches need their own number→name
            # table. v2.0.8 logs them as syscall_other.
            name = None
        if name is None:
            name = f"unknown_{arch:x}_{syscall_nr}"
        operation, rule_id_prefix = classify_syscall(name)
        if name in denied_syscalls:
            verdict = Verdict.DENY
        elif name in NETWORK_SYSCALLS and policy.default_action == SyscallAction.ALLOW:
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
                    f"args in v2.0.8)"
                ),
                timestamp_ms=int(_now_ms() - start_ms),
            )
        )
    return events


def compute_verdict(events: list[SandboxEvent], exit_code: int) -> Verdict:
    """Reduce the event list to a single overall ``Verdict``.

    - ``exit_code == -1`` (timeout / SIGKILL) → ``KILL``
    - any ``KILL`` event → ``KILL``
    - any ``DENY`` event → ``DENY``
    - otherwise → ``ALLOW``
    """
    if exit_code == -1:
        return Verdict.KILL
    for event in events:
        if event.verdict == Verdict.KILL:
            return Verdict.KILL
        if event.verdict == Verdict.DENY:
            return Verdict.DENY
    return Verdict.ALLOW


__all__ = ["classify_syscall", "compute_verdict", "parse_seccomp_log"]
