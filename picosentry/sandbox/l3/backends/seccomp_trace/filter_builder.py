from __future__ import annotations

import ctypes
import logging

from picosentry.sandbox.l3.backends._seccomp_common import (
    SAFE_SYSCALLS,
    SCMP_ACT_ALLOW,
    SCMP_ACT_KILL_PROCESS,
    SCMP_ACT_LOG,
    add_rule_safely,
    resolve_syscall,
    setup_lib,
    target_to_syscalls,
)
from picosentry.sandbox.l3.models import Policy, SyscallAction

logger = logging.getLogger("picodome.l3.seccomp_trace.filter_builder")


def build_filter(
    lib: ctypes.CDLL,
    policy: Policy,
    syscall_cache: dict[str, int],
) -> tuple[ctypes.c_void_p | None, set[str]]:
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
            syscalls = target_to_syscalls(rule.target)
            for name in syscalls:
                num = resolve_syscall(lib, name, syscall_cache)
                if num >= 0:
                    add_rule_safely(lib, ctx, SCMP_ACT_ALLOW, num, name)
        elif rule.action in (SyscallAction.DENY, SyscallAction.KILL):
            syscalls = target_to_syscalls(rule.target)
            for name in syscalls:
                num = resolve_syscall(lib, name, syscall_cache)
                if num >= 0:
                    add_rule_safely(lib, ctx, SCMP_ACT_KILL_PROCESS, num, name)
                    blocked.add(name)


    for name in SAFE_SYSCALLS:
        num = resolve_syscall(lib, name, syscall_cache)
        if num >= 0:
            add_rule_safely(lib, ctx, SCMP_ACT_ALLOW, num, name)

    return ctx, blocked


setup = setup_lib
resolve = resolve_syscall


__all__ = ["build_filter", "resolve", "setup"]
