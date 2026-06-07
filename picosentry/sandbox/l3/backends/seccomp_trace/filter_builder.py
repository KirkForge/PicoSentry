"""Filter construction for the seccomp-trace backend.

Extracted in v2.1.0 (refactor) from ``seccomp_trace_backend.py``. Pure
functions that build a seccomp BPF filter from a policy and accept the
syscall-number cache as a parameter (no class state).

Differences from ``SeccompBackend._build_filter`` (mirrors v2.0.11
``seccomp_backend.py``):
- The default action is ``SCMP_ACT_LOG`` (not ``SCMP_ACT_KILL_PROCESS``)
  when the policy has no KILL semantics, so the tracee can be observed
  in real time and the audit log captures every syscall.
- All rule additions go through ``_seccomp_common.add_rule_safely`` for
  the same Bug #2 / EACCES safety net.
"""
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
    """Build seccomp BPF filter from policy. Returns (ctx, blocked_syscalls).

    The default action is ``SCMP_ACT_KILL_PROCESS`` if the policy has any
    KILL semantics, otherwise ``SCMP_ACT_LOG`` for observation. This is
    the only place ``seccomp-trace`` differs from ``seccomp-bpf`` — the
    rest of the filter shape is identical.
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

    # Always allow essential syscalls for basic binary execution
    for name in SAFE_SYSCALLS:
        num = resolve_syscall(lib, name, syscall_cache)
        if num >= 0:
            add_rule_safely(lib, ctx, SCMP_ACT_ALLOW, num, name)

    return ctx, blocked


# Re-exports so the orchestrator can call them as ``filter_builder.<helper>``
setup = setup_lib
resolve = resolve_syscall


__all__ = ["build_filter", "resolve", "setup"]
