"""Seccomp-bpf backend with syscall observation (Linux only) — back-compat shim.

v2.0.8 (strategy A) — uses ``SCMP_ACT_LOG`` to capture every syscall the
tracee makes and emits one ``SandboxEvent`` per syscall. The filter is
identical in shape to ``SeccompBackend._build_filter`` with the default
action swapped to ``SCMP_ACT_LOG`` when no policy rule requires KILL.

**v2.0.8 limitation.** ``SCMP_ACT_LOG`` records the syscall number and
arch but not the syscall arguments. ``SandboxEvent.path`` and
``SandboxEvent.address`` are always empty in this strategy. The L4
profiler (``picosentry/sandbox/l4/profiler.py``) filters on those fields
being non-empty, so v2.0.8 events are visible to the L3 CLI summary
(``L3: allow | N events``) and to L4's stdout-derived extraction, but
``fs_ops``/``network_calls``/``spawns`` are not populated from kernel
data yet. Strategies that capture syscall arguments — B
(``PTRACE_SECCOMP``) and C (``SECCOMP_RET_USER_NOTIF``) — are v2.1.0+
work, not v2.0.x.

**KILL still wins.** When ``policy.default_action`` is ``KILL``/``DENY``,
or any rule has ``KILL``/``DENY`` action, the default action is
``SCMP_ACT_KILL_PROCESS`` and the tracee dies on the first policy
violation — identical to ``SeccompBackend``. We additionally emit a
``seccomp_violation`` event with a diagnostic, mirroring
``SeccompBackend.run:411-442``.

**Kernel requirement.** ``CONFIG_SECCOMP_LOG=y`` (default on Ubuntu, may
be disabled on minimal containers). ``is_available()`` probes with a
real fork+exec to verify ``SCMP_ACT_LOG`` loads; if the probe child is
killed the backend reports unavailable. v2.1.0 note: the probe
verifies the kernel *accepts* the LOG action, not that audit entries
are *emitted* — ``CONFIG_SECCOMP_LOG=n`` kernels accept the filter but
never produce output, so the real fix is PTRACE_SECCOMP or
SECCOMP_RET_USER_NOTIF (v2.1.0+ work).

**Note on /proc/<pid>/seccomp.** Modern mainline kernels do **not**
expose a standalone ``/proc/<pid>/seccomp`` audit-log file. The legacy
file (removed in 2.6.23) only reported seccomp mode (0/1), never audit
entries. v2.0.8 attempts a best-effort read of ``/proc/<pid>/seccomp``
before the child is reaped. The canonical audit-log integration
(auditd / ausearch) is tracked as v2.1.0+ work; v2.0.11 keeps the
best-effort proc-read path for compatibility with custom kernels and
LSM modules that restore the interface.

**Threading.** Not thread-safe (mirrors ``SeccompBackend``). One trace
per process tree.

**Shared with ``seccomp_backend.py`` (v2.0.11+).** The syscall sets,
``RuleTarget`` mapping, libseccomp argtypes, and the safe
``seccomp_rule_add`` wrapper now live in
``picosentry/sandbox/l3/backends/_seccomp_common.py`` and are imported
by both backends. This eliminates the previous "Keep in sync" maintenance
hazard: a change to the safe-syscall set or the target mapping is now
a single edit.

**v2.1.0 refactor.** This file is now a thin re-export shim. The real
implementation lives in the ``seccomp_trace/`` subpackage:

- ``seccomp_trace._audit`` — audit-message constants + x86_64 table
- ``seccomp_trace.filter_builder`` — seccomp-bpf filter construction
- ``seccomp_trace.event_parser`` — syscall classification + audit parsing
- ``seccomp_trace.process_manager`` — fork+exec + /proc/seccomp + timeouts
- ``seccomp_trace.orchestrator`` — ``SeccompTraceBackend`` class

The shim preserves the historic import path
(``picosentry.sandbox.l3.backends.seccomp_trace_backend``) so existing
callers (``picosentry/sandbox/l3/engine.py``, the test suite, and any
downstream integrations) keep working unchanged. The shim is on the
deprecation path for v2.2.0.
"""
from __future__ import annotations

# Re-export ``os`` and ``ctypes`` as attributes on this module so the
# test patches (e.g. ``patch("...seccomp_trace_backend.os.fork", ...)``
# in ``tests/sandbox/test_seccomp_trace_backend.py``) keep resolving
# through the historic module path. Without these imports, every test
# patch on this module's ``os`` / ``ctypes`` attribute would fail.
import ctypes
import os

from picosentry.sandbox.l3.backends._seccomp_common import (
    FS_READ_SYSCALLS,
    FS_WRITE_SYSCALLS,
    NETWORK_SYSCALLS,
    SAFE_SYSCALLS,
    SCMP_ACT_LOG,
    add_rule_safely,
)
from picosentry.sandbox.l3.backends.seccomp_trace import SeccompTraceBackend
from picosentry.sandbox.l3.backends.seccomp_trace._audit import (
    _AUDIT_LINE_RE,
    _LOG_ACTION_CODE,
)


__all__ = [
    "FS_READ_SYSCALLS",
    "FS_WRITE_SYSCALLS",
    "NETWORK_SYSCALLS",
    "SAFE_SYSCALLS",
    "SCMP_ACT_LOG",
    "SeccompTraceBackend",
    "_AUDIT_LINE_RE",
    "_LOG_ACTION_CODE",
    "add_rule_safely",
    "ctypes",
    "os",
]
