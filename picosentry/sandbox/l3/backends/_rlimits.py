from __future__ import annotations

import logging
import os

try:
    import resource

    HAS_RESOURCE = True
except ImportError:
    HAS_RESOURCE = False

logger = logging.getLogger("picodome.l3.rlimits")

_DEFAULT_MEMORY_LIMIT_MB = 512
_DEFAULT_FILE_SIZE_LIMIT_MB = 100
# CPU ceiling: must exceed max scan wall-time (PICODOME_MAX_SCAN_TIMEOUT, 300 s
# default) times plausible core counts, so it never kills a legitimate scan —
# it exists to bound ORPHANS that survive the wall-timeout kill (WO4.0.0-011).
_DEFAULT_CPU_LIMIT_SECONDS = 3600
# Headroom of additional processes the sandbox tree may add to the user's
# current total. RLIMIT_NPROC counts per-UID HOST-WIDE, but /proc (and any
# other in-container observation point) only sees the PID namespace — on a
# shared-UID host the visible count under-reports and any default bound makes
# EVERY fork fail (verified empirically). Therefore NPROC is OPT-IN: set
# PICODOME_PROCESS_LIMIT > 0 on dedicated-UID deployments (containers with
# their own uid, CI runners) where count+headroom is a true bound. Use a
# generous value (512+) to absorb concurrent-spawn bursts.
_DEFAULT_PROCESS_LIMIT = 0


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except (ValueError, TypeError):
        return default


def _user_process_count() -> int:
    """Best-effort count of processes currently owned by this UID (Linux only).

    Non-Linux returns 0, which disables the computed NPROC bound (an absolute
    default could not account for host process count without /proc).
    """
    uid = os.getuid() if hasattr(os, "getuid") else -1
    if uid < 0:
        return 0
    count = 0
    proc_dir = "/proc"
    try:
        entries = os.listdir(proc_dir)
    except OSError:
        return 0
    for name in entries:
        if not name.isdigit():
            continue
        try:
            with open(f"{proc_dir}/{name}/status", encoding="utf-8", errors="replace") as f:
                for line in f:
                    if line.startswith("Uid:"):
                        # Uid:\treal\teffective\tsaved\tfs
                        parts = line.split()
                        if len(parts) > 1 and parts[1] == str(uid):
                            count += 1
                        break
        except OSError:
            continue
    return count


def compute_rlimits() -> dict[str, tuple[int, int]]:
    """Compute (soft, hard) per resource name from env knobs — unit-testable.

    Knobs (0 disables): PICODOME_MEMORY_LIMIT_MB, PICODOME_FILE_SIZE_LIMIT_MB,
    PICODOME_CPU_LIMIT_SECONDS, PICODOME_PROCESS_LIMIT (headroom, see above).
    """
    memory_mb = _env_int("PICODOME_MEMORY_LIMIT_MB", _DEFAULT_MEMORY_LIMIT_MB)
    file_size_mb = _env_int("PICODOME_FILE_SIZE_LIMIT_MB", _DEFAULT_FILE_SIZE_LIMIT_MB)
    cpu_seconds = _env_int("PICODOME_CPU_LIMIT_SECONDS", _DEFAULT_CPU_LIMIT_SECONDS)
    process_headroom = _env_int("PICODOME_PROCESS_LIMIT", _DEFAULT_PROCESS_LIMIT)

    limits: dict[str, tuple[int, int]] = {}
    if memory_mb > 0:
        memory_bytes = memory_mb * 1024 * 1024
        limits["RLIMIT_AS"] = (memory_bytes, memory_bytes)
    if file_size_mb > 0:
        file_size_bytes = file_size_mb * 1024 * 1024
        limits["RLIMIT_FSIZE"] = (file_size_bytes, file_size_bytes)
    limits["RLIMIT_NOFILE"] = (256, 256)
    if cpu_seconds > 0:
        # hard = soft + 1 so a process that ignores the soft-limit SIGXCPU is
        # still SIGKILLed at the hard limit.
        limits["RLIMIT_CPU"] = (cpu_seconds, cpu_seconds + 1)
    if process_headroom > 0:
        base = _user_process_count()
        if base > 0:
            bound = base + process_headroom
            limits["RLIMIT_NPROC"] = (bound, bound)
    return limits


def set_resource_limits() -> None:
    if not HAS_RESOURCE:
        return
    for name, (soft, hard) in compute_rlimits().items():
        try:
            resource.setrlimit(getattr(resource, name), (soft, hard))
        except (ValueError, OSError):
            logger.debug("setrlimit %s failed", name, exc_info=True)


def sandbox_preexec() -> None:
    """Popen preexec_fn for sandboxed children: own session + rlimits.

    The new session makes the child a process-group leader so a timeout kill
    can take down the whole tree (grandchildren hold stdout pipes otherwise).
    """
    if hasattr(os, "setsid"):
        os.setsid()
    set_resource_limits()


def kill_process_group(pgid: int) -> None:
    """SIGKILL an entire process group; a missing group is not an error."""
    import contextlib
    import signal

    if not hasattr(os, "killpg"):
        return
    with contextlib.suppress(ProcessLookupError, PermissionError, OSError):
        os.killpg(pgid, signal.SIGKILL)


__all__ = ["compute_rlimits", "kill_process_group", "sandbox_preexec", "set_resource_limits"]
