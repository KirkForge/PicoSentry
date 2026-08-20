from __future__ import annotations

import contextlib
import ctypes
import logging
import os
import time
import warnings
from pathlib import Path

from picosentry.sandbox.l3.backends._rlimits import kill_process_group
from picosentry.sandbox.l3.backends._seccomp_common import SCMP_ACT_LOG

logger = logging.getLogger("picodome.l3.seccomp_trace.process_manager")


def wait_with_timeout(
    pid: int,
    out_fd: int,
    err_fd: int,
    timeout: float,
    log_path: str,
) -> tuple[bytes, bytes, int, str]:
    import select as _select

    stdout_chunks: list[bytes] = []
    stderr_chunks: list[bytes] = []
    deadline = time.monotonic() + timeout
    exit_code: int | None = None
    log_text = ""

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

            log_text = read_proc_seccomp(log_path)
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
        # The child ran setsid() before exec (pgid == pid): kill the whole
        # group so pipe-holding grandchildren die too (WO4.0.0-011).
        kill_process_group(pid)
        with contextlib.suppress(OSError):
            os.waitpid(pid, 0)
        exit_code = -1

    os.close(out_fd)
    os.close(err_fd)
    return b"".join(stdout_chunks), b"".join(stderr_chunks), exit_code, log_text


def read_proc_seccomp(log_path: str) -> str:
    if not log_path or not Path(log_path).exists():
        return ""
    try:
        with Path(log_path).open(encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError as e:
        logger.debug("seccomp-trace: cannot read %s: %s", log_path, e)
        return ""


def probe_log_emits(lib: ctypes.CDLL) -> bool:
    """Probe whether a child can load a SCMP_ACT_LOG filter and execve.

    WO6.0.0-018: the name is aspirational — this probe verifies the filter
    LOADS and the child runs to completion under it, NOT that seccomp
    actually EMITS log records (v2.0.8 SCMP_ACT_LOG emits nothing
    observable to /proc/<pid>/seccomp on kernels without CONFIG_SECCOMP_LOG).
    A reaped child always satisfies WIFEXITED or WIFSIGNALED, so the real
    gate is "seccomp_load returned 0 AND execve happened without the kernel
    killing the child pre-exec". The /proc/seccomp buffer emptiness is
    detected later at run time (orchestrator logs it). Renaming would break
    the public API; the docstring is the honest record.
    ponytail: ceiling — a real "log emits" probe would need to parse
    /proc/<pid>/seccomp after the child runs, but the buffer is empty by the
    time the parent reaps; upgrade to a ptrace-based probe if observability
    of emission becomes a gate.
    """
    lib.seccomp_init.argtypes = [ctypes.c_uint32]
    lib.seccomp_init.restype = ctypes.c_void_p
    lib.seccomp_load.argtypes = [ctypes.c_void_p]
    lib.seccomp_load.restype = ctypes.c_int
    lib.seccomp_release.argtypes = [ctypes.c_void_p]

    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)
        pid = os.fork()

    if pid == 0:
        ctx = lib.seccomp_init(SCMP_ACT_LOG)
        if not ctx:
            os._exit(127)
        if lib.seccomp_load(ctx) != 0:
            lib.seccomp_release(ctx)
            os._exit(127)
        lib.seccomp_release(ctx)
        try:
            os.execve("/bin/true", ["/bin/true"], {})
        except OSError:
            os._exit(127)

    try:
        _, status = os.waitpid(pid, 0)
        # The child either exited 0 (seccomp_load ok + /bin/true ran) or was
        # killed by the kernel (seccomp_load ok + execve violated the filter
        # — unlikely for SCMP_ACT_LOG which is permissive). A non-zero exit
        # (127) means seccomp_load failed or /bin/true missing — that's the
        # actual signal this probe gates on, not log emission.
        if os.WIFEXITED(status):
            return os.WEXITSTATUS(status) == 0
        # WIFSIGNALED: killed under the filter — the filter loaded, so the
        # kernel supports it; treat as "probe passed" (the load path worked).
        return os.WIFSIGNALED(status)
    except ChildProcessError:
        return False


__all__ = ["probe_log_emits", "read_proc_seccomp", "wait_with_timeout"]
