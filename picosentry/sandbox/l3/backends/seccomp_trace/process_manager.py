from __future__ import annotations

import contextlib
import ctypes
import logging
import os
import signal
import time
import warnings

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
        try:
            os.kill(pid, signal.SIGKILL)
            os.waitpid(pid, 0)
        except OSError:
            pass
        exit_code = -1

    os.close(out_fd)
    os.close(err_fd)
    return b"".join(stdout_chunks), b"".join(stderr_chunks), exit_code, log_text


def read_proc_seccomp(log_path: str) -> str:
    if not log_path or not os.path.exists(log_path):
        return ""
    try:
        with open(log_path, encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError as e:
        logger.debug("seccomp-trace: cannot read %s: %s", log_path, e)
        return ""


def probe_log_emits(lib: ctypes.CDLL) -> bool:
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

        return os.WIFEXITED(status) or os.WIFSIGNALED(status)
    except ChildProcessError:
        return False


__all__ = ["probe_log_emits", "read_proc_seccomp", "wait_with_timeout"]
