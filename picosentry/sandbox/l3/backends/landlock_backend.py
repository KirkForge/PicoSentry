from __future__ import annotations

import ctypes
import datetime
import logging
import os
import platform
import time
from typing import TYPE_CHECKING

from picosentry.sandbox.l3.backends.base import SandboxBackend
from picosentry.sandbox.l3.models import (
    SandboxResult,
    Verdict,
)
import contextlib

if TYPE_CHECKING:
    from picosentry.sandbox.l3.models import Policy
    from picosentry.sandbox.l3.session import SandboxSession

logger = logging.getLogger("picodome.l3.landlock")

LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12
LANDLOCK_ACCESS_FS_REFER = 1 << 13
LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14

LANDLOCK_ACCESS_FS_ALL = (
    LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_READ_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM
    | LANDLOCK_ACCESS_FS_REFER
    | LANDLOCK_ACCESS_FS_TRUNCATE
)

LANDLOCK_ACCESS_NET_BIND_TCP = 1 << 0
LANDLOCK_ACCESS_NET_CONNECT_TCP = 1 << 1

LANDLOCK_RULE_PATH_BENEATH = 1
LANDLOCK_RULE_NET_PORT = 2

_SYSCALL_NUMBERS: dict[str, tuple[int, int, int]] = {
    "x86_64": (446, 447, 448),
    "aarch64": (444, 445, 446),
}

_ARCH = platform.machine()
_CREATE, _ADD, _RESTRICT = _SYSCALL_NUMBERS.get(_ARCH, (446, 447, 448))


class _LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
    ]


class _LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int32),
    ]


class _LandlockNetPortAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("port", ctypes.c_uint64),
    ]


class LandlockUnavailable(RuntimeError):
    pass


def _kernel_version() -> tuple[int, int, int]:
    release = platform.uname().release
    parts = release.split(".")
    try:
        major = int(parts[0])
        minor = int(parts[1].split("-")[0].split("+")[0])
        patch = 0
        if len(parts) > 2:
            patch_str = parts[2].split("-")[0].split("+")[0]
            with contextlib.suppress(ValueError):
                patch = int(patch_str)
        return (major, minor, patch)
    except (ValueError, IndexError):
        return (0, 0, 0)


def _check_landlock_available() -> str | None:
    kver = _kernel_version()
    if kver < (5, 13, 0):
        return f"kernel {kver} < 5.13 (landlock requires >= 5.13)"
    if platform.system() != "Linux":
        return f"not Linux (got {platform.system()})"
    return None


def _syscall(libc: ctypes.CDLL, num: int, *args) -> int:
    ctypes.set_errno(0)
    ret = libc.syscall(num, *args)
    err = ctypes.get_errno()
    ctypes.set_errno(0)
    return ret if ret >= 0 else -err


def _landlock_create_ruleset(libc: ctypes.CDLL, attr: _LandlockRulesetAttr) -> int:
    ret = _syscall(libc, _CREATE, ctypes.byref(attr), ctypes.sizeof(attr), 0)
    if isinstance(ret, int) and ret < 0:
        errno = -ret
        if errno == 2:
            raise LandlockUnavailable("landlock not built into kernel (ENOENT)")
        if errno == 38:
            raise LandlockUnavailable("landlock syscall not implemented (ENOSYS)")
        if errno == 1:
            raise LandlockUnavailable("landlock requires CAP_SYS_ADMIN or no_new_privs (EPERM)")
        if errno == 95:
            raise LandlockUnavailable("landlock not supported (EOPNOTSUPP)")
        raise LandlockUnavailable(f"landlock_create_ruleset failed: errno={errno}")
    return ret


def _landlock_add_rule(libc: ctypes.CDLL, ruleset_fd: int, rule_type: int, attr: ctypes.Structure) -> int:
    ret = _syscall(libc, _ADD, ruleset_fd, rule_type, ctypes.byref(attr), 0)
    if isinstance(ret, int) and ret < 0:
        logger.warning("landlock_add_rule failed: errno=%d rule_type=%d", -ret, rule_type)
    return ret


def _landlock_restrict_self(libc: ctypes.CDLL, ruleset_fd: int) -> int:
    ret = _syscall(libc, _RESTRICT, ruleset_fd, 0)
    if isinstance(ret, int) and ret < 0:
        logger.warning("landlock_restrict_self failed: errno=%d", -ret)
    return ret


class LandlockBackend(SandboxBackend):
    def __init__(self, *, fallback_to_seccomp: bool = True):
        self._fallback_to_seccomp = fallback_to_seccomp
        self._libc: ctypes.CDLL | None = None

    @property
    def name(self) -> str:
        return "landlock"

    @property
    def isolation_level(self) -> str:
        return "filesystem_policy"

    @property
    def enforcement_guarantee(self) -> str:
        return "high"

    def is_available(self) -> bool:
        reason = _check_landlock_available()
        if reason is not None:
            logger.debug("landlock unavailable: %s", reason)
            return False
        try:
            libc = ctypes.CDLL("libc.so.6", use_errno=True)
        except OSError:
            return False
        attr = _LandlockRulesetAttr()
        attr.handled_access_fs = LANDLOCK_ACCESS_FS_ALL
        attr.handled_access_net = 0
        try:
            fd = _landlock_create_ruleset(libc, attr)
            os.close(fd)
            return True
        except LandlockUnavailable:
            logger.debug("landlock probe failed, marking unavailable")
            return False

    def run(
        self,
        command: list[str],
        policy: Policy,
        timeout: float | None = None,
        cwd: str | None = None,
        env: dict | None = None,
    ) -> SandboxResult:
        if not self.is_available():
            if self._fallback_to_seccomp:
                from picosentry.sandbox.l3.backends.seccomp_backend import SeccompBackend

                logger.info("landlock unavailable, falling back to seccomp-only")
                return SeccompBackend().run(command, policy, timeout=timeout, cwd=cwd, env=env)
            raise LandlockUnavailable("landlock backend unavailable and fallback disabled")

        libc = self._get_libc()
        start_time = time.monotonic()

        workspace_root = cwd or "/tmp"
        read_only_paths = {"/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/proc", "/sys", "/dev"}
        read_write_paths = {workspace_root}

        attr = _LandlockRulesetAttr()
        attr.handled_access_fs = LANDLOCK_ACCESS_FS_ALL
        attr.handled_access_net = 0

        try:
            ruleset_fd = _landlock_create_ruleset(libc, attr)
        except LandlockUnavailable:
            if self._fallback_to_seccomp:
                from picosentry.sandbox.l3.backends.seccomp_backend import SeccompBackend

                logger.info("landlock ruleset creation failed, falling back to seccomp-only")
                return SeccompBackend().run(command, policy, timeout=timeout, cwd=cwd, env=env)
            raise

        try:
            for path in sorted(read_only_paths):
                try:
                    path_fd = os.open(path, os.O_PATH | os.O_DIRECTORY)
                except OSError:
                    logger.debug("landlock: skipping read-only path %s (not accessible)", path)
                    continue
                try:
                    rule_attr = _LandlockPathBeneathAttr()
                    rule_attr.allowed_access = (
                        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR | LANDLOCK_ACCESS_FS_EXECUTE
                    )
                    rule_attr.parent_fd = path_fd
                    _landlock_add_rule(libc, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, rule_attr)
                finally:
                    os.close(path_fd)

            for path in sorted(read_write_paths):
                try:
                    path_fd = os.open(path, os.O_PATH | os.O_DIRECTORY)
                except OSError:
                    logger.debug("landlock: skipping read-write path %s (not accessible)", path)
                    continue
                try:
                    rule_attr = _LandlockPathBeneathAttr()
                    rule_attr.allowed_access = LANDLOCK_ACCESS_FS_ALL
                    rule_attr.parent_fd = path_fd
                    _landlock_add_rule(libc, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, rule_attr)
                finally:
                    os.close(path_fd)

            pid = os.fork()
            if pid == 0:
                try:
                    _landlock_restrict_self(libc, ruleset_fd)
                except Exception:
                    os._exit(127)

                os.close(ruleset_fd)
                try:
                    child_env = {**os.environ, **env} if env else dict(os.environ)
                    os.execvpe(command[0], command, child_env)
                except Exception:
                    os._exit(126)
            else:
                os.close(ruleset_fd)
                _, status = os.waitpid(pid, 0)
                exit_code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -os.WTERMSIG(status)
        except Exception:
            with contextlib.suppress(OSError):
                os.close(ruleset_fd)
            raise

        elapsed = time.monotonic() - start_time

        return SandboxResult(
            run_id=f"landlock-{os.getpid()}-{int(start_time)}",
            timestamp=datetime.datetime.now(datetime.timezone.utc).isoformat(),
            command=command,
            overall_verdict=Verdict.ALLOW if exit_code == 0 else Verdict.DENY,
            exit_code=exit_code,
            duration_ms=int(elapsed * 1000),
            events=[],
            policy_name=policy.name if hasattr(policy, "name") else "landlock-default",
            degraded=False,
            stdout="",
            stderr="",
        )

    def run_in_session(self, session: SandboxSession) -> SandboxResult:
        return self.run(
            session.command,
            session.policy,
            timeout=session.timeout,
            cwd=session.cwd,
            env=session.env,
        )

    def _get_libc(self) -> ctypes.CDLL:
        if self._libc is None:
            self._libc = ctypes.CDLL("libc.so.6", use_errno=True)
        return self._libc
