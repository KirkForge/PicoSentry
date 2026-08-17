from __future__ import annotations

import contextlib
import ctypes
import datetime
import errno
import glob as _glob
import logging
import os
import platform
import select
import shutil
import stat
import tempfile
import time
from typing import TYPE_CHECKING

from picosentry.sandbox.l3.backends._env_defaults import default_child_env
from picosentry.sandbox.l3.backends._rlimits import kill_process_group, set_resource_limits
from picosentry.sandbox.l3.backends.base import SandboxBackend
from picosentry.sandbox.l3.models import (
    RuleTarget,
    SandboxResult,
    SyscallAction,
    Verdict,
)

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

LANDLOCK_ACCESS_FS_V1 = (
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
)
LANDLOCK_ACCESS_FS_ALL = LANDLOCK_ACCESS_FS_V1 | LANDLOCK_ACCESS_FS_REFER | LANDLOCK_ACCESS_FS_TRUNCATE

# Bits valid on a path-beneath rule whose parent_fd is a file, not a directory.
_FILE_ONLY_ACCESS = (
    LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_REFER
    | LANDLOCK_ACCESS_FS_TRUNCATE
)

LANDLOCK_ACCESS_NET_BIND_TCP = 1 << 0
LANDLOCK_ACCESS_NET_CONNECT_TCP = 1 << 1
LANDLOCK_ACCESS_NET_ALL = LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP

LANDLOCK_RULE_PATH_BENEATH = 1

LANDLOCK_CREATE_RULESET_VERSION = 1 << 0

_PR_SET_NO_NEW_PRIVS = 38

# Kernel versions that introduced each access right (for honest error messages).
_NET_MIN_KERNEL = "6.7"
_REFER_MIN_KERNEL = "5.19"
_TRUNCATE_MIN_KERNEL = "6.2"
_NET_ABI = 4  # landlock ABI introducing the network access rights

# The landlock syscall allocation is uniform across architectures (x86_64
# syscall_64.tbl matches asm-generic/unistd.h, which aarch64/riscv64 use).
# The per-arch map is kept so a genuinely divergent arch is a one-line add.
_SYSCALL_NUMBERS: dict[str, tuple[int, int, int]] = {
    "x86_64": (444, 445, 446),
    "aarch64": (444, 445, 446),
}

_ARCH = platform.machine()
_CREATE, _ADD, _RESTRICT = _SYSCALL_NUMBERS.get(_ARCH, (444, 445, 446))


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


def _landlock_abi_version(libc: ctypes.CDLL) -> int:
    """Highest supported landlock ABI (0 = landlock not usable here)."""
    ret = _syscall(libc, _CREATE, None, 0, LANDLOCK_CREATE_RULESET_VERSION)
    return ret if isinstance(ret, int) and ret >= 0 else 0


def _abi_fs_bits(abi: int) -> int:
    bits = LANDLOCK_ACCESS_FS_V1
    if abi >= 2:
        bits |= LANDLOCK_ACCESS_FS_REFER
    if abi >= 3:
        bits |= LANDLOCK_ACCESS_FS_TRUNCATE
    # ponytail: ABI 5 IOCTL_DEV not handled — ioctls stay unrestricted; add when a policy needs it
    return bits


def _landlock_create_ruleset(libc: ctypes.CDLL, attr: _LandlockRulesetAttr) -> int:
    ret = _syscall(libc, _CREATE, ctypes.byref(attr), ctypes.sizeof(attr), 0)
    if isinstance(ret, int) and ret < 0:
        errno_num = -ret
        if errno_num == errno.ENOENT:
            raise LandlockUnavailable("landlock not built into kernel (ENOENT)")
        if errno_num == errno.ENOSYS:
            raise LandlockUnavailable("landlock syscall not implemented (ENOSYS)")
        if errno_num == errno.EPERM:
            raise LandlockUnavailable("landlock requires CAP_SYS_ADMIN or no_new_privs (EPERM)")
        if errno_num == errno.EOPNOTSUPP:
            raise LandlockUnavailable("landlock disabled at boot (EOPNOTSUPP; check lsm= kernel param)")
        if errno_num == errno.E2BIG:
            kver = _kernel_version()
            raise LandlockUnavailable(
                f"kernel {kver} rejects requested access rights — REFER needs >= {_REFER_MIN_KERNEL}, "
                f"TRUNCATE >= {_TRUNCATE_MIN_KERNEL}, NET >= {_NET_MIN_KERNEL} (E2BIG)"
            )
        raise LandlockUnavailable(f"landlock_create_ruleset failed: errno={errno_num}")
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


def _set_no_new_privs(libc: ctypes.CDLL) -> int:
    """prctl(PR_SET_NO_NEW_PRIVS, 1) — required before unprivileged restrict_self."""
    ret = libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    return ret if isinstance(ret, int) else 0


def _target_denied(policy: Policy, target: RuleTarget) -> bool:
    for rule in policy.rules:
        if rule.target == target:
            if rule.action == SyscallAction.ALLOW:
                return False
            if rule.action in (SyscallAction.DENY, SyscallAction.KILL):
                return True
    return policy.default_action in (SyscallAction.DENY, SyscallAction.KILL)


def _explicitly_denied(policy: Policy, target: RuleTarget) -> bool:
    return any(
        rule.target == target and rule.action in (SyscallAction.DENY, SyscallAction.KILL) for rule in policy.rules
    )


def _net_handling(policy: Policy, abi: int) -> tuple[int, list[str]]:
    """Handled NET bits + honest ceiling labels for deny rules landlock cannot enforce.

    Handled bits follow effective denial (explicit rule or default_action=DENY);
    ceiling labels — which mark the result degraded — only fire on rules the
    policy explicitly denies, so ambient catch-all posture (which landlock never
    fully covers, e.g. process_spawn) does not render "degraded" meaningless.
    """
    ceilings: list[str] = []
    handled = 0
    out_denied = _target_denied(policy, RuleTarget.NETWORK_OUT)
    bind_denied = _target_denied(policy, RuleTarget.NETWORK_BIND)
    if abi >= _NET_ABI:
        if out_denied:
            handled |= LANDLOCK_ACCESS_NET_CONNECT_TCP
        if bind_denied:
            handled |= LANDLOCK_ACCESS_NET_BIND_TCP
        # ponytail: allow side stays unhandled — landlock has no wildcard port, so
        # "allow all connects" would need 65535 add_rule calls; port-scoped allows
        # wait for a policy that actually lists ports/addresses
    else:
        if _explicitly_denied(policy, RuleTarget.NETWORK_OUT):
            ceilings.append(f"network_out (needs kernel >= {_NET_MIN_KERNEL})")
        if _explicitly_denied(policy, RuleTarget.NETWORK_BIND):
            ceilings.append(f"network_bind (needs kernel >= {_NET_MIN_KERNEL})")
    if _explicitly_denied(policy, RuleTarget.NETWORK_IN):
        ceilings.append("network_in (landlock cannot restrict inbound/accept)")
    if _explicitly_denied(policy, RuleTarget.DNS_QUERY):
        ceilings.append("dns_query (landlock cannot restrict UDP)")
    return handled, ceilings


def _glob_anchor(pattern: str) -> str | None:
    """Longest glob-free directory prefix of a policy path (None = unbounded)."""
    if pattern.startswith("**"):
        return None
    cut = len(pattern)
    for i, ch in enumerate(pattern):
        if ch in "*?[":
            cut = i
            break
    anchor = pattern[:cut].rstrip("/")
    return anchor or None


def _has_glob_chars(pattern: str) -> bool:
    return any(c in pattern for c in "*?[")


def _is_ancestor_or_eq(ancestor: str, path: str) -> bool:
    if ancestor == "/":
        return True
    return path == ancestor or path.startswith(ancestor + os.sep)


def _build_grants(policy: Policy, command: list[str], workspace_root: str, handled_fs: int) -> list[tuple[str, int]]:
    """Translate Policy rules into (path, access-bits) grants for the ruleset.

    Launch parity with the seccomp backend: the runtime tree (loader, binaries)
    must stay readable/executable regardless of FILE_EXEC rules — seccomp exempts
    execve from explicit blocking for the same reason. "/proc/self"-style paths
    are kept literal: they must be granted in the child, where "self" resolves
    to the sandboxed process (a parent-side rule would pin the parent's pid).
    """
    grants: dict[str, int] = {}

    def grant(path: str, bits: int) -> None:
        if not os.path.isabs(path):
            path = os.path.join(workspace_root, path)
        key = path if path.startswith("/proc/self") else os.path.realpath(path)
        grants[key] = grants.get(key, 0) | (bits & handled_fs)

    read_denied = _target_denied(policy, RuleTarget.FILE_READ)
    write_denied = _target_denied(policy, RuleTarget.FILE_WRITE)

    ro = LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR
    if not read_denied:
        # EXECUTE is required on the runtime tree: the kernel loads the ELF
        # interpreter at execve time and that access is EXECUTE-checked too.
        for p in ("/usr", "/lib", "/lib64", "/bin", "/sbin"):
            grant(p, ro | LANDLOCK_ACCESS_FS_EXECUTE)
        grant("/etc", ro)
        cmd_path = shutil.which(command[0]) or command[0]
        # The runtime needs more than the binary's dir: interpreters discover
        # their stdlib/pyvenv.cfg from both the argv[0] tree and the resolved
        # binary's install tree (venvs symlink to an external prefix).
        for chain in (os.path.realpath(cmd_path), os.path.abspath(cmd_path)):
            bin_dir = os.path.dirname(chain)
            grant(bin_dir, ro | LANDLOCK_ACCESS_FS_EXECUTE)
            parent = os.path.dirname(bin_dir)
            if parent not in ("", "/"):
                grant(parent, ro)  # install/venv root: lib/, pyvenv.cfg
        for rule in policy.rules:
            if rule.target == RuleTarget.FILE_READ and rule.action == SyscallAction.ALLOW:
                if not rule.paths:
                    grant("/", ro)  # path-blind allow-all-read, mirroring seccomp semantics
                    continue
                for p in rule.paths:
                    anchor = _glob_anchor(p)
                    if anchor is None:
                        logger.debug("landlock: unbounded glob %s not representable (covered by base/cwd anchors)", p)
                        continue
                    grant(anchor, ro)

    for rule in policy.rules:
        if rule.target == RuleTarget.FILE_EXEC and rule.action == SyscallAction.ALLOW:
            for p in rule.paths:
                if "**" in p:
                    logger.debug("landlock: unbounded exec glob %s skipped", p)
                    continue
                matches = sorted(_glob.glob(p)) if _has_glob_chars(p) else [p]
                for m in matches:
                    grant(m, LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE)

    if not write_denied:
        rw = handled_fs & ~LANDLOCK_ACCESS_FS_EXECUTE
        # ponytail: workspace is data-not-code — execve of freshly written payloads
        # is withheld; a runtime that must exec its own output needs a FILE_EXEC allow
        grant(workspace_root, rw)
        for rule in policy.rules:
            if rule.target == RuleTarget.FILE_WRITE and rule.action == SyscallAction.ALLOW:
                if not rule.paths:
                    logger.debug("landlock: path-blind write allow not widened to '/' (ceiling: list paths)")
                    continue
                for p in rule.paths:
                    anchor = _glob_anchor(p)
                    if anchor is None:
                        continue
                    target = os.path.realpath(anchor if os.path.isabs(anchor) else os.path.join(workspace_root, anchor))
                    if _is_ancestor_or_eq(target, workspace_root):
                        grant(workspace_root, rw)  # tighten broad ancestors (e.g. /tmp) to the workspace
                    else:
                        grant(target, rw)

    return sorted(grants.items())


def _add_path_rule(libc: ctypes.CDLL, ruleset_fd: int, path: str, bits: int) -> None:
    if bits == 0:
        return
    try:
        path_fd = os.open(path, os.O_PATH | os.O_CLOEXEC)
    except OSError:
        logger.debug("landlock: skipping inaccessible path %s", path)
        return
    try:
        mode = os.fstat(path_fd).st_mode
        if not stat.S_ISDIR(mode):
            if not stat.S_ISREG(mode):
                # ponytail: chardev/fifo/socket inodes (e.g. /dev/null) cannot hold
                # landlock rules — device writes stay denied; redirect to workspace
                logger.debug("landlock: skipping non-regular path %s", path)
                return
            bits &= _FILE_ONLY_ACCESS  # directory-only rights on a file fd are EINVAL
        rule_attr = _LandlockPathBeneathAttr()
        rule_attr.allowed_access = bits
        rule_attr.parent_fd = path_fd
        _landlock_add_rule(libc, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH, rule_attr)
    finally:
        os.close(path_fd)


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
        if _landlock_abi_version(libc) < 1:
            logger.debug("landlock ABI probe failed (not built in or disabled via lsm=)")
            return False
        return True

    def run(
        self,
        command: list[str],
        policy: Policy,
        timeout: float | None = None,
        cwd: str | None = None,
        env: dict | None = None,
    ) -> SandboxResult:
        if not self.is_available():
            return self._unavailable(command, policy, timeout, cwd, env, "landlock unavailable")

        libc = self._get_libc()
        start_time = time.monotonic()

        abi = _landlock_abi_version(libc)
        if abi < 1:
            return self._unavailable(command, policy, timeout, cwd, env, "landlock ABI probe failed at run time")

        workspace_root = os.path.realpath(cwd) if cwd else tempfile.mkdtemp(prefix="picodome-landlock-")
        created_workspace = cwd is None

        handled_fs = _abi_fs_bits(abi)
        handled_net, net_ceilings = _net_handling(policy, abi)
        if net_ceilings:
            logger.warning(
                "landlock: policy denies %s but this kernel (ABI %d) cannot enforce it",
                ", ".join(net_ceilings),
                abi,
            )

        grants = _build_grants(policy, command, workspace_root, handled_fs)

        attr = _LandlockRulesetAttr()
        attr.handled_access_fs = handled_fs
        attr.handled_access_net = handled_net

        try:
            ruleset_fd = _landlock_create_ruleset(libc, attr)
        except LandlockUnavailable:
            if created_workspace:
                shutil.rmtree(workspace_root, ignore_errors=True)
            return self._unavailable(command, policy, timeout, cwd, env, "landlock ruleset creation failed")

        out_r: int | None = None
        err_r: int | None = None
        try:
            for path, bits in grants:
                if not path.startswith("/proc/self"):
                    _add_path_rule(libc, ruleset_fd, path, bits)

            out_r, out_w = os.pipe()
            err_r, err_w = os.pipe()

            pid = os.fork()
            if pid == 0:
                # Child: setsid → chdir → rlimits → no_new_privs → restrict → exec
                # (own session so a timeout kill takes the whole tree; cwd must
                # be resolved before the ruleset applies).
                os.close(out_r)
                os.close(err_r)
                if hasattr(os, "setsid"):
                    with contextlib.suppress(OSError):
                        os.setsid()
                os.dup2(out_w, 1)
                os.dup2(err_w, 2)
                os.close(out_w)
                os.close(err_w)

                if cwd:
                    try:
                        os.chdir(cwd)
                    except OSError:
                        os._exit(125)  # distinct code: requested cwd unusable
                try:
                    set_resource_limits()
                except Exception:
                    os._exit(127)

                # "/proc/self"-style grants resolve to this child only here.
                for path, bits in grants:
                    if path.startswith("/proc/self"):
                        _add_path_rule(libc, ruleset_fd, path, bits)

                if _set_no_new_privs(libc) != 0:
                    os._exit(127)
                if _landlock_restrict_self(libc, ruleset_fd) < 0:
                    os._exit(127)
                os.close(ruleset_fd)
                try:
                    child_env = dict(env) if env is not None else default_child_env()
                    if env is None:
                        child_env["TMPDIR"] = workspace_root
                    os.execvpe(command[0], command, child_env)
                except Exception:
                    os._exit(126)
            else:
                os.close(ruleset_fd)
                os.close(out_w)
                os.close(err_w)

                stdout_chunks: list[bytes] = []
                stderr_chunks: list[bytes] = []
                exit_code: int | None = None
                deadline = time.monotonic() + (timeout or 30.0)
                while exit_code is None:
                    # Drain while polling: a child writing >64KB would otherwise
                    # block on the pipe buffer and never reach the deadline check.
                    rlist, _, _ = select.select([out_r, err_r], [], [], 0.05)
                    for fd in rlist:
                        data = os.read(fd, 65536)
                        if data:
                            (stdout_chunks if fd == out_r else stderr_chunks).append(data)

                    wpid, status = os.waitpid(pid, os.WNOHANG)
                    if wpid == pid:
                        exit_code = os.WEXITSTATUS(status) if os.WIFEXITED(status) else -os.WTERMSIG(status)
                        break
                    if time.monotonic() >= deadline:
                        # Child ran setsid() (pgid == pid): kill the group so
                        # grandchildren die too (WO4.0.0-011).
                        kill_process_group(pid)
                        with contextlib.suppress(OSError):
                            _, status = os.waitpid(pid, 0)
                        exit_code = -9
                        break

                # Final drain: child has exited and its write ends are closed (EOF).
                for fd, chunks in ((out_r, stdout_chunks), (err_r, stderr_chunks)):
                    with contextlib.suppress(OSError):
                        os.set_blocking(fd, False)
                    try:
                        while True:
                            data = os.read(fd, 65536)
                            if not data:
                                break
                            chunks.append(data)
                    except OSError:
                        pass
                    with contextlib.suppress(OSError):
                        os.close(fd)
        except Exception:
            with contextlib.suppress(OSError):
                os.close(ruleset_fd)
            for leftover in (out_r, err_r):
                if leftover is not None:
                    with contextlib.suppress(OSError):
                        os.close(leftover)
            if created_workspace:
                shutil.rmtree(workspace_root, ignore_errors=True)
            raise

        if created_workspace:
            shutil.rmtree(workspace_root, ignore_errors=True)

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
            backend_name=self.name,
            isolation_level=self.isolation_level,
            enforcement_guarantee=self.enforcement_guarantee,
            degraded=bool(net_ceilings),
            stdout=b"".join(stdout_chunks).decode("utf-8", errors="replace").strip(),
            stderr=b"".join(stderr_chunks).decode("utf-8", errors="replace").strip(),
        )

    def _unavailable(
        self,
        command: list[str],
        policy: Policy,
        timeout: float | None,
        cwd: str | None,
        env: dict | None,
        reason: str,
    ) -> SandboxResult:
        if self._fallback_to_seccomp:
            from picosentry.sandbox.l3.backends.seccomp_backend import SeccompBackend

            logger.info("%s, falling back to seccomp-only", reason)
            return SeccompBackend().run(command, policy, timeout=timeout, cwd=cwd, env=env)
        raise LandlockUnavailable(f"{reason} and fallback disabled")

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
