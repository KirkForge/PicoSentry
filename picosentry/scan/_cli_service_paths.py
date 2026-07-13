"""Path validation helpers for the scan CLI service."""

from __future__ import annotations

import contextlib
import os
from pathlib import Path


def _workspace_root() -> Path:
    """Return the workspace root for validating external file paths.

    Defaults to the current working directory so relative paths behave as users
    expect. Override with ``PICOSENTRY_SCANS_WORKSPACE_ROOT`` for CI/monorepo
    layouts where inputs and outputs live outside the project directory.
    """
    env_root = os.environ.get("PICOSENTRY_SCANS_WORKSPACE_ROOT")
    if env_root:
        return Path(env_root).resolve()
    return Path.cwd()


def _secure_realpath(path_str: str, description: str = "path") -> Path:
    """Return the canonical path of an existing file/directory without following
    symlinks, using an open file descriptor.

    This narrows the TOCTOU window between ``resolve()`` and the eventual open:
    the returned path is read from ``/proc/self/fd/<n>`` for the descriptor we
    actually opened.  If ``path_str`` is a symlink the open fails with
    ``O_NOFOLLOW``.
    """
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW
    try:
        fd = os.open(path_str, flags)
    except IsADirectoryError:
        fd = os.open(path_str, flags | os.O_DIRECTORY)
    except OSError as exc:
        raise ValueError(f"{description}: cannot open {path_str}: {exc}") from exc

    try:
        proc_path = f"/proc/self/fd/{fd}"
        real = Path(os.path.realpath(proc_path))
        return real
    finally:
        with contextlib.suppress(OSError):
            os.close(fd)


def _resolve_external_path(
    path_str: str,
    workspace_root: Path,
    *,
    must_exist: bool = False,
    description: str = "path",
) -> Path:
    """Resolve a CLI path argument and reject traversal/symlink surprises.

    Relative paths are resolved against the current working directory, matching
    the behavior of the underlying filesystem calls.  Absolute paths must still
    lie inside the workspace root.  Symlinks are rejected to avoid ambiguous
    resolution.
    """
    if not isinstance(path_str, str) or not path_str:
        raise ValueError(f"{description} must be a non-empty string")
    if path_str.startswith(("http://", "https://")):
        raise ValueError(f"{description} cannot be a remote URL: {path_str}")

    candidate = Path(path_str)

    if candidate.is_symlink():
        raise ValueError(f"{description} cannot be a symlink: {path_str}")

    resolved = candidate.resolve(strict=False)
    if not resolved.is_relative_to(workspace_root):
        raise ValueError(f"{description} must be inside the workspace root ({workspace_root}): {path_str}")

    if must_exist:
        if not resolved.exists():
            raise ValueError(f"{description} does not exist: {resolved}")
        # Re-open the path to obtain the canonical location of the inode we
        # will actually use, closing the symlink/traversal TOCTOU window.
        resolved = _secure_realpath(str(resolved), description=description)
        if not resolved.is_relative_to(workspace_root):
            raise ValueError(f"{description} resolves outside the workspace root ({workspace_root}): {path_str}")

    return resolved
