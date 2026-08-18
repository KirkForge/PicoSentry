from __future__ import annotations

import math
import os
from pathlib import Path
from typing import Any


API_VERSION = "v1"


CORS_ALLOW_ORIGINS = os.environ.get("PICODOME_CORS_ORIGINS", "").replace("\r", "").replace("\n", "")
CORS_ALLOW_METHODS = "GET, POST, OPTIONS"
CORS_ALLOW_HEADERS = "Content-Type, Authorization, X-Tenant, X-Request-ID"
CORS_MAX_AGE = "86400"  # 24 hours
_CORS_ALLOW_ORIGINS_LIST = [o.strip() for o in CORS_ALLOW_ORIGINS.split(",") if o.strip()]
_CORS_DENY_BY_DEFAULT = not _CORS_ALLOW_ORIGINS_LIST and CORS_ALLOW_ORIGINS != "*"
_ENTERPRISE_MODE = os.environ.get("PICODOME_ENTERPRISE_MODE", "").lower() in ("1", "true", "yes")


if _ENTERPRISE_MODE and CORS_ALLOW_ORIGINS == "*":
    import logging

    logger = logging.getLogger("picodome.daemon")
    logger.warning(
        "ENTERPRISE MODE: CORS origin is wildcard ('*'). "
        "Set PICODOME_CORS_ORIGINS to specific trusted origins for production."
    )


ALLOWED_COMMANDS: frozenset[str] = frozenset(
    {
        "echo",
        "printf",
        "cat",
        "head",
        "tail",
        "sort",
        "wc",
        "grep",
        "jq",
        "yq",
        "npm",
        "npx",
        "yarn",
        "pnpm",
        "pip",
        "pip3",
        "cargo",
        "go",
        "mvn",
        "gradle",
        "make",
        "cmake",
        "dotnet",
        "gem",
        "bundle",
        "php",
        "composer",
    }
)

# Policy decision (WO4.0.0-018): interpreters (node/python/…) and command
# WRAPPERS (env/xargs/nohup/timeout/stdbuf) are denied as scan ENTRYPOINTS —
# both are arbitrary-code-execution by the caller, and before the wrappers
# were listed, `env bash -c …` sailed past a denylist that banned `bash`.
# This intentionally means the shipped L4 "python-script"/node baselines do
# not fire via daemon submits — they serve the library/CLI paths (workspace
# scans, pipeline). find/awk/sed remain allowed: partial-risk file tools,
# documented split rather than a false promise.
DENIED_COMMANDS: frozenset[str] = frozenset(
    {
        "rm",
        "rmdir",
        "mkfs",
        "dd",
        "format",
        "shutdown",
        "reboot",
        "halt",
        "poweroff",
        "passwd",
        "useradd",
        "userdel",
        "usermod",
        "groupadd",
        "groupdel",
        "iptables",
        "ip6tables",
        "nft",
        "systemctl",
        "service",
        "mount",
        "umount",
        "crontab",
        "ssh",
        "telnet",
        "nc",
        "ncat",
        "curl",
        "wget",
        "bash",
        "sh",
        "zsh",
        "fish",
        "python",
        "python3",
        "perl",
        "ruby",
        "node",
        "sudo",
        "su",
        "doas",
        "chmod",
        "chown",
        "chgrp",
        "chattr",
        "env",
        "xargs",
        "nohup",
        "timeout",
        "stdbuf",
    }
)


def validate_command(command: list[str]) -> str | None:
    """Shared command allow/deny check — used by the HTTP handler and the gRPC servicer."""
    if not command:
        return "Empty command"
    from pathlib import Path as _Path

    base_name = _Path(command[0]).name

    if _ENTERPRISE_MODE:
        if base_name not in ALLOWED_COMMANDS:
            return f"Command '{base_name}' is not in enterprise allowlist"
    elif base_name in DENIED_COMMANDS:
        return f"Command '{base_name}' is denied by server policy"
    return None


def max_scan_timeout_seconds() -> float:
    """Upper bound for scan timeout from env (default 300 s). Shared by HTTP and gRPC."""
    try:
        return max(1.0, float(os.environ.get("PICODOME_MAX_SCAN_TIMEOUT", "300")))
    except ValueError:
        return 300.0


def sanitize_scan_timeout(raw: Any) -> float | None:
    """Shared untrusted-timeout guard (WO5.0.0-002): numeric + finite check,
    then clamp to the server cap. Returns None when the value is unusable —
    callers must REJECT (a NaN/±Inf/garbage timeout is a bad request, never
    a silent default; NaN reached subprocess backends as an unhandled
    ValueError with an orphaned child)."""
    try:
        parsed = float(raw)
    except (TypeError, ValueError):
        return None
    if not math.isfinite(parsed):
        return None
    return min(parsed, max_scan_timeout_seconds())


def workspace_root() -> Path:
    """Server-side workspace root that caller-supplied scan cwd values are confined to."""
    return Path(os.environ.get("PICODOME_WORKSPACE_ROOT", str(Path.home() / ".picodome" / "workspace")))


def confine_cwd(cwd: str | None) -> Path | None:
    """Resolve a caller-supplied cwd against the workspace root.

    Returns the resolved path if it stays inside the workspace root, otherwise
    None (caller must reject). Empty/None cwd returns None meaning "server default".
    """
    if not cwd:
        return None
    root = workspace_root().resolve()
    resolved = Path(cwd).resolve()
    try:
        resolved.relative_to(root)
    except ValueError:
        return None
    return resolved


__all__ = [
    "ALLOWED_COMMANDS",
    "API_VERSION",
    "CORS_ALLOW_HEADERS",
    "CORS_ALLOW_METHODS",
    "CORS_ALLOW_ORIGINS",
    "CORS_MAX_AGE",
    "DENIED_COMMANDS",
    "_CORS_ALLOW_ORIGINS_LIST",
    "_CORS_DENY_BY_DEFAULT",
    "_ENTERPRISE_MODE",
    "confine_cwd",
    "max_scan_timeout_seconds",
    "sanitize_scan_timeout",
    "validate_command",
    "workspace_root",
]
