"""Shared default child-environment allowlist for sandbox backends.

ADR (WO4.0.0-010): the ``env=None`` path is an ALLOWLIST, not a denylist.
The previous default (daemon env minus a suffix denylist) leaked everything
the patterns missed — ``SECRET_KEY_FILE``, ``*_APIKEY``, ``KUBECONFIG``,
``SSH_AUTH_SOCK`` — and the backends' own curated 4-var allowlists were dead
code on the engine path while the subprocess backend's wider list diverged.
One allowlist here is the single source of truth for every backend.

Documented exceptions:
- Callers passing an explicit ``env`` dict get it verbatim (the engine still
  strips secret-looking keys via ``engine._strip_env`` — defense in depth).
- Landlock overrides ``TMPDIR`` to the per-run workspace when env is None.
"""

from __future__ import annotations

import os

# The subprocess backend's curated set (the richest of the old per-backend
# lists) plus the two backend-selection knobs. Keep deliberately minimal:
# runtime/locale/package-manager discovery only — no credentials, no config
# pointers like KUBECONFIG/SSH_AUTH_SOCK/NPM_CONFIG_USERCONFIG.
SANDBOX_ENV_ALLOWLIST: frozenset[str] = frozenset(
    {
        "PATH",
        "HOME",
        "USER",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "TERM",
        "TMPDIR",
        "TEMP",
        "TMP",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
        "PYTHONPATH",
        "PYTHONHOME",
        "PYTHONIOENCODING",
        "NODE_PATH",
        "NPM_CONFIG_PREFIX",
        "PICODOME_SANDBOX_BACKEND",
        "PICODOME_ALLOW_DEGRADED",
    }
)


def default_child_env() -> dict[str, str]:
    """The env a sandboxed child receives when the caller passes none."""
    return {k: v for k, v in os.environ.items() if k in SANDBOX_ENV_ALLOWLIST}
