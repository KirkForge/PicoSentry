"""Backward-compatible re-export shim for the split CLI service helpers.

New code should import from the focused modules directly:
- ``picosentry.scan._cli_service_paths``
- ``picosentry.scan._cli_service_formatters``
- ``picosentry.scan._cli_service_worker``
- ``picosentry.scan._cli_service_policy``
"""

from __future__ import annotations

from picosentry.scan._cli_service_formatters import (
    _format_quiet,
    _format_summary,
    _print_verbose_details,
)
from picosentry.scan._cli_service_paths import (
    _resolve_external_path,
    _secure_realpath,
    _workspace_root,
)
from picosentry.scan._cli_service_policy import _apply_policy
from picosentry.scan._cli_service_worker import (
    ScanError,
    ScanTimeout,
    _scan_worker,
)

__all__ = [
    "ScanError",
    "ScanTimeout",
    "_apply_policy",
    "_format_quiet",
    "_format_summary",
    "_print_verbose_details",
    "_resolve_external_path",
    "_scan_worker",
    "_secure_realpath",
    "_workspace_root",
]
