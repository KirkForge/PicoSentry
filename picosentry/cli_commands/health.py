"""`picosentry health` top-level command wiring."""

from __future__ import annotations

import argparse
import importlib.util
import sys

from picosentry.cli_commands import register


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    subparsers.add_parser("health", help="Run health checks")


def cmd(_args: argparse.Namespace) -> int:
    print("PicoSentry Health Check")
    print("=" * 40)

    checks = []

    if importlib.util.find_spec("picosentry.scan.engine") is not None:
        checks.append(("scan", "ok", "engine importable"))
    else:
        checks.append(("scan", "FAIL", "picosentry.scan.engine not available"))

    try:
        from picosentry.sandbox import __version__

        checks.append(("sandbox", "ok", f"v{__version__} importable"))
    except ImportError as e:
        checks.append(("sandbox", "FAIL", str(e)))

    try:
        from picosentry.watch import __version__

        checks.append(("watch", "ok", f"v{__version__} importable"))
    except ImportError as e:
        checks.append(("watch", "FAIL", str(e)))

    try:
        from picosentry.serve.config.version import __version__ as sv

        checks.append(("serve", "ok", f"v{sv} importable"))
    except ImportError as e:
        checks.append(("serve", "FAIL", str(e)))

    all_ok = all(s == "ok" for _, s, _ in checks)
    for name, status, msg in checks:
        icon = "✓" if status == "ok" else "✗"
        print(f"  {icon} {name}: {msg}")

    if all_ok:
        print("All components healthy.")
        return 0
    print("Some components failed to load.")
    return 1


register("health", add_arguments, cmd)
