"""Shared CLI helpers used by multiple command modules."""

from __future__ import annotations

import argparse
import sys
from collections.abc import Callable


_EXTRA_HINTS: dict[str, str] = {
    "fastapi": "serve",
    "uvicorn": "watch-server",
    "pydantic": "serve",
    "jwt": "serve",  # PyJWT
    "passlib": "serve",
    "python_multipart": "serve",
    "multipart": "serve",
    "croniter": "serve",
    "requests": "scan",
    "opentelemetry": "otel",
    "sigstore": "sigstore",
}


def extra_for_missing_module(modname: str) -> str | None:
    root = modname.split(".", 1)[0].lower().replace("-", "_")
    return _EXTRA_HINTS.get(root)


def require_extra(extra: str, what: str) -> Callable[[], None]:
    def _fail() -> None:
        print(
            f"picosentry: {what} requires the optional '{extra}' extra.\n"
            f"  Install it with:  pip install 'picosentry[{extra}]'\n"
            f"  Or install everything:  pip install 'picosentry[all]'",
            file=sys.stderr,
        )
        sys.exit(2)

    return _fail


def import_or_warn(import_fn: Callable[[], object], extra: str, what: str):
    try:
        return import_fn()
    except ImportError as e:
        missing = getattr(e, "name", None)
        if not missing:
            msg = str(e)
            for sep in ("No module named '", "No module named "):
                if sep in msg:
                    tail = msg.split(sep, 1)[1]
                    missing = tail.split("'", 1)[0].split()[0]
                    break
        detected = extra_for_missing_module(missing) if missing else None
        if detected is not None:
            require_extra(detected or extra, what)()
        raise


def forward_flag(argv: list[str], args: argparse.Namespace, *flags: str, boolean: bool = False, default=None) -> None:
    name = flags[0]  # use the long form for the flag name
    dest = name.lstrip("-").replace("-", "_")

    val = getattr(args, dest, None)

    if val is None and len(flags) > 1:
        short_dest = flags[1].lstrip("-").replace("-", "_")
        val = getattr(args, short_dest, None)

    if val is None or val in (default, ()):
        return

    if boolean:
        if val is True:
            argv.append(name)
    elif isinstance(val, list):
        argv.extend([name, *list(val)])
    else:
        argv.extend([name, str(val)])
