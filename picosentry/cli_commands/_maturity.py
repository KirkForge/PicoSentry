"""Maturity badges and warnings for beta/experimental subcommands."""

from __future__ import annotations

import os
import sys
from collections.abc import Callable


_COMMAND_MATURITY: dict[str, tuple[str, str]] = {
    "scan": ("STABLE", "Core supply-chain scanner (7 ecosystems)."),
    "sandbox": (
        "STABLE",
        "Runtime sandbox + behavioral analysis. seccomp-bpf backend is Linux-only.",
    ),
    "watch": (
        "STABLE",
        "LLM prompt-injection detection and output validation. "
        "Deterministic regex + lexical classifier; not a semantic/LLM guarantee.",
    ),
    "serve": (
        "BETA",
        "API server, dashboard, and orchestration. Security review and regression tests in place.",
    ),
    "daemon": (
        "BETA",
        "Sandbox daemon (HTTP API + optional gRPC). Auth, rate limiting, TLS/mTLS, and audit in place.",
    ),
    "admission": (
        "BETA",
        "K8s admission webhook server. Validates pod security contexts and "
        "optionally scans container images via the daemon.",
    ),
    "corpus": (
        "STABLE",
        "Corpus marketplace — export, import, validate, sign, and list IoC packs.",
    ),
}


def emit_maturity_warning(command: str, quiet: bool = False) -> None:
    if command not in _COMMAND_MATURITY:
        return
    badge, summary = _COMMAND_MATURITY[command]
    if badge == "STABLE":
        return
    if os.environ.get("PICOSENTRY_MATURITY_ACK") == "1":
        return
    if quiet and badge == "BETA":
        return
    icon = "⚠️" if badge == "BETA" else "🔬"
    print(
        f"{icon}  picosentry {command} is {badge}. {summary}",
        file=sys.stderr,
    )
    print(
        "    Set PICOSENTRY_MATURITY_ACK=1 to suppress this warning.",
        file=sys.stderr,
    )


def maturity_badge(command: str) -> str:
    return _COMMAND_MATURITY.get(command, ("UNKNOWN", ""))[0]


def wrap_with_maturity(command: str, quiet: bool = False) -> Callable[[Callable[[], int]], Callable[[], int]]:
    """Decorator-style helper for simple commands that just need a warning."""

    def _decorator(fn: Callable[[], int]) -> Callable[[], int]:
        def _run() -> int:
            emit_maturity_warning(command, quiet=quiet)
            return fn()

        return _run

    return _decorator
