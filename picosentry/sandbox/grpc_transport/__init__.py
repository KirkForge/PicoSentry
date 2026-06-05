"""PicoDome gRPC Transport — optional high-throughput transport for daemon mode.

This module provides gRPC client and server implementations as an alternative
to the built-in HTTP daemon. gRPC is OPTIONAL — if ``grpcio`` is not installed,
imports will not crash; the module degrades gracefully with a warning log.

Design principles:
  - gRPC is an opt-in transport, not the default.
  - The existing HTTP daemon must work unchanged.
  - All gRPC calls are audit-logged.
  - TLS/mTLS support via the existing mTLS module.
  - Lazy imports — grpcio is only loaded when actually needed.
"""

from __future__ import annotations

import logging

logger = logging.getLogger("picodome.grpc_transport")

_GRPC_AVAILABLE: bool | None = None


def is_grpc_available() -> bool:
    """Check if grpcio is installed and importable.

    Returns True if grpcio is available, False otherwise.
    Caches the result after first check.
    """
    global _GRPC_AVAILABLE
    if _GRPC_AVAILABLE is None:
        try:
            import grpc  # noqa: F401

            _GRPC_AVAILABLE = True
            logger.debug("grpcio is available")
        except ImportError:
            _GRPC_AVAILABLE = False
            logger.warning("grpcio is not installed — gRPC transport unavailable. Install with: pip install grpcio")
    return _GRPC_AVAILABLE


__all__ = [
    "PicoDomeGRPCClient",
    "PicoDomeGRPCServer",
    "is_grpc_available",
]

# Lazy imports — only resolve when accessed


def __getattr__(name: str):
    if name == "PicoDomeGRPCServer":
        from picosentry.sandbox.grpc_transport.server import PicoDomeGRPCServer

        return PicoDomeGRPCServer
    if name == "PicoDomeGRPCClient":
        from picosentry.sandbox.grpc_transport.client import PicoDomeGRPCClient

        return PicoDomeGRPCClient
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
