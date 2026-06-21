from __future__ import annotations

import importlib.util
import logging

logger = logging.getLogger("picodome.grpc_transport")

_GRPC_AVAILABLE: bool | None = None


def is_grpc_available() -> bool:
    global _GRPC_AVAILABLE
    if _GRPC_AVAILABLE is None:
        if importlib.util.find_spec("grpc") is not None:
            _GRPC_AVAILABLE = True
            logger.debug("grpcio is available")
        else:
            _GRPC_AVAILABLE = False
            logger.warning("grpcio is not installed — gRPC transport unavailable. Install with: pip install grpcio")
    return _GRPC_AVAILABLE


__all__ = [
    "PicoDomeGRPCClient",
    "PicoDomeGRPCServer",
    "is_grpc_available",
]


def __getattr__(name: str):
    if name == "PicoDomeGRPCServer":
        from picosentry.sandbox.grpc_transport.server import PicoDomeGRPCServer

        return PicoDomeGRPCServer
    if name == "PicoDomeGRPCClient":
        from picosentry.sandbox.grpc_transport.client import PicoDomeGRPCClient

        return PicoDomeGRPCClient
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
