from __future__ import annotations

import logging
import os

try:
    import resource

    HAS_RESOURCE = True
except ImportError:
    HAS_RESOURCE = False

logger = logging.getLogger("picodome.l3.rlimits")

_DEFAULT_MEMORY_LIMIT_MB = 512
_DEFAULT_FILE_SIZE_LIMIT_MB = 100


def set_resource_limits() -> None:
    if not HAS_RESOURCE:
        return
    try:
        memory_mb = int(os.environ.get("PICODOME_MEMORY_LIMIT_MB", _DEFAULT_MEMORY_LIMIT_MB))
        file_size_mb = int(os.environ.get("PICODOME_FILE_SIZE_LIMIT_MB", _DEFAULT_FILE_SIZE_LIMIT_MB))
    except (ValueError, TypeError):
        memory_mb = _DEFAULT_MEMORY_LIMIT_MB
        file_size_mb = _DEFAULT_FILE_SIZE_LIMIT_MB
    memory_bytes = memory_mb * 1024 * 1024
    file_size_bytes = file_size_mb * 1024 * 1024
    resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
    resource.setrlimit(resource.RLIMIT_FSIZE, (file_size_bytes, file_size_bytes))
    resource.setrlimit(resource.RLIMIT_NOFILE, (256, 256))
