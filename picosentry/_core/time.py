from __future__ import annotations

import time


def now_ms() -> float:
    return time.monotonic() * 1000