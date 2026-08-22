"""WO7.0.0-026: gRPC Health() caches check_health to prevent DoS."""

from __future__ import annotations

import threading
import time
from unittest.mock import MagicMock, patch

from picosentry.sandbox.grpc_transport._servicer import PicoDomeServicer


def _servicer():
    return PicoDomeServicer(scan_engine=MagicMock(), start_time=time.time(), scan_count_ref=MagicMock())


def test_health_caches_check_health_within_ttl():
    servicer = _servicer()
    servicer._health_cache_ttl = 5.0

    call_count = {"n": 0}

    class _Check:
        def __init__(self, healthy=True):
            self.healthy = healthy

    def _fake_check_health():
        call_count["n"] += 1
        return [_Check()]

    with patch("picosentry.sandbox.health.check_health", side_effect=_fake_check_health):
        for _ in range(10):
            request = MagicMock()
            context = MagicMock()
            servicer.Health(request, context)

    assert call_count["n"] == 1, f"check_health called {call_count['n']} times, expected 1 (cached)"


def test_health_cache_expires_after_ttl():
    servicer = _servicer()
    servicer._health_cache_ttl = 0.05

    call_count = {"n": 0}

    class _Check:
        def __init__(self, healthy=True):
            self.healthy = healthy

    def _fake_check_health():
        call_count["n"] += 1
        return [_Check()]

    with patch("picosentry.sandbox.health.check_health", side_effect=_fake_check_health):
        servicer.Health(MagicMock(), MagicMock())
        servicer.Health(MagicMock(), MagicMock())
        time.sleep(0.06)
        servicer.Health(MagicMock(), MagicMock())

    assert call_count["n"] == 2, f"check_health called {call_count['n']} times, expected 2 (cache expired once)"


def test_health_concurrent_calls_share_one_check():
    servicer = _servicer()
    servicer._health_cache_ttl = 5.0

    barrier = threading.Barrier(20)
    call_count = {"n": 0}
    lock = threading.Lock()

    class _Check:
        def __init__(self, healthy=True):
            self.healthy = healthy

    def _fake_check_health():
        with lock:
            call_count["n"] += 1
        return [_Check()]

    def _hit():
        barrier.wait(timeout=5)
        servicer.Health(MagicMock(), MagicMock())

    with patch("picosentry.sandbox.health.check_health", side_effect=_fake_check_health):
        threads = [threading.Thread(target=_hit) for _ in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

    assert call_count["n"] <= 2, f"concurrent calls caused {call_count['n']} check_health invocations"
