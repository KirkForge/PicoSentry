"""WO5.0.0-031 gate: serve multi-worker readiness.

Two layers, honestly labeled:

1. In-process tests exercise the cross-worker PROTOCOLS directly against the
   shared sqlite DB: two JobScheduler instances racing for one lease
   (exactly-one-fire + takeover), two RateLimitMiddleware instances sharing
   persisted counters, outbox publish→poll fanout onto a foreign bus, and
   WS slow-consumer isolation.
2. ONE end-to-end test boots TWO real uvicorn server processes against one
   shared sqlite DB — the actual production multi-worker topology (separate
   processes, zero shared memory) — and proves through real HTTP/WS:
   boot-time add_job convergence (simultaneous boot crashed on base with
   UNIQUE constraint failure), exactly one scheduler leader across the two
   processes, event fanout from worker A's API to worker B's WS + event
   history, and rate limits counted across workers.

   What this file does NOT prove: cron double-fire over real minute
   boundaries (the in-process lease tests cover the mechanism without
   wall-clock waits) and metrics aggregation (DECISION: per-worker
   /metrics, aggregation belongs to the scraper — see
   picosentry/serve/services/metrics.py docstring).
"""

from __future__ import annotations

import asyncio
import os
import socket
import time
from datetime import datetime, timedelta

import pytest

from picosentry.serve.middleware.rate_limit import RateLimitMiddleware
from picosentry.serve.services.event_bus import EventBus, OutboxPoller
from picosentry.serve.services.scheduler import JobScheduler, _utcnow
from picosentry.serve.services.websocket_manager import ConnectionManager


def _wait_until(predicate, timeout: float, interval: float = 0.05) -> bool:
    """Poll a predicate with small injected waits; no unbounded sleeps."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(interval)
    return predicate()


# ---------------------------------------------------------------------------
# (b) scheduler leader lease — in-process, two instances, one shared DB
# ---------------------------------------------------------------------------


class _LeaseClock:
    """Controllable replacement for scheduler._utcnow (no wall sleeps)."""

    def __init__(self) -> None:
        self.now = _utcnow()

    def __call__(self) -> datetime:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += timedelta(seconds=seconds)


def _fresh_scheduler(lease_ttl: int = 15, tick_sleep: float = 0.05) -> JobScheduler:
    sched = JobScheduler()
    sched.lease_ttl = lease_ttl
    sched._tick_sleep = tick_sleep
    return sched


def test_lease_held_exclusively_and_taken_over_on_expiry(monkeypatch) -> None:
    clock = _LeaseClock()
    monkeypatch.setattr("picosentry.serve.services.scheduler._utcnow", clock)
    a = _fresh_scheduler(lease_ttl=10)
    b = _fresh_scheduler(lease_ttl=10)

    assert a._try_acquire_lease() is True  # seed row is long expired
    assert b._try_acquire_lease() is False  # a holds it
    assert a._try_acquire_lease() is True  # holder renews unconditionally

    clock.advance(11)  # lease expired: a stopped heartbeating (crashed)
    assert b._try_acquire_lease() is True  # standby takes over
    assert a._try_acquire_lease() is False  # the old holder is demoted

    b._release_lease()
    assert a._try_acquire_lease() is True  # released lease is acquirable again
    a._release_lease()  # do not leak a fake-clock lease into the next test


def test_add_job_atomic_under_concurrent_boot(tmp_path) -> None:
    """Simultaneous lifespan add_job() from two workers must converge, not
    crash the loser on the name UNIQUE constraint (verified on base)."""
    a = _fresh_scheduler()
    b = _fresh_scheduler()
    name = f"boot_race_{int(time.time() * 1000)}"

    job_a = a.add_job(name=name, cron="* * * * *", command="cleanup", params={})
    job_b = b.add_job(name=name, cron="* * * * *", command="cleanup", params={})
    assert job_a == job_b  # both converged on the same row


# ---------------------------------------------------------------------------
# (a-lite) outbox fanout onto a foreign worker's bus — in-process
# ---------------------------------------------------------------------------


def test_outbox_fanout_to_foreign_bus() -> None:
    bus_a = EventBus()
    bus_a.outbox_enabled = True
    bus_b = EventBus()
    seen: list = []
    bus_b.subscribe("multi.test", seen.append)

    poller = OutboxPoller(bus_b, interval=0.05, retention_seconds=3600)
    poller.start()
    try:
        event = bus_a.publish("multi.test", {"v": 1}, source="test")
        assert _wait_until(lambda: len(seen) == 1, timeout=3), f"foreign dispatch missing: {seen}"
        assert seen[0].id == event.id
        assert seen[0].payload == {"v": 1}
        assert any(e.id == event.id for e in bus_b.get_history("multi.test", limit=50))

        # Own-worker events must not loop back: bus_b's own publish is
        # dispatched synchronously and skipped by its poller.
        own = bus_b.publish("multi.test", {"v": 2}, source="b")
        time.sleep(0.3)  # several poll intervals
        assert len([e for e in seen if e.id == own.id]) == 1
    finally:
        poller.stop()


def test_outbox_fanout_skips_local_only_side_effect_subscribers() -> None:
    """WO6.0.0-009: foreign rows must fan out to history + ordinary
    subscribers (WS) but SKIP local_only side-effect subscribers (the
    orchestrator correlation/escalation subscriber). Without this skip every
    worker re-fires escalation Nx — a false-outage generator in a security
    product."""
    bus_a = EventBus()
    bus_a.outbox_enabled = True
    bus_b = EventBus()
    plain_seen: list = []
    side_effect_seen: list = []
    bus_b.subscribe("multi.demux", plain_seen.append)
    bus_b.subscribe("multi.demux", side_effect_seen.append, local_only=True)

    poller = OutboxPoller(bus_b, interval=0.05, retention_seconds=3600)
    poller.start()
    try:
        bus_a.publish("multi.demux", {"v": 1}, source="worker-a")
        assert _wait_until(lambda: len(plain_seen) == 1, timeout=3), f"plain subscriber missed: {plain_seen}"
        time.sleep(0.3)  # several poll intervals — side_effect must never fire
        assert len(side_effect_seen) == 0, f"local_only side-effect re-fired for foreign row: {side_effect_seen}"
        assert any(e.type == "multi.demux" for e in bus_b.get_history("multi.demux", limit=50)), (
            "history missing foreign row"
        )

        # Sanity: bus_b's OWN publish still fires both (local_only only
        # applies to foreign/outbox-polled rows).
        own_plain: list = []
        own_side: list = []
        bus_b.subscribe("multi.demux2", own_plain.append)
        bus_b.subscribe("multi.demux2", own_side.append, local_only=True)
        bus_b.publish("multi.demux2", {"v": 2}, source="worker-b")
        assert len(own_plain) == 1 and len(own_side) == 1, "local publish did not fire local_only subscriber"
    finally:
        poller.stop()


# ---------------------------------------------------------------------------
# (c-lite) rate limit counted across two middleware instances — in-process
# ---------------------------------------------------------------------------


def test_rate_limit_counters_shared_across_two_instances() -> None:
    m1 = RateLimitMiddleware(app=None, max_requests_per_ip=3, window=60, persist=True, sync_interval=0.1)
    m2 = RateLimitMiddleware(app=None, max_requests_per_ip=3, window=60, persist=True, sync_interval=0.1)
    key = f"mw-{time.time()}-{os.getpid()}"

    now = time.time()
    for i in range(3):
        limited, _ = m1._record_and_check("ip", key, 3, now + i * 0.001, m1.ip_requests)
        assert not limited
    limited, _ = m1._record_and_check("ip", key, 3, now + 0.01, m1.ip_requests)
    assert limited, "worker 1 must be limited after its own 3 requests"

    # Beyond the sync window, worker 1's next request flushes its counts to
    # the shared table and worker 2's next request pulls them in: the same
    # client is limited on the other worker too. (Flushing is lazy — it
    # rides on the next request, which is the production behavior.)
    time.sleep(0.25)
    m1._record_and_check("ip", key, 3, now + 0.3, m1.ip_requests)
    limited, _ = m2._record_and_check("ip", key, 3, now + 0.31, m2.ip_requests)
    assert limited, "worker 2 did not see worker 1's counted requests"


# ---------------------------------------------------------------------------
# (d) WS slow consumer never blocks a fast consumer — in-process
# ---------------------------------------------------------------------------


class _SlowSocket:
    def __init__(self, delay: float) -> None:
        self.delay = delay
        self.sent: list[str] = []
        self.busy = False

    async def accept(self) -> None:
        pass

    async def send_text(self, message: str) -> None:
        self.busy = True
        await asyncio.sleep(self.delay)
        self.sent.append(message)
        self.busy = False


@pytest.mark.asyncio
async def test_slow_ws_consumer_does_not_block_fast_consumer() -> None:
    manager = ConnectionManager()
    manager.BROADCAST_DRAIN_TIMEOUT = 0.1
    fast, slow = _SlowSocket(delay=0.0), _SlowSocket(delay=0.4)
    await manager.connect(fast, channels=["*"], org_id=None)
    await manager.connect(slow, channels=["*"], org_id=None)

    started = time.monotonic()
    await manager.broadcast("multi.ws", {"n": 1})
    elapsed = time.monotonic() - started

    # The fast client's delivery must not wait for the slow one's 0.4s send
    # (broadcast itself gives up waiting at the 0.1s drain cap).
    assert elapsed < 0.35, f"broadcast serialized behind the slow consumer ({elapsed:.2f}s)"
    assert len(fast.sent) == 1, "fast consumer was not served first"

    await asyncio.sleep(0.45)  # slow send completes on its own schedule
    assert len(slow.sent) == 1


# ---------------------------------------------------------------------------
# end-to-end: two REAL uvicorn workers on one shared sqlite DB
# ---------------------------------------------------------------------------

_SUBPROC_TIMEOUT = 90.0


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
