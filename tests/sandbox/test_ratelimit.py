"""Tests for rate limiting and job queuing."""

import threading
import time

from picosentry.sandbox.ratelimit import JobPriority, JobQueue, RateLimitConfig, TokenBucketLimiter


class TestTokenBucketLimiter:
    def test_allow_within_burst(self):
        limiter = TokenBucketLimiter(RateLimitConfig(rate_per_second=1.0, burst_size=5))
        for _ in range(5):
            assert limiter.allow("actor-1") is True

    def test_reject_over_burst(self):
        limiter = TokenBucketLimiter(RateLimitConfig(rate_per_second=1.0, burst_size=3))
        for _ in range(3):
            limiter.allow("actor-1")
        assert limiter.allow("actor-1") is False

    def test_tokens_refill(self):
        limiter = TokenBucketLimiter(RateLimitConfig(rate_per_second=100.0, burst_size=1))
        limiter.allow("actor-1")  # consume the 1 token
        assert limiter.allow("actor-1") is False
        time.sleep(0.02)  # wait for refill at 100/sec
        assert limiter.allow("actor-1") is True

    def test_independent_actors(self):
        limiter = TokenBucketLimiter(RateLimitConfig(rate_per_second=1.0, burst_size=2))
        assert limiter.allow("actor-a") is True
        assert limiter.allow("actor-a") is True
        assert limiter.allow("actor-a") is False
        # actor-b has its own bucket
        assert limiter.allow("actor-b") is True

    def test_global_rate_limit(self):
        limiter = TokenBucketLimiter(
            RateLimitConfig(
                rate_per_second=10.0,
                burst_size=100,
                global_rps=5.0,
            )
        )
        # Global burst is 50 (5*10), exhaust it
        for _ in range(50):
            assert limiter.allow("actor-1") is True
        assert limiter.allow("actor-2") is False  # global limit hit

    def test_get_status(self):
        limiter = TokenBucketLimiter()
        limiter.allow("actor-1")
        status = limiter.get_status("actor-1")
        assert status["actor"] == "actor-1"
        assert "tokens_available" in status

    def test_reset_actor(self):
        limiter = TokenBucketLimiter(RateLimitConfig(burst_size=1))
        limiter.allow("actor-1")
        assert limiter.allow("actor-1") is False
        limiter.reset("actor-1")
        assert limiter.allow("actor-1") is True

    def test_thread_safety(self):
        limiter = TokenBucketLimiter(RateLimitConfig(rate_per_second=100.0, burst_size=50))
        results = []

        def worker():
            for _ in range(20):
                results.append(limiter.allow("shared-actor"))

        threads = [threading.Thread(target=worker) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        # Some should succeed, some should fail
        assert len(results) == 100


class TestJobQueue:
    def test_enqueue_dequeue(self):
        q = JobQueue(max_size=10)
        job = q.enqueue(command=["echo", "test"], actor="user1")
        assert job is not None
        assert q.size() == 1
        dequeued = q.dequeue(timeout=1.0)
        assert dequeued is not None
        assert dequeued.job_id == job.job_id

    def test_priority_ordering(self):
        q = JobQueue(max_size=10)
        q.enqueue(command=["echo", "low"], actor="u1", priority=JobPriority.LOW)
        q.enqueue(command=["echo", "critical"], actor="u2", priority=JobPriority.CRITICAL)
        q.enqueue(command=["echo", "normal"], actor="u3", priority=JobPriority.NORMAL)

        first = q.dequeue(timeout=1.0)
        assert first.priority == JobPriority.CRITICAL
        second = q.dequeue(timeout=1.0)
        assert second.priority == JobPriority.NORMAL
        third = q.dequeue(timeout=1.0)
        assert third.priority == JobPriority.LOW

    def test_fifo_within_priority(self):
        q = JobQueue(max_size=10)
        q.enqueue(command=["echo", "1"], actor="u1", priority=JobPriority.NORMAL)
        q.enqueue(command=["echo", "2"], actor="u2", priority=JobPriority.NORMAL)
        first = q.dequeue(timeout=1.0)
        second = q.dequeue(timeout=1.0)
        assert first.actor == "u1"
        assert second.actor == "u2"

    def test_max_size_enforced(self):
        q = JobQueue(max_size=2)
        q.enqueue(command=["echo", "1"], actor="u1")
        q.enqueue(command=["echo", "2"], actor="u2")
        result = q.enqueue(command=["echo", "3"], actor="u3", priority=JobPriority.LOW)
        assert result is None  # dropped

    def test_complete_job(self):
        q = JobQueue(max_size=10)
        job = q.enqueue(command=["echo", "test"], actor="u1")
        dequeued = q.dequeue(timeout=1.0)  # noqa: F841
        q.complete(job.job_id, result={"verdict": "ALLOW"})
        result = q.get_result(job.job_id)
        assert result == {"verdict": "ALLOW"}

    def test_fail_job(self):
        q = JobQueue(max_size=10)
        job = q.enqueue(command=["echo", "test"], actor="u1")
        q.dequeue(timeout=1.0)
        q.fail(job.job_id, error="timeout")
        j = q.get(job.job_id)
        assert j.status == "failed"

    def test_get_stats(self):
        q = JobQueue(max_size=100)
        q.enqueue(command=["echo", "1"], actor="u1", priority=JobPriority.HIGH)
        q.enqueue(command=["echo", "2"], actor="u2", priority=JobPriority.LOW)
        stats = q.get_stats()
        assert stats["queue_size"] == 2
        assert stats["total_enqueued"] == 2

    def test_purge_expired(self):
        q = JobQueue(max_size=10)
        job = q.enqueue(command=["echo", "old"], actor="u1")  # noqa: F841
        # Manually set created_at to the past
        with q._lock:
            for j in q._heap:
                j.created_at = time.monotonic() - 7200
        expired = q.purge_expired(max_age_seconds=3600)
        assert expired == 1
        assert q.size() == 0

    def test_dequeue_timeout(self):
        q = JobQueue(max_size=10)
        result = q.dequeue(timeout=0.1)
        assert result is None  # empty queue, timeout expired
