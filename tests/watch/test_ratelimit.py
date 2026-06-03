"""Tests for PicoWatch rate limiter (sliding window)."""

from __future__ import annotations

import time

from picosentry.watch.ratelimit import RateLimiter


class TestRateLimiter:
    """Test sliding window rate limiter."""

    def test_allows_requests_under_limit(self) -> None:
        """Requests under the limit are allowed."""
        limiter = RateLimiter(max_requests=5, window_seconds=60)
        for _ in range(5):
            assert limiter.is_allowed("192.168.1.1") is True

    def test_blocks_requests_over_limit(self) -> None:
        """Requests over the limit are blocked."""
        limiter = RateLimiter(max_requests=3, window_seconds=60)
        for _ in range(3):
            limiter.is_allowed("10.0.0.1")
        assert limiter.is_allowed("10.0.0.1") is False

    def test_separate_ips_are_independent(self) -> None:
        """Each IP has its own rate limit counter."""
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        assert limiter.is_allowed("1.1.1.1") is True
        assert limiter.is_allowed("1.1.1.1") is True
        assert limiter.is_allowed("1.1.1.1") is False
        # Different IP should still be allowed
        assert limiter.is_allowed("2.2.2.2") is True

    def test_reset_specific_ip(self) -> None:
        """Resetting a specific IP clears only that IP's state."""
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        limiter.is_allowed("1.1.1.1")
        limiter.is_allowed("1.1.1.1")
        limiter.is_allowed("2.2.2.2")

        limiter.reset("1.1.1.1")
        # 1.1.1.1 should be allowed again
        assert limiter.is_allowed("1.1.1.1") is True
        # 2.2.2.2 still has 1 request, should be allowed
        assert limiter.is_allowed("2.2.2.2") is True

    def test_reset_all_ips(self) -> None:
        """Resetting with no IP clears all state."""
        limiter = RateLimiter(max_requests=1, window_seconds=60)
        limiter.is_allowed("1.1.1.1")
        limiter.is_allowed("2.2.2.2")

        limiter.reset()
        assert limiter.is_allowed("1.1.1.1") is True
        assert limiter.is_allowed("2.2.2.2") is True

    def test_active_clients_count(self) -> None:
        """active_clients reflects the number of tracked IPs."""
        limiter = RateLimiter(max_requests=10, window_seconds=60)
        assert limiter.active_clients == 0
        limiter.is_allowed("1.1.1.1")
        assert limiter.active_clients == 1
        limiter.is_allowed("2.2.2.2")
        assert limiter.active_clients == 2

    def test_default_values(self) -> None:
        """Default rate limiter has sensible defaults."""
        limiter = RateLimiter()
        assert limiter.max_requests == 100
        assert limiter.window_seconds == 60

    def test_window_expiry(self) -> None:
        """Timestamps outside the window are pruned and new requests allowed."""
        limiter = RateLimiter(max_requests=2, window_seconds=1)
        # Fill up the limit
        limiter.is_allowed("3.3.3.3")
        limiter.is_allowed("3.3.3.3")
        assert limiter.is_allowed("3.3.3.3") is False

        # Wait for window to expire
        time.sleep(1.1)
        # Should be allowed again after window expires
        assert limiter.is_allowed("3.3.3.3") is True

    def test_sliding_window_partial_expiry(self) -> None:
        """Old timestamps are pruned but recent ones remain."""
        limiter = RateLimiter(max_requests=3, window_seconds=2)
        limiter.is_allowed("4.4.4.4")
        time.sleep(0.3)
        limiter.is_allowed("4.4.4.4")
        time.sleep(0.3)
        limiter.is_allowed("4.4.4.4")

        # At the limit
        assert limiter.is_allowed("4.4.4.4") is False

        # Wait for first timestamp to expire
        time.sleep(1.5)
        # Old timestamps pruned, new requests allowed
        assert limiter.is_allowed("4.4.4.4") is True

    def test_blocked_request_does_not_consume_slot(self) -> None:
        """A blocked request doesn't add a timestamp."""
        limiter = RateLimiter(max_requests=2, window_seconds=60)
        limiter.is_allowed("5.5.5.5")
        limiter.is_allowed("5.5.5.5")
        # This one is blocked — it should NOT add a timestamp
        assert limiter.is_allowed("5.5.5.5") is False
        # Still at max — no slot consumed by blocked request
        assert limiter.is_allowed("5.5.5.5") is False

        limiter.reset("5.5.5.5")
        # After reset, should be allowed
        assert limiter.is_allowed("5.5.5.5") is True
