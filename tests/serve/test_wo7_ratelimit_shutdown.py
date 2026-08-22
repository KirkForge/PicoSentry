"""WO7.0.0-029: rate-limit background flush thread must stop in lifespan/SIGTERM shutdown.

Without calling rate_limiter.shutdown() before db.close(), the flush thread
keeps writing after the DB is closed, producing spurious persistence errors.
"""

from __future__ import annotations

import time
from unittest.mock import patch

from fastapi.testclient import TestClient

from picosentry.serve.api import server as server_mod
from picosentry.serve.middleware.rate_limit import RateLimitMiddleware


def _find_rate_limiter(app) -> RateLimitMiddleware | None:
    """Walk the middleware stack to find the RateLimitMiddleware instance."""
    node = getattr(app, "middleware_stack", None)
    while node is not None:
        if isinstance(node, RateLimitMiddleware):
            return node
        node = getattr(node, "app", None)
    return None


class TestRateLimiterShutdown:
    def test_shutdown_stops_flush_thread(self):
        """RateLimitMiddleware.shutdown() must stop the background flush thread.

        A persist=True instance starts a flush thread; shutdown() must set the
        stop event and join the thread so no post-shutdown flush can run.
        """
        mw = RateLimitMiddleware(app=None, max_requests_per_ip=5, window=60, persist=True, sync_interval=0.1)
        assert hasattr(mw, "_flush_thread"), "flush thread was never started"
        assert mw._flush_thread.is_alive(), "flush thread not running"
        assert not mw._flush_stop.is_set(), "stop event already set"
        mw.shutdown()
        assert mw._flush_stop.is_set(), "shutdown() did not set the stop event"
        assert not mw._flush_thread.is_alive(), "flush thread still running after shutdown()"

    def test_shutdown_noop_without_flush_thread(self):
        """shutdown() must not crash when persist=False (no flush thread started)."""
        mw = RateLimitMiddleware(app=None, max_requests_per_ip=5, window=60, persist=False)
        assert not hasattr(mw, "_flush_thread"), "flush thread should not exist with persist=False"
        mw.shutdown()

    def test_stop_rate_limiter_helper_calls_shutdown(self):
        """_stop_rate_limiter() must find the mounted instance and call shutdown()."""
        with TestClient(server_mod.app) as client:
            assert client.get("/health").status_code == 200
            rl = _find_rate_limiter(server_mod.app)
            assert rl is not None, "RateLimitMiddleware not mounted"
            with patch.object(rl, "shutdown") as mock_shutdown:
                server_mod._stop_rate_limiter()
            mock_shutdown.assert_called_once(), "_stop_rate_limiter() did not call shutdown() on the mounted instance"

    def test_stop_rate_limiter_noop_when_stack_not_built(self):
        """_stop_rate_limiter must not crash when middleware_stack is None."""
        with patch.object(server_mod.app, "middleware_stack", None):
            server_mod._stop_rate_limiter()

    def test_lifespan_shutdown_calls_stop_rate_limiter(self):
        """The lifespan shutdown path must call _stop_rate_limiter before db.close().

        We patch _stop_rate_limiter and db.close to record call order; the
        rate limiter must stop first to avoid post-close flush errors.
        """
        call_order: list[str] = []
        original_stop = server_mod._stop_rate_limiter
        original_close = server_mod.db.close

        def _tracking_stop():
            call_order.append("stop_rate_limiter")
            original_stop()

        def _tracking_close():
            call_order.append("db_close")
            original_close()

        with (
            patch.object(server_mod, "_stop_rate_limiter", _tracking_stop),
            patch.object(server_mod.db, "close", _tracking_close),
            TestClient(server_mod.app) as client,
        ):
            assert client.get("/health").status_code == 200

        assert "stop_rate_limiter" in call_order, "lifespan shutdown did not call _stop_rate_limiter"
        assert "db_close" in call_order, "lifespan shutdown did not call db.close"
        rl_idx = call_order.index("stop_rate_limiter")
        db_idx = call_order.index("db_close")
        assert rl_idx < db_idx, (
            f"db.close() (step {db_idx}) ran before _stop_rate_limiter (step {rl_idx}) — "
            "flush thread can write after DB is closed"
        )

    def test_flush_thread_does_not_run_after_shutdown(self):
        """After shutdown(), the flush loop must not execute any more ticks.

        A persist=True instance with a short sync interval will tick the flush
        loop; after shutdown() the loop must exit cleanly without errors.
        """
        mw = RateLimitMiddleware(app=None, max_requests_per_ip=5, window=60, persist=True, sync_interval=0.05)
        time.sleep(0.1)
        assert mw._flush_thread.is_alive(), "flush thread should be ticking"
        mw.shutdown()
        # Give the thread time to exit.
        mw._flush_thread.join(timeout=2)
        assert not mw._flush_thread.is_alive(), "flush thread did not exit after shutdown()"
