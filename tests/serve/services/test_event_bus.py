"""Regression tests for EventBus exception narrowing (P4 #10)."""

from __future__ import annotations

import pytest

from picosentry.serve.services.event_bus import EventBus


class TestEventBusExceptionNarrowing:
    """Subscriber failures must be isolated, but programmer errors must propagate."""

    def test_operational_handler_error_is_isolated(self, caplog):
        bus = EventBus()
        calls = []

        def _good(event):
            calls.append(event)

        def _bad(event):
            raise RuntimeError("subscriber operational failure")

        bus.subscribe("test.event", _good)
        bus.subscribe("test.event", _bad)

        with caplog.at_level("ERROR", logger="picoshogun.EventBus"):
            bus.publish("test.event", {"payload": 1})

        assert len(calls) == 1
        assert "subscriber operational failure" in caplog.text

    def test_unexpected_handler_error_propagates(self):
        bus = EventBus()

        def _bad(event):
            raise NameError("programmer bug")

        bus.subscribe("test.event", _bad)
        with pytest.raises(NameError, match="programmer bug"):
            bus.publish("test.event", {"payload": 1})

    def test_later_subscribers_still_run_after_operational_error(self, caplog):
        bus = EventBus()
        calls = []

        def _bad(event):
            raise ValueError("bad subscriber")

        def _good(event):
            calls.append(event)

        bus.subscribe("test.event", _bad)
        bus.subscribe("test.event", _good)

        with caplog.at_level("ERROR", logger="picoshogun.EventBus"):
            bus.publish("test.event", {"payload": 1})

        assert len(calls) == 1
