"""Event bus for pub/sub communication between components."""
import logging
import threading
import uuid
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger("picoshogun.EventBus")

@dataclass
class Event:
    id: str
    type: str
    source: str
    payload: dict[str, Any]
    timestamp: datetime
    priority: str = "normal"  # low, normal, high, critical

class EventBus:
    """Event bus with priority queues and filtering."""

    def __init__(self):
        self.subscribers: dict[str, list[Callable]] = defaultdict(list)
        self.persistent_subscribers: dict[str, list[str]] = defaultdict(list)
        self.event_history: list[Event] = []
        self.max_history = 1000
        self._lock = threading.Lock()
        self._running = True

    def subscribe(self, event_type: str, callback: Callable,
                  persistent: bool = False, subscriber_id: str = None) -> str:
        """Subscribe to events of a specific type."""
        sub_id = subscriber_id or str(uuid.uuid4())

        with self._lock:
            self.subscribers[event_type].append(callback)
            if persistent:
                self.persistent_subscribers[event_type].append(sub_id)

        logger.debug("Subscriber %s registered for %s", sub_id, event_type)
        return sub_id

    def unsubscribe(self, event_type: str, callback: Callable) -> bool:
        """Unsubscribe a callback."""
        with self._lock:
            if event_type in self.subscribers:
                try:
                    self.subscribers[event_type].remove(callback)
                    return True
                except ValueError:
                    pass
        return False

    def publish(self, event_type: str, payload: dict, source: str = "system",
                priority: str = "normal") -> Event:
        """Publish an event to all subscribers."""
        event = Event(
            id=str(uuid.uuid4()),
            type=event_type,
            source=source,
            payload=payload,
            timestamp=datetime.now(timezone.utc),
            priority=priority
        )

        with self._lock:
            self.event_history.append(event)
            if len(self.event_history) > self.max_history:
                self.event_history = self.event_history[-self.max_history:]

        # Notify subscribers (outside lock for non-blocking)
        callbacks = []
        with self._lock:
            callbacks = self.subscribers.get(event_type, []).copy()
            callbacks.extend(self.subscribers.get("*", []))  # Wildcard subscribers

        for callback in callbacks:
            try:
                callback(event)
            except Exception as e:
                logger.error("Event handler failed for %s: %s", event_type, e)

        logger.debug("Event published: %s (%s)", event_type, event.id)
        return event

    def get_history(self, event_type: str = None, limit: int = 100) -> list[Event]:
        """Get recent event history."""
        with self._lock:
            events = self.event_history
            if event_type:
                events = [e for e in events if e.type == event_type]
            return events[-limit:]

    def get_subscribers(self) -> dict[str, int]:
        """Get subscriber counts per event type."""
        with self._lock:
            return {k: len(v) for k, v in self.subscribers.items()}

    def clear_history(self):
        """Clear event history."""
        with self._lock:
            self.event_history.clear()

    def shutdown(self):
        """Shutdown event bus."""
        self._running = False
        with self._lock:
            self.subscribers.clear()
            self.persistent_subscribers.clear()
            self.event_history.clear()

# Global event bus instance
event_bus = EventBus()

# Convenience functions
def emit(event_type: str, **kwargs):
    """Quick event emission."""
    return event_bus.publish(event_type, kwargs)

def on(event_type: str, callback: Callable):
    """Quick subscription."""
    return event_bus.subscribe(event_type, callback)
