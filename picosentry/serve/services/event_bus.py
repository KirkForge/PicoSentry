import json
import logging
import os
import socket
import threading
import uuid
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

logger = logging.getLogger("picoshogun.EventBus")

# Exceptions a subscriber callback is expected to raise for operational
# problems.  Programmer errors such as NameError or AssertionError should
# propagate so they are noticed.
_HANDLER_ERRORS: tuple[type[BaseException], ...] = (
    OSError,
    RuntimeError,
    ValueError,
    TypeError,
    AttributeError,
)

# Operational failures the outbox poller tolerates without dying: the DB
# may blip (locked, migrating); the poller retries on the next tick.
_POLL_ERRORS: tuple[type[BaseException], ...] = (
    OSError,
    RuntimeError,
    ValueError,
)

_OUTBOX_BATCH = 500


def worker_identity() -> str:
    """Stable per-process identity used to skip own outbox rows and to hold
    the scheduler lease."""
    return f"{socket.gethostname()}:{os.getpid()}:{uuid.uuid4().hex[:8]}"


@dataclass
class Event:
    id: str
    type: str
    source: str
    payload: dict[str, Any]
    timestamp: datetime
    priority: str = "normal"  # low, normal, high, critical
    org_id: str | None = None


class EventBus:
    """Thread-safe publish/subscribe event bus for decoupled inter-service messaging.

    Multi-worker mode (API_WORKERS>1 or PICOSHOGUN_EVENT_OUTBOX=true): every
    publish() is also persisted to the shared ``event_outbox`` table; each
    worker's OutboxPoller re-dispatches foreign rows to its own subscribers
    and history, so WS clients and the /events/history stream see events
    published on ANY worker. Single-process mode is unchanged — persistence
    and the poller only exist once outbox_enabled is flipped (server
    lifespan does that).
    """

    def __init__(self):
        self.subscribers: dict[str, list[Callable]] = defaultdict(list)
        self.persistent_subscribers: dict[str, list[str]] = defaultdict(list)
        self.event_history: list[Event] = []
        self.max_history = 1000
        self._lock = threading.Lock()
        self._running = True
        self.outbox_enabled = False
        self.worker_id = worker_identity()

    def subscribe(
        self, event_type: str, callback: Callable, persistent: bool = False, subscriber_id: str | None = None
    ) -> str:
        sub_id = subscriber_id or str(uuid.uuid4())

        with self._lock:
            self.subscribers[event_type].append(callback)
            if persistent:
                self.persistent_subscribers[event_type].append(sub_id)

        logger.debug("Subscriber %s registered for %s", sub_id, event_type)
        return sub_id

    def unsubscribe(self, event_type: str, callback: Callable) -> bool:
        with self._lock:
            if event_type in self.subscribers:
                try:
                    self.subscribers[event_type].remove(callback)
                    return True
                except ValueError:
                    pass
        return False

    def publish(
        self,
        event_type: str,
        payload: dict,
        source: str = "system",
        priority: str = "normal",
        org_id: str | None = None,
    ) -> Event:
        event = Event(
            id=str(uuid.uuid4()),
            type=event_type,
            source=source,
            payload=payload,
            timestamp=datetime.now(timezone.utc),
            priority=priority,
            org_id=org_id,
        )

        if self.outbox_enabled:
            self._persist_outbox(event)

        self._dispatch(event)
        logger.debug("Event published: %s (%s)", event_type, event.id)
        return event

    def _dispatch(self, event: Event) -> None:
        """Append to history and invoke matching subscribers."""
        with self._lock:
            self.event_history.append(event)
            if len(self.event_history) > self.max_history:
                self.event_history = self.event_history[-self.max_history :]

        callbacks = []
        with self._lock:
            callbacks = self.subscribers.get(event.type, []).copy()
            callbacks.extend(self.subscribers.get("*", []))  # Wildcard subscribers

        for callback in callbacks:
            try:
                callback(event)
            except _HANDLER_ERRORS:
                logger.exception("Event handler failed for %s", event.type)

    def _persist_outbox(self, event: Event) -> None:
        from picosentry.serve.database.manager import db

        try:
            db.execute_insert(
                "INSERT INTO event_outbox (id, type, source, payload, priority, org_id, worker_id, created_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    event.id,
                    event.type,
                    event.source,
                    json.dumps(event.payload, default=str),
                    event.priority,
                    event.org_id,
                    self.worker_id,
                    event.timestamp,
                ),
            )
        except _POLL_ERRORS:
            # Outbox persistence is best-effort: local delivery must not be
            # lost because the shared DB blinked. Ceiling: an event whose
            # insert failed is invisible to the other workers.
            logger.warning("Event outbox persist failed for %s; other workers will miss it", event.type, exc_info=True)

    def get_history(self, event_type: str | None = None, limit: int = 100, org_id: str | None = None) -> list[Event]:
        with self._lock:
            events = self.event_history
            if event_type:
                events = [e for e in events if e.type == event_type]
            if org_id is not None:
                events = [e for e in events if e.org_id == org_id]
            return events[-limit:]

    def get_subscribers(self) -> dict[str, int]:
        with self._lock:
            return {k: len(v) for k, v in self.subscribers.items()}

    def clear_history(self):
        with self._lock:
            self.event_history.clear()

    def shutdown(self):
        self._running = False
        with self._lock:
            self.subscribers.clear()
            self.persistent_subscribers.clear()
            self.event_history.clear()


class OutboxPoller:
    """Per-worker drain of the shared event_outbox table.

    Polls seq > last_seen every ``interval`` seconds and re-dispatches
    foreign rows onto the local bus. Rows created before this poller
    started are replayed into history ONLY — subscribers (webhooks, alert
    hub) must not observe side effects for events that predate the
    process. Own-worker rows are skipped (publish() already dispatched
    them synchronously).

    ponytail: DB polling, not LISTEN/NOTIFY or redis — the DB is already
    the shared substrate and polling at ~1s is one indexed range SELECT;
    upgrade to LISTEN/NOTIFY if sub-second fanout latency ever matters.
    """

    def __init__(self, bus: EventBus, interval: float = 1.0, retention_seconds: int = 3600):
        self.bus = bus
        self.interval = max(interval, 0.05)
        self.retention = timedelta(seconds=retention_seconds)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._started_at: datetime | None = None
        self._last_prune: datetime | None = None

    def start(self) -> None:
        if self.is_running():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name=f"event-outbox-{self.bus.worker_id[:12]}", daemon=True)
        self._thread.start()

    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
            self._thread = None

    def _db(self):
        from picosentry.serve.database.manager import db

        return db

    def _run(self) -> None:
        db = self._db()
        self._started_at = datetime.now(timezone.utc)
        try:
            row = db.execute_one("SELECT COALESCE(MAX(seq), 0) AS seq FROM event_outbox")
            last = int(row["seq"]) if row else 0
        except _POLL_ERRORS:
            logger.exception("Event outbox poller could not read starting seq; disabled")
            return
        logger.info("Event outbox poller started at seq=%d (interval=%.2fs)", last, self.interval)
        while not self._stop.is_set():
            try:
                last = self._drain(last)
                self._maybe_prune()
            except _POLL_ERRORS:
                logger.warning("Event outbox poll tick failed", exc_info=True)
            self._stop.wait(self.interval)

    def _drain(self, last: int) -> int:
        db = self._db()
        rows = db.execute(
            "SELECT seq, id, type, source, payload, priority, org_id, worker_id, created_at "
            "FROM event_outbox WHERE seq > ? ORDER BY seq LIMIT ?",
            (last, _OUTBOX_BATCH),
        )
        replay_cutoff = self._started_at
        for row in rows:
            last = max(last, int(row["seq"]))
            if row["worker_id"] == self.bus.worker_id:
                continue
            payload = json.loads(row["payload"]) if row["payload"] else {}
            event = Event(
                id=row["id"],
                type=row["type"],
                source=row["source"],
                payload=payload,
                timestamp=row["created_at"],
                priority=row["priority"] or "normal",
                org_id=row["org_id"],
            )
            if replay_cutoff is not None and event.timestamp < replay_cutoff:
                # Pre-boot row: warm the history only.
                with self.bus._lock:
                    self.bus.event_history.append(event)
                    if len(self.bus.event_history) > self.bus.max_history:
                        self.bus.event_history = self.bus.event_history[-self.bus.max_history :]
            else:
                self.bus._dispatch(event)
        return last

    def _maybe_prune(self) -> None:
        now = datetime.now(timezone.utc)
        if self._last_prune is not None and now - self._last_prune < timedelta(seconds=300):
            return
        self._last_prune = now
        db = self._db()
        db.execute("DELETE FROM event_outbox WHERE created_at < ?", (now - self.retention,))


event_bus = EventBus()


def on(event_type: str, callback: Callable):
    return event_bus.subscribe(event_type, callback)
