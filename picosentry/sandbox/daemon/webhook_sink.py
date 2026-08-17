"""Bounded asynchronous wrapper for the (synchronous, retrying) WebhookSink.

Mirrors the serve app's audit-writer pattern (picosentry/serve/middleware/
audit.py): one FIFO queue + one writer thread + a monotonic drop counter, so
a slow/unreachable webhook (4 retries x 10s backoff) can never stall the
request thread that recorded the audit event.
"""

from __future__ import annotations

import contextlib
import logging
import os
import queue
import threading
import time
from typing import TYPE_CHECKING, Any

from picosentry.sandbox.audit.sinks.base import AuditSink, SinkConfig

if TYPE_CHECKING:
    from picosentry.sandbox.audit.logger import AuditEvent

logger = logging.getLogger("picodome.daemon.webhook_sink")

DEFAULT_QUEUE_SIZE = 256


class QueuedWebhookSink(AuditSink):
    def __init__(self, inner: AuditSink, maxsize: int | None = None) -> None:
        super().__init__(SinkConfig())
        self._inner = inner
        if maxsize is None:
            try:
                maxsize = max(1, int(os.environ.get("PICODOME_WEBHOOK_QUEUE", str(DEFAULT_QUEUE_SIZE))))
            except ValueError:
                maxsize = DEFAULT_QUEUE_SIZE
        self._queue: queue.Queue[AuditEvent | None] = queue.Queue(maxsize=maxsize)
        self.dropped = 0  # monotonic drop counter; surfaced via stats()
        self._writer: threading.Thread | None = None
        self._stopping = threading.Event()

    @property
    def name(self) -> str:
        return f"QueuedWebhookSink({self._inner.name})"

    def start(self) -> None:
        self._inner.start()
        self._stopping.clear()
        self._writer = threading.Thread(target=self._run, name="picodome-webhook-writer", daemon=True)
        self._writer.start()

    def send(self, event: AuditEvent) -> None:
        """Enqueue only — never blocks, never retries inline."""
        try:
            self._queue.put(event, block=False)
        except queue.Full:
            self.dropped += 1
            self._record_dropped()
            logger.warning("Webhook queue full — dropping event (dropped so far: %d)", self.dropped)

    def _run(self) -> None:
        while True:
            event = self._queue.get()
            try:
                if event is None or self._stopping.is_set():
                    return
                self._inner.send(event)
            except Exception:
                logger.exception("Unexpected error in webhook writer thread")
            finally:
                self._queue.task_done()

    def flush(self, timeout: float = 2.0) -> None:
        end = time.monotonic() + timeout
        while not self._queue.empty() and time.monotonic() < end:
            time.sleep(0.01)

    def stop(self) -> None:
        self._stopping.set()
        with contextlib.suppress(queue.Full):
            self._queue.put_nowait(None)  # sentinel — wake the writer if idle
        if self._writer is not None and self._writer.is_alive():
            self._writer.join(timeout=5.0)
        self._inner.stop()

    @property
    def stats(self) -> dict[str, Any]:
        inner_stats = getattr(self._inner, "stats", None)
        merged = dict(inner_stats) if inner_stats is not None else {}
        merged["queue_dropped"] = self.dropped
        merged["queue_depth"] = self._queue.qsize()
        return merged


__all__ = ["QueuedWebhookSink"]
