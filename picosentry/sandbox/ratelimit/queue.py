
from __future__ import annotations

import heapq
import logging
import threading
import time
import uuid
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any

logger = logging.getLogger("picodome.ratelimit.queue")


class JobPriority(IntEnum):

    CRITICAL = 0
    HIGH = 1
    NORMAL = 2
    LOW = 3


@dataclass(order=False)
class QueuedJob:

    job_id: str
    command: list[str]
    actor: str
    priority: JobPriority = JobPriority.NORMAL
    created_at: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)
    status: str = "queued"

    def __lt__(self, other: QueuedJob) -> bool:
        if self.priority != other.priority:
            return self.priority < other.priority
        return self.created_at < other.created_at

    def to_dict(self) -> dict[str, Any]:
        return {
            "actor": self.actor,
            "command": self.command,
            "created_at": self.created_at,
            "job_id": self.job_id,
            "metadata": self.metadata,
            "priority": self.priority.name,
            "status": self.status,
        }


class JobQueue:

    def __init__(self, max_size: int = 1000) -> None:
        self._heap: list[QueuedJob] = []
        self._jobs: dict[str, QueuedJob] = {}
        self._max_size = max_size
        self._lock = threading.Lock()
        self._not_empty = threading.Condition(self._lock)
        self._completed: dict[str, dict] = {}
        self._stats = {
            "enqueued": 0,
            "dequeued": 0,
            "completed": 0,
            "dropped": 0,
            "expired": 0,
        }

    def enqueue(
        self,
        command: list[str],
        actor: str,
        priority: JobPriority = JobPriority.NORMAL,
        metadata: dict[str, Any] | None = None,
    ) -> QueuedJob | None:
        with self._not_empty:
            if len(self._heap) >= self._max_size:

                if priority >= JobPriority.LOW:
                    self._stats["dropped"] += 1
                    logger.warning("Job queue full (%d), dropping LOW priority job", len(self._heap))
                    return None

                self._evict_lowest()
                if len(self._heap) >= self._max_size:
                    self._stats["dropped"] += 1
                    return None

            job_id = str(uuid.uuid4())[:8]
            job = QueuedJob(
                job_id=job_id,
                command=command,
                actor=actor,
                priority=priority,
                created_at=time.monotonic(),
                metadata=metadata or {},
            )
            heapq.heappush(self._heap, job)
            self._jobs[job_id] = job
            self._stats["enqueued"] += 1
            self._not_empty.notify()
            return job

    def dequeue(self, timeout: float | None = None) -> QueuedJob | None:
        deadline = None
        if timeout is not None:
            deadline = time.monotonic() + timeout

        with self._not_empty:
            while not self._heap:
                if deadline is not None:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        return None
                    self._not_empty.wait(timeout=remaining)
                else:
                    self._not_empty.wait(timeout=1.0)
                    if not self._heap:
                        continue

            if not self._heap:
                return None

            job = heapq.heappop(self._heap)
            job.status = "processing"
            self._stats["dequeued"] += 1
            return job

    def complete(self, job_id: str, result: dict | None = None) -> None:
        with self._lock:
            if job_id in self._jobs:
                self._jobs[job_id].status = "completed"
                if result:
                    self._completed[job_id] = result
                self._stats["completed"] += 1

    def fail(self, job_id: str, error: str = "") -> None:
        with self._lock:
            if job_id in self._jobs:
                self._jobs[job_id].status = "failed"
                self._stats["completed"] += 1

    def get(self, job_id: str) -> QueuedJob | None:
        with self._lock:
            return self._jobs.get(job_id)

    def get_result(self, job_id: str) -> dict | None:
        with self._lock:
            return self._completed.get(job_id)

    def list_pending(self, limit: int = 50) -> list[QueuedJob]:
        with self._lock:
            pending = [j for j in self._jobs.values() if j.status == "queued"]
            pending.sort()
            return pending[:limit]

    def size(self) -> int:
        with self._lock:
            return len(self._heap)

    def get_stats(self) -> dict[str, Any]:
        with self._lock:
            by_priority = {}
            for p in JobPriority:
                by_priority[p.name] = sum(1 for j in self._jobs.values() if j.priority == p and j.status == "queued")
            return {
                "queue_size": len(self._heap),
                "max_size": self._max_size,
                "by_priority": by_priority,
                "total_enqueued": self._stats["enqueued"],
                "total_dequeued": self._stats["dequeued"],
                "total_completed": self._stats["completed"],
                "total_dropped": self._stats["dropped"],
            }

    def purge_expired(self, max_age_seconds: float = 3600) -> int:
        with self._lock:
            cutoff = time.monotonic() - max_age_seconds
            expired_ids = [j.job_id for j in self._heap if j.created_at < cutoff and j.status == "queued"]
            for job_id in expired_ids:
                self._jobs[job_id].status = "expired"
                self._stats["expired"] += 1
            self._heap = [j for j in self._heap if j.job_id not in set(expired_ids)]
            heapq.heapify(self._heap)
            return len(expired_ids)

    def _evict_lowest(self) -> None:
        if not self._heap:
            return

        worst_idx = -1
        worst_priority = -1
        worst_time = -1.0
        for i, job in enumerate(self._heap):
            if job.priority.value > worst_priority or (
                job.priority.value == worst_priority and job.created_at > worst_time
            ):
                worst_idx = i
                worst_priority = job.priority.value
                worst_time = job.created_at

        if worst_idx >= 0:
            evicted = self._heap.pop(worst_idx)
            evicted.status = "dropped"
            self._stats["dropped"] += 1
            heapq.heapify(self._heap)
