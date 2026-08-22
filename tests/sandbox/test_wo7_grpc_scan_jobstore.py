"""WO7.0.0-014: gRPC Scan persists to job_store, tenant-scoped."""

from __future__ import annotations

import time
from unittest.mock import MagicMock

from picosentry.sandbox.grpc_transport._servicer import PicoDomeServicer


class FakeSandboxResult:
    def __init__(self, verdict="ALLOW", exit_code=0):
        self.overall_verdict = type("V", (), {"value": verdict})()
        self.exit_code = exit_code
        self.duration_ms = 1

    def to_dict(self, deterministic=False):
        return {"verdict": self.overall_verdict.value}


class FakeAnalysisResult:
    def __init__(self, verdict="CLEAN"):
        self.overall_verdict = type("V", (), {"value": verdict})()
        self.findings = []

    def to_dict(self, deterministic=False):
        return {"verdict": self.overall_verdict.value}


def _servicer_with_store(job_store):
    engine = MagicMock()
    engine.scan = lambda **kw: FakeSandboxResult()
    engine.analyze = lambda sr, **kw: FakeAnalysisResult()
    servicer = PicoDomeServicer(
        scan_engine=engine,
        start_time=time.time(),
        scan_count_ref=MagicMock(),
        job_store=job_store,
    )
    return servicer


def test_scan_persists_to_job_store():
    """A gRPC Scan call creates a job_store row with matching job_id."""
    added = {}
    updated = {}

    class FakeStore:
        def add(self, job_id, command, actor, tenant_id=None):
            added["job_id"] = job_id
            added["command"] = command
            added["actor"] = actor
            added["tenant_id"] = tenant_id
            return {"job_id": job_id, "status": "pending"}

        def update(self, job_id, **kwargs):
            updated["job_id"] = job_id
            updated.update(kwargs)

    servicer = _servicer_with_store(FakeStore())

    request = MagicMock()
    request.command = ["echo", "hello"]
    request.policy = ""
    request.timeout = 30.0
    request.cwd = ""

    context = MagicMock()
    context.invocation_metadata.return_value = []

    result = servicer.Scan(request, context)

    assert added["job_id"] is not None
    assert added["command"] == ["echo", "hello"]
    assert result.job_id == added["job_id"]
    assert updated["job_id"] == added["job_id"]
    assert updated["status"] == "completed"


def test_scan_without_store_does_not_crash():
    """No job_store injected → scan still works, just not persisted."""
    servicer = _servicer_with_store(None)

    request = MagicMock()
    request.command = ["echo", "hello"]
    request.policy = ""
    request.timeout = 30.0
    request.cwd = ""

    context = MagicMock()
    context.invocation_metadata.return_value = []

    result = servicer.Scan(request, context)
    assert result is not None


def test_scan_tenant_id_persisted():
    """The job_store row carries the resolved tenant_id."""

    class FakeStore:
        def __init__(self):
            self.last_tenant = None

        def add(self, job_id, command, actor, tenant_id=None):
            self.last_tenant = tenant_id
            return {"job_id": job_id}

        def update(self, job_id, **kwargs):
            pass

    store = FakeStore()
    servicer = _servicer_with_store(store)

    request = MagicMock()
    request.command = ["echo", "hello"]
    request.policy = ""
    request.timeout = 30.0
    request.cwd = ""

    context = MagicMock()
    context.invocation_metadata.return_value = []

    servicer.Scan(request, context)
    assert store.last_tenant is not None
