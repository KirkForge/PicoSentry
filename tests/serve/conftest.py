"""Shared pytest fixtures and configuration for PicoShogun tests."""

import atexit
import os
import shutil
import sys
import tempfile
import uuid
from pathlib import Path

import pytest
import contextlib

# Ensure project root is on sys.path
ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(ROOT))
os.environ["PICOSHOGUN_ENV"] = "test"
os.environ["PICOSHOGUN_SECRET_KEY"] = "test-key-for-pytest-at-least-32-bytes!"
# Registration defaults to OFF in production (see
# picosentry/serve/config/settings.py SecurityConfig.allow_registration).
# The /auth/register endpoint returns 403 unless we explicitly enable it for
# the test environment — these tests are end-to-end auth flows and need to be
# able to provision fresh users per test.
os.environ.setdefault("PICOSHOGUN_ALLOW_REGISTRATION", "true")
# The /scans endpoint is gated on PICOSHOGUN_SCANS_WORKSPACE_ROOT.  The
# test corpus uses /tmp as a safe workspace — it's writable, the tests
# are short-lived, and /tmp is the directory the test_integration suite
# was already passing.  Production must configure this explicitly.
os.environ.setdefault("PICOSHOGUN_SCANS_WORKSPACE_ROOT", "/tmp")
# SQLite tests must not share the default on-disk database.  When pytest-xdist
# runs workers in parallel, concurrent access to the same ``picoshogun.db`` file
# produces OperationalError (database is locked / table already exists).  Give
# every process its own fresh temp directory so each worker starts from a clean
# DB and cannot inherit stale schema/data left behind by a previous CI run or
# an overlapping test invocation.
_worker = os.environ.get("PYTEST_XDIST_WORKER", "master")
_run_id = uuid.uuid4().hex[:8]
_db_dir = Path(tempfile.mkdtemp(prefix=f"picoshogun-test-{_run_id}-{_worker}-"))
_db_path = _db_dir / "picoshogun.db"
os.environ["PICOSHOGUN_DATABASE_PATH"] = str(_db_path)
atexit.register(shutil.rmtree, _db_dir, ignore_errors=True)
# WAL mode on CI runners can produce disk I/O errors under pytest-xdist
# contention.  Use a classic rollback journal for the test DB; concurrency is
# serialized per worker anyway.  Synchronous=OFF keeps the test DB fast and
# avoids spurious I/O errors on over-contended CI temp storage.
os.environ["PICOSHOGUN_DATABASE_JOURNAL_MODE"] = "DELETE"
os.environ["PICOSHOGUN_DATABASE_SYNCHRONOUS"] = "OFF"


def _find_and_clear_rate_limiter(app):
    """Walk the middleware stack to find and reset RateLimitMiddleware."""
    from picosentry.serve.middleware.rate_limit import RateLimitMiddleware

    if not app.middleware_stack:
        return
    obj = app.middleware_stack
    depth = 0
    while obj is not None and depth < 30:
        if isinstance(obj, RateLimitMiddleware):
            obj.ip_requests.clear()
            obj.org_requests.clear()
            if obj._redis_backend is not None:
                with contextlib.suppress(Exception):
                    obj._redis_backend.reset()
            return
        if hasattr(obj, "app"):
            obj = obj.app
        else:
            break
        depth += 1


def _mock_dns_resolver(hostname):
    """Mock DNS resolver for tests — returns a safe public IP for any hostname.

    This avoids live DNS lookups during tests, which would fail in offline/CI
    environments and make webhook URL validation depend on external DNS.
    """
    # Return a well-known public IP (Cloudflare 1.1.1.1 resolver) for any hostname
    # that isn't already an IP literal. Private/loopback IPs are still caught
    # by the SSRF network check in _is_safe_webhook_url.
    import ipaddress

    try:
        # If it's already an IP, just return it — the SSRF checker handles it
        ipaddress.ip_address(hostname)
        return [hostname]
    except ValueError:
        pass
    # Known test hostnames that should resolve to specific IPs
    known = {
        "example.com": ["93.184.216.34"],
        "example.org": ["93.184.216.34"],
        "hook.example.com": ["93.184.216.34"],
        "hook2.example.com": ["93.184.216.34"],
    }
    if hostname in known:
        return known[hostname]
    # Default: return a safe public IP for any unknown hostname
    return ["93.184.216.34"]


@pytest.fixture(autouse=True)
def _patch_webhook_dns():
    """Patch webhook manager to use mock DNS resolver in tests."""
    from picosentry.serve.services.webhooks import webhook_manager

    original = webhook_manager.dns_resolver
    webhook_manager.dns_resolver = _mock_dns_resolver
    yield
    webhook_manager.dns_resolver = original


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    """Clear rate limiter state before each test to avoid 429 accumulation."""
    from fastapi.testclient import TestClient

    from picosentry.serve.api.server import app

    # Force middleware stack build if not yet built
    if not app.middleware_stack:
        try:
            tc = TestClient(app)
            tc.get("/health/live")
        except Exception:
            pass

    _find_and_clear_rate_limiter(app)
    yield
    _find_and_clear_rate_limiter(app)


@pytest.fixture(autouse=True)
def _shutdown_serve_otel():
    """Shut down any OpenTelemetry provider created by serve tests.

    Stops background OTLP export threads so the pytest process exits cleanly.
    """
    yield
    from picosentry.serve.services.observability import shutdown_telemetry

    shutdown_telemetry()
