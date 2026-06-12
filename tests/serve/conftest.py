"""Shared pytest fixtures and configuration for PicoShogun tests."""
import os
import sys
from pathlib import Path

import pytest

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
            return
        if hasattr(obj, 'app'):
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
