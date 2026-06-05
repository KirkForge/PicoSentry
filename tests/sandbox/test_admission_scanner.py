"""Tests for container image scanner — B18.

Covers:
- Image scanning disabled (no scan)
- Image scanning with mock daemon (CLEAN verdict)
- Image scanning with DENY verdict
- Image scanning with high-severity findings
- Fail-open when daemon unreachable
- Config from environment
- Multiple containers in one pod
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, ClassVar
from unittest import mock

import pytest

from picosentry.sandbox.admission import AdmissionRequest
from picosentry.sandbox.admission.scanner import SEVERITY_LEVELS, ImageScanner


class MockScanHandler(BaseHTTPRequestHandler):
    """Mock PicoDome daemon that returns scan results."""

    verdict: ClassVar[str] = "CLEAN"
    findings: ClassVar[list[dict[str, Any]]] = []

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(content_length)

        response = {
            "job_id": "test-job",
            "verdict": MockScanHandler.verdict,
            "findings": MockScanHandler.findings,
        }
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode("utf-8"))

    def log_message(self, format, *args):
        pass


@pytest.fixture
def mock_daemon():
    """Start a mock PicoDome daemon."""
    server = HTTPServer(("127.0.0.1", 0), MockScanHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()


def _make_pod_request(images: list[str]) -> AdmissionRequest:
    """Build an AdmissionRequest with container images."""
    containers = [{"name": f"c-{i}", "image": img} for i, img in enumerate(images)]
    return AdmissionRequest(
        uid="test-uid",
        kind={"group": "", "version": "v1", "kind": "Pod"},
        name="test-pod",
        namespace="default",
        operation="CREATE",
        object_raw={"apiVersion": "v1", "kind": "Pod", "spec": {"containers": containers}},
    )


class TestImageScannerDisabled:
    def test_disabled_allows_all(self):
        scanner = ImageScanner(enabled=False)
        req = _make_pod_request(["nginx:latest"])
        allowed, _ = scanner.scan_pod(req)
        assert allowed

    def test_disabled_by_default_env(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            scanner = ImageScanner()
            assert not scanner.enabled


class TestImageScannerClean:
    def test_clean_verdict_allowed(self, mock_daemon):
        MockScanHandler.verdict = "CLEAN"
        MockScanHandler.findings = []
        scanner = ImageScanner(enabled=True, daemon_url=mock_daemon)
        req = _make_pod_request(["nginx:latest"])
        allowed, _ = scanner.scan_pod(req)
        assert allowed


class TestImageScannerDeny:
    def test_deny_verdict_blocked(self, mock_daemon):
        MockScanHandler.verdict = "DENY"
        MockScanHandler.findings = [{"severity": "critical", "rule": "CVE-2024-1234"}]
        scanner = ImageScanner(enabled=True, daemon_url=mock_daemon)
        req = _make_pod_request(["vulnerable:latest"])
        allowed, reason = scanner.scan_pod(req)
        assert not allowed
        assert "denied" in reason.lower()

    def test_high_severity_blocked(self, mock_daemon):
        MockScanHandler.verdict = "CLEAN"
        MockScanHandler.findings = [{"severity": "high", "rule": "CVE-2024-5678"}]
        scanner = ImageScanner(enabled=True, min_severity="high", daemon_url=mock_daemon)
        req = _make_pod_request(["nginx:latest"])
        allowed, reason = scanner.scan_pod(req)
        assert not allowed
        assert "high" in reason.lower()

    def test_low_severity_allowed(self, mock_daemon):
        MockScanHandler.verdict = "CLEAN"
        MockScanHandler.findings = [{"severity": "low", "rule": "INFO-001"}]
        scanner = ImageScanner(enabled=True, min_severity="high", daemon_url=mock_daemon)
        req = _make_pod_request(["nginx:latest"])
        allowed, _ = scanner.scan_pod(req)
        assert allowed


class TestImageScannerFailOpen:
    def test_daemon_unreachable_allows(self):
        scanner = ImageScanner(enabled=True, daemon_url="http://localhost:1", timeout=1.0)
        req = _make_pod_request(["nginx:latest"])
        allowed, _ = scanner.scan_pod(req)
        assert allowed  # fail-open


class TestImageScannerMultipleContainers:
    def test_all_containers_scanned(self, mock_daemon):
        MockScanHandler.verdict = "CLEAN"
        MockScanHandler.findings = []
        scanner = ImageScanner(enabled=True, daemon_url=mock_daemon)
        req = _make_pod_request(["nginx:latest", "redis:7", "postgres:16"])
        allowed, _ = scanner.scan_pod(req)
        assert allowed

    def test_one_bad_image_blocks(self, mock_daemon):
        # First scan returns CLEAN, second returns DENY
        call_count = [0]
        original_post = MockScanHandler.do_POST

        def alternating_post(self):
            call_count[0] += 1
            if call_count[0] % 2 == 0:
                MockScanHandler.verdict = "DENY"
                MockScanHandler.findings = [{"severity": "critical"}]
            else:
                MockScanHandler.verdict = "CLEAN"
                MockScanHandler.findings = []
            original_post(self)

        MockScanHandler.do_POST = alternating_post
        scanner = ImageScanner(enabled=True, daemon_url=mock_daemon)
        req = _make_pod_request(["nginx:latest", "bad:latest"])
        allowed, _reason = scanner.scan_pod(req)
        assert not allowed


class TestImageScannerConfig:
    def test_min_severity_level(self):
        scanner = ImageScanner(min_severity="critical")
        assert scanner.min_severity_level == SEVERITY_LEVELS["critical"]

    def test_env_config(self):
        with mock.patch.dict(
            os.environ,
            {
                "PICODOME_ADMISSION_SCAN_ENABLED": "true",
                "PICODOME_ADMISSION_DAEMON_URL": "http://mydaemon:8443",
            },
        ):
            scanner = ImageScanner()
            assert scanner.enabled
            assert scanner.daemon_url == "http://mydaemon:8443"

    def test_empty_pod_allowed(self):
        scanner = ImageScanner(enabled=True)
        req = AdmissionRequest(
            uid="t",
            kind={},
            name="t",
            namespace="d",
            operation="CREATE",
            object_raw={},
        )
        allowed, _ = scanner.scan_pod(req)
        assert allowed
