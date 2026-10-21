"""Tests for container image scanner — B18.

Covers:
- Image scanning disabled (no scan)
- Image scanning with mock daemon (CLEAN verdict)
- Image scanning with DENY verdict
- Image scanning with high-severity findings
- Fail-closed when daemon unreachable (default)
- Opt-out fail-open when daemon unreachable
- Config from environment
- Multiple containers in one pod
- CLI argument defaults
"""

from __future__ import annotations

import argparse
import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any, ClassVar
from unittest import mock

import pytest

from picosentry.sandbox.admission import AdmissionRequest
from picosentry.sandbox.admission.scanner import (
    SEVERITY_LEVELS,
    ImageScanner,
    _assert_daemon_url_safe,
)
from picosentry.sandbox.cli_commands.admission import add_arguments


class MockScanHandler(BaseHTTPRequestHandler):
    """Mock PicoDome daemon that returns scan results."""

    verdict: ClassVar[str] = "CLEAN"
    findings: ClassVar[list[dict[str, Any]]] = []
    l3_verdict: ClassVar[str | None] = None
    l4_verdict: ClassVar[str | None] = None

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(content_length)

        # The REAL /api/v1/scan response shape (sandbox/daemon/
        # handler_routes_post.py): l3_verdict / l4_verdict / findings_count
        # plus an `analysis` dict. WO9.0.0-001: the old mock returned a
        # made-up `verdict`/`findings` shape that the scanner happened to
        # read, so these tests passed while the real daemon's response was
        # never understood — the mock was validating the bug.
        l3 = MockScanHandler.l3_verdict or ("DENY" if MockScanHandler.verdict == "DENY" else "ALLOW")
        l4 = MockScanHandler.l4_verdict or ("MALICIOUS" if MockScanHandler.verdict == "DENY" else "CLEAN")
        response = {
            "job_id": "test-job",
            "l3_verdict": l3,
            "l4_verdict": l4,
            "findings_count": len(MockScanHandler.findings),
            "analysis": {
                "findings": MockScanHandler.findings,
                "overall_verdict": l4,
            },
        }
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(response).encode("utf-8"))

    def log_message(self, format, *args):
        pass


@pytest.fixture
def mock_daemon():
    """Start a mock PicoDome daemon.

    The handler's response is class-level state, so it is reset on both entry
    and exit — otherwise one test's verdict leaks into the next.
    """
    MockScanHandler.verdict = "CLEAN"
    MockScanHandler.findings = []
    MockScanHandler.l3_verdict = None
    MockScanHandler.l4_verdict = None
    server = HTTPServer(("127.0.0.1", 0), MockScanHandler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield f"http://127.0.0.1:{port}"
    server.shutdown()
    MockScanHandler.verdict = "CLEAN"
    MockScanHandler.findings = []
    MockScanHandler.l3_verdict = None
    MockScanHandler.l4_verdict = None


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


class TestImageScannerFailClosed:
    def test_daemon_unreachable_denies_by_default(self):
        scanner = ImageScanner(enabled=True, daemon_url="http://localhost:1", timeout=1.0)
        req = _make_pod_request(["nginx:latest"])
        allowed, reason = scanner.scan_pod(req)
        assert not allowed
        assert "unreachable" in reason.lower() or "scan" in reason.lower()

    def test_daemon_unreachable_allows_when_opted_out(self):
        scanner = ImageScanner(
            enabled=True,
            daemon_url="http://localhost:1",
            timeout=1.0,
            fail_closed=False,
        )
        req = _make_pod_request(["nginx:latest"])
        allowed, _ = scanner.scan_pod(req)
        assert allowed


class TestImageScannerMultipleContainers:
    def test_all_containers_scanned(self, mock_daemon):
        MockScanHandler.verdict = "CLEAN"
        MockScanHandler.findings = []
        scanner = ImageScanner(enabled=True, daemon_url=mock_daemon)
        req = _make_pod_request(["nginx:latest", "redis:7", "postgres:16"])
        allowed, _ = scanner.scan_pod(req)
        assert allowed

    def test_one_bad_image_blocks(self, mock_daemon, monkeypatch):
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

        # monkeypatch restores the class method at teardown; assigning it
        # directly leaked the alternation into every later test.
        monkeypatch.setattr(MockScanHandler, "do_POST", alternating_post)
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
            assert scanner._fail_closed

    def test_env_fail_closed_opt_out(self):
        with mock.patch.dict(
            os.environ,
            {
                "PICODOME_ADMISSION_SCAN_ENABLED": "true",
                "PICODOME_ADMISSION_FAIL_CLOSED": "false",
            },
        ):
            scanner = ImageScanner()
            assert not scanner._fail_closed

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


class TestAdmissionCLIFailClosed:
    def _parse(self, argv: list[str]) -> argparse.Namespace:
        parser = argparse.ArgumentParser()
        subparsers = parser.add_subparsers()
        add_arguments(subparsers)
        return parser.parse_args(argv)

    def test_scan_fail_closed_defaults_true(self):
        args = self._parse(["admission", "--cert-file=/tmp/t.crt", "--key-file=/tmp/t.key", "--scan-enabled"])
        assert args.scan_fail_closed is True

    def test_scan_fail_closed_can_be_disabled(self):
        args = self._parse(
            [
                "admission",
                "--cert-file=/tmp/t.crt",
                "--key-file=/tmp/t.key",
                "--scan-enabled",
                "--no-scan-fail-closed",
            ]
        )
        assert args.scan_fail_closed is False


class TestDaemonURLSSRFGuard:
    """B-gap #7: a misconfigured daemon URL must not reach a metadata endpoint."""

    @pytest.mark.parametrize(
        "url",
        [
            "http://127.0.0.1:8443",  # loopback default — legitimate
            "http://localhost:8443",
            "http://10.0.0.5:8443",  # cluster-internal — legitimate
            "http://picodome-daemon.svc:8443",  # k8s service DNS
            "https://mydaemon.example.com",
        ],
    )
    def test_safe_urls_allowed(self, url):
        _assert_daemon_url_safe(url)  # must not raise

    @pytest.mark.parametrize(
        "url",
        [
            "http://169.254.169.254/latest/meta-data/",  # AWS/GCP/Azure metadata
            "http://169.254.170.2/",  # ECS task metadata
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://[fe80::1]:80/",  # IPv6 link-local
        ],
    )
    def test_metadata_urls_rejected(self, url):
        with pytest.raises(ValueError):
            _assert_daemon_url_safe(url)

    def test_enabled_scanner_rejects_metadata_daemon(self):
        with pytest.raises(ValueError):
            ImageScanner(enabled=True, daemon_url="http://169.254.169.254/")

    def test_disabled_scanner_skips_validation(self):
        # Validation only fires when scanning is active.
        ImageScanner(enabled=False, daemon_url="http://169.254.169.254/")


class TestImageScannerRealDaemonShape:
    """WO9.0.0-001: the admission scanner read `verdict`/`findings`, which the
    daemon does not emit — it emits l3_verdict/l4_verdict/findings_count. The
    scanner therefore always saw CLEAN and never blocked a pod: admission
    control was a complete no-op."""

    def test_malicious_l4_verdict_blocks(self, mock_daemon):
        MockScanHandler.l3_verdict = "CLEAN"
        MockScanHandler.l4_verdict = "MALICIOUS"
        MockScanHandler.findings = [{"severity": "CRITICAL", "rule_id": "L4-PRIVESC-003"}]
        scanner = ImageScanner(enabled=True, daemon_url=mock_daemon)
        allowed, reason = scanner.scan_pod(_make_pod_request(["evil:latest"]))
        assert not allowed, "MALICIOUS l4_verdict must block the pod"
        assert reason

    def test_suspicious_l4_verdict_blocks(self, mock_daemon):
        MockScanHandler.l3_verdict = "CLEAN"
        MockScanHandler.l4_verdict = "SUSPICIOUS"
        MockScanHandler.findings = [{"severity": "HIGH", "rule_id": "L4-EXFIL-003"}]
        scanner = ImageScanner(enabled=True, min_severity="high", daemon_url=mock_daemon)
        allowed, _reason = scanner.scan_pod(_make_pod_request(["suspicious:latest"]))
        assert not allowed, "SUSPICIOUS l4_verdict must block the pod"

    def test_deny_l3_verdict_blocks(self, mock_daemon):
        MockScanHandler.l3_verdict = "DENY"
        MockScanHandler.l4_verdict = "CLEAN"
        MockScanHandler.findings = []
        scanner = ImageScanner(enabled=True, daemon_url=mock_daemon)
        allowed, reason = scanner.scan_pod(_make_pod_request(["denied:latest"]))
        assert not allowed, "DENY l3_verdict must block the pod"
        assert "denied" in reason.lower()

    def test_high_severity_finding_blocks(self, mock_daemon):
        MockScanHandler.l3_verdict = "CLEAN"
        MockScanHandler.l4_verdict = "CLEAN"
        MockScanHandler.findings = [{"severity": "HIGH", "rule_id": "L4-EXFIL-003"}]
        scanner = ImageScanner(enabled=True, min_severity="high", daemon_url=mock_daemon)
        allowed, _reason = scanner.scan_pod(_make_pod_request(["nginx:latest"]))
        assert not allowed, "a HIGH finding at min_severity=high must block the pod"

    def test_low_severity_finding_allowed(self, mock_daemon):
        MockScanHandler.l3_verdict = "CLEAN"
        MockScanHandler.l4_verdict = "CLEAN"
        MockScanHandler.findings = [{"severity": "LOW", "rule_id": "L4-INFO-001"}]
        scanner = ImageScanner(enabled=True, min_severity="high", daemon_url=mock_daemon)
        allowed, _reason = scanner.scan_pod(_make_pod_request(["nginx:latest"]))
        assert allowed, "a LOW finding below min_severity must not block the pod"

    def test_clean_response_allowed(self, mock_daemon):
        MockScanHandler.l3_verdict = "CLEAN"
        MockScanHandler.l4_verdict = "CLEAN"
        MockScanHandler.findings = []
        scanner = ImageScanner(enabled=True, daemon_url=mock_daemon)
        allowed, _reason = scanner.scan_pod(_make_pod_request(["nginx:latest"]))
        assert allowed


class TestUnreadableScanResponse:
    """A response the scanner cannot interpret must not read as "clean".

    WO9.0.0-001: field-name drift between the scanner and the daemon turned
    admission control into a no-op with no signal at all. If the daemon's
    contract changes again, the scanner must deny rather than wave the pod
    through — the fail-closed default is the safety net for exactly that.
    """

    def test_response_without_verdict_or_findings_denies(self, mock_daemon, monkeypatch):
        class _EmptyHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(content_length)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"job_id": "x", "something_else": True}).encode("utf-8"))

            def log_message(self, format, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), _EmptyHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            scanner = ImageScanner(enabled=True, daemon_url=f"http://127.0.0.1:{port}")
            allowed, reason = scanner.scan_pod(_make_pod_request(["nginx:latest"]))
            assert not allowed, "an unreadable scan response must not allow the pod"
            assert "unreadable" in reason.lower()
        finally:
            server.shutdown()

    def test_unreadable_response_allows_when_fail_open_opted_out(self, mock_daemon):
        class _EmptyHandler(BaseHTTPRequestHandler):
            def do_POST(self):
                content_length = int(self.headers.get("Content-Length", 0))
                self.rfile.read(content_length)
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"job_id": "x"}).encode("utf-8"))

            def log_message(self, format, *args):
                pass

        server = HTTPServer(("127.0.0.1", 0), _EmptyHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            scanner = ImageScanner(enabled=True, daemon_url=f"http://127.0.0.1:{port}", fail_closed=False)
            allowed, _reason = scanner.scan_pod(_make_pod_request(["nginx:latest"]))
            assert allowed, "an operator who opted out of fail-closed gets the permissive path"
        finally:
            server.shutdown()
