"""Tests for K8s admission webhook server — B16.

Covers:
- AdmissionRequest parsing from K8s AdmissionReview
- AdmissionResponse building (allow, deny, with reason)
- /validate endpoint handling
- Invalid JSON error handling
- Missing request field error
- 404 for non-validate paths
- Server start/stop lifecycle
"""

from __future__ import annotations

import json
import threading
from http.server import HTTPServer
from typing import Any

import pytest

from picosentry.sandbox.admission import (
    AdmissionHandler,
    AdmissionRequest,
    AdmissionResponse,
    AdmissionWebhookServer,
)

SAMPLE_ADMISSION_REVIEW = {
    "apiVersion": "admission.k8s.io/v1",
    "kind": "AdmissionReview",
    "request": {
        "uid": "abc-123-def",
        "kind": {"group": "", "version": "v1", "kind": "Pod"},
        "name": "my-pod",
        "namespace": "default",
        "operation": "CREATE",
        "object": {
            "apiVersion": "v1",
            "kind": "Pod",
            "metadata": {"name": "my-pod"},
            "spec": {
                "containers": [
                    {"name": "app", "image": "nginx:latest"},
                ],
            },
        },
    },
}


class TestAdmissionRequest:
    def test_parse_from_dict(self):
        req = AdmissionRequest.from_dict(SAMPLE_ADMISSION_REVIEW["request"])
        assert req.uid == "abc-123-def"
        assert req.name == "my-pod"
        assert req.namespace == "default"
        assert req.operation == "CREATE"
        assert "containers" in req.object_raw["spec"]

    def test_empty_request(self):
        req = AdmissionRequest.from_dict({})
        assert req.uid == ""
        assert req.name == ""


class TestAdmissionResponse:
    def test_allow_response(self):
        resp = AdmissionResponse(uid="test-uid", allowed=True)
        d = resp.to_dict()
        assert d["uid"] == "test-uid"
        assert d["allowed"] is True
        assert "status" not in d

    def test_deny_response_with_reason(self):
        resp = AdmissionResponse(uid="test-uid", allowed=False, reason="privileged container")
        d = resp.to_dict()
        assert d["allowed"] is False
        assert d["status"]["code"] == 403
        assert d["status"]["message"] == "privileged container"

    def test_allow_with_reason(self):
        resp = AdmissionResponse(uid="test-uid", allowed=True, reason="all checks passed")
        d = resp.to_dict()
        assert d["allowed"] is True
        assert d["status"]["code"] == 200

    def test_response_with_patch(self):
        patch = [{"op": "add", "path": "/metadata/labels/validated", "value": "true"}]
        resp = AdmissionResponse(uid="test-uid", allowed=True, patch=patch)
        d = resp.to_dict()
        assert "patch" in d
        assert d["patchType"] == "JSONPatch"


class TestAdmissionHandler:
    def _make_request(
        self,
        path: str,
        body: dict[str, Any] | None = None,
        validator=None,
    ) -> dict[str, Any]:
        """Send a request to the admission handler and return the response."""
        import urllib.error
        import urllib.request

        # Start a test server
        AdmissionHandler.validator = validator
        server = HTTPServer(("127.0.0.1", 0), AdmissionHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            url = f"http://127.0.0.1:{port}{path}"
            data = json.dumps(body).encode("utf-8") if body else b""
            req = urllib.request.Request(
                url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            response = urllib.request.urlopen(req, timeout=5)
            return json.loads(response.read())
        finally:
            server.shutdown()

    def test_validate_denies_with_no_validator(self):
        """A webhook with no configured validator must fail closed."""
        result = self._make_request("/validate", SAMPLE_ADMISSION_REVIEW)
        assert result["response"]["allowed"] is False
        assert "no validator configured" in result["response"]["status"]["message"]

    def test_validate_denies_with_validator(self):
        def deny_all(req):
            return False, "denied by policy"

        result = self._make_request("/validate", SAMPLE_ADMISSION_REVIEW, validator=deny_all)
        assert result["response"]["allowed"] is False
        assert "denied by policy" in result["response"]["status"]["message"]

    def test_validate_allows_with_passing_validator(self):
        def allow_all(req):
            return True, ""

        result = self._make_request("/validate", SAMPLE_ADMISSION_REVIEW, validator=allow_all)
        assert result["response"]["allowed"] is True

    def test_invalid_json_returns_error(self):
        import urllib.error
        import urllib.request

        AdmissionHandler.validator = None
        server = HTTPServer(("127.0.0.1", 0), AdmissionHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            url = f"http://127.0.0.1:{port}/validate"
            req = urllib.request.Request(
                url,
                data=b"not json",
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            response = urllib.request.urlopen(req, timeout=5)
            result = json.loads(response.read())
            assert result["response"]["allowed"] is False
            assert "invalid JSON" in result["response"]["status"]["message"]
        finally:
            server.shutdown()

    def test_missing_request_field(self):
        review = {"apiVersion": "admission.k8s.io/v1", "kind": "AdmissionReview"}
        result = self._make_request("/validate", review)
        assert result["response"]["allowed"] is False

    def test_response_has_correct_api_version(self):
        result = self._make_request("/validate", SAMPLE_ADMISSION_REVIEW)
        assert result["apiVersion"] == "admission.k8s.io/v1"
        assert result["kind"] == "AdmissionReview"

    def test_response_preserves_uid(self):
        result = self._make_request("/validate", SAMPLE_ADMISSION_REVIEW)
        assert result["response"]["uid"] == "abc-123-def"

    def test_validate_with_timeout_query_parameter(self):
        """Kubernetes appends ?timeout=<s> to webhook URLs; path must still match."""

        def allow_all(req):
            return True, ""

        result = self._make_request("/validate?timeout=10s", SAMPLE_ADMISSION_REVIEW, validator=allow_all)
        assert result["response"]["allowed"] is True

    def test_non_validate_path_still_404(self):
        # HTTP 404 with no AdmissionReview body; urllib raises HTTPError.
        import urllib.error
        import urllib.request

        AdmissionHandler.validator = None
        server = HTTPServer(("127.0.0.1", 0), AdmissionHandler)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        try:
            url = f"http://127.0.0.1:{port}/not-validate"
            req = urllib.request.Request(
                url,
                data=json.dumps(SAMPLE_ADMISSION_REVIEW).encode("utf-8"),
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with pytest.raises(urllib.error.HTTPError) as exc_info:
                urllib.request.urlopen(req, timeout=5)
            assert exc_info.value.code == 404
        finally:
            server.shutdown()


class TestAdmissionWebhookServer:
    def test_server_port(self):
        server = AdmissionWebhookServer(port=9443)
        assert server.port == 9443

    def test_default_port(self):
        server = AdmissionWebhookServer()
        assert server.port == 8443
