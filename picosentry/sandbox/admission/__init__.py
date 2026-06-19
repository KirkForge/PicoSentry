from __future__ import annotations

import base64
import json
import logging
import ssl
from collections.abc import Callable
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, ClassVar

logger = logging.getLogger("picodome.admission")

_DEFAULT_PORT = 8443
_DEFAULT_HOST = "127.0.0.1"


class AdmissionRequest:
    def __init__(
        self,
        uid: str,
        kind: dict[str, str],
        name: str,
        namespace: str,
        operation: str,
        object_raw: dict[str, Any],
    ) -> None:
        self.uid = uid
        self.kind = kind
        self.name = name
        self.namespace = namespace
        self.operation = operation
        self.object_raw = object_raw

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> AdmissionRequest:
        return cls(
            uid=data.get("uid", ""),
            kind=data.get("kind", {}),
            name=data.get("name", ""),
            namespace=data.get("namespace", ""),
            operation=data.get("operation", ""),
            object_raw=data.get("object", {}),
        )


class AdmissionResponse:
    def __init__(
        self,
        uid: str,
        allowed: bool,
        reason: str = "",
        patch: dict[str, Any] | None = None,
        patch_type: str = "JSONPatch",
    ) -> None:
        self.uid = uid
        self.allowed = allowed
        self.reason = reason
        self.patch = patch
        self.patch_type = patch_type

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "uid": self.uid,
            "allowed": self.allowed,
        }
        if self.reason:
            result["status"] = {
                "code": 403 if not self.allowed else 200,
                "message": self.reason,
            }
        if self.patch:
            result["patchType"] = self.patch_type
            result["patch"] = base64.b64encode(json.dumps(self.patch).encode("utf-8")).decode("utf-8")
        return result


class AdmissionHandler(BaseHTTPRequestHandler):
    validator: ClassVar[Callable[[AdmissionRequest], tuple[bool, str]] | None] = None

    def do_POST(self) -> None:
        if self.path != "/validate":
            self.send_response(404)
            self.end_headers()
            return

        try:
            content_length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(content_length)
            review = json.loads(body)
        except (json.JSONDecodeError, ValueError) as exc:
            self._send_admission_error("invalid JSON: " + str(exc))
            return

        request_data = review.get("request", {})
        if not request_data:
            self._send_admission_error("missing 'request' field")
            return

        req = AdmissionRequest.from_dict(request_data)

        validator = AdmissionHandler.validator
        if validator:
            allowed, reason = validator(req)
        else:
            allowed, reason = True, ""

        response = AdmissionResponse(
            uid=req.uid,
            allowed=allowed,
            reason=reason,
        )

        review_response = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": response.to_dict(),
        }

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(review_response).encode("utf-8"))

    def _send_admission_error(self, error: str) -> None:
        review_response = {
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "response": {
                "uid": "",
                "allowed": False,
                "status": {
                    "code": 400,
                    "message": error,
                },
            },
        }
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(review_response).encode("utf-8"))

    def log_message(self, format, *args):
        logger.debug("Admission webhook: %s", format % args)


class AdmissionWebhookServer:
    def __init__(
        self,
        host: str = _DEFAULT_HOST,
        port: int = _DEFAULT_PORT,
        cert_file: str | Path | None = None,
        key_file: str | Path | None = None,
        validator: Any = None,
    ) -> None:
        self._host = host
        self._port = port
        self._cert_file = str(cert_file) if cert_file else ""
        self._key_file = str(key_file) if key_file else ""
        self._validator = validator
        self._server: HTTPServer | None = None

    def start(self, background: bool = False) -> None:
        AdmissionHandler.validator = self._validator

        self._server = HTTPServer((self._host, self._port), AdmissionHandler)

        if self._cert_file and self._key_file:
            ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            ctx.load_cert_chain(self._cert_file, self._key_file)
            self._server.socket = ctx.wrap_socket(self._server.socket, server_side=True)
            logger.info("Admission webhook started with TLS on port %d", self._port)
        else:
            logger.warning(
                "Admission webhook started WITHOUT TLS on port %d (K8s requires TLS — use --cert-file and --key-file)",
                self._port,
            )

        if background:
            import threading

            thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            thread.start()
            logger.info("Admission webhook running in background")
        else:
            try:
                self._server.serve_forever()
            except KeyboardInterrupt:
                self.stop()

    def stop(self) -> None:
        if self._server:
            self._server.shutdown()
            self._server = None
            logger.info("Admission webhook stopped")

    @property
    def port(self) -> int:
        return self._port
