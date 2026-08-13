from __future__ import annotations

import json
import logging
import urllib.parse
import urllib.request
import urllib.error
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any

from picosentry.firewall.scanner import FirewallScanner, FirewallVerdict, classify_path
from picosentry.scan._network import InsecureURLError, ResponseTooLargeError, UnsafeURLError, safe_urlopen

_MAX_ERROR_BODY = 1 << 20
_MAX_PASS_THROUGH_BYTES = 512 * 1024 * 1024  # ponytail: 512MB cap; stream to disk if legit tarballs exceed it

logger = logging.getLogger("picosentry.firewall.proxy")


def _sanitize_header(value: str) -> str:
    return value.replace("\r", "").replace("\n", "")


def _safe_upstream_path(path: str) -> str | None:
    if not path.startswith("/"):
        return None
    if "//" in path:
        return None
    segments = path.split("/")
    for seg in segments:
        if seg == "..":
            return None
    return path


class FirewallConfig:
    def __init__(
        self,
        listen_port: int = 3132,
        upstream_npm: str = "https://registry.npmjs.org",
        upstream_pypi: str = "https://pypi.org",
        block_severities: list[str] | None = None,
        quarantine_severities: list[str] | None = None,
        cache_ttl_seconds: int = 3600,
        cache_max_entries: int = 10_000,
        scan_timeout_seconds: int = 30,
        log_blocks: bool = True,
    ) -> None:
        self.listen_port = listen_port
        self.upstream_npm = upstream_npm.rstrip("/")
        self.upstream_pypi = upstream_pypi.rstrip("/")
        self.block_severities = block_severities or ["CRITICAL", "HIGH"]
        self.quarantine_severities = quarantine_severities or ["MEDIUM"]
        self.cache_ttl_seconds = cache_ttl_seconds
        self.cache_max_entries = cache_max_entries
        self.scan_timeout_seconds = scan_timeout_seconds
        self.log_blocks = log_blocks


class _ProxyHandler(BaseHTTPRequestHandler):
    config: FirewallConfig
    scanner: FirewallScanner

    def do_GET(self) -> None:
        parsed = classify_path(self.path)
        if parsed is None:
            self._proxy_pass()
            return

        ecosystem, name, version = parsed
        upstream_url = self._upstream_url(ecosystem, self.path)
        if upstream_url is None:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "invalid path"}')
            return

        try:
            req = urllib.request.Request(upstream_url, headers={"User-Agent": "picosentry-firewall/1.0"})
            resp, body = safe_urlopen(req, timeout=self.config.scan_timeout_seconds)
            content_type = resp.headers.get("Content-Type", "application/json")
            status = resp.status
            resp.close()
        except urllib.error.HTTPError as exc:
            self.send_response(exc.code)
            self.end_headers()
            if exc.fp and hasattr(exc.fp, "read"):
                self.wfile.write(exc.fp.read(_MAX_ERROR_BODY))
            return
        except (
            urllib.error.URLError,
            OSError,
            TimeoutError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            InsecureURLError,
            ResponseTooLargeError,
            UnsafeURLError,
        ):
            self.send_response(502)
            self.end_headers()
            self.wfile.write(b'{"error": "upstream unreachable"}')
            return

        try:
            metadata = json.loads(body)
        except (json.JSONDecodeError, UnicodeDecodeError):
            self._send_response(status, content_type, body)
            return

        if not isinstance(metadata, dict):
            self._send_response(status, content_type, body)
            return

        verdict, findings = self.scanner.scan_metadata(ecosystem, name, version, metadata)

        if verdict == FirewallVerdict.ALLOW:
            self._send_response(status, content_type, body)
            return

        if verdict == FirewallVerdict.QUARANTINE:
            reasons_str = ",".join(f.rule_id for f in findings)
            self._send_response(
                status,
                content_type,
                body,
                extra_headers=[
                    ("X-PicoSentry-Verdict", "quarantine"),
                    ("X-PicoSentry-Reasons", reasons_str),
                ],
            )
            return

        reasons = [
            {
                "rule_id": f.rule_id,
                "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                "message": f.message,
            }
            for f in findings
        ]
        block_body = json.dumps(
            {
                "verdict": verdict,
                "ecosystem": ecosystem,
                "package": name,
                "version": version,
                "reasons": reasons,
            },
            indent=2,
        )

        if verdict == FirewallVerdict.BLOCK and self.config.log_blocks:
            logger.warning(
                "BLOCKED %s/%s@%s: %d findings",
                ecosystem,
                name,
                version,
                len(findings),
            )

        self.send_response(403)
        self.send_header("Content-Type", "application/json")
        self.send_header("X-PicoSentry-Verdict", _sanitize_header(verdict))
        self.end_headers()
        self.wfile.write(block_body.encode())

    def _upstream_url(self, ecosystem: str, path: str) -> str | None:
        safe_path = _safe_upstream_path(path)
        if safe_path is None:
            return None
        base = self.config.upstream_npm if ecosystem == "npm" else self.config.upstream_pypi
        return urllib.parse.urljoin(base + "/", safe_path.lstrip("/"))

    def _proxy_pass(self) -> None:
        url = self._guess_upstream(self.path)
        if url is None:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "invalid path"}')
            return
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "picosentry-firewall/1.0"})
            resp, body = safe_urlopen(req, timeout=30, max_bytes=_MAX_PASS_THROUGH_BYTES)
            self._send_response(resp.status, resp.headers.get("Content-Type", "application/octet-stream"), body)
            resp.close()
        except urllib.error.HTTPError as exc:
            self.send_response(exc.code)
            self.end_headers()
        except (
            urllib.error.URLError,
            OSError,
            TimeoutError,
            UnicodeDecodeError,
            json.JSONDecodeError,
            InsecureURLError,
            ResponseTooLargeError,
            UnsafeURLError,
        ):
            self.send_response(502)
            self.end_headers()

    def _guess_upstream(self, path: str) -> str | None:
        safe_path = _safe_upstream_path(path)
        if safe_path is None:
            return None
        if path.startswith("/pypi/"):
            return urllib.parse.urljoin(self.config.upstream_pypi + "/", safe_path.lstrip("/"))
        return urllib.parse.urljoin(self.config.upstream_npm + "/", safe_path.lstrip("/"))

    def _send_response(
        self, status: int, content_type: str, body: bytes, extra_headers: list[tuple[str, str]] | None = None
    ) -> None:
        self.send_response(status)
        self.send_header("Content-Type", _sanitize_header(content_type))
        self.send_header("X-PicoSentry-Proxy", "true")
        if extra_headers:
            for header_name, header_value in extra_headers:
                self.send_header(header_name, _sanitize_header(header_value))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args: Any) -> None:
        logger.debug(format, *args)


class FirewallProxy:
    def __init__(self, config: FirewallConfig) -> None:
        self.config = config
        self.scanner = FirewallScanner(
            block_severities=config.block_severities,
            quarantine_severities=config.quarantine_severities,
            scan_timeout_seconds=config.scan_timeout_seconds,
            cache_ttl_seconds=config.cache_ttl_seconds,
            cache_max_entries=config.cache_max_entries,
        )

    def serve(self) -> None:
        handler = type("_Handler", (_ProxyHandler,), {"config": self.config, "scanner": self.scanner})
        server = HTTPServer(("0.0.0.0", self.config.listen_port), handler)
        logger.info("PicoSentry firewall proxy listening on port %d", self.config.listen_port)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Shutting down firewall proxy")
            server.shutdown()
