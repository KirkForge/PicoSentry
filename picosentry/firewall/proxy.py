from __future__ import annotations

import hmac
import json
import logging
import urllib.parse
import urllib.request
import urllib.error
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from typing import Any

from picosentry.firewall.scanner import FirewallScanner, FirewallVerdict, classify_path
from picosentry.scan._network import (
    InsecureURLError,
    ResponseTooLargeError,
    UnsafeURLError,
    assert_url_safe,
    safe_urlopen,
)

_MAX_ERROR_BODY = 1 << 20
_STREAM_CHUNK_BYTES = 64 * 1024
_USER_AGENT = "picosentry-firewall/1.0"

logger = logging.getLogger("picosentry.firewall.proxy")


def _open_upstream_stream(url: str, timeout: int):
    """Open an upstream response for streaming, with safe_urlopen's SSRF/HTTPS checks.

    Unlike safe_urlopen this does NOT buffer the body — the caller copies it
    in chunks so a huge tarball never lands in memory (WO4.0.0-022).
    """
    if not url.lower().startswith("https://"):
        raise InsecureURLError(f"Refusing non-HTTPS upstream URL (MITM risk): {url}")
    assert_url_safe(url)
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    return urllib.request.urlopen(req, timeout=timeout)


def _sanitize_header(value: str) -> str:
    return value.replace("\r", "").replace("\n", "")


def _safe_upstream_path(path: str) -> str | None:
    # Strip the query before validating so '?refresh=1' on a metadata URL
    # doesn't pollute the traversal check, and decode percent-encoding BEFORE
    # the '..' check so '%2e%2e' / '%2E%2E' / '..%2f' cannot bypass the guard
    # (WO7.0.0-006 — encoded-dot SSRF). The decoded path is what we return so
    # the upstream URL the classifier validated == the URL upstream sees;
    # sending raw '%2e%2e' would let the upstream decode it to '..' after our
    # guard cleared the raw form.
    if "//" in path:
        # Rejects '//attacker.com/evil' (urlsplit would consume // as netloc
        # and hide the authority from a path-only '//'-check) and '//path'
        # (empty segment). Must run on the raw form — urlsplit strips it.
        return None
    parts = urllib.parse.urlsplit(path)
    decoded = urllib.parse.unquote(parts.path)
    if not decoded.startswith("/"):
        return None
    if ".." in decoded.split("/"):
        return None
    # Defense-in-depth: a second unquote catches double-encoding
    # ('%252e%252e' → '%2e%2e' → '..'). Safe for npm/pypi registries —
    # package names are a restricted charset with no literal '%'.
    if ".." in urllib.parse.unquote(decoded).split("/"):
        return None
    return decoded + ("?" + parts.query if parts.query else "")


class FirewallConfig:
    def __init__(
        self,
        listen_port: int = 3132,
        listen_host: str = "127.0.0.1",
        upstream_npm: str = "https://registry.npmjs.org",
        upstream_pypi: str = "https://pypi.org",
        block_severities: list[str] | None = None,
        quarantine_severities: list[str] | None = None,
        auth_token: str | None = None,
        quarantine_action: str = "tag",
        cache_ttl_seconds: int = 3600,
        cache_max_entries: int = 10_000,
        scan_timeout_seconds: int = 30,
        pass_through_max_bytes: int = 512 * 1024 * 1024,
        log_blocks: bool = True,
    ) -> None:
        if quarantine_action not in ("tag", "block"):
            raise ValueError(f"quarantine_action must be 'tag' or 'block', got {quarantine_action!r}")
        self.listen_port = listen_port
        # Default loopback: a metadata firewall has no auth by default and must
        # not be reachable from the network unless explicitly exposed.
        self.listen_host = listen_host
        self.upstream_npm = upstream_npm.rstrip("/")
        self.upstream_pypi = upstream_pypi.rstrip("/")
        # Default posture: BLOCK on CRITICAL only; HIGH/MEDIUM quarantine-tag
        # (see FirewallScanner — blocking on HIGH metadata breaks every benign
        # package with an install script).
        self.block_severities = block_severities or ["CRITICAL"]
        self.quarantine_severities = quarantine_severities or ["HIGH", "MEDIUM"]
        self.auth_token = auth_token
        self.quarantine_action = quarantine_action
        self.cache_ttl_seconds = cache_ttl_seconds
        self.cache_max_entries = cache_max_entries
        self.scan_timeout_seconds = scan_timeout_seconds
        self.pass_through_max_bytes = pass_through_max_bytes
        self.log_blocks = log_blocks


class _ProxyHandler(BaseHTTPRequestHandler):
    config: FirewallConfig
    scanner: FirewallScanner

    def _authorized(self) -> bool:
        token = self.config.auth_token
        if token is None:
            return True
        presented = self.headers.get("Authorization", "")
        expected = f"Bearer {token}"
        # UTF-8 bytes: header values arrive latin-1-decoded and non-ASCII
        # str raises TypeError in compare_digest, killing the connection
        # with a traceback instead of a clean 401.
        return hmac.compare_digest(presented.encode("utf-8"), expected.encode("utf-8"))

    def do_GET(self) -> None:
        if not self._authorized():
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.send_header("WWW-Authenticate", "Bearer")
            self.end_headers()
            self.wfile.write(b'{"error": "unauthorized"}')
            return

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
            req = urllib.request.Request(upstream_url, headers={"User-Agent": _USER_AGENT})
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

        if verdict == FirewallVerdict.UNRESOLVED:
            # Upstream returned a whole-catalog doc without the requested
            # version — refuse rather than scan root fields and report a
            # false ALLOW (WO6-017).
            self.send_response(502)
            self.send_header("Content-Type", "application/json")
            self.send_header("X-PicoSentry-Verdict", "unresolved")
            self.end_headers()
            self.wfile.write(b'{"error": "version not found in upstream catalog"}')
            return

        if verdict == FirewallVerdict.ALLOW:
            self._send_response(status, content_type, body, extra_headers=[("X-PicoSentry-Verdict", "allow")])
            return

        quarantine_tags = verdict == FirewallVerdict.QUARANTINE
        if quarantine_tags and self.config.quarantine_action == "tag":
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

        if self.config.log_blocks and (verdict == FirewallVerdict.BLOCK or quarantine_tags):
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
        """Stream non-classified paths (tarballs, static assets) upstream→client in bounded memory.

        Documented decision (WO4.0.0-022, docs/manual.md#tarball-decision-explicit-not-accidental):
        this is a metadata firewall — tarballs are passed through UNINSPECTED and
        tagged with X-PicoSentry-Verdict: passthrough. Artifact scanning happens
        elsewhere (picosentry scan on the extracted tarball).
        """
        url = self._guess_upstream(self.path)
        if url is None:
            self.send_response(400)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"error": "invalid path"}')
            return
        try:
            resp = _open_upstream_stream(url, timeout=self.config.scan_timeout_seconds)
        except urllib.error.HTTPError as exc:
            self.send_response(exc.code)
            self.end_headers()
            return
        except (urllib.error.URLError, OSError, TimeoutError, InsecureURLError, UnsafeURLError):
            self.send_response(502)
            self.end_headers()
            return

        with resp:
            self.send_response(resp.status)
            content_type = resp.headers.get("Content-Type", "application/octet-stream")
            self.send_header("Content-Type", _sanitize_header(content_type))
            self.send_header("X-PicoSentry-Proxy", "true")
            self.send_header("X-PicoSentry-Verdict", "passthrough")
            self.end_headers()
            total = 0
            try:
                while True:
                    chunk = resp.read(_STREAM_CHUNK_BYTES)
                    if not chunk:
                        break
                    total += len(chunk)
                    if total > self.config.pass_through_max_bytes:
                        # Cannot unsend headers — truncate and close so the
                        # client sees a cut connection instead of us silently
                        # buffering a 512MB+ body in memory.
                        logger.warning("Pass-through body exceeded %d bytes for %s", total, self.path)
                        self.close_connection = True
                        break
                    self.wfile.write(chunk)
            except OSError:
                self.close_connection = True

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
        server = ThreadingHTTPServer((self.config.listen_host, self.config.listen_port), handler)
        server.daemon_threads = True  # never let a stuck client connection block shutdown
        logger.info(
            "PicoSentry firewall proxy listening on %s:%d",
            self.config.listen_host,
            self.config.listen_port,
        )
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            logger.info("Shutting down firewall proxy")
            server.shutdown()
