"""Comprehensive tests for PicoSentry daemon module.

Covers: HealthHandler endpoints, auth checking, rate limiting,
enterprise mode enforcement, request/response headers, _client_ip(),
run_daemon startup/signal handling, and 404 for unknown paths.
"""

from __future__ import annotations

import io
import json
import signal
import threading
import time
import unittest
from http.server import HTTPServer
from unittest.mock import MagicMock, patch

from picosentry.scan.auth import AuthConfig, RateLimiter
from picosentry.scan.daemon import (
    HealthHandler,
    run_daemon,
)
from picosentry.scan.enterprise import EnterpriseViolation

# ── Helper: create a bare HealthHandler with mocked IO ────────────────


def _make_handler(path="/health", headers=None, client_address=("127.0.0.1", 12345)):
    """Build a HealthHandler with mocked I/O for direct method testing.

    Does NOT reset class-level config — caller must set
    HealthHandler.auth_config and HealthHandler.rate_limiter explicitly.
    """
    handler = HealthHandler.__new__(HealthHandler)
    handler.path = path
    handler.client_address = client_address
    handler.wfile = io.BytesIO()
    handler.rfile = io.BytesIO()
    handler.headers = headers if headers is not None else {}
    handler.send_response = MagicMock()
    handler.send_header = MagicMock()
    handler.end_headers = MagicMock()
    handler.send_error = MagicMock()
    return handler


def _read_json_body(handler):
    handler.wfile.seek(0)
    return json.loads(handler.wfile.read())


def _read_text_body(handler):
    handler.wfile.seek(0)
    return handler.wfile.read().decode()


def _reset_handler_defaults():
    """Reset HealthHandler class-level config to safe defaults."""
    HealthHandler.auth_config = AuthConfig(mode="off")
    HealthHandler.rate_limiter = RateLimiter(rps=0)
    HealthHandler._engine_cache = None


# ── 1. HealthHandler.do_GET endpoint routing ───────────────────────────


class TestDoGetHealthEndpoints(unittest.TestCase):
    """Test /health, /healthz, /ready, /readyz endpoints via do_GET."""

    def setUp(self):
        _reset_handler_defaults()

    def test_do_get_health(self):
        handler = _make_handler(path="/health")
        with patch("picosentry.scan.logging.clear_request_context"):
            handler.do_GET()
        data = _read_json_body(handler)
        self.assertEqual(data["status"], "healthy")

    def test_do_get_healthz(self):
        handler = _make_handler(path="/healthz")
        with patch("picosentry.scan.logging.clear_request_context"):
            handler.do_GET()
        data = _read_json_body(handler)
        self.assertEqual(data["status"], "healthy")

    def test_do_get_readyz(self):
        handler = _make_handler(path="/readyz")
        with (
            patch("picosentry.scan.logging.clear_request_context"),
            patch("picosentry.scan.engine.create_default_engine") as mock_engine,
        ):
            eng = MagicMock()
            eng._corpus_version = "1.0"
            eng.list_rules.return_value = ["r1"]
            mock_engine.return_value = eng
            handler.do_GET()
        data = _read_json_body(handler)
        self.assertEqual(data["status"], "ready")

    def test_do_get_strips_query_and_fragment(self):
        handler = _make_handler(path="/health?foo=1#bar")
        with patch("picosentry.scan.logging.clear_request_context"):
            handler.do_GET()
        data = _read_json_body(handler)
        self.assertEqual(data["status"], "healthy")


class TestDoGetMetricsEndpoints(unittest.TestCase):
    """Test /metrics and /metrics/json endpoints via do_GET."""

    def setUp(self):
        _reset_handler_defaults()

    def test_do_get_metrics(self):
        handler = _make_handler(path="/metrics")
        with patch("picosentry.scan.logging.clear_request_context"):
            handler.do_GET()
        body = _read_text_body(handler)
        self.assertIn("picosentry_", body)

    def test_do_get_metrics_json(self):
        handler = _make_handler(path="/metrics/json")
        with patch("picosentry.scan.logging.clear_request_context"):
            handler.do_GET()
        data = _read_json_body(handler)
        self.assertIn("counters", data)


class TestDoGetRootEndpoint(unittest.TestCase):
    """Test / (root) endpoint via do_GET."""

    def setUp(self):
        _reset_handler_defaults()

    def test_do_get_root(self):
        handler = _make_handler(path="/")
        with patch("picosentry.scan.logging.clear_request_context"):
            handler.do_GET()
        data = _read_json_body(handler)
        self.assertEqual(data["service"], "picosentry")
        self.assertIn("version", data)
        self.assertEqual(data["auth_mode"], "off")
        self.assertIn("endpoints", data)


class TestDoGetUnknownPath(unittest.TestCase):
    """Test 404 for unknown paths."""

    def setUp(self):
        _reset_handler_defaults()

    def test_404_unknown_path(self):
        handler = _make_handler(path="/unknown")
        with patch("picosentry.scan.logging.clear_request_context"):
            handler.do_GET()
        handler.send_error.assert_called_once_with(404, "Not Found")


# ── 2. Auth checking ───────────────────────────────────────────────────


class TestAuthChecking(unittest.TestCase):
    """Test auth checking with auth=off, token, and OIDC modes."""

    def setUp(self):
        HealthHandler.rate_limiter = RateLimiter(rps=0)

    def test_auth_off_passes(self):
        HealthHandler.auth_config = AuthConfig(mode="off")
        handler = _make_handler(path="/metrics")
        result = handler._check_auth("req-1")
        self.assertTrue(result.ok)
        self.assertEqual(result.identity, "anonymous")

    def test_auth_token_missing_sends_401(self):
        HealthHandler.auth_config = AuthConfig(mode="token", token="s3cret")
        handler = _make_handler(path="/metrics", headers={})
        result = handler._check_auth("req-2")
        self.assertFalse(result.ok)
        self.assertIn("Missing", result.error)
        handler.send_response.assert_called_with(401)

    def test_auth_token_wrong_sends_403(self):
        HealthHandler.auth_config = AuthConfig(mode="token", token="s3cret")
        handler = _make_handler(path="/metrics", headers={"authorization": "Bearer wrong"})
        result = handler._check_auth("req-3")
        self.assertFalse(result.ok)
        handler.send_response.assert_called_with(403)

    def test_auth_token_valid_passes(self):
        HealthHandler.auth_config = AuthConfig(mode="token", token="s3cret")
        handler = _make_handler(path="/metrics", headers={"authorization": "Bearer s3cret"})
        result = handler._check_auth("req-4")
        self.assertTrue(result.ok)

    def test_auth_oidc_missing_header_sends_401(self):
        HealthHandler.auth_config = AuthConfig(mode="oidc", oidc_issuer="https://example.com")
        handler = _make_handler(path="/metrics", headers={})
        result = handler._check_auth("req-5")
        self.assertFalse(result.ok)
        handler.send_response.assert_called_with(401)

    def test_auth_oidc_no_pyjwt_sends_403(self):
        """When PyJWT not installed and token provided, returns denial (403)."""
        HealthHandler.auth_config = AuthConfig(mode="oidc", oidc_issuer="https://example.com")
        handler = _make_handler(path="/metrics", headers={"authorization": "Bearer some.jwt.token"})
        result = handler._check_auth("req-6")
        self.assertFalse(result.ok)
        handler.send_response.assert_called_with(403)

    def test_public_endpoint_bypasses_auth(self):
        HealthHandler.auth_config = AuthConfig(mode="token", token="s3cret", public_endpoints=["/healthz"])
        handler = _make_handler(path="/healthz", headers={})
        result = handler._check_auth("req-7")
        self.assertTrue(result.ok)
        self.assertEqual(result.identity, "anonymous")

    def test_public_endpoint_no_bypass_when_auth_off(self):
        HealthHandler.auth_config = AuthConfig(mode="off", public_endpoints=["/healthz"])
        handler = _make_handler(path="/healthz", headers={})
        result = handler._check_auth("req-8")
        self.assertTrue(result.ok)

    def test_non_public_endpoint_requires_auth(self):
        HealthHandler.auth_config = AuthConfig(mode="token", token="s3cret", public_endpoints=["/healthz"])
        handler = _make_handler(path="/metrics", headers={})
        result = handler._check_auth("req-9")
        self.assertFalse(result.ok)

    def test_do_get_metrics_auth_fails(self):
        HealthHandler.auth_config = AuthConfig(mode="token", token="s3cret")
        handler = _make_handler(path="/metrics", headers={})
        with patch("picosentry.scan.logging.clear_request_context"):
            handler.do_GET()
        handler.send_response.assert_called_with(401)

    def test_do_get_metrics_json_auth_fails(self):
        HealthHandler.auth_config = AuthConfig(mode="token", token="s3cret")
        handler = _make_handler(path="/metrics/json", headers={})
        with patch("picosentry.scan.logging.clear_request_context"):
            handler.do_GET()
        handler.send_response.assert_called_with(401)

    def test_do_get_root_auth_fails(self):
        HealthHandler.auth_config = AuthConfig(mode="token", token="s3cret")
        handler = _make_handler(path="/", headers={})
        with patch("picosentry.scan.logging.clear_request_context"):
            handler.do_GET()
        handler.send_response.assert_called_with(401)


# ── 3. Rate limiting ──────────────────────────────────────────────────


class TestRateLimiting(unittest.TestCase):
    """Test rate limiting per client IP."""

    def setUp(self):
        _reset_handler_defaults()
        HealthHandler.auth_config = AuthConfig(mode="off")

    @patch("picosentry.scan.auth.time.monotonic", return_value=1000.0)
    @patch("picosentry.scan.logging.clear_request_context")
    def test_rate_limit_allows_within_burst(self, mock_clear, mock_time):
        HealthHandler.rate_limiter = RateLimiter(rps=5, burst=3)
        handler = _make_handler(path="/health")
        handler.do_GET()
        data = _read_json_body(handler)
        self.assertEqual(data["status"], "healthy")

    @patch("picosentry.scan.auth.time.monotonic", return_value=1000.0)
    @patch("picosentry.scan.logging.clear_request_context")
    def test_rate_limit_rejects_over_burst(self, mock_clear, mock_time):
        HealthHandler.rate_limiter = RateLimiter(rps=5, burst=2)
        for _ in range(2):
            HealthHandler.rate_limiter.check("127.0.0.1")
        handler = _make_handler(path="/health")
        handler.do_GET()
        handler.send_response.assert_called_with(429)

    @patch("picosentry.scan.auth.time.monotonic", return_value=1000.0)
    @patch("picosentry.scan.logging.clear_request_context")
    def test_rate_limit_429_includes_retry_after(self, mock_clear, mock_time):
        HealthHandler.rate_limiter = RateLimiter(rps=5, burst=1)
        HealthHandler.rate_limiter.check("127.0.0.1")
        handler = _make_handler(path="/health")
        handler.do_GET()
        header_calls = handler.send_header.call_args_list
        retry_calls = [c for c in header_calls if c[0][0] == "Retry-After"]
        self.assertTrue(len(retry_calls) > 0)

    @patch("picosentry.scan.auth.time.monotonic", return_value=1000.0)
    @patch("picosentry.scan.logging.clear_request_context")
    def test_rate_limit_429_body(self, mock_clear, mock_time):
        HealthHandler.rate_limiter = RateLimiter(rps=5, burst=1)
        HealthHandler.rate_limiter.check("127.0.0.1")
        handler = _make_handler(path="/health")
        handler.do_GET()
        data = _read_json_body(handler)
        self.assertEqual(data["error"], "rate limited")
        self.assertIn("retry_after", data)

    def test_rate_limit_unlimited(self):
        HealthHandler.rate_limiter = RateLimiter(rps=0)
        handler = _make_handler(path="/health")
        result = handler._check_rate_limit("127.0.0.1", "req-1")
        self.assertTrue(result)

    @patch("picosentry.scan.auth.time.monotonic", return_value=1000.0)
    @patch("picosentry.scan.logging.clear_request_context")
    def test_do_get_returns_early_on_rate_limit(self, mock_clear, mock_time):
        HealthHandler.rate_limiter = RateLimiter(rps=5, burst=1)
        HealthHandler.rate_limiter.check("127.0.0.1")
        handler = _make_handler(path="/health")
        handler.do_GET()
        response_codes = [c[0][0] for c in handler.send_response.call_args_list]
        self.assertIn(429, response_codes)


# ── 4. Enterprise mode ────────────────────────────────────────────────


class TestEnterpriseMode(unittest.TestCase):
    """Test enterprise mode enforcement in run_daemon."""

    @patch("picosentry.scan.daemon.is_enterprise_mode", return_value=True)
    @patch("picosentry.scan.daemon.enterprise_daemon_checks")
    @patch("picosentry.scan.daemon.HTTPServer")
    @patch("picosentry.scan.audit.audit")
    def test_enterprise_auth_off_exits(self, mock_audit, mock_http, mock_checks, mock_is_enterprise):
        mock_checks.side_effect = EnterpriseViolation("Enterprise mode requires authentication.", exit_code=6)
        auth_config = AuthConfig(mode="off")
        with self.assertRaises(SystemExit) as ctx:
            run_daemon(auth_config=auth_config)
        self.assertEqual(ctx.exception.code, 6)

    @patch("picosentry.scan.daemon.is_enterprise_mode", return_value=True)
    @patch("picosentry.scan.daemon.enterprise_daemon_checks")
    @patch("picosentry.scan.daemon.HTTPServer")
    @patch("picosentry.scan.audit.audit")
    def test_enterprise_host_0000_exits(self, mock_audit, mock_http, mock_checks, mock_is_enterprise):
        mock_checks.side_effect = EnterpriseViolation("Enterprise mode requires explicit host binding.", exit_code=7)
        auth_config = AuthConfig(mode="token", token="s3cret")
        with self.assertRaises(SystemExit) as ctx:
            run_daemon(host="0.0.0.0", auth_config=auth_config)
        self.assertEqual(ctx.exception.code, 7)

    @patch("picosentry.scan.daemon.is_enterprise_mode", return_value=True)
    @patch(
        "picosentry.scan.daemon.enterprise_daemon_checks",
        return_value=["Enterprise mode: token auth is accepted but OIDC is recommended."],
    )
    @patch("picosentry.scan.daemon.HTTPServer")
    @patch("picosentry.scan.audit.audit")
    def test_enterprise_token_auth_warns(self, mock_audit, mock_http, mock_checks, mock_is_enterprise):
        auth_config = AuthConfig(mode="token", token="s3cret")
        mock_http_instance = MagicMock()
        mock_http.return_value = mock_http_instance
        mock_http_instance.serve_forever.side_effect = KeyboardInterrupt()
        run_daemon(host="127.0.0.1", auth_config=auth_config)
        mock_checks.assert_called_once_with("token", "127.0.0.1")

    @patch("picosentry.scan.daemon.is_enterprise_mode", return_value=False)
    @patch("picosentry.scan.daemon.HTTPServer")
    @patch("picosentry.scan.audit.audit")
    def test_non_enterprise_auth_off_warns(self, mock_audit, mock_http, mock_is_enterprise):
        auth_config = AuthConfig(mode="off")
        mock_http_instance = MagicMock()
        mock_http.return_value = mock_http_instance
        mock_http_instance.serve_forever.side_effect = KeyboardInterrupt()
        run_daemon(auth_config=auth_config)

    @patch("picosentry.scan.daemon.is_enterprise_mode", return_value=True)
    @patch("picosentry.scan.daemon.enterprise_daemon_checks", return_value=[])
    @patch("picosentry.scan.daemon.HTTPServer")
    @patch("picosentry.scan.audit.audit")
    def test_enterprise_mode_passes_with_secure_config(self, mock_audit, mock_http, mock_checks, mock_is_enterprise):
        auth_config = AuthConfig(mode="oidc", oidc_issuer="https://idp.example.com")
        mock_http_instance = MagicMock()
        mock_http.return_value = mock_http_instance
        mock_http_instance.serve_forever.side_effect = KeyboardInterrupt()
        run_daemon(host="127.0.0.1", auth_config=auth_config)
        mock_checks.assert_called_once_with("oidc", "127.0.0.1")


# ── 5. X-Request-Id and X-Response-Time headers ───────────────────────


class TestRequestHeaders(unittest.TestCase):
    """Test X-Request-Id and X-Response-Time-Ms headers in responses."""

    def setUp(self):
        _reset_handler_defaults()

    def test_custom_request_id_propagated(self):
        handler = _make_handler(path="/health", headers={"X-Request-Id": "my-id-42"})
        request_id = handler._request_id()
        self.assertEqual(request_id, "my-id-42")

    def test_generated_request_id_format(self):
        handler = _make_handler(path="/health", headers={})
        request_id = handler._request_id()
        self.assertTrue(request_id.startswith("req-"))

    def test_send_json_includes_request_id_header(self):
        handler = _make_handler()
        handler._send_json(200, {"ok": True}, "test-rid")
        header_calls = handler.send_header.call_args_list
        rid_calls = [c for c in header_calls if c[0][0] == "X-Request-Id"]
        self.assertTrue(len(rid_calls) > 0)
        self.assertEqual(rid_calls[0][0][1], "test-rid")

    def test_send_json_includes_response_time_when_start_time(self):
        handler = _make_handler()
        start = time.monotonic() - 0.01
        handler._send_json(200, {"ok": True}, "rid", start)
        header_calls = handler.send_header.call_args_list
        rt_calls = [c for c in header_calls if c[0][0] == "X-Response-Time-Ms"]
        self.assertTrue(len(rt_calls) > 0)

    def test_send_json_no_response_time_without_start_time(self):
        handler = _make_handler()
        handler._send_json(200, {"ok": True}, "rid", None)
        header_calls = handler.send_header.call_args_list
        rt_calls = [c for c in header_calls if c[0][0] == "X-Response-Time-Ms"]
        self.assertEqual(len(rt_calls), 0)

    def test_send_json_no_request_id_when_empty(self):
        handler = _make_handler()
        handler._send_json(200, {"ok": True}, "")
        header_calls = handler.send_header.call_args_list
        rid_calls = [c for c in header_calls if c[0][0] == "X-Request-Id"]
        self.assertEqual(len(rid_calls), 0)

    def test_do_get_health_includes_request_id_in_body(self):
        handler = _make_handler(path="/health", headers={"X-Request-Id": "rid-abc"})
        with patch("picosentry.scan.logging.clear_request_context"):
            handler.do_GET()
        data = _read_json_body(handler)
        self.assertEqual(data["request_id"], "rid-abc")


# ── 6. Individual handler methods ─────────────────────────────────────


class TestHandleHealth(unittest.TestCase):
    def setUp(self):
        _reset_handler_defaults()

    def test_handle_health_returns_healthy(self):
        handler = _make_handler()
        handler._handle_health("rid-1", time.monotonic())
        data = _read_json_body(handler)
        self.assertEqual(data["status"], "healthy")
        self.assertEqual(data["request_id"], "rid-1")


class TestHandleReadiness(unittest.TestCase):
    def setUp(self):
        _reset_handler_defaults()

    def test_readiness_ready(self):
        handler = _make_handler()
        mock_engine = MagicMock()
        mock_engine._corpus_version = "1.0.0"
        mock_engine.list_rules.return_value = ["rule1", "rule2"]
        with patch("picosentry.scan.engine.create_default_engine", return_value=mock_engine):
            handler._handle_readiness("rid-2", time.monotonic())
        data = _read_json_body(handler)
        self.assertEqual(data["status"], "ready")
        self.assertEqual(data["version"], "1.0.0")
        self.assertEqual(data["rules"], 2)
        self.assertEqual(data["request_id"], "rid-2")

    def test_readiness_not_ready_engine_fails(self):
        handler = _make_handler()
        with patch("picosentry.scan.engine.create_default_engine", side_effect=RuntimeError("init error")):
            handler._handle_readiness("rid-3", time.monotonic())
        data = _read_json_body(handler)
        self.assertEqual(data["status"], "not_ready")
        self.assertEqual(data["reason"], "engine_init_failed")
        handler.send_response.assert_called_with(503)


class TestHandleMetrics(unittest.TestCase):
    def setUp(self):
        _reset_handler_defaults()

    def test_handle_metrics_prometheus_format(self):
        handler = _make_handler()
        handler._handle_metrics("rid-4", time.monotonic())
        body = _read_text_body(handler)
        self.assertIn("picosentry_", body)
        ct_calls = [c for c in handler.send_header.call_args_list if c[0][0] == "Content-Type"]
        self.assertTrue(any("text/plain" in str(c) for c in ct_calls))

    def test_handle_metrics_includes_request_id(self):
        handler = _make_handler()
        handler._handle_metrics("rid-5", time.monotonic())
        rid_calls = [c for c in handler.send_header.call_args_list if c[0][0] == "X-Request-Id"]
        self.assertTrue(len(rid_calls) > 0)

    def test_handle_metrics_includes_response_time(self):
        handler = _make_handler()
        handler._handle_metrics("rid-6", time.monotonic())
        rt_calls = [c for c in handler.send_header.call_args_list if c[0][0] == "X-Response-Time-Ms"]
        self.assertTrue(len(rt_calls) > 0)

    def test_handle_metrics_no_start_time(self):
        handler = _make_handler()
        handler._handle_metrics("rid-7", None)
        rt_calls = [c for c in handler.send_header.call_args_list if c[0][0] == "X-Response-Time-Ms"]
        self.assertEqual(len(rt_calls), 0)

    def test_handle_metrics_no_request_id(self):
        handler = _make_handler()
        handler._handle_metrics("", time.monotonic())
        rid_calls = [c for c in handler.send_header.call_args_list if c[0][0] == "X-Request-Id"]
        self.assertEqual(len(rid_calls), 0)


class TestHandleMetricsJson(unittest.TestCase):
    def setUp(self):
        _reset_handler_defaults()

    def test_handle_metrics_json_returns_dict(self):
        handler = _make_handler()
        handler._handle_metrics_json("rid-8", time.monotonic())
        data = _read_json_body(handler)
        self.assertIn("counters", data)
        self.assertIn("uptime_seconds", data)


class TestHandleRoot(unittest.TestCase):
    def setUp(self):
        _reset_handler_defaults()

    def test_handle_root_info(self):
        handler = _make_handler()
        handler._handle_root("rid-9", time.monotonic())
        data = _read_json_body(handler)
        self.assertEqual(data["service"], "picosentry")
        self.assertIn("version", data)
        self.assertIn("endpoints", data)
        self.assertEqual(data["auth_mode"], "off")
        self.assertEqual(data["request_id"], "rid-9")


# ── 7. run_daemon startup and signal handling ─────────────────────────


class TestRunDaemon(unittest.TestCase):
    """Test run_daemon startup, config loading, and signal handling."""

    @patch("picosentry.scan.daemon.is_enterprise_mode", return_value=False)
    @patch("picosentry.scan.daemon.HTTPServer")
    @patch("signal.signal")
    @patch("picosentry.scan.audit.audit")
    def test_run_daemon_sets_class_config(self, mock_audit, mock_signal_sig, mock_http, mock_is_enterprise):
        auth_config = AuthConfig(mode="token", token="abc", rate_limit_rps=10)
        mock_http_instance = MagicMock()
        mock_http.return_value = mock_http_instance
        mock_http_instance.serve_forever.side_effect = KeyboardInterrupt()
        run_daemon(host="127.0.0.1", port=9999, auth_config=auth_config)
        self.assertEqual(HealthHandler.auth_config.mode, "token")
        self.assertIsNotNone(HealthHandler.rate_limiter)
        mock_http.assert_called_once_with(("127.0.0.1", 9999), HealthHandler)

    @patch("picosentry.scan.daemon.is_enterprise_mode", return_value=False)
    @patch("picosentry.scan.daemon.HTTPServer")
    @patch("signal.signal")
    @patch("picosentry.scan.audit.audit")
    def test_run_daemon_registers_signal_handlers(self, mock_audit, mock_signal_sig, mock_http, mock_is_enterprise):
        auth_config = AuthConfig(mode="off")
        mock_http_instance = MagicMock()
        mock_http.return_value = mock_http_instance
        mock_http_instance.serve_forever.side_effect = KeyboardInterrupt()
        run_daemon(auth_config=auth_config)
        sig_calls = [c[0][0] for c in mock_signal_sig.call_args_list]
        self.assertIn(signal.SIGTERM, sig_calls)
        self.assertIn(signal.SIGINT, sig_calls)

    @patch("picosentry.scan.daemon.is_enterprise_mode", return_value=False)
    @patch("picosentry.scan.daemon.HTTPServer")
    @patch("signal.signal")
    @patch("picosentry.scan.audit.audit")
    def test_run_daemon_shutdown_calls_server_shutdown(
        self, mock_audit, mock_signal_sig, mock_http, mock_is_enterprise
    ):
        auth_config = AuthConfig(mode="off")
        mock_http_instance = MagicMock()
        mock_http.return_value = mock_http_instance
        mock_http_instance.serve_forever.side_effect = KeyboardInterrupt()
        run_daemon(auth_config=auth_config)
        # Find the shutdown handler passed to signal.signal
        shutdown_handler = None
        for c in mock_signal_sig.call_args_list:
            if c[0][0] == signal.SIGTERM:
                shutdown_handler = c[0][1]
                break
        self.assertIsNotNone(shutdown_handler)
        # Call it to verify it calls server.shutdown()
        shutdown_handler(signal.SIGTERM, None)
        mock_http_instance.shutdown.assert_called_once()

    @patch("picosentry.scan.daemon.is_enterprise_mode", return_value=False)
    @patch("picosentry.scan.daemon.HTTPServer")
    @patch("signal.signal")
    @patch("picosentry.scan.audit.audit")
    def test_run_daemon_keyboard_interrupt(self, mock_audit, mock_signal_sig, mock_http, mock_is_enterprise):
        auth_config = AuthConfig(mode="off")
        mock_http_instance = MagicMock()
        mock_http.return_value = mock_http_instance
        mock_http_instance.serve_forever.side_effect = KeyboardInterrupt()
        run_daemon(auth_config=auth_config)
        mock_http_instance.server_close.assert_called_once()

    @patch("picosentry.scan.daemon.is_enterprise_mode", return_value=False)
    @patch("picosentry.scan.daemon.HTTPServer")
    @patch("signal.signal")
    @patch("picosentry.scan.audit.audit")
    def test_run_daemon_server_close_in_finally(self, mock_audit, mock_signal_sig, mock_http, mock_is_enterprise):
        auth_config = AuthConfig(mode="off")
        mock_http_instance = MagicMock()
        mock_http.return_value = mock_http_instance
        mock_http_instance.serve_forever.side_effect = RuntimeError("boom")
        with self.assertRaises(RuntimeError):
            run_daemon(auth_config=auth_config)
        mock_http_instance.server_close.assert_called_once()

    @patch("picosentry.scan.daemon.is_enterprise_mode", return_value=False)
    @patch("picosentry.scan.daemon.HTTPServer")
    @patch("signal.signal")
    @patch("picosentry.scan.audit.audit")
    def test_run_daemon_none_auth_config_uses_env(self, mock_audit, mock_signal_sig, mock_http, mock_is_enterprise):
        mock_http_instance = MagicMock()
        mock_http.return_value = mock_http_instance
        mock_http_instance.serve_forever.side_effect = KeyboardInterrupt()
        with (
            patch("picosentry.scan.config.load_config", side_effect=RuntimeError("no config")),
            patch.object(AuthConfig, "from_env", return_value=AuthConfig(mode="off")) as mock_from_env,
        ):
            run_daemon()
            mock_from_env.assert_called_once()

    @patch("picosentry.scan.daemon.is_enterprise_mode", return_value=False)
    @patch("picosentry.scan.daemon.HTTPServer")
    @patch("signal.signal")
    @patch("picosentry.scan.audit.audit")
    def test_run_daemon_none_auth_config_with_config_file(
        self, mock_audit, mock_signal_sig, mock_http, mock_is_enterprise
    ):
        mock_http_instance = MagicMock()
        mock_http.return_value = mock_http_instance
        mock_http_instance.serve_forever.side_effect = KeyboardInterrupt()
        mock_cfg = MagicMock()
        mock_cfg.daemon = {"mode": "token", "token": "from-config"}
        with patch("picosentry.scan.config.load_config", return_value=mock_cfg):
            run_daemon()
        self.assertEqual(HealthHandler.auth_config.mode, "token")
        self.assertEqual(HealthHandler.auth_config.token, "from-config")

    @patch("picosentry.scan.daemon.is_enterprise_mode", return_value=False)
    @patch("picosentry.scan.daemon.HTTPServer")
    @patch("signal.signal")
    @patch("picosentry.scan.audit.audit")
    def test_run_daemon_none_auth_config_no_daemon_section(
        self, mock_audit, mock_signal_sig, mock_http, mock_is_enterprise
    ):
        mock_http_instance = MagicMock()
        mock_http.return_value = mock_http_instance
        mock_http_instance.serve_forever.side_effect = KeyboardInterrupt()
        mock_cfg = MagicMock()
        mock_cfg.daemon = None
        with (
            patch("picosentry.scan.config.load_config", return_value=mock_cfg),
            patch.object(AuthConfig, "from_env", return_value=AuthConfig(mode="off")) as mock_from_env,
        ):
            run_daemon()
            mock_from_env.assert_called_once()

    @patch("picosentry.scan.daemon.is_enterprise_mode", return_value=False)
    @patch("picosentry.scan.daemon.HTTPServer")
    @patch("signal.signal")
    @patch("picosentry.scan.audit.audit")
    def test_run_daemon_prints_startup_info(self, mock_audit, mock_signal_sig, mock_http, mock_is_enterprise):
        auth_config = AuthConfig(mode="off")
        mock_http_instance = MagicMock()
        mock_http.return_value = mock_http_instance
        mock_http_instance.serve_forever.side_effect = KeyboardInterrupt()
        with patch("builtins.print") as mock_print:
            run_daemon(auth_config=auth_config)
        printed = " ".join(str(c) for c in mock_print.call_args_list)
        self.assertIn("picosentry", printed.lower())

    @patch("picosentry.scan.daemon.is_enterprise_mode", return_value=False)
    @patch("picosentry.scan.daemon.HTTPServer")
    @patch("signal.signal")
    @patch("picosentry.scan.audit.audit")
    def test_run_daemon_public_all_when_auth_off(self, mock_audit, mock_signal_sig, mock_http, mock_is_enterprise):
        auth_config = AuthConfig(mode="off")
        mock_http_instance = MagicMock()
        mock_http.return_value = mock_http_instance
        mock_http_instance.serve_forever.side_effect = KeyboardInterrupt()
        with patch("builtins.print") as mock_print:
            run_daemon(auth_config=auth_config)
            public_calls = [c for c in mock_print.call_args_list if "Public" in str(c)]
            self.assertTrue(any("all" in str(c) for c in public_calls))

    @patch("picosentry.scan.daemon.is_enterprise_mode", return_value=False)
    @patch("picosentry.scan.daemon.HTTPServer")
    @patch("signal.signal")
    @patch("picosentry.scan.audit.audit")
    def test_run_daemon_rate_limit_display(self, mock_audit, mock_signal_sig, mock_http, mock_is_enterprise):
        auth_config = AuthConfig(mode="off", rate_limit_rps=10)
        mock_http_instance = MagicMock()
        mock_http.return_value = mock_http_instance
        mock_http_instance.serve_forever.side_effect = KeyboardInterrupt()
        with patch("builtins.print") as mock_print:
            run_daemon(auth_config=auth_config)
            rate_calls = [c for c in mock_print.call_args_list if "Rate limit" in str(c)]
            self.assertTrue(any("10" in str(c) for c in rate_calls))

    @patch("picosentry.scan.daemon.is_enterprise_mode", return_value=False)
    @patch("picosentry.scan.daemon.HTTPServer")
    @patch("signal.signal")
    @patch("picosentry.scan.audit.audit")
    def test_run_daemon_rate_limit_unlimited_display(self, mock_audit, mock_signal_sig, mock_http, mock_is_enterprise):
        auth_config = AuthConfig(mode="off", rate_limit_rps=0)
        mock_http_instance = MagicMock()
        mock_http.return_value = mock_http_instance
        mock_http_instance.serve_forever.side_effect = KeyboardInterrupt()
        with patch("builtins.print") as mock_print:
            run_daemon(auth_config=auth_config)
            rate_calls = [c for c in mock_print.call_args_list if "Rate limit" in str(c)]
            self.assertTrue(any("unlimited" in str(c) for c in rate_calls))

    @patch("picosentry.scan.daemon.is_enterprise_mode", return_value=True)
    @patch("picosentry.scan.daemon.enterprise_daemon_checks", return_value=[])
    @patch("picosentry.scan.daemon.HTTPServer")
    @patch("signal.signal")
    @patch("picosentry.scan.audit.audit")
    def test_enterprise_on_prints_enterprise_msg(
        self, mock_audit, mock_signal_sig, mock_http, mock_checks, mock_is_enterprise
    ):
        auth_config = AuthConfig(mode="oidc", oidc_issuer="https://idp.example.com")
        mock_http_instance = MagicMock()
        mock_http.return_value = mock_http_instance
        mock_http_instance.serve_forever.side_effect = KeyboardInterrupt()
        with patch("builtins.print") as mock_print:
            run_daemon(host="127.0.0.1", auth_config=auth_config)
            printed = " ".join(str(c) for c in mock_print.call_args_list)
            self.assertIn("Enterprise", printed)


# ── 8. _client_ip with trusted proxies and X-Forwarded-For ────────────


class TestClientIp(unittest.TestCase):
    """Test _client_ip with various proxy configurations."""

    def setUp(self):
        _reset_handler_defaults()

    def test_direct_ip_no_proxies(self):
        handler = _make_handler(client_address=("10.0.0.1", 4321))
        self.assertEqual(handler._client_ip(), "10.0.0.1")

    def test_trusted_proxy_uses_forwarded(self):
        HealthHandler.auth_config = AuthConfig(trusted_proxies=["10.0.0.1"])
        handler = _make_handler(
            client_address=("10.0.0.1", 4321),
            headers={"X-Forwarded-For": "192.168.1.1, 10.0.0.2"},
        )
        self.assertEqual(handler._client_ip(), "192.168.1.1")

    def test_untrusted_proxy_ignores_forwarded(self):
        HealthHandler.auth_config = AuthConfig(trusted_proxies=["10.0.0.1"])
        handler = _make_handler(
            client_address=("10.0.0.99", 4321),
            headers={"X-Forwarded-For": "192.168.1.1, 10.0.0.2"},
        )
        self.assertEqual(handler._client_ip(), "10.0.0.99")

    def test_trusted_proxy_no_forwarded_header(self):
        HealthHandler.auth_config = AuthConfig(trusted_proxies=["10.0.0.1"])
        handler = _make_handler(
            client_address=("10.0.0.1", 4321),
            headers={},
        )
        self.assertEqual(handler._client_ip(), "10.0.0.1")

    def test_empty_forwarded_uses_direct(self):
        HealthHandler.auth_config = AuthConfig(trusted_proxies=["10.0.0.1"])
        handler = _make_handler(
            client_address=("10.0.0.1", 4321),
            headers={"X-Forwarded-For": ""},
        )
        self.assertEqual(handler._client_ip(), "10.0.0.1")

    def test_none_client_address_returns_unknown(self):
        handler = _make_handler()
        handler.client_address = None
        self.assertEqual(handler._client_ip(), "unknown")

    def test_empty_trusted_proxies_list(self):
        HealthHandler.auth_config = AuthConfig(trusted_proxies=[])
        handler = _make_handler(
            client_address=("10.0.0.1", 4321),
            headers={"X-Forwarded-For": "192.168.1.1"},
        )
        self.assertEqual(handler._client_ip(), "10.0.0.1")


# ── 9. Additional coverage: log_message, _get_headers_dict, _request_id ─


class TestLogMessage(unittest.TestCase):
    def test_log_message_uses_debug_logger(self):
        handler = _make_handler()
        with patch("picosentry.scan.daemon.logger") as mock_logger:
            handler.log_message("test %s", "msg")
            mock_logger.debug.assert_called_once()


class TestGetHeadersDict(unittest.TestCase):
    def test_lowercase_keys(self):
        handler = _make_handler()
        handler.headers = {"Content-Type": "text/plain", "X-Request-Id": "abc"}
        result = handler._get_headers_dict()
        self.assertEqual(result["content-type"], "text/plain")
        self.assertEqual(result["x-request-id"], "abc")

    def test_empty_headers(self):
        handler = _make_handler()
        handler.headers = {}
        result = handler._get_headers_dict()
        self.assertEqual(result, {})


class TestRequestIdMonotonic(unittest.TestCase):
    def test_counter_increments(self):
        import picosentry.scan.daemon as dm

        original = dm._request_counter
        try:
            dm._request_counter = 0
            handler1 = _make_handler(headers={})
            handler2 = _make_handler(headers={})
            id1 = handler1._request_id()
            id2 = handler2._request_id()
            self.assertNotEqual(id1, id2)
            self.assertTrue(id1.startswith("req-"))
            self.assertTrue(id2.startswith("req-"))
        finally:
            dm._request_counter = original


# ── 10. _check_rate_limit unit tests ────────────────────────────────────


class TestCheckRateLimitUnit(unittest.TestCase):
    """Unit tests for _check_rate_limit."""

    def setUp(self):
        HealthHandler.auth_config = AuthConfig(mode="off")

    def test_unlimited_always_allows(self):
        HealthHandler.rate_limiter = RateLimiter(rps=0)
        handler = _make_handler()
        self.assertTrue(handler._check_rate_limit("1.2.3.4", "rid"))

    def test_limited_sends_429(self):
        HealthHandler.rate_limiter = RateLimiter(rps=5, burst=1)
        HealthHandler.rate_limiter.check("1.2.3.4")
        handler = _make_handler()
        result = handler._check_rate_limit("1.2.3.4", "rid")
        self.assertFalse(result)
        handler.send_response.assert_called_with(429)

    def test_limited_includes_request_id_header(self):
        HealthHandler.rate_limiter = RateLimiter(rps=5, burst=1)
        HealthHandler.rate_limiter.check("1.2.3.4")
        handler = _make_handler()
        handler._check_rate_limit("1.2.3.4", "my-rid")
        rid_calls = [c for c in handler.send_header.call_args_list if c[0][0] == "X-Request-Id"]
        self.assertTrue(len(rid_calls) > 0)

    def test_limited_no_request_id_when_empty(self):
        HealthHandler.rate_limiter = RateLimiter(rps=5, burst=1)
        HealthHandler.rate_limiter.check("1.2.3.4")
        handler = _make_handler()
        handler._check_rate_limit("1.2.3.4", "")
        rid_calls = [c for c in handler.send_header.call_args_list if c[0][0] == "X-Request-Id"]
        self.assertEqual(len(rid_calls), 0)


# ── 11. _check_auth path stripping ─────────────────────────────────────


class TestCheckAuthPathStripping(unittest.TestCase):
    def setUp(self):
        HealthHandler.rate_limiter = RateLimiter(rps=0)

    def test_check_auth_path_strips_query(self):
        HealthHandler.auth_config = AuthConfig(mode="token", token="s3cret", public_endpoints=["/healthz"])
        handler = _make_handler(path="/healthz?foo=1", headers={})
        result = handler._check_auth("rid")
        self.assertTrue(result.ok)
        self.assertEqual(result.identity, "anonymous")

    def test_check_auth_path_strips_fragment(self):
        HealthHandler.auth_config = AuthConfig(mode="token", token="s3cret", public_endpoints=["/healthz"])
        handler = _make_handler(path="/healthz#section", headers={})
        result = handler._check_auth("rid")
        self.assertTrue(result.ok)


# ── 12. Integration-style: HTTPServer test harness ────────────────────


class TestHTTPServerIntegration(unittest.TestCase):
    """Integration test using real HTTPServer + urllib.request."""

    def setUp(self):
        _reset_handler_defaults()
        self.server = HTTPServer(("127.0.0.1", 0), HealthHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()

    def _get(self, path):
        import urllib.request

        url = f"http://127.0.0.1:{self.port}{path}"
        with urllib.request.urlopen(url) as resp:
            body = resp.read().decode()
            return resp.status, json.loads(body), dict(resp.headers)

    def test_health_via_http(self):
        status, body, _headers = self._get("/health")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "healthy")

    def test_healthz_via_http(self):
        status, body, _headers = self._get("/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(body["status"], "healthy")

    def test_root_via_http(self):
        status, body, _headers = self._get("/")
        self.assertEqual(status, 200)
        self.assertEqual(body["service"], "picosentry")

    def test_metrics_json_via_http(self):
        status, body, _ = self._get("/metrics/json")
        self.assertEqual(status, 200)
        self.assertIn("counters", body)

    def test_404_via_http(self):
        import urllib.error
        import urllib.request

        url = f"http://127.0.0.1:{self.port}/nonexistent"
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(url)
        self.assertEqual(ctx.exception.code, 404)

    def test_response_time_header(self):
        import urllib.request

        url = f"http://127.0.0.1:{self.port}/health"
        with urllib.request.urlopen(url) as resp:
            self.assertIn("X-Response-Time-Ms", dict(resp.headers))

    def test_request_id_header(self):
        import urllib.request

        url = f"http://127.0.0.1:{self.port}/health"
        req = urllib.request.Request(url, headers={"X-Request-Id": "int-test-42"})
        with urllib.request.urlopen(req) as resp:
            body = json.loads(resp.read().decode())
            self.assertEqual(body["request_id"], "int-test-42")
            self.assertEqual(resp.headers.get("X-Request-Id"), "int-test-42")


class TestHTTPServerIntegrationWithAuth(unittest.TestCase):
    """Integration test with token auth enabled."""

    def setUp(self):
        HealthHandler.auth_config = AuthConfig(
            mode="token",
            token="s3cret-token",
            public_endpoints=["/healthz", "/readyz"],
        )
        HealthHandler.rate_limiter = RateLimiter(rps=0)
        self.server = HTTPServer(("127.0.0.1", 0), HealthHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()

    def test_public_endpoint_no_auth_needed(self):
        import urllib.request

        url = f"http://127.0.0.1:{self.port}/healthz"
        with urllib.request.urlopen(url) as resp:
            self.assertEqual(resp.status, 200)

    def test_metrics_requires_auth(self):
        import urllib.error
        import urllib.request

        url = f"http://127.0.0.1:{self.port}/metrics"
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(url)
        self.assertEqual(ctx.exception.code, 401)

    def test_metrics_with_valid_token(self):
        import urllib.request

        url = f"http://127.0.0.1:{self.port}/metrics"
        req = urllib.request.Request(url, headers={"Authorization": "Bearer s3cret-token"})
        with urllib.request.urlopen(req) as resp:
            self.assertEqual(resp.status, 200)

    def test_metrics_with_invalid_token(self):
        import urllib.error
        import urllib.request

        url = f"http://127.0.0.1:{self.port}/metrics"
        req = urllib.request.Request(url, headers={"Authorization": "Bearer wrong-token"})
        with self.assertRaises(urllib.error.HTTPError) as ctx:
            urllib.request.urlopen(req)
        self.assertEqual(ctx.exception.code, 403)


class TestHTTPServerIntegrationWithRateLimit(unittest.TestCase):
    """Integration test with rate limiting."""

    def setUp(self):
        HealthHandler.auth_config = AuthConfig(mode="off")
        HealthHandler.rate_limiter = RateLimiter(rps=1, burst=2)
        self.server = HTTPServer(("127.0.0.1", 0), HealthHandler)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever)
        self.thread.daemon = True
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.thread.join(timeout=2)
        self.server.server_close()

    def test_rate_limited_429(self):
        import urllib.error
        import urllib.request

        url = f"http://127.0.0.1:{self.port}/health"
        # Exhaust burst
        urllib.request.urlopen(url)
        urllib.request.urlopen(url)
        # Next should be 429
        try:
            urllib.request.urlopen(url)
            self.fail("Expected HTTPError 429")
        except urllib.error.HTTPError as e:
            self.assertEqual(e.code, 429)


if __name__ == "__main__":
    unittest.main()
