from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from picosentry.firewall.proxy import FirewallConfig, FirewallProxy
from picosentry.firewall.scanner import FirewallVerdict, classify_path


def _make_finding(rule_id, severity_value, message):
    return type(
        "_F",
        (),
        {
            "rule_id": rule_id,
            "severity": MagicMock(value=severity_value),
            "message": message,
        },
    )()


class TestClassifyPath:
    def test_npm_package(self):
        assert classify_path("/express") == ("npm", "express", "latest")

    def test_npm_package_version(self):
        assert classify_path("/express/4.18.0") == ("npm", "express", "4.18.0")

    def test_npm_scoped_package(self):
        result = classify_path("/@types/node")
        assert result is not None
        assert result[0] == "npm"
        assert result[1] == "@types/node"

    def test_pypi_package(self):
        assert classify_path("/pypi/requests/json") == ("pypi", "requests", "latest")

    def test_pypi_package_version(self):
        assert classify_path("/pypi/requests/2.31.0/json") == ("pypi", "requests", "2.31.0")

    def test_unknown_path(self):
        assert classify_path("/favicon.ico") is None

    def test_npm_encoded_scope(self):
        result = classify_path("/@babel%2Fcore")
        assert result is not None
        assert result[0] == "npm"

    def test_npm_dotted_package(self):
        result = classify_path("/socket.io")
        assert result is not None
        assert result[0] == "npm"


class TestFirewallConfig:
    def test_defaults(self):
        config = FirewallConfig()
        assert config.listen_port == 3132
        assert config.listen_host == "127.0.0.1"
        assert config.upstream_npm == "https://registry.npmjs.org"
        assert config.upstream_pypi == "https://pypi.org"
        assert config.block_severities == ["CRITICAL"]
        assert config.quarantine_severities == ["HIGH", "MEDIUM"]
        assert config.auth_token is None
        assert config.quarantine_action == "tag"
        assert config.cache_ttl_seconds == 3600
        assert config.log_blocks is True

    def test_custom_port(self):
        config = FirewallConfig(listen_port=8080)
        assert config.listen_port == 8080

    def test_custom_listen_host(self):
        config = FirewallConfig(listen_host="0.0.0.0")
        assert config.listen_host == "0.0.0.0"

    def test_invalid_quarantine_action_rejected(self):
        import pytest

        with pytest.raises(ValueError):
            FirewallConfig(quarantine_action="nonsense")

    def test_strips_trailing_slash(self):
        config = FirewallConfig(
            upstream_npm="https://registry.npmjs.org/",
            upstream_pypi="https://pypi.org/",
        )
        assert config.upstream_npm == "https://registry.npmjs.org"
        assert config.upstream_pypi == "https://pypi.org"


class TestFirewallProxy:
    def test_proxy_creates_scanner(self):
        config = FirewallConfig()
        proxy = FirewallProxy(config)
        assert proxy.scanner is not None
        assert proxy.config is config

    def test_proxy_scanner_has_configured_thresholds(self):
        config = FirewallConfig(
            block_severities=["CRITICAL"],
            quarantine_severities=["MEDIUM"],
        )
        proxy = FirewallProxy(config)
        assert proxy.scanner._block_sevs == {"CRITICAL"}
        assert proxy.scanner._quarantine_sevs == {"MEDIUM"}


class TestProxyHandlerVerdictLogic:
    def test_blocked_verdict_returns_403(self):
        from picosentry.firewall.proxy import _ProxyHandler, FirewallConfig

        config = FirewallConfig()
        proxy = FirewallProxy(config)
        handler_class = type(
            "_H",
            (_ProxyHandler,),
            {"config": config, "scanner": proxy.scanner},
        )
        handler = object.__new__(handler_class)
        handler.path = "/evil-pkg/1.0.0"
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()
        handler.wfile = MagicMock()
        handler.log_message = MagicMock()
        handler.scanner.scan_metadata = MagicMock(
            return_value=(
                FirewallVerdict.BLOCK,
                [_make_finding("L2-POST-001", "CRITICAL", "postinstall script")],
            )
        )
        with patch("picosentry.firewall.proxy.safe_urlopen") as mock_safe:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.headers = MagicMock()
            mock_resp.headers.get.return_value = "application/json"
            mock_safe.return_value = (mock_resp, json.dumps({"name": "evil-pkg", "version": "1.0.0"}).encode())
            handler.do_GET()
            calls = [str(c) for c in handler.send_response.call_args_list]
            assert any("403" in c for c in calls)

    def test_allowed_verdict_passes_through(self):
        from picosentry.firewall.proxy import _ProxyHandler, FirewallConfig

        config = FirewallConfig()
        proxy = FirewallProxy(config)
        handler_class = type(
            "_H",
            (_ProxyHandler,),
            {"config": config, "scanner": proxy.scanner},
        )
        handler = object.__new__(handler_class)
        handler.path = "/safe-pkg/1.0.0"
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()
        handler.wfile = MagicMock()
        handler.log_message = MagicMock()
        handler.scanner.scan_metadata = MagicMock(return_value=(FirewallVerdict.ALLOW, []))
        with patch("picosentry.firewall.proxy.safe_urlopen") as mock_safe:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.headers = MagicMock()
            mock_resp.headers.get.return_value = "application/json"
            mock_safe.return_value = (mock_resp, json.dumps({"name": "safe-pkg"}).encode())
            handler.do_GET()
            calls = [str(c) for c in handler.send_response.call_args_list]
            assert any("200" in c for c in calls)

    def test_quarantine_verdict_passes_through(self):
        from picosentry.firewall.proxy import _ProxyHandler, FirewallConfig

        config = FirewallConfig()
        proxy = FirewallProxy(config)
        handler_class = type(
            "_H",
            (_ProxyHandler,),
            {"config": config, "scanner": proxy.scanner},
        )
        handler = object.__new__(handler_class)
        handler.path = "/warn-pkg/1.0.0"
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()
        handler.wfile = MagicMock()
        handler.log_message = MagicMock()
        handler.scanner.scan_metadata = MagicMock(
            return_value=(
                FirewallVerdict.QUARANTINE,
                [_make_finding("L2-OBFS-001", "MEDIUM", "obfuscated code")],
            )
        )
        with patch("picosentry.firewall.proxy.safe_urlopen") as mock_safe:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.headers = MagicMock()
            mock_resp.headers.get.return_value = "application/json"
            mock_safe.return_value = (mock_resp, json.dumps({"name": "warn-pkg"}).encode())
            handler.do_GET()
            calls = [str(c) for c in handler.send_response.call_args_list]
            assert any("200" in c for c in calls)
            header_dict = {args[0]: args[1] for args, _ in handler.send_header.call_args_list}
            assert header_dict.get("X-PicoSentry-Verdict") == "quarantine"
            assert "X-PicoSentry-Reasons" in header_dict

    def test_oversized_upstream_returns_502(self):
        from picosentry.firewall.proxy import _ProxyHandler, FirewallConfig
        from picosentry.scan._network import ResponseTooLargeError

        config = FirewallConfig()
        proxy = FirewallProxy(config)
        handler_class = type(
            "_H",
            (_ProxyHandler,),
            {"config": config, "scanner": proxy.scanner},
        )
        handler = object.__new__(handler_class)
        handler.path = "/big-pkg/1.0.0"
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()
        handler.wfile = MagicMock()
        handler.log_message = MagicMock()
        with patch("picosentry.firewall.proxy.safe_urlopen", side_effect=ResponseTooLargeError("too big")):
            handler.do_GET()
            calls = [str(c) for c in handler.send_response.call_args_list]
            assert any("502" in c for c in calls)

    def test_unresolved_verdict_returns_502(self):
        # WO6-017: an unresolvable version (whole-catalog doc without the
        # requested version) must 502, not fall back to scanning root fields.
        from picosentry.firewall.proxy import _ProxyHandler, FirewallConfig

        config = FirewallConfig()
        proxy = FirewallProxy(config)
        handler_class = type(
            "_H",
            (_ProxyHandler,),
            {"config": config, "scanner": proxy.scanner},
        )
        handler = object.__new__(handler_class)
        handler.path = "/acme-lib/9.9.9"
        handler.send_response = MagicMock()
        handler.send_header = MagicMock()
        handler.end_headers = MagicMock()
        handler.wfile = MagicMock()
        handler.log_message = MagicMock()
        handler.scanner.scan_metadata = MagicMock(return_value=(FirewallVerdict.UNRESOLVED, []))
        with patch("picosentry.firewall.proxy.safe_urlopen") as mock_safe:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.headers = MagicMock()
            mock_resp.headers.get.return_value = "application/json"
            mock_safe.return_value = (
                mock_resp,
                json.dumps({"name": "acme-lib", "versions": {"1.0.0": {}}}).encode(),
            )
            handler.do_GET()
        calls = [str(c) for c in handler.send_response.call_args_list]
        assert any("502" in c for c in calls)
        header_dict = {args[0]: args[1] for args, _ in handler.send_header.call_args_list}
        assert header_dict.get("X-PicoSentry-Verdict") == "unresolved"


class TestSafeUpstreamPath:
    def test_rejects_dotdot(self):
        from picosentry.firewall.proxy import _safe_upstream_path

        assert _safe_upstream_path("/../../../etc/passwd") is None

    def test_rejects_double_slash(self):
        from picosentry.firewall.proxy import _safe_upstream_path

        assert _safe_upstream_path("//attacker.com/evil") is None

    def test_rejects_no_leading_slash(self):
        from picosentry.firewall.proxy import _safe_upstream_path

        assert _safe_upstream_path("relative/path") is None

    def test_accepts_normal_path(self):
        from picosentry.firewall.proxy import _safe_upstream_path

        assert _safe_upstream_path("/express/4.18.0") == "/express/4.18.0"


class TestSanitizeHeader:
    def test_strips_cr(self):
        from picosentry.firewall.proxy import _sanitize_header

        assert _sanitize_header("text/html\r") == "text/html"

    def test_strips_lf(self):
        from picosentry.firewall.proxy import _sanitize_header

        assert _sanitize_header("text/html\n") == "text/html"

    def test_strips_crlf_injection(self):
        from picosentry.firewall.proxy import _sanitize_header

        assert _sanitize_header("text/html\r\nX-Malicious: injected") == "text/htmlX-Malicious: injected"


def _make_handler(path, config):
    from picosentry.firewall.proxy import _ProxyHandler

    proxy = FirewallProxy(config)
    handler_class = type("_H", (_ProxyHandler,), {"config": config, "scanner": proxy.scanner})
    handler = object.__new__(handler_class)
    handler.path = path
    handler.send_response = MagicMock()
    handler.send_header = MagicMock()
    handler.end_headers = MagicMock()
    handler.wfile = MagicMock()
    handler.log_message = MagicMock()
    handler.headers = {}
    return handler


def _upstream_json(payload):
    mock_resp = MagicMock()
    mock_resp.status = 200
    mock_resp.headers = MagicMock()
    mock_resp.headers.get.return_value = "application/json"
    return mock_resp, json.dumps(payload).encode()


class TestProxyAuth:
    def test_no_token_configured_allows_anonymous(self):
        handler = _make_handler("/safe-pkg/1.0.0", FirewallConfig())
        handler.scanner.scan_metadata = MagicMock(return_value=(FirewallVerdict.ALLOW, []))
        with patch("picosentry.firewall.proxy.safe_urlopen") as mock_safe:
            mock_safe.return_value = _upstream_json({"name": "safe-pkg"})
            handler.do_GET()
            assert any("200" in str(c) for c in handler.send_response.call_args_list)

    def test_missing_token_returns_401(self):
        handler = _make_handler("/safe-pkg/1.0.0", FirewallConfig(auth_token="sekrit"))
        handler.do_GET()
        assert any("401" in str(c) for c in handler.send_response.call_args_list)
        headers = {args[0]: args[1] for args, _ in handler.send_header.call_args_list}
        assert headers.get("WWW-Authenticate") == "Bearer"

    def test_wrong_token_returns_401(self):
        handler = _make_handler("/safe-pkg/1.0.0", FirewallConfig(auth_token="sekrit"))
        handler.headers = {"Authorization": "Bearer wrong"}
        handler.do_GET()
        assert any("401" in str(c) for c in handler.send_response.call_args_list)

    def test_correct_bearer_token_passes(self):
        handler = _make_handler("/safe-pkg/1.0.0", FirewallConfig(auth_token="sekrit"))
        handler.headers = {"Authorization": "Bearer sekrit"}
        handler.scanner.scan_metadata = MagicMock(return_value=(FirewallVerdict.ALLOW, []))
        with patch("picosentry.firewall.proxy.safe_urlopen") as mock_safe:
            mock_safe.return_value = _upstream_json({"name": "safe-pkg"})
            handler.do_GET()
            assert any("200" in str(c) for c in handler.send_response.call_args_list)

    def test_non_bearer_scheme_rejected(self):
        handler = _make_handler("/safe-pkg/1.0.0", FirewallConfig(auth_token="sekrit"))
        handler.headers = {"Authorization": "Basic c2VrcmlpdA=="}
        handler.do_GET()
        assert any("401" in str(c) for c in handler.send_response.call_args_list)

    def test_non_ascii_authorization_returns_clean_401(self):
        # WO5.0.0-012: latin-1 header bytes (0xE9 = é) decode to a non-ASCII
        # str; compare_digest on str raises TypeError and used to kill the
        # connection with a traceback instead of a 401.
        handler = _make_handler("/safe-pkg/1.0.0", FirewallConfig(auth_token="sekrit"))
        handler.headers = {"Authorization": "Bearer caf\xe9"}
        handler.do_GET()
        assert any("401" in str(c) for c in handler.send_response.call_args_list)

    def test_non_ascii_but_correct_length_token_returns_401(self):
        handler = _make_handler("/safe-pkg/1.0.0", FirewallConfig(auth_token="sekrit"))
        handler.headers = {"Authorization": "Bearer s\xe9krit"}
        handler.do_GET()
        assert any("401" in str(c) for c in handler.send_response.call_args_list)


class TestQueryDecoratedPaths:
    """WO5.0.0-012: query-decorated metadata URLs must be scanned under a clean name."""

    def test_pypi_query_url_scanned_with_clean_name(self):
        handler = _make_handler("/pypi/requests/2.31.0/json?refresh=1", FirewallConfig())
        handler.scanner.scan_metadata = MagicMock(return_value=(FirewallVerdict.ALLOW, []))
        with patch("picosentry.firewall.proxy.safe_urlopen") as mock_safe:
            payload = {"info": {"name": "requests", "version": "2.31.0"}}
            mock_safe.return_value = _upstream_json(payload)
            handler.do_GET()
            handler.scanner.scan_metadata.assert_called_once_with("pypi", "requests", "2.31.0", payload)
            header_dict = {args[0]: args[1] for args, _ in handler.send_header.call_args_list}
            assert header_dict.get("X-PicoSentry-Verdict") == "allow"
            upstream_url = mock_safe.call_args[0][0].full_url
            assert "refresh=1" in upstream_url

    def test_pypi_quarantine_on_query_url_not_passthrough(self):
        handler = _make_handler("/pypi/requests/2.31.0/json?refresh=1", FirewallConfig())
        handler.scanner.scan_metadata = MagicMock(
            return_value=(FirewallVerdict.QUARANTINE, [_make_finding("L2-OBFS-001", "MEDIUM", "obfuscated code")])
        )
        with patch("picosentry.firewall.proxy.safe_urlopen") as mock_safe:
            mock_safe.return_value = _upstream_json({"info": {"name": "requests"}})
            handler.do_GET()
            header_dict = {args[0]: args[1] for args, _ in handler.send_header.call_args_list}
            assert header_dict.get("X-PicoSentry-Verdict") == "quarantine"

    def test_npm_query_url_scanned_with_clean_name(self):
        handler = _make_handler("/lodash?meta=1", FirewallConfig())
        handler.scanner.scan_metadata = MagicMock(return_value=(FirewallVerdict.ALLOW, []))
        with patch("picosentry.firewall.proxy.safe_urlopen") as mock_safe:
            payload = {"name": "lodash", "versions": {}}
            mock_safe.return_value = _upstream_json(payload)
            handler.do_GET()
            handler.scanner.scan_metadata.assert_called_once_with("npm", "lodash", "latest", payload)


class TestQuarantineAction:
    def test_tag_action_serves_body_with_headers(self):
        handler = _make_handler("/warn-pkg/1.0.0", FirewallConfig())
        handler.scanner.scan_metadata = MagicMock(
            return_value=(FirewallVerdict.QUARANTINE, [_make_finding("L2-OBFS-001", "MEDIUM", "obf")])
        )
        with patch("picosentry.firewall.proxy.safe_urlopen") as mock_safe:
            mock_safe.return_value = _upstream_json({"name": "warn-pkg"})
            handler.do_GET()
            assert any("200" in str(c) for c in handler.send_response.call_args_list)
            headers = {args[0]: args[1] for args, _ in handler.send_header.call_args_list}
            assert headers.get("X-PicoSentry-Verdict") == "quarantine"

    def test_block_action_returns_403(self):
        handler = _make_handler("/warn-pkg/1.0.0", FirewallConfig(quarantine_action="block"))
        handler.scanner.scan_metadata = MagicMock(
            return_value=(FirewallVerdict.QUARANTINE, [_make_finding("L2-OBFS-001", "MEDIUM", "obf")])
        )
        with patch("picosentry.firewall.proxy.safe_urlopen") as mock_safe:
            mock_safe.return_value = _upstream_json({"name": "warn-pkg"})
            handler.do_GET()
            assert any("403" in str(c) for c in handler.send_response.call_args_list)


def _stream_resp(chunks):
    resp = MagicMock()
    resp.status = 200
    resp.headers = MagicMock()
    resp.headers.get.return_value = "application/octet-stream"
    resp.read.side_effect = chunks
    return resp


class TestPassThroughStreaming:
    def test_streams_chunks_and_tags_passthrough(self):
        handler = _make_handler("/left-pad/-/left-pad-1.3.0.tgz", FirewallConfig())
        chunks = [b"a" * 100, b"b" * 100, b""]
        with patch("picosentry.firewall.proxy._open_upstream_stream", return_value=_stream_resp(chunks)):
            handler.do_GET()
        headers = {args[0]: args[1] for args, _ in handler.send_header.call_args_list}
        assert headers.get("X-PicoSentry-Verdict") == "passthrough"
        assert headers.get("X-PicoSentry-Proxy") == "true"
        written = b"".join(c.args[0] for c in handler.wfile.write.call_args_list)
        assert written == b"a" * 100 + b"b" * 100

    def test_aborts_when_body_exceeds_cap(self):
        handler = _make_handler(
            "/left-pad/-/left-pad-1.3.0.tgz",
            FirewallConfig(pass_through_max_bytes=150),
        )
        chunks = [b"a" * 100, b"b" * 100, b"c" * 100, b""]
        with patch("picosentry.firewall.proxy._open_upstream_stream", return_value=_stream_resp(chunks)):
            handler.do_GET()
        written = b"".join(c.args[0] for c in handler.wfile.write.call_args_list)
        assert len(written) == 100  # cap=150 exceeded when chunk 2 lands -> abort before writing it
        assert handler.close_connection is True

    def test_upstream_http_error_proxied(self):
        import urllib.error

        handler = _make_handler("/left-pad/-/left-pad-1.3.0.tgz", FirewallConfig())
        with patch(
            "picosentry.firewall.proxy._open_upstream_stream",
            side_effect=urllib.error.HTTPError("url", 404, "Not Found", None, None),
        ):
            handler.do_GET()
            assert any("404" in str(c) for c in handler.send_response.call_args_list)

    def test_upstream_unreachable_502(self):
        import urllib.error

        handler = _make_handler("/left-pad/-/left-pad-1.3.0.tgz", FirewallConfig())
        with patch(
            "picosentry.firewall.proxy._open_upstream_stream",
            side_effect=urllib.error.URLError("no route"),
        ):
            handler.do_GET()
            assert any("502" in str(c) for c in handler.send_response.call_args_list)

    def test_http_upstream_refused(self):
        from picosentry.scan._network import InsecureURLError

        handler = _make_handler("/left-pad/-/left-pad-1.3.0.tgz", FirewallConfig(upstream_npm="http://registry.local"))
        with patch(
            "picosentry.firewall.proxy._open_upstream_stream",
            side_effect=InsecureURLError("http"),
        ):
            handler.do_GET()
            assert any("502" in str(c) for c in handler.send_response.call_args_list)


class TestServeWiring:
    def test_serve_binds_configured_host_and_port_threaded(self):
        config = FirewallConfig(listen_host="127.0.0.1", listen_port=9999)
        proxy = FirewallProxy(config)
        with patch("picosentry.firewall.proxy.ThreadingHTTPServer") as mock_server_cls:
            instance = mock_server_cls.return_value
            proxy.serve()
        mock_server_cls.assert_called_once()
        bind_args = mock_server_cls.call_args[0][0]
        assert bind_args == ("127.0.0.1", 9999)
        assert instance.daemon_threads is True
        instance.serve_forever.assert_called_once()

    def test_serve_shutdown_on_keyboard_interrupt(self):
        config = FirewallConfig()
        proxy = FirewallProxy(config)
        with patch("picosentry.firewall.proxy.ThreadingHTTPServer") as mock_server_cls:
            instance = mock_server_cls.return_value
            instance.serve_forever.side_effect = KeyboardInterrupt()
            proxy.serve()
            instance.shutdown.assert_called_once()
