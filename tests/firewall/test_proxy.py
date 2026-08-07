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
        assert config.upstream_npm == "https://registry.npmjs.org"
        assert config.upstream_pypi == "https://pypi.org"
        assert config.block_severities == ["CRITICAL", "HIGH"]
        assert config.quarantine_severities == ["MEDIUM"]
        assert config.cache_ttl_seconds == 3600
        assert config.log_blocks is True

    def test_custom_port(self):
        config = FirewallConfig(listen_port=8080)
        assert config.listen_port == 8080

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
        with patch("picosentry.firewall.proxy.urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.headers = MagicMock()
            mock_resp.headers.get.return_value = "application/json"
            mock_resp.read.return_value = json.dumps({"name": "evil-pkg", "version": "1.0.0"}).encode()
            mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_resp)
            mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)
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
        with patch("picosentry.firewall.proxy.urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.headers = MagicMock()
            mock_resp.headers.get.return_value = "application/json"
            mock_resp.read.return_value = json.dumps({"name": "safe-pkg"}).encode()
            mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_resp)
            mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)
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
        with patch("picosentry.firewall.proxy.urllib.request.urlopen") as mock_urlopen:
            mock_resp = MagicMock()
            mock_resp.status = 200
            mock_resp.headers = MagicMock()
            mock_resp.headers.get.return_value = "application/json"
            mock_resp.read.return_value = json.dumps({"name": "warn-pkg"}).encode()
            mock_urlopen.return_value.__enter__ = MagicMock(return_value=mock_resp)
            mock_urlopen.return_value.__exit__ = MagicMock(return_value=False)
            handler.do_GET()
            calls = [str(c) for c in handler.send_response.call_args_list]
            assert any("200" in c for c in calls)
            header_dict = {args[0]: args[1] for args, _ in handler.send_header.call_args_list}
            assert header_dict.get("X-PicoSentry-Verdict") == "quarantine"
            assert "X-PicoSentry-Reasons" in header_dict


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
