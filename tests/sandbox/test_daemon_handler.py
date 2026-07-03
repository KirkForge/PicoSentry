"""Tests for daemon HTTP handler paths — covers the PicoDomeHandler API surface."""

from __future__ import annotations

import io
import os
from importlib import import_module
from unittest.mock import MagicMock, patch

import pytest

import picosentry.sandbox.audit.logger as audit_logger_mod
from picosentry.sandbox.audit import AuditLogger
from picosentry.sandbox.auth import RBAC, TokenAuth
from picosentry.sandbox.daemon.server import PicoDomeDaemon, PicoDomeHandler, create_app
from picosentry.sandbox.ratelimit import RateLimitConfig, TokenBucketLimiter


@pytest.fixture(autouse=True)
def reset_audit_singleton():
    original = audit_logger_mod._audit_logger
    yield
    audit_logger_mod._audit_logger = original


@pytest.fixture(autouse=True)
def reset_cluster_singleton():
    """Reset the global cluster manager singleton before and after each test."""
    from picosentry.sandbox.cluster import manager as cluster_manager_mod

    original = cluster_manager_mod._cluster_manager
    cluster_manager_mod._cluster_manager = None
    yield
    cluster_manager_mod._cluster_manager = original


def _make_handler(tmp_path, token=None, rate_config=None):
    """Create a mock-ready PicoDomeHandler with auth and rate limiting."""
    audit_dir = tmp_path / "audit"
    test_audit = AuditLogger(log_dir=audit_dir, max_bytes=1024 * 1024)
    audit_logger_mod._audit_logger = test_audit

    if rate_config is None:
        rate_config = RateLimitConfig(rate_per_second=100, burst_size=100)

    if token:
        with patch.dict(os.environ, {"PICODOME_API_TOKENS": token}, clear=False):
            rbac = RBAC()
            auth = TokenAuth(rbac=rbac)
    else:
        rbac = RBAC()
        auth = TokenAuth(rbac=rbac)

    limiter = TokenBucketLimiter(config=rate_config)

    PicoDomeHandler.rbac = rbac
    PicoDomeHandler.auth = auth
    PicoDomeHandler.rate_limiter = limiter
    PicoDomeHandler.job_store = MagicMock()

    return test_audit


def _new_handler():
    """Create a bare PicoDomeHandler with mocked I/O."""
    handler = PicoDomeHandler.__new__(PicoDomeHandler)
    handler.headers = {}
    handler._send_json = MagicMock()
    handler._send_error = MagicMock()
    handler._send_text = MagicMock()
    handler.send_response = MagicMock()
    handler.send_header = MagicMock()
    handler.end_headers = MagicMock()
    handler.wfile = io.BytesIO()
    handler._metrics_only = False
    handler._scan_count = 0
    handler._scan_total_ms = 0
    handler._alert_count = 0
    handler._start_time = 0
    return handler


# ─── Handler method tests ───────────────────────────────────────────


class TestHandlerHealth:
    def test_health_endpoint(self, tmp_path):
        _make_handler(tmp_path)
        handler = _new_handler()
        handler._handle_health()
        handler._send_json.assert_called_once()
        data = handler._send_json.call_args[0][0]
        assert data["status"] == "healthy"


class TestHandlerReady:
    def test_ready_endpoint(self, tmp_path):
        _make_handler(tmp_path)
        handler = _new_handler()
        handler._handle_ready()
        handler._send_json.assert_called_once()


class TestHandlerMetrics:
    def test_metrics_endpoint(self, tmp_path):
        _make_handler(tmp_path)
        handler = _new_handler()
        handler._handle_metrics()
        # Metrics writes directly to wfile, not _send_text
        output = handler.wfile.getvalue()
        assert b"picodome_scans_total" in output or handler._send_text.called or handler.wfile.getvalue() != b""


class TestHandlerPolicies:
    def test_list_policies(self, tmp_path):
        _make_handler(tmp_path)
        handler = _new_handler()
        handler._handle_list_policies()
        handler._send_json.assert_called_once()

    def test_get_policy_not_found(self, tmp_path):
        _make_handler(tmp_path)
        handler = _new_handler()
        handler._handle_get_policy("nonexistent-policy")
        handler._send_error.assert_called_once()


class TestHandlerBaselines:
    def test_list_baselines(self, tmp_path):
        _make_handler(tmp_path)
        handler = _new_handler()
        handler._handle_list_baselines()
        handler._send_json.assert_called_once()


class TestHandlerStats:
    def test_stats_endpoint(self, tmp_path):
        _make_handler(tmp_path)
        handler = _new_handler()
        handler._scan_count = 10
        handler._scan_total_ms = 5000
        handler._alert_count = 2
        handler._start_time = 0
        handler._handle_stats()
        handler._send_json.assert_called_once()


class TestHandlerScans:
    def test_list_scans(self, tmp_path):
        _make_handler(tmp_path)
        handler = _new_handler()
        handler._handle_list_scans({})
        handler._send_json.assert_called_once()


class TestHandlerValidateCommand:
    def test_deny_bash(self, tmp_path):
        _make_handler(tmp_path)
        handler = _new_handler()
        result = handler._validate_command(["bash", "-c", "echo pwned"])
        assert result is not None
        assert "bash" in result.lower()

    def test_deny_sh(self, tmp_path):
        _make_handler(tmp_path)
        handler = _new_handler()
        result = handler._validate_command(["sh", "-c", "echo pwned"])
        assert result is not None

    def test_deny_curl(self, tmp_path):
        _make_handler(tmp_path)
        handler = _new_handler()
        result = handler._validate_command(["curl", "http://evil.com"])
        assert result is not None

    def test_deny_wget(self, tmp_path):
        _make_handler(tmp_path)
        handler = _new_handler()
        result = handler._validate_command(["wget", "http://evil.com"])
        assert result is not None

    def test_deny_nc(self, tmp_path):
        _make_handler(tmp_path)
        handler = _new_handler()
        result = handler._validate_command(["nc", "-l", "4444"])
        assert result is not None

    def test_deny_python_shell(self, tmp_path):
        _make_handler(tmp_path)
        handler = _new_handler()
        result = handler._validate_command(["python3", "-c", "import os; os.system('id')"])
        assert result is not None

    def test_allow_echo(self, tmp_path):
        _make_handler(tmp_path)
        handler = _new_handler()
        result = handler._validate_command(["echo", "hello"])
        assert result is None

    def test_allow_ls(self, tmp_path):
        _make_handler(tmp_path)
        handler = _new_handler()
        result = handler._validate_command(["ls", "-la"])
        assert result is None


class TestHandlerCORS:
    def test_options_returns_cors(self, tmp_path):
        _make_handler(tmp_path)
        handler = _new_handler()
        handler.do_OPTIONS()
        handler.send_response.assert_called_with(204)


class TestHandlerTlsConfig:
    def test_tls_config_endpoint(self, tmp_path):
        _make_handler(tmp_path)
        handler = _new_handler()
        handler._handle_tls_config()
        handler._send_json.assert_called_once()


class TestHandlerTenants:
    def test_list_tenants(self, tmp_path):
        _make_handler(tmp_path)
        handler = _new_handler()
        handler._handle_list_tenants()
        handler._send_json.assert_called_once()


class TestHandlerRequestId:
    def test_generate_request_id(self, tmp_path):
        _make_handler(tmp_path)
        handler = _new_handler()
        handler.headers = {}
        rid = handler._generate_request_id()
        assert isinstance(rid, str)
        assert len(rid) > 0

    def test_use_existing_request_id(self, tmp_path):
        _make_handler(tmp_path)
        handler = _new_handler()
        handler.headers = {"X-Request-ID": "existing-id-123"}
        rid = handler._generate_request_id()
        assert rid == "existing-id-123"


class TestHandlerCommonHeaders:
    def test_add_common_headers(self, tmp_path):
        _make_handler(tmp_path)
        handler = _new_handler()
        handler.headers = {}
        handler._add_common_headers("test-req-id")
        assert handler.send_header.call_count >= 2


# ─── create_app factory ────────────────────────────────────────────


class TestCreateApp:
    def test_create_app_returns_daemon(self):
        daemon = create_app(host="127.0.0.1", port=0)
        assert isinstance(daemon, PicoDomeDaemon)
        assert daemon._host == "127.0.0.1"

    def test_create_app_with_port(self):
        daemon = create_app(port=9999)
        assert daemon._port == 9999

    def test_create_app_with_tokens(self):
        with patch.dict(os.environ, {}, clear=True):
            create_app(tokens="test-token-abc123456789012345678901234567890")
            assert os.environ.get("PICODOME_API_TOKENS") == "test-token-abc123456789012345678901234567890"


# ─── PicoDomeDaemon lifecycle ───────────────────────────────────────


class TestDaemonLifecycle:
    def test_init_defaults(self):
        with patch.dict(os.environ, {}, clear=False):
            daemon = PicoDomeDaemon()
            assert daemon._host == "127.0.0.1"
            assert daemon._port == 8443

    def test_init_custom(self):
        daemon = PicoDomeDaemon(host="0.0.0.0", port=9999)
        assert daemon._host == "0.0.0.0"
        assert daemon._port == 9999

    def test_init_metrics_port(self):
        daemon = PicoDomeDaemon(metrics_port=9090)
        assert daemon._metrics_port == 9090

    def test_init_cluster_config(self):
        daemon = PicoDomeDaemon(cluster_config={"cluster_token": "secret", "backend": "memory"})
        assert daemon._cluster_config["cluster_token"] == "secret"
        assert daemon._cluster_config["backend"] == "memory"

    def test_stop_is_idempotent(self):
        daemon = PicoDomeDaemon()
        daemon._server = None
        daemon._metrics_server = None
        daemon._cluster_manager = None
        daemon._sinks = []
        daemon.stop()  # should not raise

    def test_cluster_manager_starts_with_token(self):
        daemon = PicoDomeDaemon(
            host="127.0.0.1",
            port=0,
            cluster_config={"cluster_token": "test-token", "backend": "memory"},
        )
        daemon.start(background=True)
        try:
            assert daemon._cluster_manager is not None
            assert daemon._cluster_manager.is_running
            assert daemon._cluster_manager.cluster_token == "test-token"
        finally:
            daemon.stop()

    def test_cluster_manager_not_started_without_token(self):
        daemon = PicoDomeDaemon(host="127.0.0.1", port=0)
        daemon.start(background=True)
        try:
            assert daemon._cluster_manager is None
        finally:
            daemon.stop()

    def test_cluster_manager_stops_with_daemon(self):
        from picosentry.sandbox.cluster.manager import get_cluster_manager

        daemon = PicoDomeDaemon(
            host="127.0.0.1",
            port=0,
            cluster_config={"cluster_token": "stop-test", "backend": "memory"},
        )
        daemon.start(background=True)
        manager = daemon._cluster_manager
        try:
            assert manager is not None
            assert manager.is_running
            # The daemon uses the global singleton so HTTP handlers see the same manager.
            assert get_cluster_manager() is manager
        finally:
            daemon.stop()
        assert not manager.is_running


class TestDaemonBackendMap:
    """Regression tests for the daemon scan backend resolver.

    The handler once pointed the backend map at the old ``picodome`` namespace,
    so explicit ``backend`` selections always failed. These tests ensure the
    map stays in sync with the real backend classes in ``picosentry.sandbox``.
    """

    def test_daemon_backend_map_classes_are_importable(self):
        from picosentry.sandbox.daemon.handler_routes_post import _DAEMON_BACKEND_MAP
        from picosentry.sandbox.l3.backends.base import SandboxBackend

        for backend_name, cls_path in _DAEMON_BACKEND_MAP.items():
            module_path, cls_name = cls_path.rsplit(":", 1)
            module = import_module(module_path)
            backend_cls = getattr(module, cls_name)
            assert issubclass(backend_cls, SandboxBackend), (
                f"{backend_name} backend {cls_path} is not a SandboxBackend subclass"
            )


class TestDaemonExceptionHandling:
    """Security regression tests for daemon exception handling."""

    def test_audit_failure_is_logged_not_swallowed(self, tmp_path, caplog):
        import logging

        from picosentry.sandbox.daemon.handler_routes_get import _check_cluster_token as get_check

        _make_handler(tmp_path)
        handler = _new_handler()
        handler.path = "/api/v1/cluster/snapshot"
        handler.headers = {}
        handler._send_error = MagicMock()

        class _BoomAudit:
            def record(self, **kwargs):
                raise RuntimeError("audit disk full")

        with (
            caplog.at_level(logging.WARNING, logger="picodome.daemon"),
            patch("picosentry.sandbox.daemon.handler_routes_get.get_audit_logger", return_value=_BoomAudit()),
        ):
            mgr = MagicMock()
            mgr.state.cluster_token = "secret"
            get_check(handler, mgr)

        assert any("Audit record failed" in r.message for r in caplog.records)
        handler._send_error.assert_called_once()

    def test_scan_failure_does_not_leak_internal_details(self, tmp_path, monkeypatch):
        import json

        from picosentry.sandbox.daemon import handler_routes_post
        from picosentry.sandbox.errors import ErrorCodes

        _make_handler(tmp_path, token="test-token-32-chars-long-for-perm")
        handler = _new_handler()
        handler.headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(json.dumps({"command": ["echo", "hi"]}))),
        }
        handler.rfile = io.BytesIO(json.dumps({"command": ["echo", "hi"]}).encode())

        def _boom(*args, **kwargs):
            raise RuntimeError("internal secret details")

        monkeypatch.setattr(handler_routes_post, "sandbox_run", _boom)

        handler._handle_submit_scan("test-token-32-chars-long-for-perm")

        handler._send_error.assert_called_once()
        args = handler._send_error.call_args[0]
        assert args[0] == ErrorCodes.SCAN_FAILED
        detail = handler._send_error.call_args[1].get("detail", "")
        assert "internal secret details" not in detail
        assert "RuntimeError" not in detail

    def test_invalid_backend_does_not_leak_import_error(self, tmp_path, monkeypatch):
        import json

        from picosentry.sandbox.daemon import handler_routes_post
        from picosentry.sandbox.errors import ErrorCodes

        _make_handler(tmp_path, token="test-token-32-chars-long-for-perm")
        handler = _new_handler()
        handler.headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(json.dumps({"command": ["echo", "hi"], "backend": "seccomp-bpf"}))),
        }
        handler.rfile = io.BytesIO(json.dumps({"command": ["echo", "hi"], "backend": "seccomp-bpf"}).encode())

        def _boom(*args, **kwargs):
            raise ImportError("cannot import seccomp module")

        monkeypatch.setattr(handler_routes_post, "import_module", _boom)

        handler._handle_submit_scan("test-token-32-chars-long-for-perm")

        handler._send_error.assert_called_once()
        args = handler._send_error.call_args[0]
        assert args[0] == ErrorCodes.BACKEND_UNAVAILABLE
        detail = handler._send_error.call_args[1].get("detail", "")
        assert "cannot import seccomp module" not in detail
        assert "ImportError" not in detail

    def test_invalid_policy_returns_validation_detail(self, tmp_path):
        import json

        from picosentry.sandbox.errors import ErrorCodes

        _make_handler(tmp_path, token="test-token-32-chars-long-for-perm")
        handler = _new_handler()
        body = json.dumps({"default_action": "invalid"})
        handler.headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        }
        handler.rfile = io.BytesIO(body.encode())

        handler._handle_create_policy("test-token-32-chars-long-for-perm")

        handler._send_error.assert_called_once()
        args = handler._send_error.call_args[0]
        assert args[0] == ErrorCodes.INVALID_POLICY

    def test_policy_creation_unexpected_error_is_sanitized(self, tmp_path, monkeypatch):
        import json

        from picosentry.sandbox.l3 import policy as policy_mod
        from picosentry.sandbox.errors import ErrorCodes

        _make_handler(tmp_path, token="test-token-32-chars-long-for-perm")
        handler = _new_handler()
        body = json.dumps({"name": "test"})
        handler.headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        }
        handler.rfile = io.BytesIO(body.encode())

        def _boom(*args, **kwargs):
            raise RuntimeError("database corruption secret")

        monkeypatch.setattr(policy_mod, "_policy_from_dict", _boom)

        handler._handle_create_policy("test-token-32-chars-long-for-perm")

        handler._send_error.assert_called_once()
        args = handler._send_error.call_args[0]
        assert args[0] == ErrorCodes.INVALID_POLICY
        detail = handler._send_error.call_args[1].get("detail", "")
        assert "database corruption secret" not in detail
        assert "RuntimeError" not in detail

    def test_redis_health_failure_uses_in_memory_fallback(self, tmp_path, monkeypatch, caplog):
        import logging

        import picosentry.sandbox.redis_health as redis_health_mod

        _make_handler(tmp_path)
        handler = _new_handler()

        def _boom():
            raise OSError("redis unreachable")

        monkeypatch.setattr(redis_health_mod, "check_redis_health", _boom)

        with caplog.at_level(logging.DEBUG, logger="picodome.daemon"):
            handler._handle_health()

        handler._send_json.assert_called_once()
        data = handler._send_json.call_args[0][0]
        assert data["status"] == "healthy"
        assert data["redis"]["connected"] is False
        assert data["redis"]["mode"] == "in-memory"
        assert any("Redis health check failed" in r.message for r in caplog.records)

    def test_cluster_snapshot_get_failure_is_sanitized(self, tmp_path, monkeypatch, caplog):
        import logging

        import picosentry.sandbox.cluster.manager as cluster_manager_mod

        _make_handler(tmp_path)
        handler = _new_handler()
        handler.path = "/api/v1/cluster/snapshot"
        handler.headers = {}

        class _BoomState:
            cluster_token = ""

            def get_state_snapshot(self):
                raise RuntimeError("internal cluster state secret")

        class _BoomMgr:
            is_running = True
            state = _BoomState()

        monkeypatch.setattr(cluster_manager_mod, "get_cluster_manager", lambda: _BoomMgr())

        with caplog.at_level(logging.WARNING, logger="picodome.daemon"):
            handler._handle_cluster_snapshot()

        handler._send_error.assert_called_once()
        args = handler._send_error.call_args[0]
        assert args[0] == 500
        detail = handler._send_error.call_args[1].get("detail", "")
        assert "internal cluster state secret" not in detail
        assert "RuntimeError" not in detail
        assert any("Failed to get cluster snapshot" in r.message for r in caplog.records)

    def test_retention_save_failure_does_not_fail_scan(self, tmp_path, monkeypatch):
        import json

        from picosentry.sandbox.daemon import handler_routes_post
        from picosentry.sandbox.l3.engine import SandboxResult

        _make_handler(tmp_path, token="test-token-32-chars-long-for-perm")
        handler = _new_handler()
        handler.headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(json.dumps({"command": ["echo", "hi"]}))),
        }
        handler.rfile = io.BytesIO(json.dumps({"command": ["echo", "hi"]}).encode())

        result = SandboxResult(
            command=["echo", "hi"],
            exit_code=0,
            stdout="hi",
            stderr="",
            duration_ms=1,
            backend_name="subprocess",
            isolation_level="observational_only",
            enforcement_guarantee="none",
            degraded=True,
        )

        class _BoomRetention:
            def save_scan_result(self, *args, **kwargs):
                raise OSError("retention disk full")

        analysis = MagicMock()
        analysis.to_dict.return_value = {}
        analysis.overall_verdict.value = "ALLOW"
        analysis.findings = []

        engine = MagicMock()
        engine.analyze.return_value = analysis

        monkeypatch.setattr(handler_routes_post, "sandbox_run", lambda **kwargs: result)
        monkeypatch.setattr(handler_routes_post, "create_default_engine", lambda: engine)
        monkeypatch.setattr(handler_routes_post, "get_retention_manager", _BoomRetention)

        handler._handle_submit_scan("test-token-32-chars-long-for-perm")

        handler._send_json.assert_called_once()
        assert handler._send_json.call_args.kwargs.get("status") == 201

    def test_cluster_merge_failure_is_sanitized(self, tmp_path, monkeypatch, caplog):
        import json
        import logging

        import picosentry.sandbox.cluster.manager as cluster_manager_mod

        _make_handler(tmp_path, token="test-token-32-chars-long-for-perm")
        handler = _new_handler()
        body = json.dumps({"nodes": {}})
        handler.headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        }
        handler.rfile = io.BytesIO(body.encode())

        class _BoomState:
            cluster_token = ""

            def list_nodes(self):
                return []

            def merge_state(self, snapshot):
                raise RuntimeError("merge secret failure")

            def get_leader_id(self):
                return "leader"

        class _BoomMgr:
            is_running = True
            state = _BoomState()

        monkeypatch.setattr(cluster_manager_mod, "get_cluster_manager", lambda: _BoomMgr())

        with caplog.at_level(logging.WARNING, logger="picodome.daemon"):
            handler._handle_cluster_merge_snapshot()

        handler._send_error.assert_called_once()
        args = handler._send_error.call_args[0]
        assert args[0] == 500
        detail = handler._send_error.call_args[1].get("detail", "")
        assert "merge secret failure" not in detail
        assert "RuntimeError" not in detail
        assert any("Cluster snapshot merge failed" in r.message for r in caplog.records)


class TestHandlerPolicySignatureVerify:
    """Daemon must verify custom policy signatures when a verification key is configured."""

    def _policy_body(self, name: str) -> str:
        import json

        return json.dumps(
            {
                "name": name,
                "version": "1.0",
                "default_action": "deny",
                "rules": [
                    {"rule_id": "DAEMON-001", "target": "file_read", "action": "allow", "paths": ["/tmp/**"]},
                ],
            }
        )

    def test_create_policy_auto_signs_when_key_configured(self, tmp_path, monkeypatch):
        from picosentry.sandbox.policy_versioned import store as store_mod
        from picosentry.sandbox.policy_versioned.signing import generate_key, key_to_hex

        key = generate_key()
        monkeypatch.setenv("PICODOME_POLICY_KEY", key_to_hex(key))
        monkeypatch.setenv("PICODOME_POLICY_STORE_DIR", str(tmp_path))
        monkeypatch.setattr(store_mod, "_policy_store", None)

        _make_handler(tmp_path, token="test-token-32-chars-long-for-perm")
        handler = _new_handler()
        body = self._policy_body("auto-signed")
        handler.headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(body)),
        }
        handler.rfile = io.BytesIO(body.encode())

        handler._handle_create_policy("test-token-32-chars-long-for-perm")

        handler._send_json.assert_called_once()
        sig_path = tmp_path / "auto-signed" / "latest.json.sig"
        assert sig_path.is_file()

    def test_submit_scan_rejects_unsigned_custom_policy_when_key_configured(self, tmp_path, monkeypatch):
        import json

        from picosentry.sandbox import l3
        from picosentry.sandbox.errors import ErrorCodes
        from picosentry.sandbox.policy_versioned import store as store_mod
        from picosentry.sandbox.policy_versioned.signing import generate_key, key_to_hex
        from picosentry.sandbox.policy_versioned.store import VersionedPolicyStore

        key = generate_key()
        monkeypatch.setenv("PICODOME_POLICY_KEY", key_to_hex(key))
        monkeypatch.setenv("PICODOME_POLICY_STORE_DIR", str(tmp_path))
        monkeypatch.setattr(store_mod, "_policy_store", None)

        # Pre-create an unsigned custom policy in the store.
        store = VersionedPolicyStore(store_dir=tmp_path)
        body_data = json.loads(self._policy_body("unsigned-custom"))
        from picosentry.sandbox.l3.policy import _policy_from_dict

        store.save(_policy_from_dict(body_data), author="pytest", change_description="test")

        _make_handler(tmp_path, token="test-token-32-chars-long-for-perm")
        handler = _new_handler()
        scan_body = json.dumps({"command": ["echo", "hi"], "policy": "unsigned-custom"})
        handler.headers = {
            "Content-Type": "application/json",
            "Content-Length": str(len(scan_body)),
        }
        handler.rfile = io.BytesIO(scan_body.encode())

        # Avoid actually running a sandbox; the policy verification should fail first.
        def _no_run(*args, **kwargs):
            raise AssertionError("sandbox_run should not be called")

        monkeypatch.setattr(l3.engine, "sandbox_run", _no_run)

        handler._handle_submit_scan("test-token-32-chars-long-for-perm")

        handler._send_error.assert_called_once()
        args = handler._send_error.call_args[0]
        assert args[0] == ErrorCodes.INVALID_POLICY
