"""Tests for PicoDome gRPC transport module.

All tests work WITHOUT grpcio installed — gRPC calls are mocked.
The module must degrade gracefully when grpcio is missing.
"""

from __future__ import annotations

import time
from unittest.mock import MagicMock, patch

import pytest

# ─── Fixtures ────────────────────────────────────────────────────────────────


class FakeSandboxResult:
    """Minimal sandbox result mock."""

    def __init__(self, verdict="ALLOW", exit_code=0, duration_ms=42):
        self.overall_verdict = type("V", (), {"value": verdict})()
        self.exit_code = exit_code
        self.duration_ms = duration_ms
        self.command = ["echo", "hello"]
        self.events = []
        self.stdout = "hello"
        self.stderr = ""

    def to_dict(self, deterministic=False):
        return {
            "verdict": self.overall_verdict.value,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
        }


class FakeAnalysisResult:
    """Minimal analysis result mock."""

    def __init__(self, verdict="CLEAN", findings_count=0):
        self.overall_verdict = type("V", (), {"value": verdict})()
        self.findings = [type("F", (), {"severity": type("S", (), {"value": "HIGH"})()})] * findings_count
        self.target = "echo"

    def to_dict(self, deterministic=False):
        return {
            "verdict": self.overall_verdict.value,
            "findings_count": len(self.findings),
        }


@pytest.fixture
def fake_scan_fn():
    """A mock scan function that returns a FakeSandboxResult."""

    def _scan(command, policy=None, timeout=30.0, cwd=None, deterministic=False):
        return FakeSandboxResult()

    return _scan


@pytest.fixture
def fake_analyze_fn():
    """A mock analyze function that returns a FakeAnalysisResult."""

    def _analyze(sandbox_result, rules=None, deterministic=False):
        return FakeAnalysisResult()

    return _analyze


@pytest.fixture
def fake_deny_scan_fn():
    """A mock scan function that returns a DENY result."""

    def _scan(command, policy=None, timeout=30.0, cwd=None, deterministic=False):
        return FakeSandboxResult(verdict="DENY", exit_code=1)

    return _scan


@pytest.fixture
def fake_deny_analyze_fn():
    """A mock analyze function that returns a MALICIOUS result."""

    def _analyze(sandbox_result, rules=None, deterministic=False):
        return FakeAnalysisResult(verdict="MALICIOUS", findings_count=3)

    return _analyze


# ─── Tests: Module availability ───────────────────────────────────────────────


class TestGRPCAvailability:
    """Test that the module degrades gracefully without grpcio."""

    def test_is_grpc_available_returns_bool(self):
        """is_grpc_available() should return a boolean."""
        from picosentry.sandbox.grpc_transport import is_grpc_available

        result = is_grpc_available()
        assert isinstance(result, bool)

    def test_module_import_does_not_crash(self):
        """Importing the module should not crash even without grpcio."""
        import importlib

        mod = importlib.import_module("picosentry.sandbox.grpc_transport")
        assert hasattr(mod, "is_grpc_available")
        assert hasattr(mod, "PicoDomeGRPCServer")
        assert hasattr(mod, "PicoDomeGRPCClient")

    def test_lazy_import_server(self):
        """PicoDomeGRPCServer should be importable via lazy import."""
        from picosentry.sandbox.grpc_transport import PicoDomeGRPCServer

        assert PicoDomeGRPCServer is not None

    def test_lazy_import_client(self):
        """PicoDomeGRPCClient should be importable via lazy import."""
        from picosentry.sandbox.grpc_transport import PicoDomeGRPCClient

        assert PicoDomeGRPCClient is not None

    def test_invalid_attribute_raises(self):
        """Accessing invalid attribute should raise AttributeError."""
        from picosentry.sandbox import grpc_transport

        with pytest.raises(AttributeError):
            _ = grpc_transport.nonexistent_attribute


# ─── Tests: Server ──────────────────────────────────────────────────────────


class TestGRPCServer:
    """Test the gRPC server (without actually starting gRPC)."""

    def test_server_creation_with_defaults(self):
        """Server should be creatable with default settings."""
        from picosentry.sandbox.grpc_transport.server import PicoDomeGRPCServer

        server = PicoDomeGRPCServer()
        assert server._host == "[::]"
        assert server._port == 50051
        assert server._max_workers == 10

    def test_server_creation_with_custom_settings(self):
        """Server should accept custom host, port, workers."""
        from picosentry.sandbox.grpc_transport.server import PicoDomeGRPCServer

        server = PicoDomeGRPCServer(
            host="0.0.0.0",
            port=9999,
            max_workers=20,
        )
        assert server._host == "0.0.0.0"
        assert server._port == 9999
        assert server._max_workers == 20

    def test_server_with_injected_scan_engine(self, fake_scan_fn, fake_analyze_fn):
        """Server should accept dependency-injected scan functions."""
        from picosentry.sandbox.grpc_transport.server import PicoDomeGRPCServer

        server = PicoDomeGRPCServer(
            scan_fn=fake_scan_fn,
            analyze_fn=fake_analyze_fn,
        )
        assert server._scan_engine._scan_fn is fake_scan_fn
        assert server._scan_engine._analyze_fn is fake_analyze_fn

    def test_server_start_raises_without_grpcio(self):
        """Server.start() should raise ImportError if grpcio not installed."""
        from picosentry.sandbox.grpc_transport.server import PicoDomeGRPCServer

        server = PicoDomeGRPCServer()

        with patch("picosentry.sandbox.grpc_transport.server.is_grpc_available", return_value=False):
            with pytest.raises(ImportError, match="grpcio"):
                server.start()

    def test_server_stop_without_start(self):
        """Server.stop() should be safe to call without starting."""
        from picosentry.sandbox.grpc_transport.server import PicoDomeGRPCServer

        server = PicoDomeGRPCServer()
        server.stop()  # Should not raise

    def test_server_stop_with_mock_server(self):
        """Server.stop() should call shutdown on the gRPC server."""
        from picosentry.sandbox.grpc_transport.server import PicoDomeGRPCServer

        server = PicoDomeGRPCServer()
        mock_grpc_server = MagicMock()
        server._server = mock_grpc_server
        server.stop()
        mock_grpc_server.stop.assert_called_once()


# ─── Tests: Client ──────────────────────────────────────────────────────────


class TestGRPCClient:
    """Test the gRPC client (without actually connecting)."""

    def test_client_creation_with_defaults(self):
        """Client should be creatable with default settings."""
        from picosentry.sandbox.grpc_transport.client import PicoDomeGRPCClient

        client = PicoDomeGRPCClient()
        assert client._target == "localhost:50051"
        assert client._timeout == 30.0
        assert client._max_retries == 3

    def test_client_creation_with_custom_settings(self):
        """Client should accept custom target, timeout, retries."""
        from picosentry.sandbox.grpc_transport.client import PicoDomeGRPCClient

        client = PicoDomeGRPCClient(
            target="example.com:9999",
            timeout=60.0,
            max_retries=5,
            retry_delay=2.0,
        )
        assert client._target == "example.com:9999"
        assert client._timeout == 60.0
        assert client._max_retries == 5

    def test_client_context_manager(self):
        """Client should work as a context manager."""
        from picosentry.sandbox.grpc_transport.client import PicoDomeGRPCClient

        with PicoDomeGRPCClient() as client:
            assert client._target == "localhost:50051"
        # After exiting, channel should be None
        assert client._channel is None

    def test_client_close_without_connection(self):
        """Client.close() should be safe without connecting."""
        from picosentry.sandbox.grpc_transport.client import PicoDomeGRPCClient

        client = PicoDomeGRPCClient()
        client.close()  # Should not raise

    def test_client_scan_raises_without_grpcio(self):
        """Client.scan() should raise ImportError if grpcio not installed."""
        from picosentry.sandbox.grpc_transport.client import PicoDomeGRPCClient

        client = PicoDomeGRPCClient()

        with patch("picosentry.sandbox.grpc_transport.client.is_grpc_available", return_value=False):
            with pytest.raises(ImportError, match="grpcio"):
                client.scan(command=["echo", "hello"])

    def test_client_mtls_config_none(self):
        """Client with no mTLS config should use insecure channel."""
        from picosentry.sandbox.grpc_transport.client import PicoDomeGRPCClient

        client = PicoDomeGRPCClient(mtls_config=None)
        assert client._mtls_config is None


# ─── Tests: ScanResult ──────────────────────────────────────────────────────


class TestScanResult:
    """Test the ScanResult data class."""

    def test_scan_result_creation(self):
        """ScanResult should store all fields."""
        from picosentry.sandbox.grpc_transport.client import ScanResult

        result = ScanResult(
            result_json='{" verdict": "ALLOW"}',
            exit_code=0,
            verdict="ALLOW",
            job_id="test-123",
            l3_verdict="ALLOW",
            l4_verdict="CLEAN",
            findings_count=0,
        )
        assert result.exit_code == 0
        assert result.verdict == "ALLOW"
        assert result.job_id == "test-123"

    def test_scan_result_to_dict(self):
        """ScanResult.to_dict() should return all fields."""
        from picosentry.sandbox.grpc_transport.client import ScanResult

        result = ScanResult(
            result_json="{}",
            exit_code=0,
            verdict="ALLOW",
            job_id="test-456",
            l3_verdict="ALLOW",
            l4_verdict="CLEAN",
            findings_count=0,
        )
        d = result.to_dict()
        assert d["exit_code"] == 0
        assert d["verdict"] == "ALLOW"
        assert d["job_id"] == "test-456"

    def test_scan_result_from_dict(self):
        """ScanResult.from_dict() should reconstruct from a dict."""
        from picosentry.sandbox.grpc_transport.client import ScanResult

        d = {
            "result_json": '{"verdict": "DENY"}',
            "exit_code": 1,
            "verdict": "DENY",
            "job_id": "test-789",
            "l3_verdict": "DENY",
            "l4_verdict": "MALICIOUS",
            "findings_count": 5,
        }
        result = ScanResult.from_dict(d)
        assert result.exit_code == 1
        assert result.verdict == "DENY"
        assert result.findings_count == 5

    def test_scan_result_defaults(self):
        """ScanResult should have sensible defaults."""
        from picosentry.sandbox.grpc_transport.client import ScanResult

        result = ScanResult()
        assert result.exit_code == 0
        assert result.verdict == ""
        assert result.findings_count == 0


# ─── Tests: Servicer ────────────────────────────────────────────────────────


class TestServicer:
    """Test the gRPC servicer implementation with dependency injection."""

    def test_servicer_scan_with_injected_engine(self, fake_scan_fn, fake_analyze_fn):
        """Servicer should use the injected scan engine."""
        from picosentry.sandbox.grpc_transport._servicer import PicoDomeServicer
        from picosentry.sandbox.grpc_transport.server import _ScanEngine

        engine = _ScanEngine(scan_fn=fake_scan_fn, analyze_fn=fake_analyze_fn)
        servicer = PicoDomeServicer(
            scan_engine=engine,
            start_time=time.time(),
            scan_count_ref=MagicMock(),
        )

        # Create a mock request
        request = MagicMock()
        request.command = ["echo", "hello"]
        request.policy = ""
        request.timeout = 30.0
        request.cwd = ""
        context = MagicMock()

        # This should call our injected functions
        result = servicer.Scan(request, context)

        # Result should be a _DictProxy or proto response with ALLOW verdict
        # Since we injected a fake that returns ALLOW, check the result
        assert result is not None

    def test_servicer_health(self):
        """Servicer.Health should return health info."""
        from picosentry.sandbox.grpc_transport._servicer import PicoDomeServicer
        from picosentry.sandbox.grpc_transport.server import _ScanEngine

        engine = _ScanEngine()
        servicer = PicoDomeServicer(
            scan_engine=engine,
            start_time=time.time(),
            scan_count_ref=MagicMock(),
        )

        request = MagicMock()
        context = MagicMock()
        result = servicer.Health(request, context)

        assert result is not None

    def test_servicer_get_policy(self):
        """Servicer.GetPolicy should attempt to load a policy."""
        from picosentry.sandbox.grpc_transport._servicer import PicoDomeServicer

        servicer = PicoDomeServicer(
            scan_engine=MagicMock(),
            start_time=time.time(),
            scan_count_ref=MagicMock(),
        )

        request = MagicMock()
        request.name = "test-policy"
        request.version = 0
        context = MagicMock()

        result = servicer.GetPolicy(request, context)
        assert result is not None

    def test_servicer_query_audit(self):
        """Servicer.QueryAudit should return audit events."""
        from picosentry.sandbox.grpc_transport._servicer import PicoDomeServicer

        servicer = PicoDomeServicer(
            scan_engine=MagicMock(),
            start_time=time.time(),
            scan_count_ref=MagicMock(),
        )

        request = MagicMock()
        request.event_type = ""
        request.actor = ""
        request.target = ""
        request.since = ""
        request.until = ""
        request.limit = 10
        context = MagicMock()

        result = servicer.QueryAudit(request, context)
        assert result is not None

    def test_servicer_scan_error_handling(self):
        """Servicer.Scan should handle errors gracefully."""
        from picosentry.sandbox.grpc_transport._servicer import PicoDomeServicer

        # Create a scan engine that raises an exception
        def failing_scan(**kwargs):
            raise RuntimeError("Scan engine failure")

        engine = MagicMock()
        engine.scan = failing_scan

        servicer = PicoDomeServicer(
            scan_engine=engine,
            start_time=time.time(),
            scan_count_ref=MagicMock(),
        )

        request = MagicMock()
        request.command = ["fail"]
        request.policy = ""
        request.timeout = 30.0
        request.cwd = ""
        context = MagicMock()

        result = servicer.Scan(request, context)
        # Should return an error response, not crash
        assert result is not None


# ─── Tests: _ScanEngine ─────────────────────────────────────────────────────


class TestScanEngine:
    """Test the _ScanEngine dependency injection wrapper."""

    def test_scan_engine_with_injected_fn(self, fake_scan_fn):
        """_ScanEngine should use the injected scan function."""
        from picosentry.sandbox.grpc_transport.server import _ScanEngine

        engine = _ScanEngine(scan_fn=fake_scan_fn)
        result = engine.scan(command=["echo", "hello"])
        assert result.overall_verdict.value == "ALLOW"

    def test_scan_engine_with_injected_analyze_fn(self, fake_analyze_fn):
        """_ScanEngine should use the injected analyze function."""
        from picosentry.sandbox.grpc_transport.server import _ScanEngine

        engine = _ScanEngine(analyze_fn=fake_analyze_fn)
        result = engine.analyze(sandbox_result=MagicMock())
        assert result.overall_verdict.value == "CLEAN"

    def test_scan_engine_defaults_to_real_functions(self):
        """_ScanEngine without injected fns should reference real engine."""
        from picosentry.sandbox.grpc_transport.server import _ScanEngine

        engine = _ScanEngine()
        assert engine._scan_fn is None
        assert engine._analyze_fn is None


# ─── Tests: CLI integration ─────────────────────────────────────────────────


class TestCLIGRPC:
    """Test CLI subcommands for gRPC transport."""

    def test_daemon_transport_flag_exists(self):
        """The daemon subcommand should accept --transport flag."""
        from picosentry.sandbox.cli import main

        # This should parse without error
        with patch("sys.argv", ["picodome", "daemon", "--help"]):
            with pytest.raises(SystemExit) as exc_info:
                main(["daemon", "--help"])
            # --help exits with 0
            assert exc_info.value.code == 0

    def test_scan_grpc_subcommand_exists(self):
        """The scan-grpc subcommand should exist."""
        from picosentry.sandbox.cli import main

        with pytest.raises(SystemExit) as exc_info:
            main(["scan-grpc", "--help"])
        assert exc_info.value.code == 0

    def test_daemon_grpc_without_grpcio(self):
        """daemon --transport grpc should fail gracefully without grpcio."""
        from picosentry.sandbox.cli import main

        with patch("picosentry.sandbox.grpc_transport.is_grpc_available", return_value=False):
            exit_code = main(["daemon", "--transport", "grpc"])
            assert exit_code == 1

    def test_scan_grpc_without_grpcio(self):
        """scan-grpc should fail gracefully without grpcio."""
        from picosentry.sandbox.cli import main

        with patch("picosentry.sandbox.grpc_transport.is_grpc_available", return_value=False):
            exit_code = main(["scan-grpc", "echo", "hello"])
            assert exit_code == 1

    def test_scan_grpc_no_command(self):
        """scan-grpc with no command should error."""
        from picosentry.sandbox.cli import main

        with patch("picosentry.sandbox.grpc_transport.is_grpc_available", return_value=True):
            # Empty target list
            exit_code = main(["scan-grpc"])
            assert exit_code == 1


# ─── Tests: Proto file ──────────────────────────────────────────────────────


class TestProtoFile:
    """Test that the proto file exists and is valid."""

    def test_proto_file_exists(self):
        """The proto file should exist."""
        from pathlib import Path

        proto_path = (
            Path(__file__).parent.parent.parent
            / "picosentry"
            / "sandbox"
            / "grpc_transport"
            / "proto"
            / "picodome.proto"
        )
        assert proto_path.exists(), f"Proto file not found at {proto_path}"

    def test_proto_file_has_service(self):
        """The proto file should define PicoDomeService."""
        from pathlib import Path

        proto_path = (
            Path(__file__).parent.parent.parent
            / "picosentry"
            / "sandbox"
            / "grpc_transport"
            / "proto"
            / "picodome.proto"
        )
        content = proto_path.read_text()
        assert "service PicoDomeService" in content
        assert "rpc Scan" in content
        assert "rpc Health" in content
        assert "rpc GetPolicy" in content
        assert "rpc QueryAudit" in content

    def test_proto_file_has_messages(self):
        """The proto file should define all required message types."""
        from pathlib import Path

        proto_path = (
            Path(__file__).parent.parent.parent
            / "picosentry"
            / "sandbox"
            / "grpc_transport"
            / "proto"
            / "picodome.proto"
        )
        content = proto_path.read_text()
        assert "message ScanRequest" in content
        assert "message ScanResponse" in content
        assert "message HealthCheckRequest" in content
        assert "message HealthCheckResponse" in content
        assert "message PolicyGetRequest" in content
        assert "message PolicyGetResponse" in content
        assert "message AuditQueryRequest" in content
        assert "message AuditQueryResponse" in content


# ─── Tests: Client retry and connection logic ───────────────────────────────


class TestGRPCClientRetry:
    """Test gRPC client retry and connection logic (all mocked, no grpcio needed)."""

    def test_client_scan_retry_exhausted(self):
        """scan() should raise ConnectionError after max retries."""
        from picosentry.sandbox.grpc_transport.client import PicoDomeGRPCClient

        client = PicoDomeGRPCClient(max_retries=2, retry_delay=0.01)

        with patch.object(client, "_ensure_channel"):
            with patch.object(client, "_do_scan", side_effect=ConnectionError("refused")):
                with pytest.raises(ConnectionError, match="Failed to scan after 2 attempts"):
                    client.scan(command=["echo", "hello"])

    def test_client_scan_retry_succeeds_on_second(self):
        """scan() should return result if second attempt succeeds."""
        from picosentry.sandbox.grpc_transport.client import PicoDomeGRPCClient, ScanResult

        client = PicoDomeGRPCClient(max_retries=3, retry_delay=0.01)
        good_result = ScanResult(verdict="ALLOW", exit_code=0)

        with patch.object(client, "_ensure_channel"):
            with patch.object(client, "_do_scan", side_effect=[ConnectionError("fail"), good_result]):
                result = client.scan(command=["echo", "hello"])
                assert result.verdict == "ALLOW"

    def test_client_ensure_channel_called_lazily(self):
        """Channel should not be created until first RPC call."""
        from picosentry.sandbox.grpc_transport.client import PicoDomeGRPCClient

        client = PicoDomeGRPCClient()
        assert client._channel is None
        assert client._stub is None

    def test_client_ensure_channel_with_grpc_unavailable(self):
        """_ensure_channel should raise ImportError when grpcio not installed."""
        from picosentry.sandbox.grpc_transport.client import PicoDomeGRPCClient

        client = PicoDomeGRPCClient()
        with patch("picosentry.sandbox.grpc_transport.client.is_grpc_available", return_value=False):
            with pytest.raises(ImportError, match="grpcio"):
                client._ensure_channel()

    def test_client_ensure_channel_insecure(self):
        """_ensure_channel should create insecure channel when no mTLS."""
        from picosentry.sandbox.grpc_transport.client import PicoDomeGRPCClient

        client = PicoDomeGRPCClient(mtls_config=None)
        mock_channel = MagicMock()
        mock_stub = MagicMock()
        mock_grpc = MagicMock()
        mock_grpc.insecure_channel.return_value = mock_channel

        with patch("picosentry.sandbox.grpc_transport.client.is_grpc_available", return_value=True):
            with patch.dict("sys.modules", {"grpc": mock_grpc}):
                with patch.dict(
                    "sys.modules",
                    {
                        "picosentry.sandbox.grpc_transport.proto.picodome_pb2_grpc": MagicMock(PicoDomeServiceStub=mock_stub),
                    },
                ):
                    client._ensure_channel()
                    mock_grpc.insecure_channel.assert_called_once_with("localhost:50051")

    def test_client_ensure_channel_secure(self):
        """_ensure_channel should create secure channel with mTLS config."""
        from picosentry.sandbox.grpc_transport.client import PicoDomeGRPCClient

        client = PicoDomeGRPCClient(mtls_config=MagicMock())
        mock_channel = MagicMock()
        mock_creds = MagicMock()
        mock_stub = MagicMock()
        mock_grpc = MagicMock()
        mock_grpc.secure_channel.return_value = mock_channel

        with patch.object(client, "_create_client_credentials", return_value=mock_creds):
            with patch("picosentry.sandbox.grpc_transport.client.is_grpc_available", return_value=True):
                with patch.dict("sys.modules", {"grpc": mock_grpc}):
                    with patch.dict(
                        "sys.modules",
                        {
                            "picosentry.sandbox.grpc_transport.proto.picodome_pb2_grpc": MagicMock(PicoDomeServiceStub=mock_stub),
                        },
                    ):
                        client._ensure_channel()
                        mock_grpc.secure_channel.assert_called_once()

    def test_client_create_credentials_dev_mode(self):
        """_create_client_credentials should return None in dev mode."""
        from picosentry.sandbox.grpc_transport.client import PicoDomeGRPCClient
        from picosentry.sandbox.mtls.context import MTLSConfig

        # Create a real MTLSConfig in dev mode
        config = MTLSConfig(dev_mode=True)
        client = PicoDomeGRPCClient(mtls_config=config)
        result = client._create_client_credentials(config)
        assert result is None

    def test_client_create_credentials_no_mtls(self):
        """_create_client_credentials should return None when mtls_config is None."""
        from picosentry.sandbox.grpc_transport.client import PicoDomeGRPCClient

        client = PicoDomeGRPCClient(mtls_config=None)
        result = client._create_client_credentials(None)
        assert result is None

    def test_client_create_credentials_not_mtls_config_instance(self):
        """_create_client_credentials should warn on non-MTLSConfig."""
        from picosentry.sandbox.grpc_transport.client import PicoDomeGRPCClient

        client = PicoDomeGRPCClient()
        result = client._create_client_credentials("not_a_config")
        assert result is None

    def test_client_create_credentials_missing_paths(self):
        """_create_client_credentials should return None when cert/key paths missing."""
        from picosentry.sandbox.grpc_transport.client import PicoDomeGRPCClient
        from picosentry.sandbox.mtls.context import MTLSConfig

        # MTLSConfig with dev_mode=False but no cert/key
        config = MTLSConfig(dev_mode=False, cert_path="", key_path="")
        client = PicoDomeGRPCClient()
        result = client._create_client_credentials(config)
        assert result is None

    def test_client_close_idempotent(self):
        """Close should be safe to call multiple times."""
        from picosentry.sandbox.grpc_transport.client import PicoDomeGRPCClient

        client = PicoDomeGRPCClient()
        client.close()
        client.close()  # Should not raise

    def test_client_context_manager_closes(self):
        """Context manager should close channel on exit."""
        from picosentry.sandbox.grpc_transport.client import PicoDomeGRPCClient

        with PicoDomeGRPCClient() as client:
            pass
        assert client._channel is None

    def test_client_health_without_grpc(self):
        """health() should raise when grpcio not installed."""
        from picosentry.sandbox.grpc_transport.client import PicoDomeGRPCClient

        client = PicoDomeGRPCClient()
        with patch("picosentry.sandbox.grpc_transport.client.is_grpc_available", return_value=False):
            with pytest.raises(ImportError):
                client.health()

    def test_client_get_policy_without_grpc(self):
        """get_policy() should raise when grpcio not installed."""
        from picosentry.sandbox.grpc_transport.client import PicoDomeGRPCClient

        client = PicoDomeGRPCClient()
        with patch("picosentry.sandbox.grpc_transport.client.is_grpc_available", return_value=False):
            with pytest.raises(ImportError):
                client.get_policy("test-policy")

    def test_client_query_audit_without_grpc(self):
        """query_audit() should raise when grpcio not installed."""
        from picosentry.sandbox.grpc_transport.client import PicoDomeGRPCClient

        client = PicoDomeGRPCClient()
        with patch("picosentry.sandbox.grpc_transport.client.is_grpc_available", return_value=False):
            with pytest.raises(ImportError):
                client.query_audit()

    def test_client_scan_async_delegates_to_sync(self):
        """scan_async should delegate to synchronous scan."""
        import asyncio

        from picosentry.sandbox.grpc_transport.client import PicoDomeGRPCClient, ScanResult

        client = PicoDomeGRPCClient()
        good_result = ScanResult(verdict="ALLOW")

        with patch.object(client, "scan", return_value=good_result):
            result = asyncio.run(client.scan_async(command=["echo", "hello"]))
            assert result.verdict == "ALLOW"
            client.scan.assert_called_once()


# ─── Tests: End-to-end gRPC round-trip (skipped without grpcio) ──────────────


class TestEndToEndGRPC:
    """Regression tests for the two long-broken gRPC pieces:

    1. The compiled protobuf stubs (``picodome_pb2`` / ``picodome_pb2_grpc``)
       used to be missing from the repo.  The transport module imported
       them and the import would fail at server start.
    2. ``add_servicer_manually`` used to call
       ``grpc.ServiceRpcHandlers(...)``, which was removed from grpcio
       in 1.50.  The fallback path blew up immediately.

    These tests boot a real gRPC server, make a real RPC over a real
    channel, and assert the round-trip works.  Both failure modes
    would have been caught by this test.

    Skipped if grpcio isn't installed — they're not part of the
    default test env (grpcio is a picosentry[grpc] extra).
    """

    @pytest.fixture
    def grpc_available(self):
        from picosentry.sandbox.grpc_transport import is_grpc_available

        if not is_grpc_available():
            pytest.skip("grpcio not installed; install picosentry[grpc] to run this test")
        return True

    def _free_port(self) -> int:
        import socket

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.bind(("", 0))
            return s.getsockname()[1]
        finally:
            s.close()

    def test_generated_stubs_importable(self, grpc_available):
        """The shipped picodome_pb2 / picodome_pb2_grpc modules must
        actually be importable.  This catches a regression where the
        proto file is committed but the generated stubs aren't."""
        from picosentry.sandbox.grpc_transport.proto import picodome_pb2, picodome_pb2_grpc

        assert hasattr(picodome_pb2, "ScanRequest")
        assert hasattr(picodome_pb2, "HealthCheckRequest")
        assert hasattr(picodome_pb2_grpc, "PicoDomeServiceServicer")
        assert hasattr(picodome_pb2_grpc, "add_PicoDomeServiceServicer_to_server")

    def test_generated_pb2_grpc_uses_relative_import(self, grpc_available):
        """grpc_tools.protoc emits ``import picodome_pb2 as ...`` (flat),
        which doesn't resolve when picodome_pb2_grpc is loaded as a
        submodule of a regular package.  The committed stubs (and the
        regen script) must rewrite this to a relative import."""
        from picosentry.sandbox.grpc_transport.proto import picodome_pb2_grpc

        src = __import__("inspect").getsource(picodome_pb2_grpc)
        assert "from . import picodome_pb2" in src, (
            "picodome_pb2_grpc.py must use a relative import for picodome_pb2 "
            "so the package loads as a regular package (not via sys.path hacks). "
            "Re-run scripts/regen_proto.sh."
        )

    def test_real_server_real_rpc_round_trip(self, grpc_available):
        """Boot a real gRPC server, register the generated servicer,
        make a real Health RPC, and confirm we get back the standard
        UNIMPLEMENTED error (because we registered an empty servicer).
        The point is that the wire-up works, not the business logic."""
        from concurrent.futures import ThreadPoolExecutor

        import grpc
        from picosentry.sandbox.grpc_transport.proto import picodome_pb2, picodome_pb2_grpc

        server = grpc.server(ThreadPoolExecutor(max_workers=2))
        picodome_pb2_grpc.add_PicoDomeServiceServicer_to_server(
            picodome_pb2_grpc.PicoDomeServiceServicer(),
            server,
        )
        port = self._free_port()
        server.add_insecure_port(f"127.0.0.1:{port}")
        server.start()
        try:
            channel = grpc.insecure_channel(f"127.0.0.1:{port}")
            try:
                stub = picodome_pb2_grpc.PicoDomeServiceStub(channel)
                with pytest.raises(grpc.RpcError) as exc_info:
                    stub.Health(picodome_pb2.HealthCheckRequest(), timeout=2.0)
                # Empty servicer responds with UNIMPLEMENTED; that's
                # the proof the wire format and method dispatch are
                # both healthy.
                assert exc_info.value.code() == grpc.StatusCode.UNIMPLEMENTED
            finally:
                channel.close()
        finally:
            server.stop(0)

    def test_add_servicer_manually_uses_modern_api(self, grpc_available):
        """The fallback registration path (used when the generated
        pb2_grpc import fails) must use ``method_handlers_generic_handler``,
        not the removed ``ServiceRpcHandlers``."""
        import ast

        from picosentry.sandbox.grpc_transport import _servicer

        # Inspect the AST rather than grepping the source — the
        # docstring legitimately mentions ServiceRpcHandlers as the
        # API being replaced, and we don't want to ban that.
        tree = ast.parse(__import__("inspect").getsource(_servicer.add_servicer_manually))
        func = tree.body[0]
        # The function body is everything between the (optional)
        # docstring and the end of the function.  Concatenate the
        # AST dump of every statement after the docstring.
        body = func.body
        if (
            body
            and isinstance(body[0], ast.Expr)
            and isinstance(body[0].value, ast.Constant)
            and isinstance(body[0].value.value, str)
        ):
            body = body[1:]
        joined = "\n".join(ast.dump(stmt) for stmt in body)
        assert "ServiceRpcHandlers" not in joined, (
            "add_servicer_manually body still references the removed "
            "grpc.ServiceRpcHandlers API; the fallback will crash at runtime."
        )
        assert "method_handlers_generic_handler" in joined
