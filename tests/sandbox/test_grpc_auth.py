"""gRPC transport auth — WO4.0.0-002.

Regression tests for the auth-bypass fix: shared TokenAuth+RBAC interceptor,
command validation, timeout clamp, cwd confinement and the plaintext-bind
refusal beyond loopback.
"""

from __future__ import annotations

import socket
import threading
import time
from unittest.mock import MagicMock, patch

import pytest

SUBMITTER_TOKEN = "picodome-submitter-unit-test-token-0000000001"
READER_TOKEN = "picodome-reader-unit-test-token-00000000000002"
ADMIN_TOKEN = "picodome-admin-unit-test-token-00000000000000003"


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _make_auth():
    from picosentry.sandbox.auth import RBAC, TokenAuth

    rbac = RBAC()
    auth = TokenAuth(rbac=rbac)
    return auth


class FakeSandboxResult:
    def __init__(self, verdict="ALLOW", exit_code=0):
        self.overall_verdict = type("V", (), {"value": verdict})()
        self.exit_code = exit_code
        self.duration_ms = 1

    def to_dict(self, deterministic=False):
        return {"verdict": self.overall_verdict.value}


class FakeAnalysisResult:
    def __init__(self, verdict="CLEAN"):
        self.overall_verdict = type("V", (), {"value": verdict})()
        self.findings = []

    def to_dict(self, deterministic=False):
        return {"verdict": self.overall_verdict.value}


# ─── Plaintext bind refusal ──────────────────────────────────────────────────


class TestPlaintextBindRefusal:
    def test_loopback_host_detection(self):
        from picosentry.sandbox.grpc_transport.auth import is_loopback_host

        assert is_loopback_host("127.0.0.1")
        assert is_loopback_host("localhost")
        assert is_loopback_host("::1")
        assert is_loopback_host("[::1]")
        assert not is_loopback_host("0.0.0.0")
        assert not is_loopback_host("[::]")
        assert not is_loopback_host("192.168.1.10")

    def test_start_refuses_plaintext_beyond_loopback(self):
        from picosentry.sandbox.grpc_transport.server import PicoDomeGRPCServer

        server = PicoDomeGRPCServer(host="0.0.0.0", port=50051)
        with pytest.raises(RuntimeError, match=r"plaintext.*non-loopback|Refusing"):
            server.start()

    def test_start_refuses_wildcard_ipv6_plaintext(self):
        from picosentry.sandbox.grpc_transport.server import PicoDomeGRPCServer

        server = PicoDomeGRPCServer(host="[::]", port=50051)
        with pytest.raises(RuntimeError):
            server.start()


# ─── Servicer hardening (unit level, mocked context) ─────────────────────────


def _servicer(scan_fn=None, analyze_fn=None):
    from picosentry.sandbox.grpc_transport._servicer import PicoDomeServicer
    from picosentry.sandbox.grpc_transport.server import _ScanEngine

    engine = _ScanEngine(scan_fn=scan_fn, analyze_fn=analyze_fn)
    return PicoDomeServicer(scan_engine=engine, start_time=time.time(), scan_count_ref=MagicMock())


def _request(command=("echo", "hi"), policy="", timeout=30.0, cwd=""):
    request = MagicMock()
    request.command = list(command)
    request.policy = policy
    request.timeout = timeout
    request.cwd = cwd
    return request


class TestServicerHardening:
    def test_denied_command_rejected(self):
        servicer = _servicer()
        context = MagicMock()
        context.is_active.return_value = False
        servicer.Scan(_request(command=("rm", "-rf", "/")), context)
        assert context.abort.called
        code = context.abort.call_args[0][0]
        assert code.name == "PERMISSION_DENIED"

    def test_denied_command_never_reaches_engine(self):
        calls = []

        def scan_fn(**kwargs):
            calls.append(kwargs)
            return FakeSandboxResult()

        servicer = _servicer(scan_fn=scan_fn, analyze_fn=lambda sr, **kw: FakeAnalysisResult())
        context = MagicMock()
        context.is_active.return_value = False
        servicer.Scan(_request(command=("bash", "-c", "x")), context)
        assert calls == []

    def test_timeout_clamped_to_max(self):
        seen = {}

        def scan_fn(**kwargs):
            seen["timeout"] = kwargs["timeout"]
            return FakeSandboxResult()

        servicer = _servicer(scan_fn=scan_fn, analyze_fn=lambda sr, **kw: FakeAnalysisResult())
        context = MagicMock()
        result = servicer.Scan(_request(timeout=99999.0), context)
        assert seen["timeout"] <= 300.0
        assert result is not None

    def test_cwd_escape_rejected(self, monkeypatch):
        monkeypatch.setenv("PICODOME_WORKSPACE_ROOT", "/tmp/picodome-ws-test")
        servicer = _servicer()
        context = MagicMock()
        context.is_active.return_value = False
        servicer.Scan(_request(cwd="/etc"), context)
        assert context.abort.called
        assert context.abort.call_args[0][0].name == "PERMISSION_DENIED"

    def test_cwd_inside_workspace_allowed(self, monkeypatch, tmp_path):
        ws = tmp_path / "ws"
        ws.mkdir()
        target = ws / "proj"
        target.mkdir()
        monkeypatch.setenv("PICODOME_WORKSPACE_ROOT", str(ws))
        seen = {}

        def scan_fn(**kwargs):
            seen["cwd"] = kwargs["cwd"]
            return FakeSandboxResult()

        servicer = _servicer(scan_fn=scan_fn, analyze_fn=lambda sr, **kw: FakeAnalysisResult())
        context = MagicMock()
        context.is_active.return_value = True
        servicer.Scan(_request(cwd=str(target)), context)
        assert not context.abort.called
        assert seen["cwd"].startswith(str(ws))

    def test_traversal_policy_name_rejected(self):
        servicer = _servicer()
        context = MagicMock()
        context.is_active.return_value = False
        servicer.Scan(_request(policy="../../etc/passwd"), context)
        assert context.abort.called
        assert context.abort.call_args[0][0].name in ("INVALID_ARGUMENT", "NOT_FOUND")

    def test_get_policy_traversal_rejected(self):
        servicer = _servicer()
        context = MagicMock()
        request = MagicMock()
        request.name = "../escape"
        request.version = 0
        servicer.GetPolicy(request, context)
        assert context.abort.called
        assert context.abort.call_args[0][0].name == "INVALID_ARGUMENT"


# ─── Bearer metadata extraction ──────────────────────────────────────────────


class TestBearerExtraction:
    def test_extracts_bearer_token(self):
        from picosentry.sandbox.grpc_transport.auth import bearer_token_from_metadata

        md = [("authorization", "Bearer abc123"), ("x-tenant", "t1")]
        assert bearer_token_from_metadata(md) == "abc123"

    def test_case_insensitive_key(self):
        from picosentry.sandbox.grpc_transport.auth import bearer_token_from_metadata

        assert bearer_token_from_metadata([("Authorization", "Bearer xyz")]) == "xyz"

    def test_missing_returns_empty(self):
        from picosentry.sandbox.grpc_transport.auth import bearer_token_from_metadata

        assert bearer_token_from_metadata([]) == ""
        assert bearer_token_from_metadata(None) == ""
        assert bearer_token_from_metadata([("x-other", "1")]) == ""

    def test_authorize_rejects_unknown_token(self):
        from picosentry.sandbox.grpc_transport.auth import authorize

        auth = _make_auth()
        with patch.dict("os.environ", {"PICODOME_API_TOKENS": SUBMITTER_TOKEN}):
            auth2 = _make_auth()
            assert authorize(auth2, SUBMITTER_TOKEN, "scan:submit")
            assert not authorize(auth2, "picodome-submitter-wrong-token-0000000001", "scan:submit")
        # auth (no tokens configured, non-dev) rejects everything
        assert not authorize(auth, SUBMITTER_TOKEN, "scan:submit")


# ─── End-to-end over real grpcio ─────────────────────────────────────────────


def _grpc_available() -> bool:
    from picosentry.sandbox.grpc_transport import is_grpc_available

    return is_grpc_available()


class TestEndToEndAuth:
    """Boot the real server (plaintext on loopback) and verify the interceptor."""

    @pytest.fixture(autouse=True)
    def _require_grpcio(self):
        if not _grpc_available():
            pytest.skip("grpcio not installed")

    @pytest.fixture
    def server(self):
        from picosentry.sandbox.grpc_transport.server import PicoDomeGRPCServer

        with patch.dict(
            "os.environ",
            {"PICODOME_API_TOKENS": f"{SUBMITTER_TOKEN},{READER_TOKEN},{ADMIN_TOKEN}"},
        ):
            auth = _make_auth()
        port = _free_port()
        srv = PicoDomeGRPCServer(
            host="127.0.0.1",
            port=port,
            scan_fn=lambda **kw: FakeSandboxResult(),
            analyze_fn=lambda sr, **kw: FakeAnalysisResult(),
            auth=auth,
        )
        thread = threading.Thread(target=srv.start, daemon=True)
        thread.start()
        import grpc

        channel = grpc.insecure_channel(f"127.0.0.1:{port}")
        grpc.channel_ready_future(channel).result(timeout=5.0)
        from picosentry.sandbox.grpc_transport.proto import picodome_pb2_grpc as pb2_grpc

        yield pb2_grpc.PicoDomeServiceStub(channel)
        channel.close()
        srv.stop(0)

    def _stub(self, server):
        return server

    def test_unauthenticated_scan_rejected(self, server):
        import grpc

        from picosentry.sandbox.grpc_transport.proto import picodome_pb2 as pb2

        with pytest.raises(grpc.RpcError) as exc_info:
            server.Scan(pb2.ScanRequest(command=["echo", "hi"]), timeout=3)
        assert exc_info.value.code() == grpc.StatusCode.UNAUTHENTICATED

    def test_wrong_role_rejected(self, server):
        import grpc

        from picosentry.sandbox.grpc_transport.proto import picodome_pb2 as pb2

        with pytest.raises(grpc.RpcError) as exc_info:
            server.Scan(
                pb2.ScanRequest(command=["echo", "hi"]),
                timeout=3,
                metadata=[("authorization", f"Bearer {READER_TOKEN}")],
            )
        assert exc_info.value.code() == grpc.StatusCode.PERMISSION_DENIED

    def test_submitter_scan_succeeds(self, server):
        from picosentry.sandbox.grpc_transport.proto import picodome_pb2 as pb2

        response = server.Scan(
            pb2.ScanRequest(command=["echo", "hi"]),
            timeout=5,
            metadata=[("authorization", f"Bearer {SUBMITTER_TOKEN}")],
        )
        assert response.verdict == "CLEAN"

    def test_unauthenticated_query_audit_rejected(self, server):
        import grpc

        from picosentry.sandbox.grpc_transport.proto import picodome_pb2 as pb2

        with pytest.raises(grpc.RpcError) as exc_info:
            server.QueryAudit(pb2.AuditQueryRequest(), timeout=3)
        assert exc_info.value.code() == grpc.StatusCode.UNAUTHENTICATED

    def test_reader_can_query_audit(self, server):
        from picosentry.sandbox.grpc_transport.proto import picodome_pb2 as pb2

        response = server.QueryAudit(
            pb2.AuditQueryRequest(limit=5),
            timeout=5,
            metadata=[("authorization", f"Bearer {READER_TOKEN}")],
        )
        assert response.count >= 0

    def test_health_open_without_token(self, server):
        from picosentry.sandbox.grpc_transport.proto import picodome_pb2 as pb2

        response = server.Health(pb2.HealthCheckRequest(), timeout=3)
        # healthy flag depends on the environment; the point is it answers.
        assert response.version

    def test_denied_command_over_wire(self, server):
        import grpc

        from picosentry.sandbox.grpc_transport.proto import picodome_pb2 as pb2

        with pytest.raises(grpc.RpcError) as exc_info:
            server.Scan(
                pb2.ScanRequest(command=["sudo", "rm", "-rf", "/"]),
                timeout=3,
                metadata=[("authorization", f"Bearer {SUBMITTER_TOKEN}")],
            )
        assert exc_info.value.code() == grpc.StatusCode.PERMISSION_DENIED

    def test_cwd_escape_over_wire(self, server, monkeypatch):
        import grpc

        from picosentry.sandbox.grpc_transport.proto import picodome_pb2 as pb2

        monkeypatch.setenv("PICODOME_WORKSPACE_ROOT", "/tmp/picodome-ws-test")
        with pytest.raises(grpc.RpcError) as exc_info:
            server.Scan(
                pb2.ScanRequest(command=["echo", "hi"], cwd="/etc"),
                timeout=3,
                metadata=[("authorization", f"Bearer {SUBMITTER_TOKEN}")],
            )
        assert exc_info.value.code() == grpc.StatusCode.PERMISSION_DENIED
