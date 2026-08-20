"""WO6.0.0-004 — gRPC QueryAudit tenant-scope parity with the HTTP route.

The gRPC QueryAudit servicer used to return ALL tenants' audit events to any
audit:read token — the interceptor enforced RBAC but applied no tenant filter,
while the HTTP mirror (handler_routes_get._handle_audit_query) scoped non-operator
tokens to their own tenant. This gate proves both transports now filter
identically:

- a tenant reader token sees only its own tenant's events on BOTH transports
- an operator token sees all events on BOTH transports

The audit events are recorded with explicit ``tenant_id`` metadata (the same
shape the HTTP scan path writes — see ``handler_routes_post._handle_submit``),
so the post-query filter applied by both routes has something to filter on.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import socket
import threading
import time

import pytest

import picosentry.sandbox.audit.logger as audit_logger_mod
from picosentry.sandbox.audit import AuditEventType, AuditLogger
from picosentry.sandbox.tenant import reset_tenant_registry

TOKEN_ALPHA_READER = "picodome-reader-alpha-tenant-0000000001"
TOKEN_BETA_READER = "picodome-reader-beta-tenant-0000000002"
TOKEN_OPERATOR = "picodome-admin-operator-tenant-000003"


def _sha(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _tenant_env() -> dict[str, str]:
    return {
        "PICODOME_TENANTS": "alpha:Alpha;beta:Beta",
        "PICODOME_TENANT_TOKEN_MAP": f"{_sha(TOKEN_ALPHA_READER)}:alpha,{_sha(TOKEN_BETA_READER)}:beta",
        "PICODOME_TENANT_OPERATOR_TOKENS": _sha(TOKEN_OPERATOR),
    }


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _grpc_available() -> bool:
    try:
        from picosentry.sandbox.grpc_transport import is_grpc_available

        return is_grpc_available()
    except Exception:
        return False


def _record_tenant_events(audit: AuditLogger) -> None:
    """Seed the audit log with one event per tenant + an infra event (no
    tenant_id) — the same shape HTTP scans produce."""
    audit.record(event_type=AuditEventType.SCAN_START, actor="alpha-actor", metadata={"tenant_id": "alpha"})
    audit.record(event_type=AuditEventType.SCAN_START, actor="beta-actor", metadata={"tenant_id": "beta"})
    audit.record(event_type=AuditEventType.SCAN_COMPLETE, actor="alpha-actor", metadata={"tenant_id": "alpha"})
    audit.record(event_type=AuditEventType.AUTH_SUCCESS, actor="anon", metadata={})


@pytest.fixture(autouse=True)
def _clean_singletons():
    original_audit = audit_logger_mod._audit_logger
    yield
    audit_logger_mod._audit_logger = original_audit
    reset_tenant_registry()


def _make_auth():
    from picosentry.sandbox.auth import RBAC, TokenAuth

    rbac = RBAC()
    return TokenAuth(rbac=rbac)


def _http(port: int, path: str, token: str | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Accept": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    conn.request("GET", path, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, json.loads(data) if data else {}


def _wait_healthy(port: int, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status, _ = _http(port, "/health")
            if status == 200:
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError("daemon did not become healthy")


class FakeSandboxResult:
    def __init__(self) -> None:
        self.overall_verdict = type("V", (), {"value": "ALLOW"})()
        self.exit_code = 0
        self.duration_ms = 1

    def to_dict(self, deterministic=False):
        return {"verdict": "ALLOW"}


class FakeAnalysisResult:
    def __init__(self) -> None:
        self.overall_verdict = type("V", (), {"value": "CLEAN"})()
        self.findings: list = []

    def to_dict(self, deterministic=False):
        return {"verdict": "CLEAN"}


class TestGrpcAuditTenantScope:
    """WO6.0.0-004: gRPC QueryAudit must scope non-operator tokens to their
    own tenant, mirroring the HTTP route."""

    @pytest.fixture(autouse=True)
    def _require_grpcio(self):
        if not _grpc_available():
            pytest.skip("grpcio not installed")

    @pytest.fixture
    def server(self, tmp_path, monkeypatch):
        # Isolated audit log seeded once per server.
        audit_logger_mod._audit_logger = AuditLogger(log_dir=tmp_path / "audit", max_bytes=1024 * 1024)
        _record_tenant_events(audit_logger_mod._audit_logger)

        for key, value in {
            "PICODOME_API_TOKENS": ",".join([TOKEN_ALPHA_READER, TOKEN_BETA_READER, TOKEN_OPERATOR]),
            **_tenant_env(),
        }.items():
            monkeypatch.setenv(key, value)

        from picosentry.sandbox.grpc_transport.server import PicoDomeGRPCServer

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

    def _query(self, server, token: str, limit: int = 100):
        from picosentry.sandbox.grpc_transport.proto import picodome_pb2 as pb2

        return server.QueryAudit(
            pb2.AuditQueryRequest(limit=limit),
            timeout=5,
            metadata=[("authorization", f"Bearer {token}")],
        )

    def test_alpha_reader_sees_only_alpha_events(self, server):
        resp = self._query(server, TOKEN_ALPHA_READER)
        events = json.loads(resp.events_json)
        assert resp.count == len(events)
        tenant_ids = {e["metadata"].get("tenant_id") for e in events}
        # alpha reader sees ONLY alpha's events — no beta, no infra leak
        assert tenant_ids == {"alpha"}, tenant_ids
        assert all(e["metadata"].get("tenant_id") == "alpha" for e in events)

    def test_beta_reader_sees_only_beta_events(self, server):
        resp = self._query(server, TOKEN_BETA_READER)
        events = json.loads(resp.events_json)
        tenant_ids = {e["metadata"].get("tenant_id") for e in events}
        assert tenant_ids == {"beta"}, tenant_ids

    def test_operator_sees_all_events(self, server):
        resp = self._query(server, TOKEN_OPERATOR)
        events = json.loads(resp.events_json)
        tenant_ids = {e["metadata"].get("tenant_id") for e in events}
        # Operator sees both tenants AND the infra event (no tenant_id).
        assert {"alpha", "beta"}.issubset(tenant_ids), tenant_ids
        assert any(e["event_type"] == "auth_success" for e in events)


class TestHttpAuditTenantScope:
    """Mirror of the gRPC seat over the real HTTP daemon — regression-guards
    the HTTP side that the gRPC seat was modeled on (WO5.0.0-001)."""

    def test_http_alpha_and_operator_scope(self, tmp_path, monkeypatch):
        from picosentry.sandbox.daemon.server import PicoDomeDaemon

        audit_logger_mod._audit_logger = AuditLogger(log_dir=tmp_path / "audit", max_bytes=1024 * 1024)
        _record_tenant_events(audit_logger_mod._audit_logger)

        port = _free_port()
        for key, value in {
            "PICODOME_JOB_STORE_DIR": str(tmp_path / "jobs"),
            "PICODOME_API_TOKENS": ",".join([TOKEN_ALPHA_READER, TOKEN_BETA_READER, TOKEN_OPERATOR]),
            **_tenant_env(),
        }.items():
            monkeypatch.setenv(key, value)

        daemon = PicoDomeDaemon(host="127.0.0.1", port=port)
        daemon.start(background=True)
        _wait_healthy(port)
        try:
            _, alpha_audit = _http(port, "/api/v1/audit", token=TOKEN_ALPHA_READER)
            tenant_ids = {e["metadata"].get("tenant_id") for e in alpha_audit["events"]}
            assert tenant_ids == {"alpha"}, tenant_ids

            _, op_audit = _http(port, "/api/v1/audit", token=TOKEN_OPERATOR)
            op_tids = {e["metadata"].get("tenant_id") for e in op_audit["events"]}
            assert {"alpha", "beta"}.issubset(op_tids), op_tids
            assert any(e["event_type"] == "auth_success" for e in op_audit["events"])
        finally:
            daemon.stop()


class TestGrpcHttpTenantScopeParity:
    """The shape contract: both transports apply the SAME filter rule
    (non-operator → own tenant; operator → all). Unit-level so it runs
    everywhere, no network."""

    def test_both_filters_use_metadata_tenant_id(self, tmp_path, monkeypatch):
        # Prove the rule is identical by exercising the servicer and the
        # HTTP handler with the same seeded audit log + the same token set,
        # and asserting the response event sets match.
        from picosentry.sandbox.daemon.constants import max_list_limit
        from picosentry.sandbox.grpc_transport._servicer import PicoDomeServicer
        from picosentry.sandbox.tenant import TenantContext, TenantId, setup_tenant_registry

        audit = AuditLogger(log_dir=tmp_path / "audit", max_bytes=1024 * 1024)
        _record_tenant_events(audit)
        monkeypatch.setattr(audit_logger_mod, "_audit_logger", audit)

        registry = setup_tenant_registry(
            [
                TenantContext(tenant_id=TenantId("alpha")),
                TenantContext(tenant_id=TenantId("beta")),
            ]
        )
        registry.map_token(_sha(TOKEN_ALPHA_READER), TenantId("alpha"))
        registry.map_token(_sha(TOKEN_BETA_READER), TenantId("beta"))
        registry.map_operator_token(_sha(TOKEN_OPERATOR))

        # gRPC path: invoke the servicer's QueryAudit directly with a mocked
        # context carrying the bearer metadata (the interceptor is bypassed;
        # the servicer's own tenant filter is what we test).
        servicer = PicoDomeServicer(scan_engine=None, start_time=time.time(), scan_count_ref=None)

        def _ctx(token: str):
            ctx = type("Ctx", (), {})()
            ctx.invocation_metadata = lambda: [("authorization", f"Bearer {token}")]
            return ctx

        def _grpc_query(token: str) -> set[str | None]:
            req = type("Req", (), {})()
            req.event_type = ""
            req.actor = ""
            req.target = ""
            req.since = ""
            req.until = ""
            req.limit = max_list_limit()
            resp = servicer.QueryAudit(req, _ctx(token))
            events = json.loads(resp.events_json)
            return {e["metadata"].get("tenant_id") for e in events}

        # HTTP path: reuse the same audit + the same filter the route applies.
        def _http_filter(token: str) -> set[str | None]:
            token_hash = _sha(token)
            is_op = registry.is_operator_token(token_hash)
            events = audit.query(limit=max_list_limit())
            if not is_op:
                tid = str(registry.resolve_tenant(token_hash))
                events = [e for e in events if e.metadata.get("tenant_id") == tid]
            return {e.metadata.get("tenant_id") for e in events}

        assert _grpc_query(TOKEN_ALPHA_READER) == _http_filter(TOKEN_ALPHA_READER) == {"alpha"}
        assert _grpc_query(TOKEN_BETA_READER) == _http_filter(TOKEN_BETA_READER) == {"beta"}
        # Operator: both see alpha + beta + the infra event (None tenant_id)
        assert _grpc_query(TOKEN_OPERATOR) == _http_filter(TOKEN_OPERATOR)
        assert {"alpha", "beta"}.issubset(_grpc_query(TOKEN_OPERATOR))
