"""WO5.0.0-001 — tenant isolation in PRODUCTION wiring.

The gate: boot the REAL PicoDomeDaemon (in-process, real HTTP server, real
auth, real tenant registry loaded from env — NOT a hand-wired handler) with
PICODOME_TENANTS / PICODOME_TENANT_TOKEN_MAP / PICODOME_TENANT_OPERATOR_TOKENS
set, and prove:

(a) two tokens land in different tenants — job isolation BOTH directions,
    cross-tenant get/list indistinguishable from not-found
(b) foreign token + victim X-Tenant header → denied (403)
(c) submitted jobs land in the token's tenant (header may only confirm)
(d) sqlite pre-tenancy row (tenant_id NULL) is readable as DEFAULT tenant
(e) audit + /api/v1/tenants scoping: tenant tokens see own, operator sees all
"""

from __future__ import annotations

import hashlib
import http.client
import json
import socket
import sqlite3
import time
from typing import ClassVar
from unittest.mock import patch

import pytest

import picosentry.sandbox.audit.logger as audit_logger_mod
import picosentry.sandbox.daemon.handler_routes_post as handler_routes_post
from picosentry.sandbox.audit import AuditLogger
from picosentry.sandbox.daemon.server import PicoDomeDaemon
from picosentry.sandbox.tenant import reset_tenant_registry

TOKEN_ACME = "picodome-admin-acme-tenant-token-00000001"
TOKEN_GLOBEX = "picodome-admin-globex-tenant-token-000002"
TOKEN_DEFAULT = "picodome-admin-default-tenant-token-000003"
TOKEN_OPERATOR = "picodome-admin-operator-tenant-token-00004"


def _sha(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _tenant_env() -> dict[str, str]:
    return {
        "PICODOME_TENANTS": "acme:Acme Corp;globex:Globex Inc",
        "PICODOME_TENANT_TOKEN_MAP": f"{_sha(TOKEN_ACME)}:acme,{_sha(TOKEN_GLOBEX)}:globex",
        "PICODOME_TENANT_OPERATOR_TOKENS": _sha(TOKEN_OPERATOR),
    }


@pytest.fixture(autouse=True)
def _clean_singletons():
    original_audit = audit_logger_mod._audit_logger
    from picosentry.sandbox.daemon.handler import PicoDomeHandler

    saved = (PicoDomeHandler.scan_executor, PicoDomeHandler.scan_slots)
    yield
    PicoDomeHandler.scan_executor, PicoDomeHandler.scan_slots = saved
    audit_logger_mod._audit_logger = original_audit
    reset_tenant_registry()


@pytest.fixture(autouse=True)
def fake_engine(monkeypatch):
    """Keep the sandbox cheap/deterministic; the daemon wiring is what's under test."""
    monkeypatch.setattr(handler_routes_post, "sandbox_run", _fake_sandbox_run)
    monkeypatch.setattr(handler_routes_post, "profile_from_sandbox_result", lambda sr: object())
    monkeypatch.setattr(handler_routes_post, "create_default_engine", lambda: _FakeL4Engine())
    monkeypatch.setattr(handler_routes_post, "get_retention_manager", lambda: _NoRetention())


class _FakeSandboxResult:
    overall_verdict = type("V", (), {"value": "ALLOW"})()
    exit_code = 0
    duration_ms = 1
    backend_name = "test"
    isolation_level = "test"
    enforcement_guarantee = "best-effort"
    degraded = False

    def to_dict(self, deterministic=False):
        return {"verdict": "ALLOW"}


class _FakeAnalysisResult:
    overall_verdict = type("V", (), {"value": "CLEAN"})()
    findings: ClassVar[list] = []

    def to_dict(self, deterministic=False):
        return {"verdict": "CLEAN"}


class _FakeL4Engine:
    def analyze(self, profile, rules=None, deterministic=False):
        return _FakeAnalysisResult()


class _NoRetention:
    def save_scan_result(self, blob, package_name="unknown"):
        return None


def _fake_sandbox_run(**kwargs):
    return _FakeSandboxResult()


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _http(
    port: int, method: str, path: str, body: dict | None = None, token: str | None = None, tenant: str | None = None
):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if tenant:
        headers["X-Tenant"] = tenant
    payload = json.dumps(body) if body is not None else None
    conn.request(method, path, body=payload, headers=headers)
    resp = conn.getresponse()
    data = resp.read()
    conn.close()
    return resp.status, json.loads(data) if data else {}


def _wait_healthy(port: int, timeout: float = 5.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            status, _ = _http(port, "GET", "/health")
            if status == 200:
                return
        except OSError:
            time.sleep(0.05)
    raise TimeoutError("daemon did not become healthy")


def _boot_tenant_daemon(tmp_path, monkeypatch, extra_env: dict[str, str] | None = None) -> int:
    """Boot the real daemon with production tenant env; returns its port."""
    audit_logger_mod._audit_logger = AuditLogger(log_dir=tmp_path / "audit", max_bytes=1024 * 1024)
    port = _free_port()
    env = {
        "PICODOME_JOB_STORE_DIR": str(tmp_path / "jobs"),
        "PICODOME_API_TOKENS": ",".join([TOKEN_ACME, TOKEN_GLOBEX, TOKEN_DEFAULT, TOKEN_OPERATOR]),
        "PICODOME_RATE_PER_SECOND": "50",
        "PICODOME_GLOBAL_RPS": "100",
        **_tenant_env(),
        **(extra_env or {}),
    }
    for key, value in env.items():
        monkeypatch.setenv(key, value)
    daemon = PicoDomeDaemon(host="127.0.0.1", port=port)
    daemon.start(background=True)
    _wait_healthy(port)
    return port


def _submit(port: int, token: str, text: str, tenant: str | None = None):
    return _http(
        port,
        "POST",
        "/api/v1/scan",
        body={"command": ["echo", text]},
        token=token,
        tenant=tenant,
    )


class TestTenantIsolationProduction:
    def test_two_tokens_land_in_different_tenants(self, tmp_path, monkeypatch):
        """(a)+(c): submissions land in the token's tenant; isolation both ways."""
        port = _boot_tenant_daemon(tmp_path, monkeypatch)

        status_a, body_a = _submit(port, TOKEN_ACME, "acme-secret")
        status_b, body_b = _submit(port, TOKEN_GLOBEX, "globex-secret")
        assert status_a == 201 and status_b == 201
        job_a, job_b = body_a["job_id"], body_b["job_id"]

        # (c) each job persisted under its token's tenant
        _, got_a = _http(port, "GET", f"/api/v1/scan/{job_a}", token=TOKEN_ACME)
        assert got_a["tenant_id"] == "acme"
        _, got_b = _http(port, "GET", f"/api/v1/scan/{job_b}", token=TOKEN_GLOBEX)
        assert got_b["tenant_id"] == "globex"

        # (a) cross-tenant get is indistinguishable from not-found, both directions
        status, _ = _http(port, "GET", f"/api/v1/scan/{job_a}", token=TOKEN_GLOBEX)
        assert status == 404
        status, _ = _http(port, "GET", f"/api/v1/scan/{job_b}", token=TOKEN_ACME)
        assert status == 404

        # (a) cross-tenant list excludes the other tenant's jobs
        _, listing_a = _http(port, "GET", "/api/v1/scans", token=TOKEN_ACME)
        assert listing_a["count"] == 1
        assert listing_a["scans"][0]["tenant_id"] == "acme"
        assert listing_a["scans"][0]["command"] == ["echo", "acme-secret"]
        _, listing_b = _http(port, "GET", "/api/v1/scans", token=TOKEN_GLOBEX)
        assert listing_b["count"] == 1
        assert listing_b["scans"][0]["command"] == ["echo", "globex-secret"]

    def test_foreign_token_with_victim_header_denied(self, tmp_path, monkeypatch):
        """(b): globex token + X-Tenant: acme must not reach acme's data."""
        port = _boot_tenant_daemon(tmp_path, monkeypatch)
        _, body_a = _submit(port, TOKEN_ACME, "acme-secret")
        job_a = body_a["job_id"]

        # Read path
        status, body = _http(port, "GET", f"/api/v1/scan/{job_a}", token=TOKEN_GLOBEX, tenant="acme")
        assert status == 403, body

        # Submit path: foreign token cannot submit INTO the victim's namespace
        status, body = _submit(port, TOKEN_GLOBEX, "evil", tenant="acme")
        assert status == 403, body

        # List path with a lying header is rejected too
        status, _ = _http(port, "GET", "/api/v1/scans", token=TOKEN_GLOBEX, tenant="acme")
        assert status == 403

        # The victim's own narrow header still works
        status, _ = _http(port, "GET", f"/api/v1/scan/{job_a}", token=TOKEN_ACME, tenant="acme")
        assert status == 200

        # Unmapped tokens may not borrow a header either
        status, _ = _http(port, "GET", f"/api/v1/scan/{job_a}", token=TOKEN_DEFAULT, tenant="acme")
        assert status == 403

        # Operator tokens MAY narrow into any tenant
        status, body = _http(port, "GET", f"/api/v1/scan/{job_a}", token=TOKEN_OPERATOR, tenant="acme")
        assert status == 200, body

    def test_sqlite_null_tenant_row_readable_as_default(self, tmp_path, monkeypatch):
        """(d): pre-upgrade sqlite rows (tenant_id NULL) belong to DEFAULT."""
        db_path = tmp_path / "jobs.db"
        port = _boot_tenant_daemon(
            tmp_path, monkeypatch, {"PICODOME_STORE_BACKEND": "sqlite", "PICODOME_SQLITE_PATH": str(db_path)}
        )

        # Touch the store once so the lazy schema exists, then write a
        # pre-tenancy row directly (as an upgraded install would have).
        _http(port, "GET", "/api/v1/scans", token=TOKEN_DEFAULT)
        conn = sqlite3.connect(str(db_path))
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        conn.execute(
            """INSERT INTO jobs (job_id, command, actor, status, created_at, completed_at,
                                  result, error, schema_version)
               VALUES ('legacy-job-1', ?, 'legacy-actor', 'completed', ?, '', '', '', 1)""",
            (json.dumps(["echo", "pre-tenancy"]), now),
        )
        conn.commit()
        conn.close()

        # DEFAULT-tenant token (unmapped) sees it; tenant tokens do not.
        status, body = _http(port, "GET", "/api/v1/scan/legacy-job-1", token=TOKEN_DEFAULT)
        assert status == 200, body
        assert body["job_id"] == "legacy-job-1"

        status, _ = _http(port, "GET", "/api/v1/scan/legacy-job-1", token=TOKEN_ACME)
        assert status == 404
        status, _ = _http(port, "GET", "/api/v1/scan/legacy-job-1", token=TOKEN_GLOBEX)
        assert status == 404

    def test_audit_and_tenant_listing_scoping(self, tmp_path, monkeypatch):
        """(e): tenant tokens see only their own audit events + own tenant;
        operator tokens see all."""
        port = _boot_tenant_daemon(tmp_path, monkeypatch)
        _submit(port, TOKEN_ACME, "acme-secret")
        _submit(port, TOKEN_GLOBEX, "globex-secret")

        # Tenant token: only its own tenant's events (AUTH_SUCCESS has no
        # tenant metadata and must not leak).
        _, audit_acme = _http(port, "GET", "/api/v1/audit", token=TOKEN_ACME)
        tenant_ids = {e["metadata"].get("tenant_id") for e in audit_acme["events"]}
        assert tenant_ids <= {"acme"}, tenant_ids
        assert any(
            e["event_type"] == "scan_start" and e["metadata"].get("tenant_id") == "acme" for e in audit_acme["events"]
        )
        assert not any("globex" in json.dumps(e) for e in audit_acme["events"])

        _, audit_globex = _http(port, "GET", "/api/v1/audit", token=TOKEN_GLOBEX)
        assert all(e["metadata"].get("tenant_id") == "globex" for e in audit_globex["events"])

        # Operator: sees everything, including both tenants and infra events.
        _, audit_op = _http(port, "GET", "/api/v1/audit", token=TOKEN_OPERATOR)
        assert any(e["metadata"].get("tenant_id") == "acme" for e in audit_op["events"])
        assert any(e["metadata"].get("tenant_id") == "globex" for e in audit_op["events"])
        assert any(e["event_type"] == "auth_success" for e in audit_op["events"])

        # /api/v1/tenants: own tenant only vs all tenants for the operator.
        _, tenants_acme = _http(port, "GET", "/api/v1/tenants", token=TOKEN_ACME)
        assert [t["tenant_id"] for t in tenants_acme["tenants"]] == ["acme"]

        _, tenants_op = _http(port, "GET", "/api/v1/tenants", token=TOKEN_OPERATOR)
        assert {t["tenant_id"] for t in tenants_op["tenants"]} == {"acme", "globex"}


class TestResolveTenantUnit:
    """Unit-level checks of the resolve rule (cheap complements to the boot tests)."""

    def test_header_mismatch_raises_and_operator_narrows(self):
        from picosentry.sandbox.tenant import (
            TenantContext,
            TenantId,
            TenantMismatchError,
            setup_tenant_registry,
        )

        registry = setup_tenant_registry()
        registry.register(TenantContext(tenant_id=TenantId("acme")))
        registry.register(TenantContext(tenant_id=TenantId("globex")))
        registry.map_token("hash-acme", TenantId("acme"))
        registry.map_operator_token("hash-op")

        assert str(registry.resolve_tenant("hash-acme")) == "acme"
        assert str(registry.resolve_tenant("hash-acme", header_tenant="acme")) == "acme"
        with pytest.raises(TenantMismatchError):
            registry.resolve_tenant("hash-acme", header_tenant="globex")
        with pytest.raises(TenantMismatchError):
            registry.resolve_tenant("unknown-hash", header_tenant="acme")
        # Operator may select any registered tenant; unknown header falls back.
        registry.map_token("hash-op", TenantId("acme"))
        assert str(registry.resolve_tenant("hash-op", header_tenant="globex")) == "globex"
        assert str(registry.resolve_tenant("hash-op")) == "acme"

    def test_daemon_boot_loads_registry_from_env(self, tmp_path, monkeypatch):
        """The wiring itself: PicoDomeDaemon.__init__ must call the env loader."""
        port = _free_port()
        for key, value in _tenant_env().items():
            monkeypatch.setenv(key, value)
        with patch.dict("os.environ", {"PICODOME_JOB_STORE_DIR": str(tmp_path / "jobs")}):
            PicoDomeDaemon(host="127.0.0.1", port=port)
        from picosentry.sandbox.tenant import get_tenant_registry

        registry = get_tenant_registry()
        assert {str(t.tenant_id) for t in registry.list_tenants()} == {"acme", "globex"}
        assert registry.resolve_tenant(_sha(TOKEN_ACME)) == "acme"
