"""Daemon tenant-isolation + secret-redaction tests — WO4.0.0-010.

Proves, through the real handler methods and a real TenantAwareScanJobStore:
- a tenant's scan (and its stdout) cannot be read by another tenant's token
- jobs persist with their tenant_id
- exfiltrated secret material (SUS-003/008/009 hits) is withheld from the
  response, the job store and retention — replaced by marker + sha256 + len
  with an explicit redaction flag.
"""

from __future__ import annotations

import hashlib
import io
import json
from unittest.mock import MagicMock

import pytest

import picosentry.sandbox.audit.logger as audit_logger_mod
from picosentry.sandbox.audit import AuditLogger
from picosentry.sandbox.daemon.handler import PicoDomeHandler
from picosentry.sandbox.daemon.store import PersistentScanJobStore
from picosentry.sandbox.tenant import (
    TenantContext,
    TenantId,
    reset_tenant_registry,
    setup_tenant_registry,
)
from picosentry.sandbox.tenant.store import TenantAwareScanJobStore

TOKEN_A = "token-alpha-0123456789abcdef"
TOKEN_B = "token-beta-0123456789abcdef"


@pytest.fixture(autouse=True)
def _clean_audit_singleton():
    original = audit_logger_mod._audit_logger
    yield
    audit_logger_mod._audit_logger = original


@pytest.fixture(autouse=True)
def _clean_tenant_registry():
    reset_tenant_registry()
    yield
    reset_tenant_registry()


def _make_tenant_handler(tmp_path, monkeypatch):
    """Wire a real TenantAwareScanJobStore + two tenants into the handler."""
    audit_logger_mod._audit_logger = AuditLogger(log_dir=tmp_path / "audit", max_bytes=1024 * 1024)

    registry = setup_tenant_registry(
        [
            TenantContext(tenant_id=TenantId("alpha")),
            TenantContext(tenant_id=TenantId("beta")),
        ]
    )
    registry.map_token(hashlib.sha256(TOKEN_A.encode()).hexdigest(), TenantId("alpha"))
    registry.map_token(hashlib.sha256(TOKEN_B.encode()).hexdigest(), TenantId("beta"))

    backing = PersistentScanJobStore(store_dir=tmp_path / "jobs")
    PicoDomeHandler.job_store = TenantAwareScanJobStore(backing)

    monkeypatch.setattr(PicoDomeHandler, "scan_executor", None)
    monkeypatch.setattr(PicoDomeHandler, "scan_slots", None)
    return backing


def _new_handler(token: str | None):
    handler = PicoDomeHandler.__new__(PicoDomeHandler)
    handler.headers = {"Authorization": f"Bearer {token}"} if token else {}
    handler._send_json = MagicMock()
    handler._send_error = MagicMock()
    return handler


def _fake_sandbox_run(stdout: str, rule_ids: list[str]):
    """sandbox_run stand-in returning a result with the given events."""
    from picosentry.sandbox.l3.engine import SandboxResult
    from picosentry.sandbox.l3.models import SandboxEvent, Verdict

    events = [SandboxEvent(rule_id=rid, verdict=Verdict.DENY, operation="pattern", detail=rid) for rid in rule_ids]
    return SandboxResult(
        command=["cat", "~/.ssh/id_ed25519"],
        overall_verdict=Verdict.DENY,
        exit_code=0,
        duration_ms=5,
        events=events,
        policy_name="default",
        backend_name="subprocess",
        stdout=stdout,
        stderr="",
    )


def _submit(handler: PicoDomeHandler, monkeypatch, rule_ids: list[str] | None = None) -> None:
    import picosentry.sandbox.daemon.handler_routes_post as post_mod

    stdout = "-----BEGIN OPENSSH PRIVATE KEY-----\nfakekeymaterial\n-----END-----"
    monkeypatch.setattr(post_mod, "sandbox_run", lambda **kw: _fake_sandbox_run(stdout, rule_ids or []))

    body = json.dumps({"command": ["cat", "keyfile"]})
    handler.headers["Content-Type"] = "application/json"
    handler.headers["Content-Length"] = str(len(body))
    handler.rfile = io.BytesIO(body.encode())
    handler._handle_submit_scan(TOKEN_A)


def _returned_result(handler) -> dict:
    assert handler._send_json.called
    return handler._send_json.call_args[0][0]


class TestCrossTenantDaemonAccess:
    def test_beta_token_cannot_read_alpha_job_or_stdout(self, tmp_path, monkeypatch):
        backing = _make_tenant_handler(tmp_path, monkeypatch)

        handler_a = _new_handler(TOKEN_A)
        _submit(handler_a, monkeypatch, rule_ids=["L3-SUS-001"])
        job_id = _returned_result(handler_a)["job_id"]
        assert backing.get(job_id)["tenant_id"] == "alpha"

        # Beta asks for alpha's job → not found (existence not leaked).
        handler_b = _new_handler(TOKEN_B)
        handler_b._handle_get_scan(job_id)
        handler_b._send_error.assert_called_once()
        assert handler_b._send_json.call_count == 0

    def test_beta_list_excludes_alpha_jobs(self, tmp_path, monkeypatch):
        _make_tenant_handler(tmp_path, monkeypatch)
        handler_a = _new_handler(TOKEN_A)
        _submit(handler_a, monkeypatch)

        handler_b = _new_handler(TOKEN_B)
        handler_b._handle_list_scans({})
        data = handler_b._send_json.call_args[0][0]
        assert data["count"] == 0

        handler_a2 = _new_handler(TOKEN_A)
        handler_a2._handle_list_scans({})
        data_a = handler_a2._send_json.call_args[0][0]
        assert data_a["count"] == 1
        assert data_a["scans"][0]["tenant_id"] == "alpha"

    def test_alpha_token_can_read_own_job(self, tmp_path, monkeypatch):
        _make_tenant_handler(tmp_path, monkeypatch)
        handler_a = _new_handler(TOKEN_A)
        _submit(handler_a, monkeypatch, rule_ids=["L3-SUS-001"])
        job_id = _returned_result(handler_a)["job_id"]

        reader = _new_handler(TOKEN_A)
        reader._handle_get_scan(job_id)
        reader._send_json.assert_called_once()
        assert reader._send_json.call_args[0][0]["job_id"] == job_id


class TestExfiltratedSecretsNotReturned:
    """Premise note (verified 2026-08-17): SandboxResult.to_dict() omits
    stdout/stderr entirely, so raw exfiltrated bytes never reached callers —
    that half of the WO is RESOLVED-PREEXISTING. The redaction layer kept
    here is a regression guard: if to_dict ever grows stdout, the SUS-003/
    008/009 intercept withholds it, and callers always get the explicit
    output_redacted flag when exfiltration was detected."""

    def test_sus009_hit_flags_and_withholds(self, tmp_path, monkeypatch):
        backing = _make_tenant_handler(tmp_path, monkeypatch)
        handler = _new_handler(TOKEN_A)
        _submit(handler, monkeypatch, rule_ids=["L3-SUS-009"])

        result = _returned_result(handler)
        sandbox_dict = result["sandbox"]
        assert "fakekeymaterial" not in json.dumps(result)
        assert result["output_redacted"] is True
        assert sandbox_dict["stdout_redacted"] is True
        # The stored job must be clean too.
        job_id = result["job_id"]
        assert "fakekeymaterial" not in json.dumps(backing.get(job_id))

    def test_redaction_intercepts_stdout_if_ever_exposed(self):
        """If to_dict starts exposing stdout (future regression), the
        redaction layer still withholds it — marker + sha256 + len."""
        from picosentry.sandbox.daemon.redaction import redact_sandbox_output
        from picosentry.sandbox.l3.models import SandboxEvent, Verdict

        key_material = "-----BEGIN OPENSSH PRIVATE KEY-----\nfakekeymaterial\n-----END-----"
        event = SandboxEvent(rule_id="L3-SUS-009", verdict=Verdict.DENY, operation="op", detail="d")
        d = redact_sandbox_output({"stdout": key_material, "stderr": ""}, [event])
        assert d["stdout"] != key_material
        assert "fakekeymaterial" not in d["stdout"]
        assert d["stdout_sha256"] == hashlib.sha256(key_material.encode()).hexdigest()
        assert d["stdout_len"] == len(key_material)

    @pytest.mark.parametrize("rule", ["L3-SUS-003", "L3-SUS-008"])
    def test_sus003_and_008_also_flag(self, tmp_path, monkeypatch, rule):
        _make_tenant_handler(tmp_path, monkeypatch)
        handler = _new_handler(TOKEN_A)
        _submit(handler, monkeypatch, rule_ids=[rule])
        result = _returned_result(handler)
        assert result["output_redacted"] is True
        assert "fakekeymaterial" not in json.dumps(result)

    def test_no_flag_without_secret_hit(self, tmp_path, monkeypatch):
        """Non-exfiltration findings must not set the redaction flag (honest)."""
        _make_tenant_handler(tmp_path, monkeypatch)
        handler = _new_handler(TOKEN_A)
        _submit(handler, monkeypatch, rule_ids=["L3-SUS-001"])
        result = _returned_result(handler)
        assert result["output_redacted"] is False
        # Pre-existing contract: stdout is not exposed at all.
        assert "stdout" not in result["sandbox"]

    def test_retention_copy_is_redacted(self, tmp_path, monkeypatch):
        """The retention blob is built from the same redacted result dict."""
        import picosentry.sandbox.daemon.handler_routes_post as post_mod

        _make_tenant_handler(tmp_path, monkeypatch)
        saved: list[str] = []

        class _Retention:
            def save_scan_result(self, blob, package_name="unknown"):
                saved.append(blob)

        monkeypatch.setattr(post_mod, "get_retention_manager", lambda: _Retention())
        handler = _new_handler(TOKEN_A)
        _submit(handler, monkeypatch, rule_ids=["L3-SUS-009"])
        assert saved and "fakekeymaterial" not in saved[0]


class TestRedactionUnit:
    def test_redact_sandbox_output_noop_on_clean(self):
        from picosentry.sandbox.daemon.redaction import redact_sandbox_output

        d = {"stdout": "ok", "stderr": ""}
        out = redact_sandbox_output(d, [])
        assert out is d
        assert d["stdout"] == "ok"

    def test_redact_handles_missing_keys(self):
        from picosentry.sandbox.daemon.redaction import redact_sandbox_output
        from picosentry.sandbox.l3.models import SandboxEvent, Verdict

        event = SandboxEvent(rule_id="L3-SUS-003", verdict=Verdict.DENY, operation="op", detail="d")
        d = redact_sandbox_output({}, [event])
        assert d["stdout_redacted"] is True and d["stderr_redacted"] is True
