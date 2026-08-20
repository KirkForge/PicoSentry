"""WO5.0.0-002 — untrusted-input hardening.

- NaN/±Inf `timeout` rejected cleanly at ALL entry points (HTTP 400 via the
  real daemon, gRPC INVALID_ARGUMENT, sandbox_run ValueError) — no orphaned
  child, no ValueError escape from selectors.
- retention: traversal `package_name` (command[0]) confined to a slug inside
  the scans dir.
- policy names: all-dot components (".", "..") rejected.
- X-Request-ID restricted to [A-Za-z0-9_-]: folded/obs-fold header values are
  never reflected.
"""

from __future__ import annotations

import http.client
import json
import socket
import time
from unittest.mock import MagicMock

import pytest

import picosentry.sandbox.audit.logger as audit_logger_mod
import picosentry.sandbox.daemon.handler_routes_post as handler_routes_post
import picosentry.sandbox.retention.manager as retention_mod
from picosentry.sandbox.audit import AuditLogger
from picosentry.sandbox.daemon.server import PicoDomeDaemon
from picosentry.sandbox.tenant import reset_tenant_registry

TOKEN = "picodome-admin-input-hardening-token-01"


@pytest.fixture(autouse=True)
def _clean_singletons():
    original_audit = audit_logger_mod._audit_logger
    original_retention = retention_mod._retention_manager
    from picosentry.sandbox.daemon.handler import PicoDomeHandler

    saved = (PicoDomeHandler.scan_executor, PicoDomeHandler.scan_slots)
    yield
    PicoDomeHandler.scan_executor, PicoDomeHandler.scan_slots = saved
    audit_logger_mod._audit_logger = original_audit
    retention_mod._retention_manager = original_retention
    reset_tenant_registry()


def _free_port() -> int:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def _http(port: int, method: str, path: str, raw_body: str | None = None, token: str | None = None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    conn.request(method, path, body=raw_body, headers=headers)
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


class _FakeScanResult:
    overall_verdict = type("V", (), {"value": "ALLOW"})()
    exit_code = 0
    duration_ms = 1
    backend_name = "test"
    isolation_level = "test"
    enforcement_guarantee = "best-effort"
    degraded = False

    def to_dict(self, deterministic=False):
        return {"verdict": "ALLOW"}


@pytest.fixture()
def engine_canary(monkeypatch):
    """Fake engine that records any invocation — 'child spawned' analog."""
    calls: list[dict] = []

    def _scan(**kwargs):
        calls.append(kwargs)
        return _FakeScanResult()

    monkeypatch.setattr(handler_routes_post, "sandbox_run", _scan)
    monkeypatch.setattr(handler_routes_post, "profile_from_sandbox_result", lambda sr: object())
    monkeypatch.setattr(handler_routes_post, "create_default_engine", lambda: MagicMock())
    return calls


def _boot(monkeypatch, tmp_path) -> int:
    audit_logger_mod._audit_logger = AuditLogger(log_dir=tmp_path / "audit", max_bytes=1024 * 1024)
    port = _free_port()
    monkeypatch.setenv("PICODOME_JOB_STORE_DIR", str(tmp_path / "jobs"))
    monkeypatch.setenv("PICODOME_API_TOKENS", TOKEN)
    monkeypatch.setenv("PICODOME_RATE_PER_SECOND", "50")
    monkeypatch.setenv("PICODOME_RETENTION_INTERVAL_SECONDS", "0")
    daemon = PicoDomeDaemon(host="127.0.0.1", port=port)
    daemon.start(background=True)
    _wait_healthy(port)
    return port


# ─── NaN / ±Inf timeout ──────────────────────────────────────────────────────


class TestNonFiniteTimeout:
    @pytest.mark.parametrize(
        "raw",
        [
            '{"command": ["echo", "x"], "timeout": NaN}',
            '{"command": ["echo", "x"], "timeout": Infinity}',
            '{"command": ["echo", "x"], "timeout": -Infinity}',
        ],
    )
    def test_http_rejects_non_finite_timeout(self, tmp_path, monkeypatch, engine_canary, raw):
        """NaN/±Inf via the REAL daemon: clean 400, engine never invoked, no job persisted."""
        port = _boot(monkeypatch, tmp_path)
        status, body = _http(port, "POST", "/api/v1/scan", raw_body=raw, token=TOKEN)
        assert status == 400, body
        assert body.get("code") == "INVALID_TIMEOUT"
        assert engine_canary == []

        _, listing = _http(port, "GET", "/api/v1/scans", token=TOKEN)
        assert listing["count"] == 0

    def test_http_rejects_garbage_timeout(self, tmp_path, monkeypatch, engine_canary):
        port = _boot(monkeypatch, tmp_path)
        status, body = _http(
            port, "POST", "/api/v1/scan", raw_body='{"command": ["echo", "x"], "timeout": "banana"}', token=TOKEN
        )
        assert status == 400, body
        assert engine_canary == []

    def test_grpc_rejects_non_finite_timeout(self):
        from picosentry.sandbox.grpc_transport._servicer import PicoDomeServicer
        from picosentry.sandbox.grpc_transport.server import _ScanEngine

        calls: list[dict] = []

        def _scan(**kwargs):
            calls.append(kwargs)
            return _FakeScanResult()

        engine = _ScanEngine(scan_fn=_scan, analyze_fn=lambda sr, **kw: MagicMock())
        servicer = PicoDomeServicer(scan_engine=engine, start_time=time.time(), scan_count_ref=MagicMock())

        request = MagicMock()
        request.command = ["echo", "x"]
        request.policy = ""
        request.cwd = ""
        request.timeout = float("nan")

        context = MagicMock()
        context.is_active.return_value = False
        servicer.Scan(request, context)
        assert context.abort.called
        assert context.abort.call_args[0][0].name == "INVALID_ARGUMENT"
        assert calls == []

    def test_sandbox_run_rejects_non_finite_before_backend(self, monkeypatch):
        import picosentry.sandbox.l3.engine as engine_mod

        spawned: list[dict] = []
        monkeypatch.setattr(engine_mod, "run_session", lambda **kw: spawned.append(kw))
        for bad in (float("nan"), float("inf"), float("-inf")):
            with pytest.raises(ValueError, match="finite"):
                engine_mod.sandbox_run(["echo", "x"], timeout=bad)
        assert spawned == []

    def test_valid_timeout_still_clamped(self):
        from picosentry.sandbox.daemon.constants import sanitize_scan_timeout

        assert sanitize_scan_timeout(30) == 30.0
        assert sanitize_scan_timeout(10**9) <= 300.0
        assert sanitize_scan_timeout("60") == 60.0
        assert sanitize_scan_timeout(float("nan")) is None
        assert sanitize_scan_timeout("junk") is None
        assert sanitize_scan_timeout(None) is None

    def test_negative_timeout_rejected(self):
        """WO6.0.0-018: a negative finite timeout used to pass through clamped
        to min(neg, 300)=neg — the landlock deadline was instantly past,
        producing an honest KILL that should have been a 400 at the boundary."""
        from picosentry.sandbox.daemon.constants import sanitize_scan_timeout

        assert sanitize_scan_timeout(-1) is None
        assert sanitize_scan_timeout(-0.001) is None
        assert sanitize_scan_timeout(-300) is None
        # Zero is a valid (if useless) timeout — keep it.
        assert sanitize_scan_timeout(0) == 0.0


# ─── Retention traversal ──────────────────────────────────────────────────────


class TestRetentionTraversal:
    def test_manager_confines_traversal_names(self, tmp_path):
        from picosentry.sandbox.retention.manager import RetentionManager

        rm = RetentionManager(data_dir=tmp_path / "data")
        for evil in ("../../sensitive/evil", "..", ".", "/etc/evil", "a/../b"):
            path = rm.save_scan_result("{}", package_name=evil)
            assert path.parent == tmp_path / "data" / "scans"
        assert not (tmp_path / "sensitive").exists()
        assert not (tmp_path / "etc").exists()
        names = [p.name for p in (tmp_path / "data" / "scans").iterdir()]
        assert all("/" not in n and ".." not in n for n in names)

    def test_daemon_traversal_command_writes_inside_scans_dir(self, tmp_path, monkeypatch, engine_canary):
        """command[0] = '../../<tmp>/outside' — retention must not escape."""
        from picosentry.sandbox.retention.manager import RetentionManager

        data_dir = tmp_path / "data"
        retention_mod._retention_manager = RetentionManager(data_dir=data_dir)
        port = _boot(monkeypatch, tmp_path)

        evil = f"../../{tmp_path.name}/outside"
        status, _ = _http(port, "POST", "/api/v1/scan", raw_body=json.dumps({"command": [evil, "arg"]}), token=TOKEN)
        assert status == 201
        assert engine_canary, "scan never ran"

        scans = data_dir / "scans"
        assert scans.is_dir()
        outside = list((tmp_path / "outside").glob("*.json")) if (tmp_path / "outside").exists() else []
        assert outside == []
        files = list(scans.glob("*.json"))
        assert files, "retention wrote nothing"
        for f in files:
            assert f.parent == scans


# ─── Policy names ─────────────────────────────────────────────────────────────


class TestPolicyDotNames:
    @pytest.mark.parametrize("bad", ["", ".", "..", "..."])
    def test_store_rejects_all_dot_names(self, tmp_path, bad):
        from picosentry.sandbox.l3.models import Policy
        from picosentry.sandbox.policy_versioned.store import VersionedPolicyStore

        store = VersionedPolicyStore(store_dir=tmp_path / "policies")
        policy = Policy(name=bad, version="1.0")
        with pytest.raises(ValueError):
            store.save(policy, author="test")
        # Nothing was written at the store root
        assert sorted(p.name for p in (tmp_path / "policies").iterdir()) == []

    def test_load_policy_rejects_dot_names(self):
        from picosentry.sandbox.l3.policy import load_policy

        with pytest.raises(ValueError):
            load_policy(name=".")
        with pytest.raises(ValueError):
            load_policy(name="..")


# ─── X-Request-ID charset ─────────────────────────────────────────────────────


class TestRequestIDCharset:
    def test_unit_folds_and_junk_rejected(self):
        from picosentry.sandbox.daemon.handler import PicoDomeHandler

        def _gen(value: str) -> str:
            handler = PicoDomeHandler.__new__(PicoDomeHandler)
            handler.headers = {"X-Request-ID": value}
            return handler._generate_request_id()

        folded = "legit\n\tEvil-Header: injected-value"
        assert _gen(folded).startswith("picodome-")
        assert _gen("legit\r\nEvil: x").startswith("picodome-")
        assert _gen("spaces in id").startswith("picodome-")
        assert _gen("x" * 129).startswith("picodome-")
        assert _gen("good-id_123") == "good-id_123"

    def test_daemon_never_reflects_folded_header(self, tmp_path, monkeypatch):
        """The injection repro: obs-fold X-Request-ID must not come back."""
        port = _boot(monkeypatch, tmp_path)
        raw = (
            b"GET /health HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"X-Request-ID: legit\r\n\tEvil-Header: injected-value\r\n"
            b"Connection: close\r\n\r\n"
        )
        with socket.create_connection(("127.0.0.1", port), timeout=5) as sock:
            sock.sendall(raw)
            chunks = []
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                chunks.append(chunk)
        response = b"".join(chunks)
        assert b"Evil-Header" not in response, response[:400]
        assert b"X-Request-ID: picodome-" in response, response[:400]
