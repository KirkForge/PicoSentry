"""Policy-name path traversal — WO4.0.0-002.

The versioned policy store's read path always validated names; save() used to
mkdir/write under caller-controlled paths. These tests pin the fixed behavior
on both the store and the HTTP routes.
"""

from __future__ import annotations

import io
import json
from unittest.mock import MagicMock

import pytest

from picosentry.sandbox.policy_versioned.store import VersionedPolicyStore


def _policy(name: str):
    from picosentry.sandbox.l3.models import Policy

    return Policy(name=name, version="1.0")


class TestStoreTraversal:
    def test_save_rejects_dotdot(self, tmp_path):
        store = VersionedPolicyStore(store_dir=tmp_path)
        with pytest.raises(ValueError, match="Invalid policy name"):
            store.save(_policy("../escape"), author="tester")

    def test_save_rejects_path_separators(self, tmp_path):
        store = VersionedPolicyStore(store_dir=tmp_path)
        with pytest.raises(ValueError):
            store.save(_policy("nested/name"), author="tester")
        with pytest.raises(ValueError):
            store.save(_policy("win\\path"), author="tester")

    def test_save_rejects_empty_name(self, tmp_path):
        store = VersionedPolicyStore(store_dir=tmp_path)
        with pytest.raises(ValueError):
            store.save(_policy(""), author="tester")

    def test_nothing_written_outside_store(self, tmp_path):
        store = VersionedPolicyStore(store_dir=tmp_path)
        before = {p.name for p in tmp_path.parent.iterdir()}
        for bad in ("../escape", "..", "a/../b"):
            with pytest.raises(ValueError):
                store.save(_policy(bad), author="tester")
        after = {p.name for p in tmp_path.parent.iterdir()}
        assert before == after, f"traversal created entries outside the store: {after - before}"

    def test_load_rejects_traversal(self, tmp_path):
        store = VersionedPolicyStore(store_dir=tmp_path)
        with pytest.raises(ValueError):
            store.load("../../etc/passwd")
        with pytest.raises(ValueError):
            store.load("nested/name")

    def test_list_versions_rejects_traversal(self, tmp_path):
        store = VersionedPolicyStore(store_dir=tmp_path)
        with pytest.raises(ValueError):
            store.list_versions("../secret")

    def test_legitimate_save_still_works(self, tmp_path):
        store = VersionedPolicyStore(store_dir=tmp_path)
        pv = store.save(_policy("normal-policy"), author="tester")
        assert pv.version == 1
        assert (tmp_path / "normal-policy" / "v1.json").is_file()
        loaded = store.load("normal-policy")
        assert loaded is not None and loaded.policy.name == "normal-policy"


class TestHTTPRouteTraversal:
    """POST /policies and GET /policies/{name} must reject traversal names."""

    @pytest.fixture()
    def handler(self, tmp_path, monkeypatch):
        import picosentry.sandbox.audit.logger as audit_logger_mod
        from picosentry.sandbox.audit import AuditLogger
        from picosentry.sandbox.daemon.handler import PicoDomeHandler

        audit_logger_mod._audit_logger = AuditLogger(log_dir=tmp_path / "audit", max_bytes=1024 * 1024)
        monkeypatch.setenv("PICODOME_POLICY_STORE_DIR", str(tmp_path / "policies"))
        monkeypatch.setattr("picosentry.sandbox.policy_versioned.store._policy_store", None, raising=False)

        h = PicoDomeHandler.__new__(PicoDomeHandler)
        h._send_error = MagicMock()
        h._send_json = MagicMock()
        h.headers = {}
        yield h
        from picosentry.sandbox.policy_versioned import store as store_mod

        store_mod._policy_store = None

    def _post_policy(self, handler, body: dict):
        payload = json.dumps(body)
        handler.headers = {"Content-Type": "application/json", "Content-Length": str(len(payload))}
        handler.rfile = io.BytesIO(payload.encode())
        handler._handle_create_policy("test-token")

    def test_create_policy_traversal_rejected(self, handler, tmp_path):
        self._post_policy(handler, {"name": "../evil", "rules": []})
        handler._send_error.assert_called_once()
        assert handler._send_error.call_args[0][0].status == 400
        assert not (tmp_path.parent / "evil").exists()

    def test_create_policy_nested_path_rejected(self, handler, tmp_path):
        self._post_policy(handler, {"name": "a/b", "rules": []})
        handler._send_error.assert_called_once()
        assert not (tmp_path / "policies" / "a").exists()

    def test_get_policy_traversal_rejected(self, handler):
        handler._handle_get_policy("../../etc/passwd")
        handler._send_error.assert_called_once()
        assert handler._send_error.call_args[0][0].status == 400

    def test_create_policy_valid_name_accepted(self, handler):
        self._post_policy(handler, {"name": "legit", "rules": []})
        handler._send_json.assert_called_once()
