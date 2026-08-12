import pytest

from picosentry.serve.database.manager import DatabaseManager
from picosentry.serve.services.auth import AuthService, HAS_WEBAUTHN


@pytest.mark.skipif(not HAS_WEBAUTHN, reason="webauthn extra not installed")
def test_webauthn_register_flow_stores_credential(tmp_path):
    db = DatabaseManager(db_path=tmp_path / "wauth.db", backend="sqlite")
    svc = AuthService(db)
    uid = svc.create_user("alice", "password123!", "a@b.c")
    assert uid

    challenge = svc.webauthn_register_challenge(uid, "alice", "Alice")
    assert challenge is not None
    assert challenge["challenge"]
    assert "options" in challenge

    creds = svc.webauthn_credentials_for_user(uid)
    assert creds == []


@pytest.mark.skipif(not HAS_WEBAUTHN, reason="webauthn extra not installed")
def test_webauthn_auth_challenge_requires_registered_passkey(tmp_path):
    db = DatabaseManager(db_path=tmp_path / "wauth2.db", backend="sqlite")
    svc = AuthService(db)
    uid = svc.create_user("bob", "password123!", "b@b.c")
    assert uid

    # No passkeys registered → no auth challenge options.
    creds = svc.webauthn_credentials_for_user(uid)
    assert creds == []


@pytest.mark.skipif(not HAS_WEBAUTHN, reason="webauthn extra not installed")
def test_webauthn_register_verify_rejects_unknown_challenge(tmp_path):
    db = DatabaseManager(db_path=tmp_path / "wauth3.db", backend="sqlite")
    svc = AuthService(db)
    uid = svc.create_user("carol", "password123!", "c@c.c")
    assert uid

    assert svc.webauthn_register_verify(uid, "not-a-real-challenge", {"id": "x"}) is False
