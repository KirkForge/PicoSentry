"""AuthService security regressions: TOTP replay, password re-verify, revocation purge."""

import time
from datetime import datetime, timedelta, timezone

import pyotp
import pytest

from picosentry.serve.database.manager import DatabaseManager
from picosentry.serve.services.auth import AuthService


@pytest.fixture
def svc(tmp_path):
    db = DatabaseManager(db_path=tmp_path / "authsvc.db", backend="sqlite")
    yield AuthService(db)
    db.close()


PASSWORD = "correct-horse-battery-staple"


def _enrolled_user(svc: AuthService) -> tuple[int, str]:
    user_id = svc.create_user("alice", PASSWORD, "a@b.c")
    assert user_id
    enrolled = svc.enroll_totp(user_id, "alice")
    assert enrolled and enrolled["secret"]
    return user_id, enrolled["secret"]


class TestTotpReplay:
    def test_same_code_accepted_once_rejected_immediately_after(self, svc):
        _, secret = _enrolled_user(svc)
        code = pyotp.TOTP(secret).now()
        assert svc.verify_totp(secret, code) is True
        assert svc.verify_totp_for_user(1, code) is True
        assert svc.verify_totp_for_user(1, code) is False

    def test_login_accepts_code_once_then_demands_mfa_on_replay(self, svc):
        _, secret = _enrolled_user(svc)
        code = pyotp.TOTP(secret).now()
        ok = svc.login("alice", PASSWORD, totp_code=code)
        assert ok["status"] == "ok"
        replay = svc.login("alice", PASSWORD, totp_code=code)
        assert replay["status"] == "mfa_required"

    def test_previous_step_code_accepted_within_drift_window(self, svc):
        user_id, secret = _enrolled_user(svc)
        totp = pyotp.TOTP(secret)
        stale = totp.generate_otp(int(time.time() // 30) - 1)
        assert svc.verify_totp_for_user(user_id, stale) is True
        # Same timestep again is still a replay.
        assert svc.verify_totp_for_user(user_id, stale) is False

    def test_last_timestep_persisted_per_user(self, svc):
        user_id, secret = _enrolled_user(svc)
        code = pyotp.TOTP(secret).now()
        svc.verify_totp_for_user(user_id, code)
        row = svc._db.execute_one("SELECT totp_last_timestep FROM users WHERE id = ?", (user_id,))
        assert row["totp_last_timestep"] == int(time.time() // 30)


class TestPasswordReverify:
    def test_correct_password(self, svc):
        user_id, _ = _enrolled_user(svc)
        assert svc.verify_user_password(user_id, PASSWORD) is True

    def test_wrong_password(self, svc):
        user_id, _ = _enrolled_user(svc)
        assert svc.verify_user_password(user_id, "wrong-password") is False

    def test_unknown_user(self, svc):
        assert svc.verify_user_password(99999, PASSWORD) is False

    def test_get_totp_secret(self, svc):
        user_id, secret = _enrolled_user(svc)
        assert svc.get_totp_secret(user_id) == secret
        assert svc.get_totp_secret(99999) is None


class TestRevocationPurge:
    def test_purge_deletes_only_expired_rows(self, svc):
        user_id, _ = _enrolled_user(svc)
        old_cutoff = (datetime.now(timezone.utc) - timedelta(hours=svc.expiration_hours + 1)).strftime(
            "%Y-%m-%d %H:%M:%S"
        )
        svc._db.execute_insert(
            "INSERT INTO revoked_tokens (jti, user_id, revoked_at) VALUES (?, ?, ?)",
            ("old-jti", user_id, old_cutoff),
        )
        svc._db.execute_insert("INSERT INTO revoked_tokens (jti, user_id) VALUES (?, ?)", ("fresh-jti", user_id))

        purged = svc.purge_expired_revocations()
        assert purged == 1
        assert svc.is_token_revoked("old-jti") is False
        assert svc.is_token_revoked("fresh-jti") is True

    def test_purge_on_empty_table(self, svc):
        assert svc.purge_expired_revocations() == 0

    def test_revoke_token_binding(self, svc):
        user_id, _ = _enrolled_user(svc)
        assert svc.revoke_token("jti-a", user_id) is True
        assert svc.revoke_token("jti-a", user_id) is False
