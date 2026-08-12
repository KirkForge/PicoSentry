import hashlib
import hmac
import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any, ClassVar

try:
    import jwt

    HAS_JWT = True
except ImportError:
    HAS_JWT = False

try:
    import bcrypt

    HAS_BCRYPT = True
except ImportError:
    HAS_BCRYPT = False

try:
    import pyotp

    HAS_PYOTP = True
except ImportError:
    HAS_PYOTP = False

try:
    import webauthn
    from webauthn.helpers import base64url_to_bytes, bytes_to_base64url, generate_challenge, options_to_json
    from webauthn.helpers.structs import (
        AttestationConveyancePreference,
        AuthenticatorSelectionCriteria,
        PublicKeyCredentialDescriptor,
        PublicKeyCredentialType,
        ResidentKeyRequirement,
        UserVerificationRequirement,
    )

    HAS_WEBAUTHN = True
except ImportError:
    HAS_WEBAUTHN = False

from picosentry.serve.config.settings import settings
from picosentry.serve.database.manager import DatabaseManager, db as _default_db

logger = logging.getLogger("picoshogun.Auth")


class AuthService:
    """Manages user authentication, JWT token generation, and API key lifecycle."""

    # Defense-in-depth: refuse to instantiate the auth service with a secret
    # key that is empty, a known placeholder, or too short to resist brute
    # force.  assert_secure() is the startup gate; this check protects tests
    # and any code path that builds AuthService before that gate has run.
    _WEAK_SECRET_DENYLIST = frozenset(
        {
            "",
            "change-me-in-production",
            "changeme",
            "default",
            "secret",
            "password",
            "please-change-me",
            "your-secret-key",
            "your-secret-key-here",
        }
    )
    _MIN_SECRET_KEY_LENGTH = 32

    def __init__(self, db: DatabaseManager | None = None):
        self._db_override = db
        self.secret_key = settings.security.secret_key
        self.algorithm = settings.security.jwt_algorithm
        self.expiration_hours = settings.security.jwt_expiration_hours

        if os.environ.get("ALLOW_INSECURE_SECRET", "").lower() not in ("true", "1", "yes"):
            if self.secret_key in self._WEAK_SECRET_DENYLIST:
                raise ValueError(
                    "AuthService: secret key is empty or uses a well-known placeholder. "
                    "Set PICOSHOGUN_SECRET_KEY or ALLOW_INSECURE_SECRET=true for local dev only."
                )
            if len(self.secret_key) < self._MIN_SECRET_KEY_LENGTH:
                raise ValueError(
                    f"AuthService: secret key is {len(self.secret_key)} bytes; "
                    f"minimum is {self._MIN_SECRET_KEY_LENGTH}."
                )

    @property
    def _db(self) -> DatabaseManager:
        return self._db_override if self._db_override is not None else _default_db

    def _hash_password(self, password: str) -> str:
        if HAS_BCRYPT:
            rounds = settings.security.password_hash_rounds
            return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=rounds)).decode()

        salt = secrets.token_hex(32)
        hashed = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
        return f"pbkdf2:{salt}:{hashed.hex()}"

    def _verify_password(self, password: str, hashed: str) -> bool:
        if HAS_BCRYPT and not hashed.startswith("pbkdf2:"):
            return bcrypt.checkpw(password.encode(), hashed.encode())

        if hashed.startswith("pbkdf2:"):
            _, salt, hash_value = hashed.split(":")
            check = hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), 100000)
            return hmac.compare_digest(check.hex(), hash_value)

        return False

    def _normalize_username(self, username: str) -> str:
        return username.strip().casefold()

    def get_user_id_by_username(self, username: str) -> int | None:
        user = self._db.execute_one(
            "SELECT id FROM users WHERE username = ? AND is_active = 1", (self._normalize_username(username),)
        )
        return user["id"] if user else None

    def authenticate(self, username: str, password: str) -> str | None:
        result = self.login(username, password)
        return result.get("token")

    def login(
        self, username: str, password: str, totp_code: str | None = None, mfa_verified: bool = False
    ) -> dict[str, Any]:
        """Authenticate a user, returning a structured status.

        Statuses:
          - ``ok``: credentials valid (and TOTP verified if enabled) — ``token`` set
          - ``mfa_required``: password valid, TOTP enabled, no/invalid code supplied
          - ``invalid``: bad credentials
          - ``locked``: account is locked out

        ``mfa_verified`` is an internal escape hatch used only after a
        WebAuthn assertion has been independently verified (the passkey is
        the second factor).  It skips the MFA gate so a second-factor-proof
        caller can receive the token without re-entering a TOTP code.
        """
        normalized = self._normalize_username(username)
        now = datetime.now(timezone.utc)

        with self._db.transaction() as conn:
            cursor = conn.execute("SELECT * FROM users WHERE username = ? AND is_active = 1", (normalized,))
            row = cursor.fetchone()
            if isinstance(row, dict):
                user = row
            elif row:
                cols = [desc[0] for desc in cursor.description]
                user = dict(zip(cols, row, strict=False))
            else:
                user = None

            if not user:
                logger.warning("Auth failed: invalid credentials")
                return {"status": "invalid"}

            locked_until = user.get("locked_until")
            if locked_until:
                if isinstance(locked_until, str):
                    locked_until = datetime.fromisoformat(locked_until)
                if locked_until > now:
                    logger.warning("Auth failed: account %s locked until %s", normalized, locked_until)
                    return {"status": "locked"}

            if not self._verify_password(password, user["password_hash"]):
                self._record_failed_login(conn, user, now)
                logger.warning("Auth failed: invalid credentials")
                return {"status": "invalid"}

            # Password is correct — reset the failure counter.
            conn.execute("UPDATE users SET failed_login_attempts = 0, locked_until = NULL WHERE id = ?", (user["id"],))

            totp_secret = user.get("totp_secret")
            if not mfa_verified:
                has_webauthn = bool(self.webauthn_credentials_for_user(user["id"]))
                if totp_secret and not (totp_code and self.verify_totp(totp_secret, totp_code)):
                    methods = ["totp"] + (["webauthn"] if has_webauthn else [])
                    logger.info("User %s requires MFA", normalized)
                    return {"status": "mfa_required", "mfa_methods": methods}
                if has_webauthn and not totp_secret:
                    logger.info("User %s requires WebAuthn MFA", normalized)
                    return {"status": "mfa_required", "mfa_methods": ["webauthn"]}

            conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (now, user["id"]))

        token = self._generate_token(user["id"], user["username"], user["role"])

        logger.info("User %s authenticated", user["username"])
        return {"status": "ok", "token": token, "user_id": user["id"], "role": user["role"]}

    def _record_failed_login(self, conn, user: dict[str, Any], now: datetime) -> None:
        attempts = int(user.get("failed_login_attempts") or 0) + 1
        max_attempts = settings.security.lockout_max_attempts
        if attempts >= max_attempts:
            locked_until = now + timedelta(minutes=settings.security.lockout_window_minutes)
            conn.execute(
                "UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?",
                (attempts, locked_until, user["id"]),
            )
            logger.warning(
                "Account %s locked until %s after %d failed attempts", user["username"], locked_until, attempts
            )
        else:
            conn.execute("UPDATE users SET failed_login_attempts = ? WHERE id = ?", (attempts, user["id"]))

    def _generate_token(self, user_id: int, username: str, role: str) -> str:
        if not HAS_JWT:
            raise RuntimeError("PyJWT is required for token generation. Install with: pip install PyJWT")

        payload = {
            "user_id": user_id,
            "username": username,
            "role": role,
            "jti": secrets.token_urlsafe(16),
            "exp": datetime.now(timezone.utc) + timedelta(hours=self.expiration_hours),
            "iat": datetime.now(timezone.utc),
        }

        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def validate_token(self, token: str) -> dict[str, Any] | None:
        if token.startswith("simple:"):
            logger.warning("Rejected legacy simple-token format. Migrate to JWT.")
            return None

        if not HAS_JWT:
            logger.error("PyJWT not installed — cannot validate any tokens")
            return None

        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid token")
            return None

        jti = payload.get("jti")
        if jti and self.is_token_revoked(jti):
            logger.warning("Token revoked (jti %s)", jti)
            return None

        return {
            "id": payload["user_id"],
            "user_id": payload["user_id"],
            "username": payload["username"],
            "role": payload["role"],
            "jti": jti,
        }

    def revoke_token(self, jti: str, user_id: int | None = None) -> bool:
        """Revoke a JWT by its jti. Returns False if already revoked."""
        existing = self._db.execute_one("SELECT id FROM revoked_tokens WHERE jti = ?", (jti,))
        if existing:
            return False
        self._db.execute_insert("INSERT INTO revoked_tokens (jti, user_id) VALUES (?, ?)", (jti, user_id))
        logger.info("Token revoked (jti %s)", jti)
        return True

    def is_token_revoked(self, jti: str) -> bool:
        return self._db.execute_one("SELECT 1 FROM revoked_tokens WHERE jti = ?", (jti,)) is not None

    def enroll_totp(self, user_id: int, username: str) -> dict[str, str] | None:
        """Generate and store a TOTP secret for a user. Returns secret + otpauth URI."""
        if not HAS_PYOTP:
            logger.error("pyotp not installed — cannot enroll TOTP")
            return None
        secret = pyotp.random_base32()
        self._db.execute_insert("UPDATE users SET totp_secret = ? WHERE id = ?", (secret, user_id))
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name=username, issuer_name="PicoSentry")
        logger.info("TOTP enrolled for user %s", user_id)
        return {"secret": secret, "otpauth_uri": uri}

    def verify_totp(self, secret: str, code: str) -> bool:
        if not HAS_PYOTP:
            return False
        return pyotp.TOTP(secret).verify(code)

    def verify_totp_for_user(self, user_id: int, code: str) -> bool:
        user = self._db.execute_one("SELECT totp_secret FROM users WHERE id = ?", (user_id,))
        if not user or not user.get("totp_secret"):
            return False
        return self.verify_totp(user["totp_secret"], code)

    def webauthn_credentials_for_user(self, user_id: int) -> list[dict[str, Any]]:
        return self._db.execute(
            "SELECT id, credential_id, public_key, sign_count, created_at FROM webauthn_credentials WHERE user_id = ?",
            (user_id,),
        )

    def webauthn_register_challenge(self, user_id: int, username: str, display_name: str) -> dict[str, Any] | None:
        """Generate and persist a WebAuthn registration challenge. Returns the client options JSON."""
        if not HAS_WEBAUTHN:
            logger.error("webauthn not installed — cannot enroll passkey")
            return None
        user_handle = user_id.to_bytes(8, "big")
        options = webauthn.generate_registration_options(
            rp_id=settings.security.webauthn_rp_id,
            rp_name=settings.security.webauthn_rp_name,
            user_name=username,
            user_display_name=display_name,
            user_id=user_handle,
            attestation=AttestationConveyancePreference.NONE,
            authenticator_selection=AuthenticatorSelectionCriteria(
                resident_key=ResidentKeyRequirement.DISCOURAGED,
                user_verification=UserVerificationRequirement.DISCOURAGED,
            ),
        )
        challenge = bytes_to_base64url(options.challenge)
        self._db.execute_insert(
            "INSERT INTO webauthn_challenges (user_id, challenge, purpose) VALUES (?, ?, 'register')",
            (user_id, challenge),
        )
        logger.info("WebAuthn registration challenge issued for user %s", user_id)
        return {
            "challenge": challenge,
            "options": options_to_json(options),
        }

    def webauthn_register_verify(self, user_id: int, challenge: str, credential: dict[str, Any]) -> bool:
        """Verify a registration response and store the passkey credential."""
        if not HAS_WEBAUTHN:
            return False
        stored = self._db.execute_one(
            "SELECT challenge FROM webauthn_challenges WHERE user_id = ? AND challenge = ? AND purpose = 'register'"
            " ORDER BY created_at DESC LIMIT 1",
            (user_id, challenge),
        )
        if not stored:
            logger.warning("WebAuthn register verify: unknown challenge for user %s", user_id)
            return False
        self._db.execute_insert(
            "DELETE FROM webauthn_challenges WHERE user_id = ? AND purpose = 'register'", (user_id,)
        )
        try:
            verification = webauthn.verify_registration_response(
                credential=credential,
                expected_challenge=base64url_to_bytes(challenge),
                expected_rp_id=settings.security.webauthn_rp_id,
                expected_origin=settings.security.webauthn_origin,
            )
        except Exception:
            logger.exception("WebAuthn registration verification failed for user %s", user_id)
            return False
        self._db.execute_insert(
            "INSERT INTO webauthn_credentials (user_id, credential_id, public_key, sign_count) VALUES (?, ?, ?, ?)",
            (
                user_id,
                bytes_to_base64url(verification.credential_id),
                bytes_to_base64url(verification.credential_public_key),
                verification.sign_count,
            ),
        )
        logger.info("WebAuthn credential registered for user %s", user_id)
        return True

    def webauthn_auth_challenge(self, user_id: int) -> dict[str, Any] | None:
        """Generate a WebAuthn assertion challenge for a user's passkeys."""
        if not HAS_WEBAUTHN:
            return None
        creds = self._db.execute("SELECT credential_id FROM webauthn_credentials WHERE user_id = ?", (user_id,))
        allow = [
            PublicKeyCredentialDescriptor(
                type=PublicKeyCredentialType.PUBLIC_KEY,
                id=base64url_to_bytes(c["credential_id"]),
            )
            for c in creds
        ]
        options = webauthn.generate_authentication_options(
            rp_id=settings.security.webauthn_rp_id,
            challenge=generate_challenge(),
            allow_credentials=allow,
        )
        challenge = bytes_to_base64url(options.challenge)
        self._db.execute_insert(
            "INSERT INTO webauthn_challenges (user_id, challenge, purpose) VALUES (?, ?, 'authenticate')",
            (user_id, challenge),
        )
        logger.info("WebAuthn assertion challenge issued for user %s", user_id)
        return {
            "challenge": challenge,
            "options": options_to_json(options),
        }

    def webauthn_auth_verify(self, user_id: int, challenge: str, credential: dict[str, Any]) -> bool:
        """Verify a WebAuthn assertion against a stored passkey."""
        if not HAS_WEBAUTHN:
            return False
        stored = self._db.execute_one(
            "SELECT challenge FROM webauthn_challenges WHERE user_id = ? AND challenge = ? AND purpose = 'authenticate'"
            " ORDER BY created_at DESC LIMIT 1",
            (user_id, challenge),
        )
        if not stored:
            logger.warning("WebAuthn assertion verify: unknown challenge for user %s", user_id)
            return False
        self._db.execute_insert(
            "DELETE FROM webauthn_challenges WHERE user_id = ? AND purpose = 'authenticate'", (user_id,)
        )
        try:
            credential_id = credential["rawId"]
        except (KeyError, TypeError):
            logger.warning("WebAuthn assertion verify: missing rawId")
            return False
        stored_cred = self._db.execute_one(
            "SELECT credential_id, public_key, sign_count FROM webauthn_credentials WHERE user_id = ?",
            (user_id,),
        )
        if not stored_cred or stored_cred["credential_id"] != credential_id:
            logger.warning("WebAuthn assertion verify: unknown credential for user %s", user_id)
            return False
        try:
            verification = webauthn.verify_authentication_response(
                credential=credential,
                expected_challenge=base64url_to_bytes(challenge),
                expected_rp_id=settings.security.webauthn_rp_id,
                expected_origin=settings.security.webauthn_origin,
                credential_public_key=base64url_to_bytes(stored_cred["public_key"]),
                credential_current_sign_count=stored_cred["sign_count"],
            )
        except Exception:
            logger.exception("WebAuthn assertion verification failed for user %s", user_id)
            return False
        self._db.execute_insert(
            "UPDATE webauthn_credentials SET sign_count = ? WHERE user_id = ? AND credential_id = ?",
            (
                verification.new_sign_count,
                user_id,
                bytes_to_base64url(verification.credential_id),
            ),
        )
        logger.info("WebAuthn assertion verified for user %s", user_id)
        return True

    def create_user(self, username: str, password: str, email: str | None = None, role: str = "viewer") -> int | None:
        normalized = self._normalize_username(username)
        password_hash = self._hash_password(password)

        try:
            with self._db.transaction() as conn:
                cursor = conn.execute(
                    """
                    INSERT INTO users (username, password_hash, email, role)
                    VALUES (?, ?, ?, ?)
                """,
                    (normalized, password_hash, email, role),
                )
                user_id = cursor.lastrowid
        except Exception:
            return None

        logger.info("User created: %s (role: %s)", normalized, role)
        return user_id

    _API_KEY_PERMISSIONS: ClassVar[set[str]] = {"read", "write", "admin"}
    # A role-scoped key is enforced against the RBAC role matrix.  ``viewer``
    # is read-only; ``operator`` can run/mutate; ``admin`` is unrestricted.
    _API_KEY_ROLES: ClassVar[tuple[str, ...]] = ("viewer", "operator", "admin")

    def create_api_key(
        self,
        user_id: int,
        name: str,
        permissions: str = "read",
        role: str | None = None,
        org_id: int | None = None,
    ) -> str | None:
        allowed_permissions = self._API_KEY_PERMISSIONS
        requested = {p.strip() for p in permissions.split(",") if p.strip()}
        if not requested or not requested.issubset(allowed_permissions):
            logger.warning("API key create rejected: invalid permissions '%s'", permissions)
            return None

        # Resolve the RBAC role: an explicit role wins; otherwise derive it
        # from the legacy permissions set (read→viewer, write→operator,
        # admin→admin).  A key without a role defaults to read-only viewer so
        # a fresh key can never mint itself broader than its owner intends.
        if role is None:
            if "admin" in requested:
                role = "admin"
            elif "write" in requested:
                role = "operator"
            else:
                role = "viewer"
        if role not in self._API_KEY_ROLES:
            logger.warning("API key create rejected: invalid role '%s'", role)
            return None

        normalized = ",".join(sorted(requested))
        api_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        expires = datetime.now(timezone.utc) + timedelta(days=90)

        self._db.execute_insert(
            """
            INSERT INTO api_keys (key_hash, user_id, name, permissions, role, org_id, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """,
            (key_hash, user_id, name, normalized, role, org_id, expires),
        )

        logger.info("API key created for user %s: %s (role: %s)", user_id, name, role)
        return api_key

    def validate_api_key(self, api_key: str) -> dict[str, Any] | None:
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        key = self._db.execute_one(
            """
            SELECT ak.*, u.username, u.role
            FROM api_keys ak
            JOIN users u ON ak.user_id = u.id
            WHERE ak.key_hash = ? AND ak.is_active = 1 AND u.is_active = 1
            AND (ak.expires_at IS NULL OR ak.expires_at > ?)
        """,
            (key_hash, datetime.now(timezone.utc)),
        )

        if not key:
            return None

        # Constant-time comparison guards against timing attacks even
        # though the DB lookup already matched on key_hash.  In concurrent
        # scenarios where multiple keys share a prefix, this is defense-in-depth.
        if not hmac.compare_digest(key["key_hash"], key_hash):
            return None

        # Reject keys whose permissions are not a subset of the allowlist.
        # Guards against pre-existing rows with invalid permission strings.
        key_perms = {p.strip() for p in key["permissions"].split(",") if p.strip()}
        if not key_perms.issubset(self._API_KEY_PERMISSIONS):
            logger.warning("API key rejected: invalid stored permissions")
            return None

        # A scoped key's role is the single source of truth for RBAC.  Reject
        # any stored role outside the known matrix (same defense as above).
        key_role = key.get("role") or "viewer"
        if key_role not in self._API_KEY_ROLES:
            logger.warning("API key rejected: invalid stored role '%s'", key_role)
            return None

        self._db.execute_insert(
            "UPDATE api_keys SET last_used = ? WHERE id = ?", (datetime.now(timezone.utc), key["id"])
        )

        return {
            "id": key["id"],
            "key_id": key["id"],
            "user_id": key["user_id"],
            "username": key["username"],
            "role": key_role,
            "org_id": key.get("org_id"),
            "permissions": key["permissions"],
        }

    def revoke_api_key(self, key_id: int, user_id: int | None = None) -> bool:
        if user_id is not None:
            key = self._db.execute_one(
                "SELECT id FROM api_keys WHERE id = ? AND user_id = ? AND is_active = 1", (key_id, user_id)
            )
            if not key:
                return False
        with self._db.transaction() as conn:
            conn.execute(
                "UPDATE api_keys SET is_active = 0, revoked_at = ? WHERE id = ?", (datetime.now(timezone.utc), key_id)
            )
        return True

    def rotate_api_key(self, key_id: int, user_id: int) -> str | None:

        key = self._db.execute_one(
            "SELECT * FROM api_keys WHERE id = ? AND user_id = ? AND is_active = 1", (key_id, user_id)
        )
        if not key:
            return None

        new_api_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(new_api_key.encode()).hexdigest()
        expires = datetime.now(timezone.utc) + timedelta(days=90)

        with self._db.transaction() as conn:
            conn.execute(
                "UPDATE api_keys SET is_active = 0, revoked_at = ? WHERE id = ?", (datetime.now(timezone.utc), key_id)
            )
            conn.execute(
                """
                INSERT INTO api_keys (key_hash, user_id, name, permissions, role, org_id, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
                (
                    key_hash,
                    user_id,
                    key["name"] or "rotated-key",
                    key["permissions"] or "read",
                    key.get("role") or "viewer",
                    key.get("org_id"),
                    expires,
                ),
            )

        logger.info("API key rotated for user %s, key_id %s", user_id, key_id)
        return new_api_key

    def cleanup_expired_keys(self) -> int:
        now = datetime.now(timezone.utc)
        expired = self._db.execute(
            "SELECT id, name, user_id FROM api_keys WHERE is_active = 1 AND expires_at IS NOT NULL AND expires_at <= ?",
            (now.isoformat(),),
        )
        count = 0
        for key in expired:
            self._db.execute_insert(
                "UPDATE api_keys SET is_active = 0, revoked_at = ? WHERE id = ?", (now.isoformat(), key["id"])
            )
            logger.info("Expired API key deactivated: id=%d name=%s user_id=%s", key["id"], key["name"], key["user_id"])
            count += 1
        if count:
            logger.info("Deactivated %d expired API key(s)", count)
        return count
