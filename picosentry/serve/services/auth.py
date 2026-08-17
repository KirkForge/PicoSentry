import hashlib
import logging
import os
import secrets
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, ClassVar

try:
    import jwt
    from jwt.algorithms import RSAAlgorithm

    HAS_JWT = True
except ImportError:
    HAS_JWT = False

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import rsa

    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False

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

from picosentry._core.security import constant_time_compare
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
        # Active RSA signing keys keyed by kid.  The newest registered key
        # signs new tokens; all active keys verify (rotation window).
        self._keys: dict[str, rsa.RSAPrivateKey] = {}
        self._load_configured_key()

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

    def _load_configured_key(self) -> None:
        """Load the RSA key from PICOSHOGUN_JWT_PRIVATE_KEY (PEM or path)."""
        raw = settings.security.jwt_private_key
        if not raw:
            return
        if not HAS_CRYPTO:
            raise RuntimeError("cryptography is required for RS256 JWT signing")
        pem = raw
        if os.path.exists(raw):
            pem = Path(raw).read_text()
        try:
            key = serialization.load_pem_private_key(pem.encode(), password=None)
        except Exception as exc:  # surface any PEM parse failure
            raise ValueError("PICOSHOGUN_JWT_PRIVATE_KEY is not a valid RSA private key") from exc
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("PICOSHOGUN_JWT_PRIVATE_KEY must be an RSA private key")
        self._keys[settings.security.jwt_kid] = key

    def register_key(self, kid: str, pem: str) -> None:
        """Register a new RSA signing key for rotation.  New tokens use it."""
        if not HAS_CRYPTO:
            raise RuntimeError("cryptography is required for RS256 JWT signing")
        key = serialization.load_pem_private_key(pem.encode(), password=None)
        if not isinstance(key, rsa.RSAPrivateKey):
            raise ValueError("key must be an RSA private key")
        self._keys[kid] = key

    def retire_key(self, kid: str) -> bool:
        """Retire an active signing key.  Returns False if it was the last one."""
        if kid not in self._keys:
            return False
        if len(self._keys) == 1:
            return False
        del self._keys[kid]
        return True

    @property
    def _signing_key(self) -> rsa.RSAPrivateKey | None:
        if not self._keys:
            return None
        return next(reversed(self._keys.values()))

    @property
    def _signing_kid(self) -> str | None:
        if not self._keys:
            return None
        return next(reversed(self._keys))

    def jwks(self) -> dict[str, Any]:
        """Return the JWKS document for all active public keys."""
        keys = []
        for kid, key in self._keys.items():
            jwk = RSAAlgorithm.to_jwk(key.public_key(), as_dict=True)
            jwk["kid"] = kid
            jwk["use"] = "sig"
            jwk["alg"] = "RS256"
            keys.append(jwk)
        return {"keys": keys}

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
            return constant_time_compare(check.hex(), hash_value)

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
                if totp_secret and not (totp_code and self._verify_totp_replay(conn, user, totp_secret, totp_code)):
                    if totp_code:
                        self._record_failed_login(conn, user, now)
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

        if self._signing_key is not None:
            headers = {"kid": self._signing_kid}
            return jwt.encode(payload, self._signing_key, algorithm="RS256", headers=headers)

        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def validate_token(self, token: str) -> dict[str, Any] | None:
        if token.startswith("simple:"):
            logger.warning("Rejected legacy simple-token format. Migrate to JWT.")
            return None

        if not HAS_JWT:
            logger.error("PyJWT not installed — cannot validate any tokens")
            return None

        payload = self._decode_token(token)
        if payload is None:
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

    def _decode_token(self, token: str) -> dict[str, Any] | None:
        """Decode a token, trying RS256 (per-kid) then HS256 (legacy)."""
        # RS256: verify against each active public key, honoring the kid claim.
        if self._keys:
            try:
                kid = jwt.get_unverified_header(token).get("kid")
            except jwt.InvalidTokenError:
                kid = None
            candidates = [kid] if kid in self._keys else list(self._keys)
            for candidate in candidates:
                try:
                    return jwt.decode(token, self._keys[candidate].public_key(), algorithms=["RS256"])
                except jwt.ExpiredSignatureError:
                    logger.warning("Token expired")
                    return None
                except jwt.InvalidTokenError:
                    continue
        # HS256 fallback for legacy tokens.
        try:
            return jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid token")
            return None

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

    def purge_expired_revocations(self) -> int:
        """Delete revocation rows that can no longer match a live token.

        A token expires at most ``expiration_hours`` after issue, and issue
        precedes revocation, so any row revoked before ``now - expiration_hours``
        is safe to delete.  Keeps the revoked_tokens table from growing forever.
        """
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=self.expiration_hours)).strftime("%Y-%m-%d %H:%M:%S")
        with self._db.transaction() as conn:
            cursor = conn.execute("DELETE FROM revoked_tokens WHERE revoked_at < ?", (cutoff,))
            return max(cursor.rowcount, 0)

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

    def _totp_match_timestep(self, secret: str, code: str) -> int | None:
        """Return the timestep matching ``code`` within ±1 step of drift, else None."""
        if not HAS_PYOTP:
            return None
        totp = pyotp.TOTP(secret)
        if not totp.verify(code, valid_window=1):
            return None
        counter = int(time.time() // totp.interval)
        return max(fc for fc in (counter - 1, counter, counter + 1) if totp.generate_otp(fc) == code)

    def _totp_replay_ok(self, user: dict[str, Any], matched: int) -> bool:
        """A timestep at or before the last consumed one is a replay."""
        return matched > int(user.get("totp_last_timestep") or 0)

    def verify_totp(self, secret: str, code: str) -> bool:
        if not HAS_PYOTP:
            return False
        return self._totp_match_timestep(secret, code) is not None

    def _verify_totp_replay(self, conn, user: dict[str, Any], secret: str, code: str) -> bool:
        """Verify a TOTP code inside an open transaction, rejecting replayed timesteps."""
        matched = self._totp_match_timestep(secret, code)
        if matched is None or not self._totp_replay_ok(user, matched):
            return False
        conn.execute("UPDATE users SET totp_last_timestep = ? WHERE id = ?", (matched, user["id"]))
        return True

    def verify_totp_for_user(self, user_id: int, code: str) -> bool:
        with self._db.transaction() as conn:
            rows = self._db.execute_on(
                conn, "SELECT id, totp_secret, totp_last_timestep FROM users WHERE id = ?", (user_id,)
            )
            user = rows[0] if rows else None
            if not user or not user.get("totp_secret"):
                return False
            return self._verify_totp_replay(conn, user, user["totp_secret"], code)

    def get_totp_secret(self, user_id: int) -> str | None:
        user = self._db.execute_one("SELECT totp_secret FROM users WHERE id = ?", (user_id,))
        return user.get("totp_secret") if user else None

    def verify_user_password(self, user_id: int, password: str) -> bool:
        """Re-verify the account password for sensitive actions (MFA enroll/register)."""
        user = self._db.execute_one("SELECT password_hash FROM users WHERE id = ?", (user_id,))
        if not user:
            return False
        return self._verify_password(password, user["password_hash"])

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

    def webauthn_dummy_challenge(self) -> dict[str, Any] | None:
        """Plausible assertion options for an unknown username.

        Anti-enumeration: the authenticate-challenge route answers unknown
        usernames with the same-shaped, same-cost response as known ones.
        The challenge is not persisted, so a later assertion verify fails
        uniformly.
        """
        if not HAS_WEBAUTHN:
            return None
        options = webauthn.generate_authentication_options(rp_id=settings.security.webauthn_rp_id)
        return {
            "challenge": bytes_to_base64url(options.challenge),
            "options": options_to_json(options),
        }

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
            "SELECT credential_id, public_key, sign_count FROM webauthn_credentials"
            " WHERE user_id = ? AND credential_id = ?",
            (user_id, credential_id),
        )
        if not stored_cred:
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
        if not constant_time_compare(key["key_hash"], key_hash):
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
