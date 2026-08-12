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

    def authenticate(self, username: str, password: str) -> str | None:
        result = self.login(username, password)
        return result.get("token")

    def login(self, username: str, password: str, totp_code: str | None = None) -> dict[str, Any]:
        """Authenticate a user, returning a structured status.

        Statuses:
          - ``ok``: credentials valid (and TOTP verified if enabled) — ``token`` set
          - ``mfa_required``: password valid, TOTP enabled, no/invalid code supplied
          - ``invalid``: bad credentials
          - ``locked``: account is locked out
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
            if totp_secret and (not totp_code or not self.verify_totp(totp_secret, totp_code)):
                logger.info("User %s requires MFA", normalized)
                return {"status": "mfa_required"}

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

    def create_api_key(self, user_id: int, name: str, permissions: str = "read") -> str | None:
        allowed_permissions = self._API_KEY_PERMISSIONS
        requested = {p.strip() for p in permissions.split(",") if p.strip()}
        if not requested or not requested.issubset(allowed_permissions):
            logger.warning("API key create rejected: invalid permissions '%s'", permissions)
            return None

        normalized = ",".join(sorted(requested))
        api_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        expires = datetime.now(timezone.utc) + timedelta(days=90)

        self._db.execute_insert(
            """
            INSERT INTO api_keys (key_hash, user_id, name, permissions, expires_at)
            VALUES (?, ?, ?, ?, ?)
        """,
            (key_hash, user_id, name, normalized, expires),
        )

        logger.info("API key created for user %s: %s", user_id, name)
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

        self._db.execute_insert(
            "UPDATE api_keys SET last_used = ? WHERE id = ?", (datetime.now(timezone.utc), key["id"])
        )

        return {
            "id": key["id"],
            "key_id": key["id"],
            "user_id": key["user_id"],
            "username": key["username"],
            "role": key["role"],
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
                INSERT INTO api_keys (key_hash, user_id, name, permissions, expires_at)
                VALUES (?, ?, ?, ?, ?)
            """,
                (key_hash, user_id, key["name"] or "rotated-key", key["permissions"] or "read", expires),
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
