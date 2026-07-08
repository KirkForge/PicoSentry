import hashlib
import hmac
import logging
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

from picosentry.serve.config.settings import settings
from picosentry.serve.database.manager import DatabaseManager, db as _default_db

logger = logging.getLogger("picoshogun.Auth")


class AuthService:
    def __init__(self, db: DatabaseManager | None = None):
        self._db_override = db
        self.secret_key = settings.security.secret_key
        self.algorithm = settings.security.jwt_algorithm
        self.expiration_hours = settings.security.jwt_expiration_hours

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
        normalized = self._normalize_username(username)
        user = self._db.execute_one("SELECT * FROM users WHERE username = ? AND is_active = 1", (normalized,))

        # Generic failure path: do not reveal whether the username exists.
        if not user or not self._verify_password(password, user["password_hash"]):
            logger.warning("Auth failed: invalid credentials")
            return None

        self._db.execute_insert(
            "UPDATE users SET last_login = ? WHERE id = ?", (datetime.now(timezone.utc), user["id"])
        )

        token = self._generate_token(user["id"], user["username"], user["role"])

        logger.info("User %s authenticated", user["username"])
        return token

    def _generate_token(self, user_id: int, username: str, role: str) -> str:
        if not HAS_JWT:
            raise RuntimeError("PyJWT is required for token generation. Install with: pip install PyJWT")

        payload = {
            "user_id": user_id,
            "username": username,
            "role": role,
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
            return {
                "id": payload["user_id"],
                "user_id": payload["user_id"],
                "username": payload["username"],
                "role": payload["role"],
            }
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid token")
            return None

    def create_user(self, username: str, password: str, email: str | None = None, role: str = "viewer") -> int | None:
        normalized = self._normalize_username(username)

        existing = self._db.execute_one("SELECT id FROM users WHERE username = ?", (normalized,))
        if existing:
            return None

        password_hash = self._hash_password(password)

        user_id = self._db.execute_insert(
            """
            INSERT INTO users (username, password_hash, email, role)
            VALUES (?, ?, ?, ?)
        """,
            (normalized, password_hash, email, role),
        )

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

        with self._db.transaction() as conn:
            conn.execute(
                "UPDATE api_keys SET is_active = 0, revoked_at = ? WHERE id = ?", (datetime.now(timezone.utc), key_id)
            )

        new_api_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(new_api_key.encode()).hexdigest()
        expires = datetime.now(timezone.utc) + timedelta(days=90)

        self._db.execute_insert(
            """
            INSERT INTO api_keys (key_hash, user_id, name, permissions, expires_at)
            VALUES (?, ?, ?, ?, ?)
        """,
            (key_hash, user_id, key["name"] or "rotated-key", key["permissions"] or "read", expires),
        )

        logger.info("API key rotated for user %s, key_id %s", user_id, key_id)
        return new_api_key

    def check_permission(self, user: dict[str, Any], required: str) -> bool:
        role = user.get("role", "viewer")
        permissions = {"viewer": ["read"], "operator": ["read", "run"], "admin": ["read", "run", "write", "admin"]}
        return required in permissions.get(role, [])

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
