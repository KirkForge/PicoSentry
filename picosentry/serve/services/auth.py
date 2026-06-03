"""Authentication and authorization service with JWT and API keys."""
import hashlib
import hmac
import logging
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

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
from picosentry.serve.database.manager import db

logger = logging.getLogger("picoshogun.Auth")

class AuthService:
    """Authentication with JWT tokens and API key management."""

    def __init__(self):
        self.secret_key = settings.security.secret_key
        self.algorithm = settings.security.jwt_algorithm
        self.expiration_hours = settings.security.jwt_expiration_hours

    def _hash_password(self, password: str) -> str:
        """Hash password with bcrypt or fallback to PBKDF2."""
        if HAS_BCRYPT:
            return bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=settings.security.password_hash_rounds)).decode()

        # Fallback PBKDF2
        salt = secrets.token_hex(32)
        hashed = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
        return f"pbkdf2:{salt}:{hashed.hex()}"

    def _verify_password(self, password: str, hashed: str) -> bool:
        """Verify password against hash."""
        if HAS_BCRYPT and not hashed.startswith("pbkdf2:"):
            return bcrypt.checkpw(password.encode(), hashed.encode())

        # PBKDF2 verification (constant-time comparison to prevent timing attacks)
        if hashed.startswith("pbkdf2:"):
            _, salt, hash_value = hashed.split(":")
            check = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
            return hmac.compare_digest(check.hex(), hash_value)

        return False

    def authenticate(self, username: str, password: str) -> str | None:
        """Authenticate user and return JWT token."""
        user = db.execute_one(
            "SELECT * FROM users WHERE username = ? AND is_active = 1",
            (username,)
        )

        if not user:
            logger.warning("Auth failed: user not found")
            return None

        if not self._verify_password(password, user["password_hash"]):
            logger.warning("Auth failed: invalid password")
            return None

        # Update last login
        db.execute_insert(
            "UPDATE users SET last_login = ? WHERE id = ?",
            (datetime.now(timezone.utc), user["id"])
        )

        # Generate token
        token = self._generate_token(user["id"], username, user["role"])

        logger.info("User %s authenticated", username)
        return token

    def _generate_token(self, user_id: int, username: str, role: str) -> str:
        """Generate JWT token.

        Requires PyJWT — the simple-token fallback has been removed because
        it used non-timing-safe comparison and lacked expiration/claims.
        Install: pip install PyJWT
        """
        if not HAS_JWT:
            raise RuntimeError(
                "PyJWT is required for token generation. "
                "Install with: pip install PyJWT"
            )

        payload = {
            "user_id": user_id,
            "username": username,
            "role": role,
            "exp": datetime.now(timezone.utc) + timedelta(hours=self.expiration_hours),
            "iat": datetime.now(timezone.utc)
        }

        return jwt.encode(payload, self.secret_key, algorithm=self.algorithm)

    def validate_token(self, token: str) -> dict[str, Any] | None:
        """Validate and decode JWT token.

        Simple-token format is no longer supported — use JWT tokens only.
        Existing simple tokens will return None (treated as invalid).
        """
        if token.startswith("simple:"):
            # Legacy simple tokens are no longer accepted.
            # They used non-timing-safe comparison and lacked expiration.
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
                "role": payload["role"]
            }
        except jwt.ExpiredSignatureError:
            logger.warning("Token expired")
            return None
        except jwt.InvalidTokenError:
            logger.warning("Invalid token")
            return None

    def create_user(self, username: str, password: str,
                   email: str | None = None, role: str = "viewer") -> int | None:
        """Create new user."""
        # Check if exists
        existing = db.execute_one("SELECT id FROM users WHERE username = ?", (username,))
        if existing:
            return None

        password_hash = self._hash_password(password)

        user_id = db.execute_insert("""
            INSERT INTO users (username, password_hash, email, role)
            VALUES (?, ?, ?, ?)
        """, (username, password_hash, email, role))

        logger.info("User created: %s (role: %s)", username, role)
        return user_id

    def create_api_key(self, user_id: int, name: str,
                      permissions: str = "read") -> str | None:
        """Create API key for user."""
        api_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        expires = datetime.now(timezone.utc) + timedelta(days=90)

        db.execute_insert("""
            INSERT INTO api_keys (key_hash, user_id, name, permissions, expires_at)
            VALUES (?, ?, ?, ?, ?)
        """, (key_hash, user_id, name, permissions, expires))

        logger.info("API key created for user %s: %s", user_id, name)
        return api_key

    def validate_api_key(self, api_key: str) -> dict[str, Any] | None:
        """Validate API key."""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        key = db.execute_one("""
            SELECT ak.*, u.username, u.role
            FROM api_keys ak
            JOIN users u ON ak.user_id = u.id
            WHERE ak.key_hash = ? AND ak.is_active = 1
            AND (ak.expires_at IS NULL OR ak.expires_at > ?)
        """, (key_hash, datetime.now(timezone.utc)))

        if not key:
            return None

        # Update last used
        db.execute_insert(
            "UPDATE api_keys SET last_used = ? WHERE id = ?",
            (datetime.now(timezone.utc), key["id"])
        )

        return {
            "id": key["id"],
            "key_id": key["id"],
            "user_id": key["user_id"],
            "username": key["username"],
            "role": key["role"],
            "permissions": key["permissions"]
        }

    def revoke_api_key(self, key_id: int, user_id: int | None = None) -> bool:
        """Revoke API key. If user_id is provided, only revoke if the key belongs to that user."""
        if user_id is not None:
            key = db.execute_one(
                "SELECT id FROM api_keys WHERE id = ? AND user_id = ? AND is_active = 1",
                (key_id, user_id)
            )
            if not key:
                return False
        with db.transaction() as conn:
            conn.execute(
                "UPDATE api_keys SET is_active = 0, revoked_at = ? WHERE id = ?",
                (datetime.now(timezone.utc), key_id)
            )
        return True

    def rotate_api_key(self, key_id: int, user_id: int) -> str | None:
        """Rotate an existing API key — revoke old, create new, preserve permissions."""
        # Verify ownership
        key = db.execute_one(
            "SELECT * FROM api_keys WHERE id = ? AND user_id = ? AND is_active = 1",
            (key_id, user_id)
        )
        if not key:
            return None

        # Revoke old
        with db.transaction() as conn:
            conn.execute(
                "UPDATE api_keys SET is_active = 0, revoked_at = ? WHERE id = ?",
                (datetime.now(timezone.utc), key_id)
            )

        # Create new with same permissions
        new_api_key = secrets.token_urlsafe(32)
        key_hash = hashlib.sha256(new_api_key.encode()).hexdigest()
        expires = datetime.now(timezone.utc) + timedelta(days=90)

        db.execute_insert("""
            INSERT INTO api_keys (key_hash, user_id, name, permissions, expires_at)
            VALUES (?, ?, ?, ?, ?)
        """, (key_hash, user_id, key["name"] or "rotated-key", key["permissions"] or "read", expires))

        logger.info("API key rotated for user %s, key_id %s", user_id, key_id)
        return new_api_key

    def check_permission(self, user: dict[str, Any], required: str) -> bool:
        """Check if user has required permission."""
        role = user.get("role", "viewer")
        permissions = {
            "viewer": ["read"],
            "operator": ["read", "run"],
            "admin": ["read", "run", "write", "admin"]
        }
        return required in permissions.get(role, [])

    def cleanup_expired_keys(self) -> int:
        """Deactivate API keys past their expires_at timestamp.

        Called at startup and periodically by the scheduler.
        Returns the number of keys deactivated.
        """
        now = datetime.now(timezone.utc)
        expired = db.execute(
            "SELECT id, name, user_id FROM api_keys WHERE is_active = 1 AND expires_at IS NOT NULL AND expires_at <= ?",
            (now.isoformat(),)
        )
        count = 0
        for key in expired:
            db.execute_insert(
                "UPDATE api_keys SET is_active = 0, revoked_at = ? WHERE id = ?",
                (now.isoformat(), key["id"])
            )
            logger.info(
                "Expired API key deactivated: id=%d name=%s user_id=%s",
                key["id"], key["name"], key["user_id"]
            )
            count += 1
        if count:
            logger.info("Deactivated %d expired API key(s)", count)
        return count
