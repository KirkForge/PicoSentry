"""Organization model — multi-tenancy foundation."""
import hashlib
import secrets
from datetime import datetime, timezone
from typing import Any

from picosentry.serve.database.manager import db


class Organization:
    """
    Multi-tenant workspace. Each org has:
    - Isolated project data
    - User seats
    - Subscription tier
    - Usage limits
    """

    TIERS = {
        "free": {"users": 1, "projects": 3, "runs_per_day": 50, "storage_mb": 100},
        "starter": {"users": 5, "projects": 25, "runs_per_day": 500, "storage_mb": 1000},
        "pro": {"users": 25, "projects": 100, "runs_per_day": 5000, "storage_mb": 10000},
        "enterprise": {"users": 999, "projects": 999, "runs_per_day": 99999, "storage_mb": 999999}
    }

    @staticmethod
    def create(name: str, slug: str, owner_user_id: int, tier: str = "free") -> int | None:
        """Create new organization."""
        if db.execute_one("SELECT id FROM orgs WHERE slug = ?", (slug,)):
            return None

        api_key = f"sk_live_{secrets.token_urlsafe(32)}"
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        org_id = db.execute_insert("""
            INSERT INTO orgs (name, slug, owner_id, tier, api_key_hash, is_active, created_at)
            VALUES (?, ?, ?, ?, ?, 1, ?)
        """, (name, slug, owner_user_id, tier, api_key_hash, datetime.now(timezone.utc)))

        # Add owner as member
        db.execute_insert("""
            INSERT INTO org_users (org_id, user_id, role, invited_at, joined_at)
            VALUES (?, ?, 'admin', ?, ?)
        """, (org_id, owner_user_id, datetime.now(timezone.utc), datetime.now(timezone.utc)))

        return org_id

    @staticmethod
    def get_by_api_key(api_key: str) -> dict[str, Any] | None:
        """Lookup org by API key using SHA-256 hash comparison."""
        import hashlib
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        row = db.execute_one("""
            SELECT * FROM orgs WHERE api_key_hash = ? AND is_active = 1
        """, (key_hash,))
        return dict(row) if row else None

    @staticmethod
    def get_members(org_id: int) -> list[dict[str, Any]]:
        """List org members with roles."""
        rows = db.execute("""
            SELECT u.id, u.username, u.email, u.last_login, ou.role, ou.joined_at
            FROM org_users ou
            JOIN users u ON ou.user_id = u.id
            WHERE ou.org_id = ?
            ORDER BY ou.joined_at DESC
        """, (org_id,))
        return [dict(r) for r in rows]

    @staticmethod
    def get_usage(org_id: int) -> dict[str, Any]:
        """Current usage vs limits."""
        org = db.execute_one("SELECT * FROM orgs WHERE id = ?", (org_id,))
        if not org:
            return {}

        tier = org["tier"]
        limits = Organization.TIERS.get(tier, Organization.TIERS["free"])

        # Count users
        users = db.execute_one(
            "SELECT COUNT(*) as c FROM org_users WHERE org_id = ?",
            (org_id,)
        )["c"] or 0

        # Count projects
        projects = db.execute_one(
            "SELECT COUNT(*) as c FROM org_projects WHERE org_id = ?",
            (org_id,)
        )["c"] or 0

        # Count today's runs
        runs_today_row = db.execute_one("""
            SELECT COUNT(*) as c FROM project_runs
            WHERE org_id = ? AND DATE(run_start) = DATE('now')
        """, (org_id,))
        runs_today = runs_today_row["c"] if runs_today_row else 0

        return {
            "tier": tier,
            "users": {"used": users, "limit": limits["users"], "pct": users/limits["users"]*100 if limits["users"] > 0 else 0},
            "projects": {"used": projects, "limit": limits["projects"], "pct": projects/limits["projects"]*100 if limits["projects"] > 0 else 0},
            "runs_today": {"used": runs_today, "limit": limits["runs_per_day"], "pct": runs_today/limits["runs_per_day"]*100 if limits["runs_per_day"] > 0 else 0},
            "storage_mb": limits["storage_mb"]
        }

    @staticmethod
    def can_create_project(org_id: int) -> bool:
        """Check if org can create another project."""
        usage = Organization.get_usage(org_id)
        return usage.get("projects", {}).get("used", 0) < usage.get("projects", {}).get("limit", 0)

    @staticmethod
    def can_run(org_id: int) -> bool:
        """Check if org has remaining run quota."""
        usage = Organization.get_usage(org_id)
        return usage.get("runs_today", {}).get("used", 0) < usage.get("runs_today", {}).get("limit", 0)

    @staticmethod
    def update_tier(org_id: int, new_tier: str) -> bool:
        """Change subscription tier."""
        if new_tier not in Organization.TIERS:
            return False
        db.execute_insert(
            "UPDATE orgs SET tier = ?, updated_at = ? WHERE id = ?",
            (new_tier, datetime.now(timezone.utc), org_id)
        )
        return True

    @staticmethod
    def list_orgs_for_user(user_id: int) -> list[dict[str, Any]]:
        """All orgs where user is a member."""
        rows = db.execute("""
            SELECT o.*, ou.role as user_role
            FROM org_users ou
            JOIN orgs o ON ou.org_id = o.id
            WHERE ou.user_id = ? AND o.is_active = 1
            ORDER BY o.created_at DESC
        """, (user_id,))
        return [dict(r) for r in rows]

# Migration to add org tables
ORG_MIGRATION = """
CREATE TABLE IF NOT EXISTS orgs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    slug TEXT UNIQUE NOT NULL,
    owner_id INTEGER,
    tier TEXT DEFAULT 'free',
    api_key_hash TEXT UNIQUE,
    is_active BOOLEAN DEFAULT 1,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS org_users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER,
    user_id INTEGER,
    role TEXT DEFAULT 'member',
    invited_at TIMESTAMP,
    joined_at TIMESTAMP,
    FOREIGN KEY (org_id) REFERENCES orgs(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS org_projects (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    org_id INTEGER,
    project_id TEXT,
    added_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (org_id) REFERENCES orgs(id)
);

CREATE INDEX IF NOT EXISTS idx_orgs_slug ON orgs(slug);
CREATE INDEX IF NOT EXISTS idx_orgs_key ON orgs(api_key_hash);
CREATE INDEX IF NOT EXISTS idx_org_members ON org_users(org_id, user_id);
"""
