import hashlib
import secrets
from datetime import datetime, timezone
from typing import Any, ClassVar

from picosentry._core.security import constant_time_compare
from picosentry.serve.database.manager import db


class Organization:
    TIERS: ClassVar[dict[str, dict[str, Any]]] = {
        "free": {"users": 1, "projects": 3, "runs_per_day": 50, "storage_mb": 100},
        "starter": {"users": 5, "projects": 25, "runs_per_day": 500, "storage_mb": 1000},
        "pro": {"users": 25, "projects": 100, "runs_per_day": 5000, "storage_mb": 10000},
        "enterprise": {"users": 999, "projects": 999, "runs_per_day": 99999, "storage_mb": 999999},
    }

    @staticmethod
    def create(name: str, slug: str, owner_user_id: int, tier: str = "free") -> dict[str, Any] | None:
        if db.execute_one("SELECT id FROM orgs WHERE slug = ?", (slug,)):
            return {}

        api_key = f"sk_live_{secrets.token_urlsafe(32)}"
        api_key_hash = hashlib.sha256(api_key.encode()).hexdigest()

        try:
            with db.transaction() as conn:
                now = datetime.now(timezone.utc)
                rows = db.execute_on(
                    conn,
                    """
                    INSERT INTO orgs (name, slug, owner_id, tier, api_key_hash, is_active, created_at)
                    VALUES (?, ?, ?, ?, ?, 1, ?)
                    RETURNING id
                """,
                    (name, slug, owner_user_id, tier, api_key_hash, now),
                )
                org_id = rows[0]["id"]
                db.execute_on(
                    conn,
                    """
                    INSERT INTO org_users (org_id, user_id, role, invited_at, joined_at)
                    VALUES (?, ?, 'admin', ?, ?)
                """,
                    (org_id, owner_user_id, now, now),
                )
        except Exception:
            return None

        return {"org_id": org_id, "api_key": api_key}

    @staticmethod
    def get_by_api_key(api_key: str) -> dict[str, Any] | None:
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        row = db.execute_one(
            """
            SELECT * FROM orgs WHERE api_key_hash = ? AND is_active = 1
        """,
            (key_hash,),
        )
        if not row:
            return None
        # Defense-in-depth: constant-time comparison even after DB lookup
        if not constant_time_compare(row["api_key_hash"], key_hash):
            return None
        return dict(row)

    @staticmethod
    def get_members(org_id: int) -> list[dict[str, Any]]:
        rows = db.execute(
            """
            SELECT u.id, u.username, u.email, u.last_login, ou.role, ou.joined_at
            FROM org_users ou
            JOIN users u ON ou.user_id = u.id
            WHERE ou.org_id = ?
            ORDER BY ou.joined_at DESC
        """,
            (org_id,),
        )
        return [dict(r) for r in rows]

    @staticmethod
    def get_usage(org_id: int) -> dict[str, Any]:
        org = db.execute_one("SELECT * FROM orgs WHERE id = ?", (org_id,))
        if not org:
            return {}

        tier = org["tier"]
        limits = Organization.TIERS.get(tier, Organization.TIERS["free"])

        user_row = db.execute_one("SELECT COUNT(*) as c FROM org_users WHERE org_id = ?", (org_id,))
        users = (user_row or {}).get("c") or 0

        project_row = db.execute_one("SELECT COUNT(*) as c FROM org_projects WHERE org_id = ?", (org_id,))
        projects = (project_row or {}).get("c") or 0

        today_col = db.dialect.date_column("run_start")
        runs_today_row = db.execute_one(
            f"""
            SELECT COUNT(*) as c FROM project_runs
            WHERE org_id = ? AND {today_col} = {db.dialect.date_now()}
        """,
            (org_id,),
        )
        runs_today = runs_today_row["c"] if runs_today_row else 0

        def _pct(used: int, limit: int) -> float:
            return used / limit * 100 if limit > 0 else 0.0

        return {
            "tier": tier,
            "users": {
                "used": users,
                "limit": limits["users"],
                "pct": _pct(users, limits["users"]),
            },
            "projects": {
                "used": projects,
                "limit": limits["projects"],
                "pct": _pct(projects, limits["projects"]),
            },
            "runs_today": {
                "used": runs_today,
                "limit": limits["runs_per_day"],
                "pct": _pct(runs_today, limits["runs_per_day"]),
            },
            "storage_mb": limits["storage_mb"],
        }

    @staticmethod
    def add_project(org_id: int, project_id: str) -> None:
        """Associate a project with an organization.

        Idempotent: duplicate associations are ignored so repeated runs do not
        inflate usage counts.
        """
        db.execute_insert(
            """
            INSERT INTO org_projects (org_id, project_id, added_at)
            VALUES (?, ?, ?)
            ON CONFLICT (org_id, project_id) DO NOTHING
        """,
            (org_id, project_id, datetime.now(timezone.utc)),
        )

    @staticmethod
    def has_project(org_id: int, project_id: str) -> bool:
        row = db.execute_one(
            "SELECT id FROM org_projects WHERE org_id = ? AND project_id = ?",
            (org_id, project_id),
        )
        return row is not None

    @staticmethod
    def list_project_ids(org_id: int) -> set[str]:
        """Return the set of project IDs associated with an org via org_projects."""
        rows = db.execute(
            "SELECT project_id FROM org_projects WHERE org_id = ?",
            (org_id,),
        )
        return {r["project_id"] for r in rows} if rows else set()

    @staticmethod
    def update_tier(org_id: int, new_tier: str) -> bool:
        if new_tier not in Organization.TIERS:
            return False
        db.execute_insert(
            "UPDATE orgs SET tier = ?, updated_at = ? WHERE id = ?", (new_tier, datetime.now(timezone.utc), org_id)
        )
        return True

    @staticmethod
    def list_orgs_for_user(user_id: int) -> list[dict[str, Any]]:
        rows = db.execute(
            """
            SELECT o.*, ou.role as user_role
            FROM org_users ou
            JOIN orgs o ON ou.org_id = o.id
            WHERE ou.user_id = ? AND o.is_active = 1
            ORDER BY o.created_at DESC
        """,
            (user_id,),
        )
        return [dict(r) for r in rows]
