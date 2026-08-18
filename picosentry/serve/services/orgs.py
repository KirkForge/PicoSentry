import hashlib
import logging
import secrets
from datetime import datetime, timezone
from typing import Any, ClassVar

from picosentry._core.security import constant_time_compare
from picosentry.serve.database.manager import db
from picosentry.serve.errors import ConflictError, NotFoundError, QuotaExceededError

logger = logging.getLogger("picoshogun.Orgs")


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
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    RETURNING id
                """,
                    (name, slug, owner_user_id, tier, api_key_hash, True, now),
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
            # Silent-None here hid a postgres dialect failure for two CI
            # rounds (integer literal into BOOLEAN on the INSERT above).
            # Return contract stays None; the cause must not be invisible.
            logger.warning("org create failed (name=%r slug=%r)", name, slug, exc_info=True)
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

    MEMBER_ROLES = ("viewer", "operator", "admin")

    @staticmethod
    def add_member(org_id: int, user_id: int, role: str = "viewer") -> dict[str, Any]:
        """Invite a user: creates the membership row plus a recorded invite
        token (sha256-hashed; the raw token is returned exactly once).

        ponytail: membership is effective immediately — the invite row is the
        audit/verification artifact, not a two-step accept flow. Add an
        accept endpoint (validating the raw token against token_hash, flipping
        status/accepted_at) if out-of-band invites are ever needed.
        """
        if role not in Organization.MEMBER_ROLES:
            raise ValueError(f"Unknown member role: {role}")
        org, _ = Organization._limits_for(org_id)
        if not db.execute_one("SELECT id FROM users WHERE id = ?", (user_id,)):
            raise NotFoundError(f"User {user_id} does not exist")
        if db.execute_one("SELECT id FROM org_users WHERE org_id = ? AND user_id = ?", (org_id, user_id)):
            raise ConflictError(f"User {user_id} is already a member of this organization")

        Organization.check_member_quota(org_id)

        token = f"inv_{secrets.token_urlsafe(24)}"
        token_hash = hashlib.sha256(token.encode()).hexdigest()
        now = datetime.now(timezone.utc)
        try:
            with db.transaction() as conn:
                db.execute_on(
                    conn,
                    """
                    INSERT INTO org_users (org_id, user_id, role, invited_at, joined_at)
                    VALUES (?, ?, ?, ?, ?)
                """,
                    (org_id, user_id, role, now, now),
                )
                db.execute_on(
                    conn,
                    """
                    INSERT INTO org_invites (org_id, user_id, role, token_hash, status, created_at)
                    VALUES (?, ?, ?, ?, 'accepted', ?)
                """,
                    (org_id, user_id, role, token_hash, now),
                )
        except Exception:
            logger.warning("member add failed (org=%r user=%r)", org_id, user_id, exc_info=True)
            raise

        return {"user_id": user_id, "role": role, "invite_token": token, "invited_by_org": org["slug"]}

    @staticmethod
    def update_member_role(org_id: int, user_id: int, role: str) -> bool:
        if role not in Organization.MEMBER_ROLES:
            return False
        org, _ = Organization._limits_for(org_id)
        if user_id == org.get("owner_id"):
            # Owner lockout guard: demoting the owning member can brick the
            # org (no admin left to manage members or tier).
            raise ConflictError("The organization owner's role cannot be changed")
        if not db.execute_one("SELECT id FROM org_users WHERE org_id = ? AND user_id = ?", (org_id, user_id)):
            return False
        db.execute_insert("UPDATE org_users SET role = ? WHERE org_id = ? AND user_id = ?", (role, org_id, user_id))
        return True

    @staticmethod
    def remove_member(org_id: int, user_id: int) -> bool:
        org, _ = Organization._limits_for(org_id)
        if user_id == org.get("owner_id"):
            raise ConflictError("The organization owner cannot be removed")
        if not db.execute_one("SELECT id FROM org_users WHERE org_id = ? AND user_id = ?", (org_id, user_id)):
            return False
        db.execute_insert("DELETE FROM org_users WHERE org_id = ? AND user_id = ?", (org_id, user_id))
        return True

    @staticmethod
    def _limits_for(org_id: int) -> tuple[dict[str, Any], dict[str, Any]]:
        """(org row, tier limits) — raises KeyError-free defaults for unknown tiers."""
        org = db.execute_one("SELECT * FROM orgs WHERE id = ?", (org_id,))
        if not org:
            raise LookupError(f"org {org_id} not found")
        limits = Organization.TIERS.get(org["tier"], Organization.TIERS["free"])
        return dict(org), limits

    @staticmethod
    def _count(sql: str, params: tuple) -> int:
        row = db.execute_one(sql, params)
        return (row or {}).get("c") or 0

    @staticmethod
    def _member_count(org_id: int) -> int:
        return Organization._count("SELECT COUNT(*) as c FROM org_users WHERE org_id = ?", (org_id,))

    @staticmethod
    def _project_count(org_id: int) -> int:
        return Organization._count("SELECT COUNT(*) as c FROM org_projects WHERE org_id = ?", (org_id,))

    @staticmethod
    def _runs_today_count(org_id: int) -> int:
        today_col = db.dialect.date_column("run_start")
        return Organization._count(
            f"SELECT COUNT(*) as c FROM project_runs WHERE org_id = ? AND {today_col} = {db.dialect.date_now()}",
            (org_id,),
        )

    # Tier enforcement. get_usage reports the same counters — a rejected
    # request and the usage endpoint must never disagree.
    # ponytail: check-then-act races between concurrent requests can admit a
    # row or two over the limit (counted, not hidden — get_usage shows the
    # overshoot). Exact admission would need a count-guarded transaction per
    # insert; add if a tier is ever billed per-row.
    @staticmethod
    def check_member_quota(org_id: int) -> None:
        org, limits = Organization._limits_for(org_id)
        used = Organization._member_count(org_id)
        if used >= limits["users"]:
            raise QuotaExceededError(
                f"Tier '{org['tier']}' allows {limits['users']} members (in use: {used}). "
                "Upgrade the org tier to add more."
            )

    @staticmethod
    def check_run_quota(org_id: int) -> None:
        org, limits = Organization._limits_for(org_id)
        used = Organization._runs_today_count(org_id)
        if used >= limits["runs_per_day"]:
            raise QuotaExceededError(
                f"Tier '{org['tier']}' allows {limits['runs_per_day']} runs/day (used today: {used}). "
                "Upgrade the org tier or retry tomorrow."
            )

    @staticmethod
    def check_project_quota(org_id: int, project_id: str) -> None:
        """Reject only NEW associations: re-running an already-associated
        project never hits the project cap."""
        if Organization.has_project(org_id, project_id):
            return
        org, limits = Organization._limits_for(org_id)
        used = Organization._project_count(org_id)
        if used >= limits["projects"]:
            raise QuotaExceededError(
                f"Tier '{org['tier']}' allows {limits['projects']} projects (in use: {used}). "
                "Upgrade the org tier to register more."
            )

    @staticmethod
    def get_usage(org_id: int) -> dict[str, Any]:
        org = db.execute_one("SELECT * FROM orgs WHERE id = ?", (org_id,))
        if not org:
            return {}

        tier = org["tier"]
        limits = Organization.TIERS.get(tier, Organization.TIERS["free"])

        users = Organization._member_count(org_id)
        projects = Organization._project_count(org_id)
        runs_today = Organization._runs_today_count(org_id)

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
