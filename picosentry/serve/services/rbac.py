import logging
from enum import Enum
from typing import Any

logger = logging.getLogger("picoshogun.RBAC")


class Permission(str, Enum):
    READ_PROJECTS = "read:projects"
    READ_INTELLIGENCE = "read:intelligence"
    READ_ALERTS = "read:alerts"
    READ_METRICS = "read:metrics"
    READ_DASHBOARD = "read:dashboard"
    READ_LOGS = "read:logs"
    READ_EVENTS = "read:events"
    READ_ORGS = "read:orgs"
    READ_PLUGINS = "read:plugins"
    READ_HEALTH = "read:health"
    READ_BACKUPS = "read:backups"
    READ_AUDIT = "read:audit"
    READ_WEBHOOKS = "read:webhooks"
    READ_SCHEDULER = "read:scheduler"
    READ_ANOMALY = "read:anomaly"

    RUN_PROJECTS = "run:projects"
    WRITE_WEBHOOKS = "write:webhooks"
    WRITE_INTELLIGENCE = "write:intelligence"
    WRITE_ALERTS = "write:alerts"
    WRITE_SCHEDULER = "write:scheduler"
    WRITE_ANOMALY = "write:anomaly"

    ADMIN_USERS = "admin:users"
    ADMIN_ORGS = "admin:orgs"
    ADMIN_BACKUPS = "admin:backups"
    ADMIN_AUDIT = "admin:audit"
    ADMIN_LOGS = "admin:logs"


ROLE_PERMISSIONS: dict[str, set[Permission]] = {
    "viewer": {
        Permission.READ_PROJECTS,
        Permission.READ_INTELLIGENCE,
        Permission.READ_ALERTS,
        Permission.READ_METRICS,
        Permission.READ_DASHBOARD,
        Permission.READ_HEALTH,
        Permission.READ_ORGS,
        Permission.READ_PLUGINS,
        Permission.READ_EVENTS,
        Permission.READ_WEBHOOKS,
        Permission.READ_SCHEDULER,
        Permission.READ_ANOMALY,
    },
    "operator": {
        Permission.READ_PROJECTS,
        Permission.READ_INTELLIGENCE,
        Permission.READ_ALERTS,
        Permission.READ_METRICS,
        Permission.READ_DASHBOARD,
        Permission.READ_HEALTH,
        Permission.READ_ORGS,
        Permission.READ_PLUGINS,
        Permission.READ_EVENTS,
        Permission.READ_LOGS,
        Permission.READ_BACKUPS,
        Permission.READ_WEBHOOKS,
        Permission.READ_SCHEDULER,
        Permission.READ_ANOMALY,
        Permission.RUN_PROJECTS,
        Permission.WRITE_WEBHOOKS,
        Permission.WRITE_INTELLIGENCE,
        Permission.WRITE_ALERTS,
        Permission.WRITE_SCHEDULER,
        Permission.WRITE_ANOMALY,
    },
    "admin": {
        *Permission.__members__.values(),
    },
}


def has_permission(user: dict[str, Any], permission: Permission) -> bool:
    role = user.get("role", "viewer")
    perms = ROLE_PERMISSIONS.get(role, set())
    granted = permission in perms
    if not granted:
        logger.debug(
            "RBAC deny: role=%s needs %s (has %s)",
            role,
            permission.value,
            [p.value for p in perms],
        )
    return granted


def get_permissions(role: str) -> set[Permission]:
    return ROLE_PERMISSIONS.get(role, set())
