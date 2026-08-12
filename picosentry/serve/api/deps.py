import logging

from fastapi import Depends, Header, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from picosentry.serve.services.auth import AuthService
from picosentry.serve.services.orgs import Organization
from picosentry.serve.services.rbac import Permission, has_permission

logger = logging.getLogger("picoshogun.deps")

auth_service = AuthService()
security = HTTPBearer(auto_error=False)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    api_key: str | None = Header(None, alias="X-API-Key"),
):
    # API-key requests authenticate through the key's stored role scope so the
    # same `require_role`/`require_permission` checks that guard JWT callers
    # also bound key callers (e.g. a read-only viewer key cannot mutate).
    if api_key:
        key_user = auth_service.validate_api_key(api_key)
        if key_user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid or expired API key",
            )
        return key_user

    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing bearer token or API key",
        )
    token = credentials.credentials
    user = auth_service.validate_token(token)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired token",
        )
    return user


def require_role(required: str):
    role_levels = {"viewer": 0, "operator": 1, "admin": 2}
    min_level = role_levels.get(required, 0)

    async def _check_role(user: dict = Depends(get_current_user)):
        user_role = user.get("role", "viewer")
        if role_levels.get(user_role, 0) < min_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role: {required} (have: {user_role})",
            )
        return user

    return _check_role


def require_permission(permission: Permission):
    async def _check_permission(user: dict = Depends(get_current_user)):
        if not has_permission(user, permission):
            role = user.get("role", "viewer")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires permission: {permission.value} (role: {role})",
            )
        return user

    return _check_permission


async def get_current_org(
    api_key: str | None = Header(None, alias="X-Org-API-Key"),
    user: dict = Depends(get_current_user),
):
    user_orgs = Organization.list_orgs_for_user(user["id"])

    # A user API key minted scoped to an org may only reach that org.
    key_org_id = user.get("org_id")
    if key_org_id is not None:
        key_org = next((o for o in (user_orgs or []) if o["id"] == key_org_id), None)
        if not key_org:
            raise HTTPException(status_code=403, detail="API key is not scoped to an accessible organization")
        return key_org

    if api_key and api_key.startswith("sk_"):
        org = Organization.get_by_api_key(api_key)
        if org:
            user_org_ids = {o["id"] for o in user_orgs} if user_orgs else set()
            if org["id"] not in user_org_ids:
                logger.warning(
                    "Cross-tenant org access rejected: user %s attempted org %s",
                    user.get("username"),
                    org.get("slug"),
                )
                raise HTTPException(
                    status_code=403,
                    detail="API key does not belong to an organization you are a member of",
                )
            return org
        raise HTTPException(status_code=403, detail="Invalid organization API key")

    if not user_orgs:
        raise HTTPException(status_code=403, detail="User not associated with any organization")
    return user_orgs[0]


async def require_org_membership(
    org_id: int,
    user: dict = Depends(get_current_user),
) -> dict:
    orgs = Organization.list_orgs_for_user(user["id"])
    org = next((o for o in orgs if o["id"] == org_id), None)
    if not org:
        raise HTTPException(status_code=403, detail="Not a member of this organization")
    return org
