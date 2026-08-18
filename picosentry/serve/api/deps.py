import logging

from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from picosentry.serve.services.auth import AuthService
from picosentry.serve.services.orgs import Organization
from picosentry.serve.services.rbac import Permission, has_permission

logger = logging.getLogger("picoshogun.deps")

auth_service = AuthService()
security = HTTPBearer(auto_error=False)


def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials | None = Depends(security),
    api_key: str | None = Header(None, alias="X-API-Key"),
):
    # Sync def: FastAPI dispatches it to the threadpool, so the DB reads in
    # validate_api_key/validate_token never block the event loop.
    user = _validate_credentials(credentials, api_key)
    # Shared with the audit middleware via request.state: auth already
    # happened for this request — re-validating in the middleware doubled
    # the revocation-check DB hits per call.
    request.state.picoshogun_auth = user
    return user


def _validate_credentials(
    credentials: HTTPAuthorizationCredentials | None,
    api_key: str | None,
) -> dict:
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

    def _check_role(user: dict = Depends(get_current_user)):
        user_role = user.get("role", "viewer")
        if role_levels.get(user_role, 0) < min_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires role: {required} (have: {user_role})",
            )
        return user

    return _check_role


def require_permission(permission: Permission):
    def _check_permission(user: dict = Depends(get_current_user)):
        if not has_permission(user, permission):
            role = user.get("role", "viewer")
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Requires permission: {permission.value} (role: {role})",
            )
        return user

    return _check_permission


def get_current_org(
    request: Request,
    api_key: str | None = Header(None, alias="X-Org-API-Key"),
    org_id_header: str | None = Header(None, alias="X-Org-Id"),
    user: dict = Depends(get_current_user),
):
    org = _resolve_current_org(api_key, org_id_header, user)
    # Shared with the audit middleware (see get_current_user).
    request.state.picoshogun_org = org
    return org


def _resolve_current_org(api_key: str | None, org_id_header: str | None, user: dict) -> dict:
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

    # Org switch for multi-org JWT users: X-Org-Id selects which of the
    # caller's own orgs this request acts in. Key paths above return before
    # this point — an org-scoped key stays pinned to its org. No header =
    # first org (pre-existing behavior).
    if org_id_header is not None:
        try:
            requested_id = int(org_id_header)
        except ValueError:
            raise HTTPException(status_code=400, detail="X-Org-Id header must be a numeric org id") from None
        org = next((o for o in (user_orgs or []) if o["id"] == requested_id), None)
        if not org:
            raise HTTPException(
                status_code=403,
                detail="X-Org-Id does not match an organization you are a member of",
            )
        return org

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
