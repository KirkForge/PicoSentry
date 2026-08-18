import logging

from fastapi import APIRouter, Depends, HTTPException

from picosentry.serve.api.deps import get_current_user, require_org_membership, require_permission, require_role
from picosentry.serve.api.models import (
    OrgCreateRequest,
    OrgCreateResponse,
    OrgDetailResponse,
    OrgListResponse,
    OrgMemberInviteRequest,
    OrgMemberInviteResponse,
    OrgMemberListResponse,
    OrgMemberRemoveResponse,
    OrgMemberRoleResponse,
    OrgMemberRoleUpdateRequest,
    OrgTierUpgradeRequest,
    OrgUpgradeResponse,
    OrgUsageResponse,
)
from picosentry.serve.services.orgs import Organization
from picosentry.serve.services.rbac import Permission

logger = logging.getLogger("picoshogun.orgs")

router = APIRouter(prefix="/orgs")


@router.get("", response_model=OrgListResponse, tags=["Organizations"])
async def list_orgs(user: dict = Depends(get_current_user)):
    orgs = Organization.list_orgs_for_user(user["id"])
    return {"orgs": orgs, "count": len(orgs)}


@router.get("/{org_id}", response_model=OrgDetailResponse, tags=["Organizations"])
async def get_org(org_id: int, org: dict = Depends(require_org_membership)):
    usage = Organization.get_usage(org_id)
    return {
        "id": org["id"],
        "name": org["name"],
        "slug": org["slug"],
        "tier": org["tier"],
        "api_key": "hidden",
        "is_active": org["is_active"],
        "created_at": org["created_at"],
        "usage": usage,
    }


@router.post("", tags=["Organizations"], status_code=201, response_model=OrgCreateResponse)
async def create_org(
    request: OrgCreateRequest,
    user: dict = Depends(get_current_user),
):
    result = Organization.create(
        name=request.name,
        slug=request.slug,
        owner_user_id=user["id"],
        tier=request.tier,
    )
    if result is None:
        # Organization.create logs the cause; a swallowed internal failure
        # must not masquerade as "slug already exists" (pg-live lesson).
        logger.error("Organization creation failed internally (slug=%r)", request.slug)
        raise HTTPException(status_code=500, detail="Organization creation failed")
    if not result:
        raise HTTPException(status_code=409, detail="Organization slug already exists")
    return {
        "id": result["org_id"],
        "name": request.name,
        "slug": request.slug,
        "tier": request.tier,
        "api_key": result["api_key"],
    }


@router.get("/{org_id}/members", response_model=OrgMemberListResponse, tags=["Organizations"])
async def list_org_members(
    org_id: int,
    org: dict = Depends(require_org_membership),
):
    members = Organization.get_members(org_id)
    return {"members": members, "count": len(members)}


def _require_org_admin(org: dict) -> None:
    """Member management is org-admin work: the ADMIN_USERS permission
    (global role) AND org-level admin membership — the same dual gate the
    tier-upgrade endpoint uses. A user who is merely a member of org B
    cannot touch it even with a global admin role."""
    if org.get("user_role") != "admin":
        raise HTTPException(status_code=403, detail="Only organization admins can manage members")


@router.post(
    "/{org_id}/members",
    response_model=OrgMemberInviteResponse,
    tags=["Organizations"],
    status_code=201,
)
async def invite_org_member(
    org_id: int,
    request: OrgMemberInviteRequest,
    org: dict = Depends(require_org_membership),
    user: dict = Depends(require_permission(Permission.ADMIN_USERS)),
):
    _require_org_admin(org)
    return Organization.add_member(org_id, request.user_id, request.role)


@router.patch(
    "/{org_id}/members/{user_id}",
    response_model=OrgMemberRoleResponse,
    tags=["Organizations"],
)
async def change_org_member_role(
    org_id: int,
    user_id: int,
    request: OrgMemberRoleUpdateRequest,
    org: dict = Depends(require_org_membership),
    user: dict = Depends(require_permission(Permission.ADMIN_USERS)),
):
    _require_org_admin(org)
    changed = Organization.update_member_role(org_id, user_id, request.role)
    if not changed:
        raise HTTPException(status_code=404, detail=f"User {user_id} is not a member of this organization")
    return {"user_id": user_id, "role": request.role}


@router.delete(
    "/{org_id}/members/{user_id}",
    response_model=OrgMemberRemoveResponse,
    tags=["Organizations"],
)
async def remove_org_member(
    org_id: int,
    user_id: int,
    org: dict = Depends(require_org_membership),
    user: dict = Depends(require_permission(Permission.ADMIN_USERS)),
):
    _require_org_admin(org)
    removed = Organization.remove_member(org_id, user_id)
    if not removed:
        raise HTTPException(status_code=404, detail=f"User {user_id} is not a member of this organization")
    return {"user_id": user_id, "removed": True}


@router.get("/{org_id}/usage", response_model=OrgUsageResponse, tags=["Organizations"])
async def get_org_usage(
    org_id: int,
    org: dict = Depends(require_org_membership),
):
    return Organization.get_usage(org_id)


@router.post("/{org_id}/upgrade", response_model=OrgUpgradeResponse, tags=["Organizations"])
async def upgrade_org_tier(
    org_id: int,
    request: OrgTierUpgradeRequest,
    org: dict = Depends(require_org_membership),
    user: dict = Depends(require_role("admin")),
):
    if org.get("user_role") != "admin":
        raise HTTPException(status_code=403, detail="Only admins can upgrade tier")
    success = Organization.update_tier(org_id, request.tier)
    if not success:
        raise HTTPException(status_code=400, detail="Invalid tier")
    return {"message": f"Organization upgraded to {request.tier}", "tier": request.tier}
