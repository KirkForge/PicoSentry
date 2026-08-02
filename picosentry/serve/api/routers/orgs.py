import logging

from fastapi import APIRouter, Depends, HTTPException

from picosentry.serve.api.deps import get_current_user, require_org_membership, require_role
from picosentry.serve.api.models import (
    OrgCreateRequest,
    OrgCreateResponse,
    OrgDetailResponse,
    OrgListResponse,
    OrgMemberListResponse,
    OrgTierUpgradeRequest,
    OrgUpgradeResponse,
    OrgUsageResponse,
)
from picosentry.serve.services.orgs import Organization

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
    org_id = Organization.create(
        name=request.name,
        slug=request.slug,
        owner_user_id=user["id"],
        tier=request.tier,
    )
    if not org_id:
        raise HTTPException(status_code=409, detail="Organization slug already exists")
    return {
        "id": org_id,
        "name": request.name,
        "slug": request.slug,
        "tier": request.tier,
    }


@router.get("/{org_id}/members", response_model=OrgMemberListResponse, tags=["Organizations"])
async def list_org_members(
    org_id: int,
    org: dict = Depends(require_org_membership),
):
    members = Organization.get_members(org_id)
    return {"members": members, "count": len(members)}


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
