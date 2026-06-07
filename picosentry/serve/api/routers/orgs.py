import logging

from fastapi import APIRouter, Depends, HTTPException

from picosentry.serve.api.deps import get_current_user, require_role
from picosentry.serve.api.models import OrgCreateRequest, OrgTierUpgradeRequest
from picosentry.serve.services.orgs import Organization

logger = logging.getLogger("picoshogun.orgs")

router = APIRouter(prefix="/orgs")


@router.get("", tags=["Organizations"])
async def list_orgs(user: dict = Depends(get_current_user)):
    orgs = Organization.list_orgs_for_user(user["id"])
    return {"orgs": orgs, "count": len(orgs)}


@router.get("/{org_id}", tags=["Organizations"])
async def get_org(org_id: int, user: dict = Depends(get_current_user)):
    orgs = Organization.list_orgs_for_user(user["id"])
    org = next((o for o in orgs if o["id"] == org_id), None)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
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


@router.post("", tags=["Organizations"])
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


@router.get("/{org_id}/members", tags=["Organizations"])
async def list_org_members(
    org_id: int,
    user: dict = Depends(get_current_user),
):
    orgs = Organization.list_orgs_for_user(user["id"])
    if not any(o["id"] == org_id for o in orgs):
        raise HTTPException(status_code=403, detail="Not a member of this organization")
    members = Organization.get_members(org_id)
    return {"members": members, "count": len(members)}


@router.get("/{org_id}/usage", tags=["Organizations"])
async def get_org_usage(
    org_id: int,
    user: dict = Depends(get_current_user),
):
    orgs = Organization.list_orgs_for_user(user["id"])
    if not any(o["id"] == org_id for o in orgs):
        raise HTTPException(status_code=403, detail="Not a member of this organization")
    return Organization.get_usage(org_id)


@router.post("/{org_id}/upgrade", tags=["Organizations"])
async def upgrade_org_tier(
    org_id: int,
    request: OrgTierUpgradeRequest,
    user: dict = Depends(require_role("admin")),
):
    orgs = Organization.list_orgs_for_user(user["id"])
    org = next((o for o in orgs if o["id"] == org_id), None)
    if not org:
        raise HTTPException(status_code=404, detail="Organization not found")
    if org.get("user_role") != "admin":
        raise HTTPException(status_code=403, detail="Only admins can upgrade tier")
    success = Organization.update_tier(org_id, request.tier)
    if not success:
        raise HTTPException(status_code=400, detail="Invalid tier")
    return {"message": f"Organization upgraded to {request.tier}", "tier": request.tier}
