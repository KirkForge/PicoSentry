import logging

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from picosentry.serve.api.deps import auth_service, get_current_user
from picosentry.serve.api.models import RegisterRequest
from picosentry.serve.config.settings import settings

logger = logging.getLogger("picoshogun.auth")

router = APIRouter(prefix="/auth")


@router.post("/register", tags=["Authentication"])
async def register(request: RegisterRequest):
    if not settings.security.allow_registration:
        raise HTTPException(status_code=403, detail="Registration is disabled")
    # Registration always creates a viewer.  Admin/operator promotion must
    # happen through an authenticated admin-only path; the client cannot
    # self-elect.  ``RegisterRequest`` rejects a client-supplied ``role``
    # field at the Pydantic layer (``extra="forbid"``), so this is the
    # single source of truth for the new user's role.
    try:
        user_id = auth_service.create_user(
            username=request.username,
            password=request.password,
            email=request.email,
            role="viewer",
        )
        if not user_id:
            raise HTTPException(status_code=409, detail="Username already exists")
        return {"user_id": user_id, "username": request.username, "role": "viewer"}
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e)) from None


class _LoginRequest(BaseModel):
    username: str
    password: str


@router.post("/login", tags=["Authentication"])
async def login(request: _LoginRequest):
    token = auth_service.authenticate(request.username, request.password)
    if not token:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    user_info = auth_service.validate_token(token) or {}
    return {
        "access_token": token,
        "token_type": "bearer",
        "user_id": user_info.get("id"),
        "role": user_info.get("role"),
    }


class CreateAPIKeyRequest(BaseModel):
    name: str = "default"
    permissions: str = "read"


@router.post("/api-key", tags=["Authentication"])
async def create_api_key(
    request: CreateAPIKeyRequest,
    user: dict = Depends(get_current_user),
):
    api_key = auth_service.create_api_key(user["id"], name=request.name, permissions=request.permissions)
    return {"api_key": api_key, "name": request.name, "permissions": request.permissions}


@router.post("/api-key/{key_id}/rotate", tags=["Authentication"])
async def rotate_api_key(
    key_id: int,
    user: dict = Depends(get_current_user),
):
    new_key = auth_service.rotate_api_key(key_id, user["id"])
    if not new_key:
        raise HTTPException(status_code=404, detail="API key not found")
    return {"api_key": new_key, "message": "API key rotated successfully"}


@router.delete("/api-key/{key_id}", tags=["Authentication"], status_code=204)
async def revoke_api_key(
    key_id: int,
    user: dict = Depends(get_current_user),
):
    success = auth_service.revoke_api_key(key_id, user["id"])
    if not success:
        raise HTTPException(status_code=404, detail="API key not found")
