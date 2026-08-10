import asyncio
import logging
import threading
import time
from collections import defaultdict

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field

from picosentry.serve.api.deps import auth_service, get_current_user
from picosentry.serve.api.models import (
    APIKeyResponse,
    APIKeyRotateResponse,
    AuthLoginResponse,
    AuthRegisterResponse,
    RegisterRequest,
)
from picosentry.serve.config.settings import settings

logger = logging.getLogger("picoshogun.auth")

router = APIRouter(prefix="/auth")

_AUTH_RATE_LIMIT: dict[str, list[float]] = defaultdict(list)
_AUTH_RATE_LOCK = threading.Lock()
_AUTH_RATE_MAX = 5
_AUTH_RATE_WINDOW = 60
_AUTH_RATE_MAX_ENTRIES = 10000


def _check_auth_rate_limit(request: Request) -> None:
    client_ip = request.client.host if request.client else "unknown"
    now = time.time()
    with _AUTH_RATE_LOCK:
        _AUTH_RATE_LIMIT[client_ip] = [t for t in _AUTH_RATE_LIMIT[client_ip] if now - t < _AUTH_RATE_WINDOW]
        if len(_AUTH_RATE_LIMIT[client_ip]) >= _AUTH_RATE_MAX:
            raise HTTPException(status_code=429, detail="Too many authentication attempts")
        _AUTH_RATE_LIMIT[client_ip].append(now)
        if len(_AUTH_RATE_LIMIT) > _AUTH_RATE_MAX_ENTRIES:
            oldest_ips = sorted(
                _AUTH_RATE_LIMIT,
                key=lambda ip: _AUTH_RATE_LIMIT[ip][0] if _AUTH_RATE_LIMIT[ip] else float("inf"),
            )[: len(_AUTH_RATE_LIMIT) // 4]
            for ip in oldest_ips:
                del _AUTH_RATE_LIMIT[ip]


@router.post("/register", tags=["Authentication"], status_code=201, response_model=AuthRegisterResponse)
async def register(request: RegisterRequest, fastapi_request: Request):
    _check_auth_rate_limit(fastapi_request)
    if not settings.security.allow_registration:
        raise HTTPException(status_code=403, detail="Registration is disabled")
    # Registration always creates a viewer.  Admin/operator promotion must
    # happen through an authenticated admin-only path; the client cannot
    # self-elect.  ``RegisterRequest`` rejects a client-supplied ``role``
    # field at the Pydantic layer (``extra="forbid"``), so this is the
    # single source of truth for the new user's role.
    user_id = await asyncio.to_thread(
        auth_service.create_user,
        username=request.username,
        password=request.password,
        email=request.email,
        role="viewer",
    )
    if not user_id:
        raise HTTPException(status_code=409, detail="Username already exists")
    return {"user_id": user_id, "username": request.username, "role": "viewer"}


class _LoginRequest(BaseModel):
    model_config = {"extra": "forbid"}

    username: str
    password: str = Field(..., min_length=1, max_length=72)


@router.post("/login", tags=["Authentication"], response_model=AuthLoginResponse)
async def login(request: _LoginRequest, fastapi_request: Request):
    _check_auth_rate_limit(fastapi_request)
    token = await asyncio.to_thread(auth_service.authenticate, request.username, request.password)
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
    model_config = {"extra": "forbid"}

    name: str = Field(default="default", max_length=128)
    permissions: str = Field(default="read", pattern="^(read|write|admin)$")


@router.post("/api-key", tags=["Authentication"], status_code=201, response_model=APIKeyResponse)
async def create_api_key(
    request: CreateAPIKeyRequest,
    fastapi_request: Request,
    user: dict = Depends(get_current_user),
):
    _check_auth_rate_limit(fastapi_request)
    api_key = auth_service.create_api_key(user["id"], name=request.name, permissions=request.permissions)
    return {"api_key": api_key, "name": request.name, "permissions": request.permissions}


@router.post("/api-key/{key_id}/rotate", tags=["Authentication"], response_model=APIKeyRotateResponse)
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
