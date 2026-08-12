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
    MFAEnrollResponse,
    MFAVerifyResponse,
    RegisterRequest,
    TokenRevokeResponse,
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
    totp_code: str | None = Field(None, min_length=6, max_length=6)


@router.post("/login", tags=["Authentication"], response_model=AuthLoginResponse)
async def login(request: _LoginRequest, fastapi_request: Request):
    _check_auth_rate_limit(fastapi_request)
    result = await asyncio.to_thread(auth_service.login, request.username, request.password, request.totp_code)
    status = result.get("status")
    if status == "locked":
        raise HTTPException(status_code=423, detail="Account locked due to too many failed attempts")
    if status == "mfa_required":
        methods = ",".join(result.get("mfa_methods", ["totp"]))
        raise HTTPException(status_code=401, detail="MFA code required", headers={"X-MFA-Methods": methods})
    if status != "ok":
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {
        "access_token": result["token"],
        "token_type": "bearer",
        "user_id": result.get("user_id"),
        "role": result.get("role"),
    }


class _MFAEnrollRequest(BaseModel):
    model_config = {"extra": "forbid"}


class _MFAVerifyRequest(BaseModel):
    model_config = {"extra": "forbid"}

    code: str = Field(..., min_length=6, max_length=6)


class _RevokeTokenRequest(BaseModel):
    model_config = {"extra": "forbid"}

    jti: str = Field(..., min_length=1, max_length=128)


@router.post("/mfa/enroll", tags=["Authentication"], response_model=MFAEnrollResponse)
async def mfa_enroll(
    request: _MFAEnrollRequest,
    user: dict = Depends(get_current_user),
):
    result = auth_service.enroll_totp(user["id"], user["username"])
    if not result:
        raise HTTPException(status_code=500, detail="TOTP enrollment unavailable")
    return result


@router.post("/mfa/verify", tags=["Authentication"], response_model=MFAVerifyResponse)
async def mfa_verify(
    request: _MFAVerifyRequest,
    user: dict = Depends(get_current_user),
):
    if not auth_service.verify_totp_for_user(user["id"], request.code):
        raise HTTPException(status_code=400, detail="Invalid TOTP code")
    return {"verified": True}


class _WebAuthnRegisterChallengeRequest(BaseModel):
    model_config = {"extra": "forbid"}


class _WebAuthnRegisterVerifyRequest(BaseModel):
    model_config = {"extra": "forbid"}

    challenge: str = Field(..., min_length=1, max_length=512)
    credential: dict = Field(...)


class _WebAuthnAuthChallengeRequest(BaseModel):
    model_config = {"extra": "forbid"}

    username: str = Field(..., min_length=1, max_length=50)


class _WebAuthnAuthVerifyRequest(BaseModel):
    model_config = {"extra": "forbid"}

    username: str = Field(..., min_length=1, max_length=50)
    password: str = Field(..., min_length=1, max_length=72)
    challenge: str = Field(..., min_length=1, max_length=512)
    credential: dict = Field(...)


@router.post("/webauthn/register-challenge", tags=["Authentication"])
async def webauthn_register_challenge(
    request: _WebAuthnRegisterChallengeRequest,
    user: dict = Depends(get_current_user),
):
    result = auth_service.webauthn_register_challenge(user["id"], user["username"], user.get("username", ""))
    if not result:
        raise HTTPException(status_code=500, detail="WebAuthn enrollment unavailable")
    return result


@router.post("/webauthn/register-verify", tags=["Authentication"])
async def webauthn_register_verify(
    request: _WebAuthnRegisterVerifyRequest,
    user: dict = Depends(get_current_user),
):
    if not auth_service.webauthn_register_verify(user["id"], request.challenge, request.credential):
        raise HTTPException(status_code=400, detail="WebAuthn registration failed")
    return {"verified": True}


@router.post("/webauthn/authenticate-challenge", tags=["Authentication"])
async def webauthn_auth_challenge(
    request: _WebAuthnAuthChallengeRequest,
    fastapi_request: Request,
):
    _check_auth_rate_limit(fastapi_request)
    user = await asyncio.to_thread(auth_service.get_user_id_by_username, request.username)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    result = auth_service.webauthn_auth_challenge(user)
    if not result:
        raise HTTPException(status_code=401, detail="No passkeys registered")
    return result


@router.post("/webauthn/authenticate-verify", tags=["Authentication"], response_model=AuthLoginResponse)
async def webauthn_auth_verify(
    request: _WebAuthnAuthVerifyRequest,
    fastapi_request: Request,
):
    _check_auth_rate_limit(fastapi_request)
    # The passkey assertion is the second factor; the password must still
    # validate. Verify the assertion first so we don't hand back a token to
    # a user whose password is wrong but whose passkey was accepted.
    user_id = await asyncio.to_thread(auth_service.get_user_id_by_username, request.username)
    if not user_id:
        raise HTTPException(status_code=401, detail="Invalid credentials")
    if not auth_service.webauthn_auth_verify(user_id, request.challenge, request.credential):
        raise HTTPException(status_code=401, detail="WebAuthn assertion failed")
    result = await asyncio.to_thread(auth_service.login, request.username, request.password, None, True)
    if result.get("status") != "ok":
        raise HTTPException(status_code=401, detail="Invalid credentials")
    return {
        "access_token": result["token"],
        "token_type": "bearer",
        "user_id": result.get("user_id"),
        "role": result.get("role"),
    }


@router.post("/revoke", tags=["Authentication"], response_model=TokenRevokeResponse)
async def revoke_token(
    request: _RevokeTokenRequest,
    user: dict = Depends(get_current_user),
):
    auth_service.revoke_token(request.jti, user["id"])
    return {"revoked": True}


class CreateAPIKeyRequest(BaseModel):
    model_config = {"extra": "forbid"}

    name: str = Field(default="default", max_length=128)
    permissions: str = Field(default="read", pattern="^(read|write|admin)$")
    # Optional RBAC scope for the minted key.  When omitted the key inherits
    # a role derived from ``permissions``; ``role`` cannot exceed the caller's
    # own role — enforced against the authenticated user below.
    role: str | None = Field(default=None, pattern="^(viewer|operator|admin)$")
    org_id: int | None = Field(default=None, gt=0)


@router.post("/api-key", tags=["Authentication"], status_code=201, response_model=APIKeyResponse)
async def create_api_key(
    request: CreateAPIKeyRequest,
    fastapi_request: Request,
    user: dict = Depends(get_current_user),
):
    _check_auth_rate_limit(fastapi_request)
    role_levels = {"viewer": 0, "operator": 1, "admin": 2}
    caller_level = role_levels.get(user.get("role", "viewer"), 0)
    if request.role is not None and role_levels.get(request.role, 0) > caller_level:
        raise HTTPException(status_code=403, detail="Cannot mint a key with a role higher than your own")
    api_key = auth_service.create_api_key(
        user["id"],
        name=request.name,
        permissions=request.permissions,
        role=request.role,
        org_id=request.org_id,
    )
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
