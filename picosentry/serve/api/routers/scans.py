import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException

from picosentry.sandbox.l3.engine import sandbox_run as _sandbox_run
from picosentry.sandbox.l3.policy import default_policy as _default_policy
from picosentry.scan.engine import create_default_engine as _create_engine
from picosentry.serve.api.deps import require_role
from picosentry.serve.api.models import SandboxRunRequest, SandboxRunResponse, ScanRequest, ScanResponse
from picosentry.serve.config.settings import settings

logger = logging.getLogger("picoshogun.scans")

router = APIRouter()


@router.post("/scans", response_model=ScanResponse, tags=["Scans"])
async def create_scan(
    request: ScanRequest,
    user: dict = Depends(require_role("operator")),
):
    # Workspace-root gate (P0 fix).  Without an explicit root configured
    # we reject all scan requests rather than falling back to "any path
    # on the server is fair game".  Operators must opt in by setting
    # PICOSHOGUN_SCANS_WORKSPACE_ROOT.
    workspace_root = settings.security.scans_workspace_root
    if workspace_root is None:
        raise HTTPException(
            status_code=503,
            detail=(
                "POST /scans is disabled: PICOSHOGUN_SCANS_WORKSPACE_ROOT is not "
                "configured. Set it to a directory operators are allowed to scan."
            ),
        )

    target = Path(request.target).resolve()
    try:
        target.relative_to(workspace_root.resolve())
    except ValueError:
        # ``relative_to`` raises ValueError when target is outside the
        # root.  We deliberately don't echo the rejected path back to
        # the caller — the verdict flagged filesystem probing as the
        # main risk and "outside workspace" is enough for the operator
        # to know.
        logger.warning(
            "Scan target outside workspace: user=%s target=%s workspace=%s",
            user.get("username"), target, workspace_root,
        )
        raise HTTPException(
            status_code=403,
            detail="Target path is outside the configured scan workspace",
        )

    if not target.exists():
        raise HTTPException(status_code=400, detail=f"Target path does not exist: {request.target}")

    engine = _create_engine()
    result = engine.scan(target, rules=request.rules)

    return ScanResponse(
        scan_id=result.scan_id,
        started_at=result.started_at,
        target=result.target,
        engine_version=result.engine_version,
        findings_count=len(result.findings),
        findings=[f.to_dict() for f in result.findings],
        stats=result.stats.to_dict(),
    )


@router.get("/scans/rules", tags=["Scans"])
async def list_scan_rules(user: dict = Depends(require_role("viewer"))):
    from picosentry.scan.rules import RULE_INFO

    return {
        "rules": [
            {"id": rule_id, "description": info.get("description", "")}
            for rule_id, info in RULE_INFO.items()
        ]
    }


@router.post("/sandboxes", response_model=SandboxRunResponse, tags=["Sandbox"])
async def run_sandbox(
    request: SandboxRunRequest,
    user: dict = Depends(require_role("operator")),
):
    try:
        result = _sandbox_run(request.command, timeout=request.timeout)
    except Exception as exc:
        raise HTTPException(status_code=500, detail=f"Sandbox execution failed: {exc}") from exc

    return SandboxRunResponse(
        run_id=result.run_id,
        timestamp=result.timestamp,
        command=result.command,
        overall_verdict=result.overall_verdict.value if hasattr(result.overall_verdict, "value") else str(result.overall_verdict),
        exit_code=result.exit_code,
        duration_ms=result.duration_ms,
        events=[e.to_dict() for e in result.events],
        policy_name=result.policy_name,
    )


@router.get("/sandboxes/policies/default", tags=["Sandbox"])
async def get_default_policy(user: dict = Depends(require_role("viewer"))):
    policy = _default_policy()
    return policy.to_dict() if hasattr(policy, "to_dict") else {"policy": str(policy)}
