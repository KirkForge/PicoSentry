"""Supply chain scan and sandbox endpoints (API v1).

All scanner and sandbox functionality is built-in — no separate package required.
"""
import logging
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException

from picosentry.serve.api.deps import require_role
from picosentry.serve.api.models import SandboxRunRequest, SandboxRunResponse, ScanRequest, ScanResponse
from picosentry.scan.engine import create_default_engine as _create_engine
from picosentry.sandbox.l3.engine import sandbox_run as _sandbox_run
from picosentry.sandbox.l3.policy import default_policy as _default_policy

logger = logging.getLogger("picoshogun.scans")

router = APIRouter()


@router.post("/scans", response_model=ScanResponse, tags=["Scans"])
async def create_scan(
    request: ScanRequest,
    user: dict = Depends(require_role("viewer")),
):
    """Run an L2 supply chain scan on a project directory."""
    target = Path(request.target).resolve()
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
    """List available supply chain scanner rules."""
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
    """Run a command under L3 sandbox policy."""
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
    """Get the default L3 sandbox policy."""
    policy = _default_policy()
    return policy.to_dict() if hasattr(policy, "to_dict") else {"policy": str(policy)}
