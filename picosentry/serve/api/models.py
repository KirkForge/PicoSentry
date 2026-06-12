from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field


class ProjectRunRequest(BaseModel):
    project_id: str = Field(..., description="Project ID to run")
    timeout: int | None = Field(300, ge=10, le=3600)
    parameters: dict[str, Any] | None = Field(None)


class BatchRunRequest(BaseModel):
    project_ids: list[str] = Field(..., min_length=1, max_length=20)
    timeout: int | None = Field(300, ge=10, le=3600)


class ProjectStatus(BaseModel):
    id: str
    name: str
    category: str
    priority: int
    status: str
    version: str
    last_run: datetime | None
    run_count: int
    success_rate: float
    avg_duration: float


class AlertResponse(BaseModel):
    id: int
    project_id: str | None
    alert_type: str
    severity: str
    message: str
    channel: str
    sent: bool
    created_at: datetime


class IntelligenceItem(BaseModel):
    id: int
    source_project: str
    intel_type: str
    severity: str
    data: dict
    confidence: float
    created_at: datetime


class SystemStatus(BaseModel):
    projects_total: int
    projects_active: int
    projects_failed: int
    active_threats: int
    pending_alerts: int
    threat_score: float
    system_health: str
    uptime_seconds: float
    timestamp: datetime


class HealthCheck(BaseModel):
    component: str
    status: str
    message: str
    latency_ms: float
    timestamp: datetime


class HealthReadiness(BaseModel):
    overall: str  # healthy | degraded | critical
    checks: list[HealthCheck] = []
    timestamp: datetime | None = None


class RegisterRequest(BaseModel):
    # Role is intentionally NOT a request field.  Registration always
    # creates a viewer; admin/operator promotion must happen through an
    # authenticated admin-only path.  ``extra="forbid"`` makes any client
    # that tries to send a ``role`` (or any other unknown field) get a 422
    # response, so this contract is loud rather than silent.
    model_config = {"extra": "forbid"}

    username: str = Field(..., min_length=3, max_length=50)
    password: str = Field(..., min_length=8)
    email: str | None = Field(None)


class WebhookCreateRequest(BaseModel):
    url: str = Field(..., description="Webhook callback URL (HTTPS recommended)")
    events: list[str] = Field(default=["*"], description="Event types to subscribe to")
    name: str = Field(..., min_length=1, max_length=100, description="Webhook name")
    secret: str | None = Field(default=None, min_length=16, max_length=128, description="HMAC signing secret")


class SchedulerJobCreateRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200, description="Job name")
    cron: str = Field(..., min_length=1, description="Cron expression or 'every N minute/hour/day'")
    command: str = Field(..., description="Job command: batch, run, report, backup, cleanup")
    params: dict = Field(default={}, description="Job parameters (strings, numbers, booleans only)")
    enabled: bool = Field(default=True, description="Whether the job is active")


class OrgTierUpgradeRequest(BaseModel):
    tier: str = Field(..., pattern="^(free|starter|pro|enterprise)$")


class OrgCreateRequest(BaseModel):
    name: str = Field(..., min_length=2, max_length=100)
    slug: str = Field(..., min_length=2, max_length=50, pattern="^[a-z0-9-]+$")
    tier: str = Field("free", pattern="^(free|starter|pro|enterprise)$")


class OrgMemberInviteRequest(BaseModel):
    user_id: int = Field(..., gt=0)
    role: str = Field("member", pattern="^(admin|member|viewer)$")


class ScanRequest(BaseModel):
    target: str = Field(..., description="Path to project directory to scan")
    rules: list[str] | None = Field(None, description="Subset of rule IDs to run")
    format: str = Field("json", pattern="^(json|sarif)$")


class ScanResponse(BaseModel):
    scan_id: str
    started_at: str
    target: str
    engine_version: str
    findings_count: int
    findings: list[dict[str, Any]]
    stats: dict[str, Any]


class SandboxRunRequest(BaseModel):
    command: list[str] = Field(..., description="Command and arguments to execute under sandbox")
    policy_file: str | None = Field(None, description="Path to policy YAML file (default: built-in)")
    timeout: float | None = Field(None, ge=1, le=3600, description="Override wall-time limit (seconds)")
    format: str = Field("json", pattern="^(json|sarif)$")


class SandboxRunResponse(BaseModel):
    run_id: str
    timestamp: str
    command: list[str]
    overall_verdict: str
    exit_code: int | None
    duration_ms: int
    events: list[dict[str, Any]]
    policy_name: str
