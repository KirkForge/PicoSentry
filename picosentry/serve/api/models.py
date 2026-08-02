from datetime import datetime
from typing import Any

import pydantic
from pydantic import BaseModel, Field

try:
    from pydantic import Extra  # type: ignore[attr-defined,unused-ignore]
except ImportError:
    Extra = None  # type: ignore[misc,assignment,no-redef,unused-ignore]


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
    #
    # The config is expressed differently for Pydantic v1 (``Config.extra``)
    # and v2 (``model_config``) so tests pass regardless of which version is
    # installed.
    if pydantic.VERSION.startswith("1."):

        class Config:
            extra = Extra.forbid
    else:
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
    target: str = Field(..., max_length=512, description="Path to project directory to scan")
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
    command: list[str] = Field(..., min_length=1, description="Command and arguments to execute under sandbox")
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


class AuthRegisterResponse(BaseModel):
    user_id: str
    username: str
    role: str


class AuthLoginResponse(BaseModel):
    access_token: str
    token_type: str
    user_id: str | None = None
    role: str | None = None


class APIKeyResponse(BaseModel):
    api_key: str
    name: str
    permissions: str


class APIKeyRotateResponse(BaseModel):
    api_key: str
    message: str


class EventIngestResponse(BaseModel):
    status: str
    event: dict[str, Any]


class ChainsPersistResponse(BaseModel):
    status: str
    events_persisted: int
    chains_persisted: int
    persist_enabled: bool


class OrgResponse(BaseModel):
    id: int
    name: str
    slug: str
    tier: str
    is_active: bool


class OrgCreateResponse(BaseModel):
    id: int
    name: str
    slug: str
    tier: str


class WebhookResponse(BaseModel):
    id: str
    url: str
    events: list[str]


class SchedulerJobResponse(BaseModel):
    job_id: int | str
    status: str


class ChainListResponse(BaseModel):
    total: int
    chains: list[dict[str, Any]]


class ChainNarrativeResponse(BaseModel):
    artifact_id: str
    narrative: str
    chain_score: float
    phase_count: int
    event_count: int


class EngineStatsResponse(BaseModel):
    artifacts: int
    events: int
    cached_chains: int
    avg_events_per_artifact: float


class AnomalyRuleResponse(BaseModel):
    id: str
    metric_name: str
    threshold: float
    comparison: str
    enabled: bool
    description: str


class HealthHistoryResponse(BaseModel):
    id: int
    component: str
    status: str
    message: str
    latency_ms: float
    created_at: str


class BackupResponse(BaseModel):
    status: str
    path: str


class BackupListResponse(BaseModel):
    backups: list[str]


class LogFileEntry(BaseModel):
    name: str
    size: int
    modified: str


class LogStatsResponse(BaseModel):
    directory: str
    file_count: int
    total_size_mb: float
    max_size_mb: float
    retention_days: int
    files: list[LogFileEntry]


class LogRotateResponse(BaseModel):
    status: str


class LogEntry(BaseModel):
    file: str
    line: str


class LogQueryResponse(BaseModel):
    entries: list[LogEntry]


class AuditStatsResponse(BaseModel):
    total_entries: int
    oldest_entry: str | None
    newest_entry: str | None
    top_actions: list[dict[str, Any]]
    retention_policy: dict[str, int]


class AuditPurgeResponse(BaseModel):
    model_config = {"extra": "allow"}

    purged: int | None = None
    retention_days: int | None = None


class EventHistoryItem(BaseModel):
    id: str
    type: str
    source: str
    payload: dict[str, Any]
    timestamp: str
    priority: str


class PluginsResponse(BaseModel):
    plugins: dict[str, Any]
    dirs: list[str]


class LivenessResponse(BaseModel):
    status: str


class ReadinessResponse(BaseModel):
    status: str


class ProjectRunResponse(BaseModel):
    model_config = {"extra": "allow"}

    success: bool
    duration: float
    output: str
    stderr: str
    intelligence_count: int


class BatchRunResponse(BaseModel):
    results: dict[str, Any]


class CorrelationResponse(BaseModel):
    project_id: str
    correlations: list[dict[str, Any]]


class ThreatScoreResponse(BaseModel):
    threat_score: float
    total_threats: int
    timestamp: str


class AlertAcknowledgeResponse(BaseModel):
    status: str
    alert_id: int


class ReportSummaryResponse(BaseModel):
    total_projects: int
    active_projects: int
    failed_projects: int
    success_rate: float


class ProjectReportResponse(BaseModel):
    model_config = {"extra": "allow"}

    project: dict[str, Any]
    recent_runs: list[dict[str, Any]]
    intelligence: list[dict[str, Any]]
    correlations: list[dict[str, Any]]


class DashboardHealthCheck(BaseModel):
    component: str
    status: str
    message: str | None = None
    latency_ms: float | None = None


class DashboardHealthSummary(BaseModel):
    overall: str
    checks: list[DashboardHealthCheck]


class DashboardSummaryResponse(BaseModel):
    status: dict[str, Any]
    health: DashboardHealthSummary
    recent_projects: list[dict[str, Any]]
    recent_intelligence: list[dict[str, Any]]
    recent_alerts: list[dict[str, Any]]
    pending_alerts_count: int
    timestamp: str


class ScanRuleItem(BaseModel):
    id: str
    description: str


class ScanRulesResponse(BaseModel):
    rules: list[ScanRuleItem]


class DefaultPolicyResponse(BaseModel):
    model_config = {"extra": "allow"}

    name: str
    version: str
    default_action: str
    fail_closed: bool
    rules: list[dict[str, Any]]


class WebhookListResponse(BaseModel):
    webhooks: dict[str, dict[str, Any]]


class SchedulerJobItem(BaseModel):
    model_config = {"extra": "allow"}

    id: int
    name: str
    cron: str
    command: str
    enabled: bool
    next_run: str | None
    last_run: str | None
    last_status: str | None


class SchedulerJobListResponse(BaseModel):
    jobs: list[SchedulerJobItem]


class SchedulerJobStatusResponse(BaseModel):
    job_id: int
    status: str


class AnomalyAlertItem(BaseModel):
    model_config = {"extra": "allow"}

    rule_id: str
    metric_name: str
    value: float | int | None
    threshold: float | int | None
    comparison: str | None = None
    severity: str | None = None
    description: str | None = None
    timestamp: str | None = None


class AnomalyCheckAlertItem(BaseModel):
    rule_id: str
    metric: str
    value: float | int | None
    threshold: float | int | None
    severity: str | None = None


class AnomalyCheckResponse(BaseModel):
    triggered: int
    alerts: list[AnomalyCheckAlertItem]


class OrgListResponse(BaseModel):
    orgs: list[dict[str, Any]]
    count: int


class OrgDetailResponse(BaseModel):
    model_config = {"extra": "allow"}

    id: int
    name: str
    slug: str
    tier: str
    api_key: str
    is_active: bool
    created_at: str
    usage: dict[str, Any]


class OrgMemberItem(BaseModel):
    model_config = {"extra": "allow"}

    id: int
    username: str
    email: str | None = None
    last_login: str | None = None
    role: str
    joined_at: str | None = None


class OrgMemberListResponse(BaseModel):
    members: list[OrgMemberItem]
    count: int


class OrgUsageBucket(BaseModel):
    used: int
    limit: int
    pct: float


class OrgUsageResponse(BaseModel):
    tier: str
    users: OrgUsageBucket
    projects: OrgUsageBucket
    runs_today: OrgUsageBucket
    storage_mb: int


class OrgUpgradeResponse(BaseModel):
    message: str
    tier: str


class ChainsSummaryResponse(BaseModel):
    total_chains: int
    total_events: int
    total_artifacts: int
    layers_active: int
    layer_coverage: list[dict[str, str]]
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    avg_chain_score: float
    phase_distribution: dict[str, int]
    top_chains: list[dict[str, Any]]


class MetricsResponse(BaseModel):
    uptime_seconds: float
    metrics: dict[str, Any]
    counters: dict[str, float]
