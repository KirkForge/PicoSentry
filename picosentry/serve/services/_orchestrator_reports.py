from typing import Any, Protocol

from picosentry.serve.database.manager import db


class _StatusProvider(Protocol):
    """Duck-typed interface for summary report generation."""

    def get_status(self, org_id: int | None = None) -> dict[str, Any]: ...

    @property
    def intel(self) -> Any: ...


class _ProjectProvider(Protocol):
    """Duck-typed interface for project report generation."""

    def get_project(self, project_id: str, org_id: int | None = None) -> dict | None: ...

    def get_correlations(self, project_id: str, org_id: int | None = None) -> list[dict]: ...


def generate_summary_report(orch: _StatusProvider, org_id: int | None = None) -> str:
    status = orch.get_status(org_id=org_id)

    # An org-scoped report must contain only that org's data: the global
    # registry count and the project-keyed threat breakdown would otherwise
    # blend every tenant's numbers into org X's scheduled report.
    org_project_ids: set[str] | None = None
    if org_id is not None:
        from picosentry.serve.services.orgs import Organization

        org_project_ids = Organization.list_project_ids(org_id)
        status["projects_total"] = len(org_project_ids)

    report = f"""
╔══════════════════════════════════════════════════════════════════╗
║     PicoShogun Command Centre Report                  ║
╚══════════════════════════════════════════════════════════════════╝

Generated: {status["timestamp"]}
System Health: {status["system_health"].upper()}
Uptime: {status["uptime_seconds"]:.0f} seconds

OVERALL STATUS
──────────────
Projects:      {status["projects_total"]} total
Active Runs:   {status["projects_active"]}
Failed (24h):  {status["projects_failed"]}
Threat Level:  {status["threat_score"]:.1f}/100
Active Intel:  {status["active_threats"]} critical/high items
Pending Alerts: {status["pending_alerts"]}

THREAT SCORE BREAKDOWN
──────────────────────
"""
    for pid, score in sorted(orch.intel.threat_scores.items(), key=lambda x: -x[1])[:10]:
        if org_project_ids is not None and pid not in org_project_ids:
            continue
        report += f"  {pid}: {score:.1f}\n"

    return report


def generate_project_report(
    orch: _ProjectProvider,
    project_id: str,
    org_id: int | None = None,
) -> dict[str, Any] | None:
    project = orch.get_project(project_id, org_id=org_id)
    if not project:
        return None

    org_filter = "AND org_id = ?" if org_id is not None else ""
    params_runs: list[Any] = [project_id]
    if org_id is not None:
        params_runs.append(org_id)
    runs = db.execute(
        f"""
        SELECT * FROM project_runs
        WHERE project_id = ? {org_filter}
        ORDER BY run_start DESC LIMIT 10
    """,
        tuple(params_runs),
    )

    params_intel: list[Any] = [project_id]
    if org_id is not None:
        params_intel.append(org_id)
    intel = db.execute(
        f"""
        SELECT * FROM intelligence
        WHERE source_project = ? {org_filter}
        ORDER BY created_at DESC LIMIT 10
    """,
        tuple(params_intel),
    )

    return {
        "project": project,
        "recent_runs": [dict(r) for r in runs],
        "intelligence": [dict(r) for r in intel],
        "correlations": orch.get_correlations(project_id, org_id=org_id),
    }
