from datetime import datetime, timezone
from typing import Any

from picosentry.serve.database.manager import db


def _threat_level(score: float) -> str:
    if score >= 50:
        return "critical"
    if score >= 20:
        return "high"
    if score >= 5:
        return "medium"
    return "low"


def get_threat_score(intel: Any) -> dict[str, Any]:
    scores = intel.threat_scores
    aggregate = sum(scores.values())
    return {
        "aggregate": aggregate,
        "breakdown": dict(sorted(scores.items(), key=lambda x: -x[1])[:10]),
        "level": _threat_level(aggregate),
    }


def update_project_stats(project_id: str) -> None:
    stats = db.execute_one(
        """
        SELECT
            COUNT(*) as total,
            SUM(CASE WHEN status = 'completed' THEN 1 ELSE 0 END) as success,
            AVG(duration_seconds) as avg_dur
        FROM project_runs
        WHERE project_id = ?
    """,
        (project_id,),
    )

    if stats:
        success_rate = (stats["success"] / stats["total"] * 100) if stats["total"] > 0 else 0
        db.execute_insert(
            """
            UPDATE projects
            SET last_run = ?, run_count = ?, success_rate = ?, avg_duration = ?
            WHERE id = ?
        """,
            (
                datetime.now(timezone.utc),
                stats["total"],
                success_rate,
                stats["avg_dur"] or 0,
                project_id,
            ),
        )
