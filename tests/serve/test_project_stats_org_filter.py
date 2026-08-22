"""WO7.0.0-005 — update_project_stats must filter by org_id.

The SELECT had only project_id in WHERE — every org's runs blended into one
count for shared/global projects. This gate proves two orgs sharing a project
get independent run counts after ingesting the same project.
"""

from __future__ import annotations

from picosentry.serve.database.manager import db

_PROJECT_ID = "wo7-stats-shared-project"
_ORG_A = 778001
_ORG_B = 778002


def _insert_run(project_id, org_id, status="completed", duration=1.0):
    return db.execute_insert(
        "INSERT INTO project_runs (project_id, run_start, status, org_id, duration_seconds) VALUES (?, ?, ?, ?, ?)",
        (project_id, "2026-01-01T00:00:00+00:00", status, org_id, duration),
    )


def _ensure_project(project_id):
    db.execute_insert(
        "INSERT OR IGNORE INTO projects (id, run_count, success_rate, avg_duration) VALUES (?, 0, 0.0, 0.0)",
        (project_id,),
    )


def _get_project_row(project_id):
    return db.execute_one("SELECT run_count, success_rate FROM projects WHERE id = ?", (project_id,))


def _cleanup(project_id, *org_ids):
    db.execute(f"DELETE FROM project_runs WHERE project_id = '{project_id}'")
    db.execute(f"DELETE FROM projects WHERE id = '{project_id}'")


class TestUpdateProjectStatsOrgFilter:
    """WO7.0.0-005: update_project_stats counts only the caller's org's runs."""

    def setup_method(self):
        _cleanup(_PROJECT_ID)
        _ensure_project(_PROJECT_ID)

    def teardown_method(self):
        _cleanup(_PROJECT_ID)

    def test_org_a_count_excludes_org_b_runs(self):
        from picosentry.serve.services._orchestrator_stats import update_project_stats

        _insert_run(_PROJECT_ID, _ORG_A, status="completed", duration=2.0)
        _insert_run(_PROJECT_ID, _ORG_A, status="completed", duration=4.0)
        _insert_run(_PROJECT_ID, _ORG_B, status="completed", duration=8.0)

        update_project_stats(_PROJECT_ID, org_id=_ORG_A)

        row = _get_project_row(_PROJECT_ID)
        assert row["run_count"] == 2, f"org A should see 2 runs, got {row['run_count']}"

    def test_org_b_count_excludes_org_a_runs(self):
        from picosentry.serve.services._orchestrator_stats import update_project_stats

        _insert_run(_PROJECT_ID, _ORG_A, status="completed", duration=2.0)
        _insert_run(_PROJECT_ID, _ORG_A, status="completed", duration=4.0)
        _insert_run(_PROJECT_ID, _ORG_B, status="failed", duration=8.0)

        update_project_stats(_PROJECT_ID, org_id=_ORG_B)

        row = _get_project_row(_PROJECT_ID)
        assert row["run_count"] == 1, f"org B should see 1 run, got {row['run_count']}"

    def test_null_org_counts_only_null_runs(self):
        from picosentry.serve.services._orchestrator_stats import update_project_stats

        _insert_run(_PROJECT_ID, None, status="completed", duration=2.0)
        _insert_run(_PROJECT_ID, _ORG_A, status="completed", duration=4.0)

        update_project_stats(_PROJECT_ID, org_id=None)

        row = _get_project_row(_PROJECT_ID)
        assert row["run_count"] == 1, f"null-org should see 1 run, got {row['run_count']}"

    def test_default_org_id_none_counts_null_runs(self):
        """Backwards compat: calling without org_id counts only NULL-org runs."""
        from picosentry.serve.services._orchestrator_stats import update_project_stats

        _insert_run(_PROJECT_ID, None, status="completed", duration=2.0)
        _insert_run(_PROJECT_ID, _ORG_A, status="completed", duration=4.0)
        _insert_run(_PROJECT_ID, _ORG_A, status="completed", duration=6.0)

        update_project_stats(_PROJECT_ID)

        row = _get_project_row(_PROJECT_ID)
        assert row["run_count"] == 1, f"default (None) should see 1 null-org run, got {row['run_count']}"
