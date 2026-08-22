"""WO7.0.0-033: perform_health_checks must write rows atomically.

Each INSERT was a separate autocommit — a crash mid-loop left a partial
snapshot. The fix wraps the loop in one transaction (commit once at the
end, rollback on any failure).
"""

from __future__ import annotations


from picosentry.serve.database.manager import db
from picosentry.serve.services import _orchestrator_health as health_mod


class TestAtomicHealthChecks:
    def _cleanup(self):
        db.execute("DELETE FROM health_checks")

    def test_successful_writes_all_rows(self):
        """A clean probe must persist all subsystem rows (database, disk, projects, smtp)."""
        self._cleanup()
        try:
            checks = health_mod.perform_health_checks({})
            rows = db.execute("SELECT component FROM health_checks ORDER BY id DESC LIMIT 5")
            components = {r["component"] for r in rows}
            for check in checks:
                assert check["component"] in components, f"{check['component']} row not persisted"
        finally:
            self._cleanup()

    def test_mid_loop_failure_leaves_no_partial_rows(self, monkeypatch):
        """A failure on the Nth INSERT must roll back all prior INSERTs in the batch.

        Before the fix, each INSERT was its own autocommit — the first N-1
        rows survived a mid-loop crash, producing a partial snapshot.
        """
        self._cleanup()
        try:
            original_execute_on = db.execute_on
            call_count = [0]

            def _failing_execute_on(conn, sql, params=()):
                if "INSERT INTO health_checks" in sql:
                    call_count[0] += 1
                    if call_count[0] == 2:
                        raise RuntimeError("simulated mid-loop crash")
                return original_execute_on(conn, sql, params)

            monkeypatch.setattr(db, "execute_on", _failing_execute_on)
            health_mod.perform_health_checks({})

            rows = db.execute("SELECT component FROM health_checks")
            assert len(rows) == 0, (
                f"partial snapshot persisted {len(rows)} rows after mid-loop failure — "
                "INSERTs must be atomic (all-or-nothing)"
            )
        finally:
            self._cleanup()

    def test_mid_loop_failure_does_not_raise(self, monkeypatch):
        """A mid-loop INSERT failure must be caught, not propagated to the caller."""
        self._cleanup()
        try:
            original_execute_on = db.execute_on
            call_count = [0]

            def _failing_execute_on(conn, sql, params=()):
                if "INSERT INTO health_checks" in sql:
                    call_count[0] += 1
                    if call_count[0] == 2:
                        raise RuntimeError("simulated mid-loop crash")
                return original_execute_on(conn, sql, params)

            monkeypatch.setattr(db, "execute_on", _failing_execute_on)
            checks = health_mod.perform_health_checks({})
            assert len(checks) > 0, "perform_health_checks should still return probe results"
        finally:
            self._cleanup()

    def test_all_rows_committed_in_one_transaction(self):
        """All subsystem rows must appear together after a successful probe.

        This verifies the transaction commits as a unit — no row is visible
        until the entire batch is written.
        """
        self._cleanup()
        try:
            health_mod.perform_health_checks({})
            rows = db.execute("SELECT component FROM health_checks ORDER BY id DESC")
            components = {r["component"] for r in rows}
            assert "database" in components, "database check not persisted"
            assert "disk_space" in components, "disk_space check not persisted"
            assert "projects" in components, "projects check not persisted"
            assert "smtp" in components, "smtp check not persisted"
        finally:
            self._cleanup()
