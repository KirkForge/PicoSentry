"""Tests that picosentry/experimental.py stays a valid source of truth."""

from __future__ import annotations

from pathlib import Path

from picosentry.experimental import COMPONENT_STATUS, render_status_table


class TestExperimentalStatus:
    def test_all_statuses_are_known(self):
        """Every component must declare a recognised maturity level."""
        valid = {"Stable", "Beta", "Experimental"}
        for component in COMPONENT_STATUS:
            assert component.status in valid, f"{component.name} has unknown status {component.status!r}"

    def test_names_are_unique(self):
        """The status table cannot list the same component twice."""
        names = [c.name for c in COMPONENT_STATUS]
        assert len(names) == len(set(names))

    def test_notes_are_non_empty(self):
        for component in COMPONENT_STATUS:
            assert component.notes.strip(), f"{component.name} has empty notes"

    def test_render_status_table_is_markdown(self):
        table = render_status_table()
        lines = table.splitlines()
        assert len(lines) >= 3
        assert lines[0] == "| Component | Status | Notes |"
        assert lines[1] == "|-----------|--------|-------|"
        for line in lines[2:]:
            assert line.startswith("| ") and line.endswith(" |")
            assert line.count("|") == 4

    def test_rendered_table_matches_readme(self):
        """The README must contain the rendered table from experimental.py.

        This keeps the human-readable README in sync with the programmatic
        source of truth. If this test fails, regenerate the table with
        ``picosentry.experimental.render_status_table()``.
        """
        readme_path = Path(__file__).parent.parent / "README.md"
        readme = readme_path.read_text(encoding="utf-8")
        table = render_status_table()
        assert table in readme, "README.md status table is out of sync with picosentry/experimental.py"
