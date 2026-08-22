"""WO7-025 — gitlab template github format hard-fails.

The gitlab template passed --output for all formats including github; the
github format needs --sarif-file. WO6-021 fixed action.yml for the same
bug; the gitlab template was not updated.
"""

from __future__ import annotations

import re
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
TEMPLATE_PATH = REPO_ROOT / "ci-templates" / "gitlab-picosentry.yml"


def _template_content() -> str:
    return TEMPLATE_PATH.read_text()


class TestGitlabTemplateGithubFormat:
    def test_github_format_uses_sarif_file(self):
        content = _template_content()
        assert "--sarif-file" in content, "github format must use --sarif-file"

    def test_non_github_format_uses_output(self):
        content = _template_content()
        assert "--output" in content, "non-github formats must use --output"

    def test_github_format_routed_correctly(self):
        content = _template_content()
        assert 'PICOSENTRY_FORMAT" = "github"' in content or '"github"' in content
        assert re.search(r"github.*--sarif-file|--sarif-file.*github", content, re.DOTALL)

    def test_sarif_count_parsing_includes_github(self):
        content = _template_content()
        assert "sarif|github)" in content, "findings-count parsing must include github format"

    def test_fail_on_findings_mentions_github(self):
        content = _template_content()
        assert "github" in content.lower()

    def test_no_unconditional_output_for_all_formats(self):
        content = _template_content()
        lines = content.splitlines()
        for line in lines:
            stripped = line.strip()
            if stripped.startswith("ARGS=(scan"):
                assert "--output" not in stripped, "ARGS init must not unconditionally include --output for all formats"
