"""WO7-007 — PEP 508 dependency name extraction in advisory collector.

The split-chain ``dep.split(">")[0].split("<")[0]...`` mangles three
real-world PEP 508 forms: extras, ``~=`` compatible-release, and markers.
``packaging.requirements.Requirement`` extracts the correct name from all.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

from picosentry.scan.rules.advisory_check import _collect_pypi_packages, _pep508_name


class TestPep508NameExtraction:
    def test_extras_stripped(self):
        assert _pep508_name("requests[security]>=2.20") == "requests"

    def test_compatible_release_tilde_stripped(self):
        assert _pep508_name("requests~=2.20") == "requests"

    def test_marker_stripped(self):
        assert _pep508_name('requests; python_version<"3.11"') == "requests"

    def test_url_spec_name(self):
        assert _pep508_name("name@ https://example.com/whl") == "name"

    def test_plain_version(self):
        assert _pep508_name("requests>=2.20") == "requests"

    def test_bare_name(self):
        assert _pep508_name("requests") == "requests"

    def test_exact_match(self):
        assert _pep508_name("requests===2.20.0") == "requests"

    def test_malformed_falls_back_gracefully(self):
        assert _pep508_name("requests[") == "requests"


class TestCollectPypiPackagesPep508:
    def _make_pyproject(self, deps: list[str]) -> Path:
        tmp = Path(tempfile.mkdtemp())
        dep_str = ", ".join(f"'{d}'" for d in deps)
        content = f"[project]\nname = 'test-project'\nversion = '0.1.0'\ndependencies = [{dep_str}]\n"
        (tmp / "pyproject.toml").write_text(content)
        return tmp

    def test_extras_form_extracts_correct_name(self):
        target = self._make_pyproject(["requests[security]>=2.20"])
        packages = _collect_pypi_packages(target)
        names = [p[0] for p in packages]
        assert "requests" in names
        assert "requests[security]" not in names

    def test_compatible_release_extracts_correct_name(self):
        target = self._make_pyproject(["requests~=2.20"])
        packages = _collect_pypi_packages(target)
        names = [p[0] for p in packages]
        assert "requests" in names
        assert "requests~" not in names

    def test_marker_extracts_correct_name(self):
        target = self._make_pyproject(['requests; python_version<"3.11"'])
        packages = _collect_pypi_packages(target)
        names = [p[0] for p in packages]
        assert "requests" in names
        assert not any("python_version" in n for n in names)
