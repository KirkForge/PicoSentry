"""WO7-012 — PyPI typosquat known_legitimate uses normalized names but deps are raw.

``known_legitimate`` stores PEP 503-normalized names (``ruamel-yaml``);
deps are collected raw (``ruamel.yaml``). The compare didn't normalize →
a package was its own typosquat at edit distance 1.
"""

from __future__ import annotations

from pathlib import Path

from picosentry.scan.rules.typosquat import _detect_all_typosquat_standard, _PYPI_CONFIG, _pep503_normalize


class TestPep503Normalize:
    def test_dot_to_dash(self):
        assert _pep503_normalize("ruamel.yaml") == "ruamel-yaml"

    def test_underscore_to_dash(self):
        assert _pep503_normalize("python_dateutil") == "python-dateutil"

    def test_already_normalized(self):
        assert _pep503_normalize("ruamel-yaml") == "ruamel-yaml"

    def test_lowercase(self):
        assert _pep503_normalize("Requests") == "requests"

    def test_mixed_separators(self):
        assert _pep503_normalize("foo.bar_baz-qux") == "foo-bar-baz-qux"


class TestKnownLegitimateNormalized:
    def test_ruamel_yaml_not_self_typosquat(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("[project]\nname = 'test'\ndependencies = ['ruamel.yaml']\n")
        findings = _detect_all_typosquat_standard(tmp_path, Path("."), _PYPI_CONFIG)
        assert not any(f.package == "ruamel.yaml" for f in findings), (
            "ruamel.yaml must match known_legitimate (ruamel-yaml) after normalization — no self-typosquat"
        )

    def test_python_dateutil_not_self_typosquat(self, tmp_path: Path):
        (tmp_path / "pyproject.toml").write_text("[project]\nname = 'test'\ndependencies = ['python_dateutil']\n")
        findings = _detect_all_typosquat_standard(tmp_path, Path("."), _PYPI_CONFIG)
        assert not any(f.package == "python_dateutil" for f in findings)
