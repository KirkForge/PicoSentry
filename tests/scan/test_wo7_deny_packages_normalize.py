"""WO7-030 — deny_packages policy comparison was case-sensitive and not PEP 503 normalized.

``d_name == pkg_name`` with no normalization — ``deny 'flask'`` won't catch
installed ``Flask``. PEP 503 normalization (``-``/``_``/``.`` → ``-``, lowercase)
fixes both case and separator differences.
"""

from __future__ import annotations

import unittest

from picosentry.scan.policy_pkg.engine import Policy


class TestDenyPackagesNormalize(unittest.TestCase):
    def test_case_insensitive_match(self):
        p = Policy(deny_packages=["flask"])
        violations = p.check_packages({"Flask"})
        self.assertEqual(len(violations), 1)
        self.assertEqual(violations[0].violation_type, "deny_package")

    def test_normalized_separator_match(self):
        p = Policy(deny_packages=["flask-pytest"])
        violations = p.check_packages({"Flask_Pytest"})
        self.assertEqual(len(violations), 1)

    def test_dot_separator_match(self):
        p = Policy(deny_packages=["flask-pytest"])
        violations = p.check_packages({"Flask.Pytest"})
        self.assertEqual(len(violations), 1)

    def test_no_false_positive_on_near_match(self):
        p = Policy(deny_packages=["flask"])
        violations = p.check_packages({"flask-thing"})
        self.assertEqual(len(violations), 0)

    def test_no_false_positive_on_prefix(self):
        p = Policy(deny_packages=["flask"])
        violations = p.check_packages({"flaskful"})
        self.assertEqual(len(violations), 0)

    def test_versioned_deny_matches_name_only(self):
        p = Policy(deny_packages=["flask"])
        violations = p.check_packages({"Flask@2.0.0"})
        self.assertEqual(len(violations), 1)

    def test_versioned_deny_with_version_matches(self):
        p = Policy(deny_packages=["flask@2.0.0"])
        violations = p.check_packages({"Flask@2.0.0"})
        self.assertEqual(len(violations), 1)

    def test_deny_uppercase_matches_installed_lowercase(self):
        p = Policy(deny_packages=["Flask"])
        violations = p.check_packages({"flask"})
        self.assertEqual(len(violations), 1)

    def test_deny_normalized_with_underscore_matches_dashed(self):
        p = Policy(deny_packages=["flask_pytest"])
        violations = p.check_packages({"flask-pytest"})
        self.assertEqual(len(violations), 1)

    def test_multiple_matches(self):
        p = Policy(deny_packages=["flask", "requests"])
        violations = p.check_packages({"Flask", "Requests", "lodash"})
        self.assertEqual(len(violations), 2)
        denied_pkgs = {v.detail.get("package") for v in violations}
        self.assertEqual(denied_pkgs, {"Flask", "Requests"})


if __name__ == "__main__":
    unittest.main()
