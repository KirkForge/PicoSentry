"""Extended tests for obfuscation detection rule."""

import json
import tempfile
import unittest
from pathlib import Path

from picosentry.scan.models import Severity
from picosentry.scan.rules.obfuscation import (
    BASE64_EXEC_PATTERN,
    EVAL_PATTERN,
    HEX_STRING_PATTERN,
    SKIP_EXTENSIONS,
    UNICODE_ESCAPE_PATTERN,
    _scan_file,
    detect_obfuscation,
)


def _make_project(tmp_path, pkg_json, files=None):
    """Create a minimal project with package.json and optional files."""
    (tmp_path / "package.json").write_text(json.dumps(pkg_json))
    if files:
        for rel, content in files.items():
            fpath = tmp_path / rel
            fpath.parent.mkdir(parents=True, exist_ok=True)
            fpath.write_text(content)
    return tmp_path


class TestPatternRegexes(unittest.TestCase):
    """Test each obfuscation regex pattern."""

    def test_eval_pattern(self):
        pattern = EVAL_PATTERN[1]
        self.assertIsNotNone(pattern.search("eval("))
        self.assertIsNotNone(pattern.search("eval ("))
        self.assertIsNotNone(pattern.search("Function("))
        self.assertIsNotNone(pattern.search("new Function("))

    def test_hex_string_pattern(self):
        pattern = HEX_STRING_PATTERN[1]
        self.assertIsNotNone(pattern.search('"\\x41\\x42\\x43\\x44"'))
        self.assertIsNone(pattern.search('"abc"'))  # too short

    def test_base64_exec_pattern(self):
        pattern = BASE64_EXEC_PATTERN[1]
        self.assertIsNotNone(pattern.search("atob('c3RyaW5n') && eval("))

    def test_unicode_escape_pattern(self):
        pattern = UNICODE_ESCAPE_PATTERN[1]
        self.assertIsNotNone(pattern.search('"\\u0041\\u0042\\u0043\\u0044"'))
        self.assertIsNone(pattern.search('"AB"'))  # no unicode escapes


class TestScanFile(unittest.TestCase):
    """Test _scan_file on individual files."""

    def test_eval_in_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "test.js"
            f.write_text('eval("console.log(1)")')
            findings = _scan_file(f)
            self.assertGreater(len(findings), 0)
            self.assertEqual(findings[0].rule_id, "L2-OBFS-001")
            self.assertEqual(findings[0].severity, Severity.CRITICAL)

    def test_hex_string_in_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "test.js"
            f.write_text('var x = "\\x41\\x42\\x43\\x44\\x45";')
            findings = _scan_file(f)
            self.assertGreater(len(findings), 0)
            self.assertTrue(any(f.rule_id == "L2-OBFS-002" for f in findings))

    def test_unicode_escape_in_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "test.js"
            f.write_text('var x = "\\u0041\\u0042\\u0043\\u0044";')
            findings = _scan_file(f)
            self.assertGreater(len(findings), 0)
            self.assertTrue(any(f.rule_id == "L2-OBFS-004" for f in findings))

    def test_skip_binary_extensions(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "image.png"
            f.write_text("eval(")
            findings = _scan_file(f)
            self.assertEqual(len(findings), 0)

    def test_skip_large_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "big.js"
            f.write_text("/* padding */\n" * 50000)  # > 500KB
            findings = _scan_file(f)
            self.assertEqual(len(findings), 0)

    def test_file_not_found(self):
        findings = _scan_file(Path("/nonexistent/file.js"))
        self.assertEqual(len(findings), 0)

    def test_line_number_tracking(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "test.js"
            f.write_text("var a = 1;\neval('hello');\nvar b = 2;")
            findings = _scan_file(f)
            self.assertGreater(len(findings), 0)
            self.assertEqual(findings[0].line, 2)

    def test_multiple_matches_in_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            f = Path(tmp) / "test.js"
            f.write_text('eval("a");\neval("b");')
            findings = _scan_file(f)
            self.assertEqual(len(findings), 2)

    def test_skip_extensions(self):
        self.assertIn(".png", SKIP_EXTENSIONS)
        self.assertIn(".jpg", SKIP_EXTENSIONS)
        self.assertIn(".map", SKIP_EXTENSIONS)
        self.assertIn(".woff", SKIP_EXTENSIONS)


class TestDetectObfuscation(unittest.TestCase):
    """Test detect_obfuscation on project trees."""

    def test_root_js_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            _make_project(Path(tmp), {"name": "test", "version": "1.0.0"}, {"index.js": 'eval("malicious")'})
            findings = detect_obfuscation(Path(tmp), Path(tmp) / "corpus")
            self.assertGreater(len(findings), 0)

    def test_node_modules_scan(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text('{"name": "test"}')
            nm = root / "node_modules" / "evil"
            nm.mkdir(parents=True)
            (nm / "package.json").write_text('{"name": "evil", "version": "1.0.0"}')
            (nm / "index.js").write_text('eval("pwned")')
            findings = detect_obfuscation(root, root / "corpus")
            self.assertGreater(len(findings), 0)

    def test_no_js_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            _make_project(Path(tmp), {"name": "test", "version": "1.0.0"}, {"style.css": "body { color: red; }"})
            findings = detect_obfuscation(Path(tmp), Path(tmp) / "corpus")
            self.assertEqual(len(findings), 0)

    def test_scoped_package(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "package.json").write_text('{"name": "test"}')
            scoped = root / "node_modules" / "@scope" / "pkg"
            scoped.mkdir(parents=True)
            (scoped / "package.json").write_text('{"name": "@scope/pkg", "version": "1.0.0"}')
            (scoped / "index.js").write_text('Function("return this")()')
            findings = detect_obfuscation(root, root / "corpus")
            self.assertGreater(len(findings), 0)
            self.assertIn("@scope", findings[0].package)

    def test_empty_project(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "package.json").write_text('{"name": "empty"}')
            findings = detect_obfuscation(Path(tmp), Path(tmp) / "corpus")
            self.assertEqual(len(findings), 0)


if __name__ == "__main__":
    unittest.main()
