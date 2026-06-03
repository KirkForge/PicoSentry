"""Tests for corpus governance module."""

import pytest

from picosentry.scan.corpus_governance import (
    CorpusGovernance,
    CorpusReleaseNotes,
    CorpusSource,
    CorpusTrustLevel,
    FalsePositiveReport,
    FreshnessReport,
)


class TestCorpusTrustLevel:
    def test_all_levels(self):
        assert CorpusTrustLevel.ALL_LEVELS == (
            "first-party",
            "commercial",
            "community",
            "internal",
            "quarantined",
        )

    def test_compare(self):
        assert CorpusTrustLevel.compare("first-party", "community") > 0
        assert CorpusTrustLevel.compare("community", "first-party") < 0
        assert CorpusTrustLevel.compare("community", "community") == 0

    def test_min_for_production(self):
        assert CorpusTrustLevel.min_for_production() == "community"


class TestCorpusSource:
    def test_defaults(self):
        src = CorpusSource(name="test")
        assert src.trust_level == CorpusTrustLevel.FIRST_PARTY
        assert src.imported_at != ""

    def test_is_stale_no_review(self):
        src = CorpusSource(name="test", reviewed_at="")
        assert src.is_stale() is True

    def test_is_stale_recent(self):
        from datetime import datetime, timezone

        recent = datetime.now(timezone.utc).isoformat()
        src = CorpusSource(name="test", reviewed_at=recent)
        assert src.is_stale() is False

    def test_serialization(self):
        src = CorpusSource(name="test", trust_level="community", upstream="OSV")
        d = src.to_dict()
        restored = CorpusSource.from_dict(d)
        assert restored.name == "test"
        assert restored.trust_level == "community"
        assert restored.upstream == "OSV"


class TestFalsePositiveReport:
    def test_defaults(self):
        report = FalsePositiveReport(
            finding_id="L2-FORK-001:lodash",
            rule_id="L2-FORK-001",
            package="lodash",
        )
        assert report.status == "open"
        assert report.reported_at != ""

    def test_serialization(self):
        report = FalsePositiveReport(
            finding_id="test",
            rule_id="L2-RULE",
            package="pkg",
            justification="Not a real finding",
        )
        d = report.to_dict()
        restored = FalsePositiveReport.from_dict(d)
        assert restored.finding_id == "test"
        assert restored.justification == "Not a real finding"


class TestCorpusReleaseNotes:
    def test_summary(self):
        notes = CorpusReleaseNotes(
            version="abc123",
            added=[{"id": "CVE-1", "name": "new", "reason": "new RCE"}],
            removed=[{"id": "CVE-2", "name": "old", "reason": "withdrawn"}],
        )
        summary = notes.summary()
        assert "abc123" in summary
        assert "+1 added" in summary
        assert "-1 removed" in summary

    def test_serialization(self):
        notes = CorpusReleaseNotes(version="1.0", released_by="test")
        d = notes.to_dict()
        restored = CorpusReleaseNotes.from_dict(d)
        assert restored.version == "1.0"


class TestFreshnessReport:
    def test_empty_report(self):
        report = FreshnessReport()
        assert report.total_ioc_count() == 0
        assert report.sla_compliance()["compliant"] is True

    def test_stale_detection(self):
        src_stale = CorpusSource(name="stale", reviewed_at="2020-01-01T00:00:00Z")
        src_fresh = CorpusSource(name="fresh", reviewed_at="2099-01-01T00:00:00Z")
        report = FreshnessReport(sources=[src_stale, src_fresh])
        stale = report.stale_sources(max_age_days=30)
        assert len(stale) == 1
        assert stale[0].name == "stale"


class TestCorpusGovernance:
    @pytest.fixture
    def gov(self, tmp_path):
        return CorpusGovernance(governance_dir=tmp_path / "gov")

    def test_register_source(self, gov):
        src = CorpusSource(name="test", trust_level="community", reviewer="alice")
        gov.register_source(src)
        assert gov.get_source("test") is not None
        assert gov.get_source("test").trust_level == "community"

    def test_register_invalid_trust(self, gov):
        with pytest.raises(ValueError, match="Invalid trust level"):
            gov.register_source(CorpusSource(name="test", trust_level="unknown"))

    def test_list_sources(self, gov):
        gov.register_source(CorpusSource(name="a", trust_level="first-party"))
        gov.register_source(CorpusSource(name="b", trust_level="community"))
        sources = gov.list_sources()
        assert len(sources) == 2
        # First-party should come first
        assert sources[0].trust_level == "first-party"

    def test_remove_source(self, gov):
        gov.register_source(CorpusSource(name="test"))
        assert gov.remove_source("test") is True
        assert gov.remove_source("nonexistent") is False

    def test_false_positive_workflow(self, gov):
        report = FalsePositiveReport(
            finding_id="L2-FORK-001:lodash",
            rule_id="L2-FORK-001",
            package="lodash",
            justification="Legitimate fork",
        )
        gov.report_false_positive(report)
        fps = gov.list_false_positives()
        assert len(fps) == 1

        # Triage
        result = gov.triage_false_positive(
            finding_id="L2-FORK-001:lodash",
            triager="bob",
            status="accepted",
            resolution="suppress",
        )
        assert result is True

    def test_release_notes(self, gov):
        notes = CorpusReleaseNotes(version="1.0", released_by="alice")
        gov.add_release_notes(notes)
        retrieved = gov.get_release_notes("1.0")
        assert len(retrieved) == 1
        assert retrieved[0].version == "1.0"

    def test_validate_trust(self, gov):
        gov.register_source(CorpusSource(name="good", trust_level="community"))
        result = gov.validate_trust("good")
        assert result["valid"] is True

        result = gov.validate_trust("nonexistent")
        assert result["valid"] is False

    def test_validate_quarantined(self, gov):
        gov.register_source(CorpusSource(name="quar", trust_level="quarantined"))
        result = gov.validate_trust("quar")
        assert result["valid"] is False
        assert "quarantined" in result["reason"]
