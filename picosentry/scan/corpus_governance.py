"""
Corpus governance -- trust model, source attribution, freshness metrics,
and false-positive reporting for enterprise PicoSentry deployments.

Provides:
- Corpus trust classification (first-party, community, commercial, internal, quarantined)
- Source attribution and provenance tracking
- Freshness metrics and update SLA monitoring
- False-positive reporting and severity review workflow
- Corpus release notes generation
- Rollback and pinning support

Usage:
    from picosentry.scan.corpus_governance import (
        CorpusTrustLevel, CorpusSource, CorpusGovernance,
        FreshnessReport, FalsePositiveReport,
    )
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, ClassVar

from picosentry.scan.audit import audit

logger = logging.getLogger("picosentry.corpus_governance")


# -- Trust levels -----------------------------------------------------------


class CorpusTrustLevel:
    """Trust classification for corpus packs.

    Enterprise buyers need to know the provenance and trust level of
    every indicator in the corpus. Trust levels control:
    - Whether a pack is used automatically or requires approval
    - How stale a pack can be before alerting
    - Whether findings from that pack carry evidence attribution
    """

    FIRST_PARTY = "first-party"
    COMMERCIAL = "commercial"
    COMMUNITY = "community"
    INTERNAL = "internal"
    QUARANTINED = "quarantined"

    ALL_LEVELS = (FIRST_PARTY, COMMERCIAL, COMMUNITY, INTERNAL, QUARANTINED)

    _ORDER: ClassVar[dict[str, int]] = {
        FIRST_PARTY: 4,
        COMMERCIAL: 3,
        INTERNAL: 2,
        COMMUNITY: 1,
        QUARANTINED: 0,
    }

    @staticmethod
    def compare(a: str, b: str) -> int:
        return CorpusTrustLevel._ORDER.get(a, 0) - CorpusTrustLevel._ORDER.get(b, 0)

    @staticmethod
    def min_for_production() -> str:
        return CorpusTrustLevel.COMMUNITY


# -- Source attribution -----------------------------------------------------


@dataclass
class CorpusSource:
    """Provenance record for a corpus pack or IoC source."""

    name: str
    trust_level: str = CorpusTrustLevel.FIRST_PARTY
    origin_url: str = ""
    upstream: str = ""
    reviewer: str = ""
    reviewed_at: str = ""
    imported_at: str = ""
    sha256: str = ""
    ioc_count: int = 0
    expires_at: str = ""
    notes: str = ""

    def __post_init__(self) -> None:
        if not self.imported_at:
            self.imported_at = datetime.now(timezone.utc).isoformat()

    def is_stale(self, max_age_days: int = 30) -> bool:
        if not self.reviewed_at:
            return True
        try:
            reviewed = datetime.fromisoformat(self.reviewed_at)
            age = (datetime.now(timezone.utc) - reviewed.astimezone(timezone.utc)).days
            return age > max_age_days
        except (ValueError, TypeError):
            return True

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "trust_level": self.trust_level,
            "origin_url": self.origin_url,
            "upstream": self.upstream,
            "reviewer": self.reviewer,
            "reviewed_at": self.reviewed_at,
            "imported_at": self.imported_at,
            "sha256": self.sha256,
            "ioc_count": self.ioc_count,
            "expires_at": self.expires_at,
            "notes": self.notes,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> CorpusSource:
        return CorpusSource(
            name=d.get("name", ""),
            trust_level=d.get("trust_level", CorpusTrustLevel.COMMUNITY),
            origin_url=d.get("origin_url", ""),
            upstream=d.get("upstream", ""),
            reviewer=d.get("reviewer", ""),
            reviewed_at=d.get("reviewed_at", ""),
            imported_at=d.get("imported_at", ""),
            sha256=d.get("sha256", ""),
            ioc_count=d.get("ioc_count", 0),
            expires_at=d.get("expires_at", ""),
            notes=d.get("notes", ""),
        )


# -- False-positive reporting ----------------------------------------------


@dataclass
class FalsePositiveReport:
    """A false-positive report for a finding or IoC."""

    finding_id: str
    rule_id: str
    package: str
    severity: str = ""
    reported_by: str = ""
    reported_at: str = ""
    justification: str = ""
    status: str = "open"
    triaged_by: str = ""
    triaged_at: str = ""
    resolution: str = ""
    suppression_id: str = ""

    def __post_init__(self) -> None:
        if not self.reported_at:
            self.reported_at = datetime.now(timezone.utc).isoformat()

    def to_dict(self) -> dict[str, Any]:
        return {
            "finding_id": self.finding_id,
            "rule_id": self.rule_id,
            "package": self.package,
            "severity": self.severity,
            "reported_by": self.reported_by,
            "reported_at": self.reported_at,
            "justification": self.justification,
            "status": self.status,
            "triaged_by": self.triaged_by,
            "triaged_at": self.triaged_at,
            "resolution": self.resolution,
            "suppression_id": self.suppression_id,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> FalsePositiveReport:
        return FalsePositiveReport(
            finding_id=d.get("finding_id", ""),
            rule_id=d.get("rule_id", ""),
            package=d.get("package", ""),
            severity=d.get("severity", ""),
            reported_by=d.get("reported_by", ""),
            reported_at=d.get("reported_at", ""),
            justification=d.get("justification", ""),
            status=d.get("status", "open"),
            triaged_by=d.get("triaged_by", ""),
            triaged_at=d.get("triaged_at", ""),
            resolution=d.get("resolution", ""),
            suppression_id=d.get("suppression_id", ""),
        )


# -- Corpus release notes ---------------------------------------------------


@dataclass
class CorpusReleaseNotes:
    """Release notes for a corpus version."""

    version: str
    released_at: str = ""
    released_by: str = ""
    trust_level: str = CorpusTrustLevel.FIRST_PARTY
    added: list[dict[str, str]] = field(default_factory=list)
    changed: list[dict[str, str]] = field(default_factory=list)
    removed: list[dict[str, str]] = field(default_factory=list)
    migration_notes: str = ""
    sha256: str = ""

    def __post_init__(self) -> None:
        if not self.released_at:
            self.released_at = datetime.now(timezone.utc).isoformat()

    def summary(self) -> str:
        lines = [
            f"Corpus Release {self.version} ({self.released_at[:10]})",
            f"  Trust level: {self.trust_level}",
            f"  +{len(self.added)} added  ~{len(self.changed)} changed  -{len(self.removed)} removed",
        ]
        if self.migration_notes:
            lines.append(f"  Migration: {self.migration_notes}")
        return "\n".join(lines)

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "released_at": self.released_at,
            "released_by": self.released_by,
            "trust_level": self.trust_level,
            "added": self.added,
            "changed": self.changed,
            "removed": self.removed,
            "migration_notes": self.migration_notes,
            "sha256": self.sha256,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> CorpusReleaseNotes:
        return CorpusReleaseNotes(
            version=d.get("version", ""),
            released_at=d.get("released_at", ""),
            released_by=d.get("released_by", ""),
            trust_level=d.get("trust_level", CorpusTrustLevel.FIRST_PARTY),
            added=d.get("added", []),
            changed=d.get("changed", []),
            removed=d.get("removed", []),
            migration_notes=d.get("migration_notes", ""),
            sha256=d.get("sha256", ""),
        )


# -- Freshness report ------------------------------------------------------


@dataclass
class FreshnessReport:
    """Report on corpus freshness and update SLA compliance."""

    sources: list[CorpusSource] = field(default_factory=list)
    generated_at: str = ""

    def __post_init__(self) -> None:
        if not self.generated_at:
            self.generated_at = datetime.now(timezone.utc).isoformat()

    def stale_sources(self, max_age_days: int = 30) -> list[CorpusSource]:
        return [s for s in self.sources if s.is_stale(max_age_days)]

    def sources_by_trust(self) -> dict[str, list[CorpusSource]]:
        groups: dict[str, list[CorpusSource]] = {}
        for s in self.sources:
            groups.setdefault(s.trust_level, []).append(s)
        return groups

    def total_ioc_count(self) -> int:
        return sum(s.ioc_count for s in self.sources)

    def sla_compliance(self, max_age_days: int = 30) -> dict[str, Any]:
        stale = self.stale_sources(max_age_days)
        total = len(self.sources)
        compliant_count = total - len(stale)

        return {
            "compliant": len(stale) == 0,
            "compliance_pct": (compliant_count / total * 100) if total > 0 else 100.0,
            "total_sources": total,
            "stale_sources": len(stale),
            "max_age_days": max_age_days,
            "stale_details": [
                {"name": s.name, "trust_level": s.trust_level, "reviewed_at": s.reviewed_at} for s in stale
            ],
        }

    def to_dict(self) -> dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "total_sources": len(self.sources),
            "total_iocs": self.total_ioc_count(),
            "sources": [s.to_dict() for s in self.sources],
            "sla_compliance_30d": self.sla_compliance(30),
            "stale_sources": [s.to_dict() for s in self.stale_sources(30)],
        }


# -- Governance engine ------------------------------------------------------


class CorpusGovernance:
    """Corpus governance engine for enterprise deployments.

    Manages trust levels, source attribution, freshness monitoring,
    false-positive reporting, and release notes for all corpus sources.
    All mutations emit audit events for compliance traceability.
    """

    def __init__(self, governance_dir: Path | None = None) -> None:
        self.governance_dir = governance_dir or (Path.home() / ".local" / "share" / "picosentry" / "governance")
        self.governance_dir.mkdir(parents=True, exist_ok=True)
        self._sources: dict[str, CorpusSource] = {}
        self._fp_reports: dict[str, FalsePositiveReport] = {}
        self._release_notes: list[CorpusReleaseNotes] = []
        self._load_state()

    def _state_path(self) -> Path:
        return self.governance_dir / "governance_state.json"

    def _fp_dir(self) -> Path:
        d = self.governance_dir / "false_positives"
        d.mkdir(parents=True, exist_ok=True)
        return d

    def _load_state(self) -> None:
        state_path = self._state_path()
        if not state_path.is_file():
            return

        try:
            data = json.loads(state_path.read_text(encoding="utf-8"))
        except (json.JSONDecodeError, OSError):
            logger.warning("Failed to load governance state from %s", state_path)
            return

        sources_data = data.get("sources", {})
        # Handle both dict format (keyed by name) and list format
        items = sources_data.values() if isinstance(sources_data, dict) else sources_data
        for s in items:
            src = CorpusSource.from_dict(s)
            self._sources[src.name] = src

        for r in data.get("release_notes", []):
            self._release_notes.append(CorpusReleaseNotes.from_dict(r))

    def _save_state(self) -> None:
        state_path = self._state_path()
        data = {
            "sources": {k: v.to_dict() for k, v in self._sources.items()},
            "release_notes": [r.to_dict() for r in self._release_notes],
        }
        tmp_path = state_path.with_suffix(".tmp")
        tmp_path.write_text(json.dumps(data, indent=2, sort_keys=True), encoding="utf-8")
        tmp_path.rename(state_path)

    def register_source(self, source: CorpusSource) -> None:
        if source.trust_level not in CorpusTrustLevel.ALL_LEVELS:
            raise ValueError(f"Invalid trust level: {source.trust_level}")

        if not source.sha256:
            content = f"{source.name}:{source.imported_at}:{source.trust_level}"
            source.sha256 = hashlib.sha256(content.encode()).hexdigest()[:16]

        self._sources[source.name] = source
        self._save_state()

        audit(
            "corpus.register_source",
            target=source.name,
            metadata={
                "trust_level": source.trust_level,
                "origin_url": source.origin_url[:128],
                "reviewer": source.reviewer,
                "ioc_count": source.ioc_count,
            },
        )
        logger.info("Registered corpus source: %s (trust=%s)", source.name, source.trust_level)

    def get_source(self, name: str) -> CorpusSource | None:
        return self._sources.get(name)

    def list_sources(self, trust_level: str = "") -> list[CorpusSource]:
        sources = list(self._sources.values())
        if trust_level:
            sources = [s for s in sources if s.trust_level == trust_level]
        return sorted(sources, key=lambda s: CorpusTrustLevel._ORDER.get(s.trust_level, 0), reverse=True)

    def remove_source(self, name: str) -> bool:
        if name in self._sources:
            del self._sources[name]
            self._save_state()
            audit("corpus.remove_source", target=name, outcome="success")
            return True
        audit("corpus.remove_source", target=name, outcome="not_found")
        return False

    def freshness_report(self, max_age_days: int = 30) -> FreshnessReport:
        return FreshnessReport(sources=list(self._sources.values()))

    def report_false_positive(self, report: FalsePositiveReport) -> None:
        report_id = hashlib.sha256(f"{report.finding_id}:{report.package}:{report.reported_at}".encode()).hexdigest()[
            :12
        ]
        self._fp_reports[report_id] = report

        fp_path = self._fp_dir() / f"{report_id}.json"
        fp_path.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

        audit(
            "corpus.false_positive_report",
            target=f"{report.rule_id}:{report.package}",
            metadata={
                "finding_id": report.finding_id,
                "reported_by": report.reported_by,
                "justification": report.justification[:200],
            },
        )
        logger.info("False-positive report submitted: %s", report_id)

    def triage_false_positive(
        self,
        finding_id: str,
        triager: str,
        status: str,
        resolution: str = "",
    ) -> bool:
        for report_id, report in self._fp_reports.items():
            if report.finding_id == finding_id:
                report.status = status
                report.triaged_by = triager
                report.triaged_at = datetime.now(timezone.utc).isoformat()
                report.resolution = resolution

                fp_path = self._fp_dir() / f"{report_id}.json"
                fp_path.write_text(json.dumps(report.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

                audit(
                    "corpus.false_positive_triage",
                    target=finding_id,
                    metadata={"status": status, "resolution": resolution, "triager": triager},
                )
                return True
        return False

    def list_false_positives(self, status: str = "") -> list[FalsePositiveReport]:
        reports = list(self._fp_reports.values())
        if status:
            reports = [r for r in reports if r.status == status]
        return sorted(reports, key=lambda r: r.reported_at, reverse=True)

    def add_release_notes(self, notes: CorpusReleaseNotes) -> None:
        self._release_notes.append(notes)
        self._save_state()

        audit(
            "corpus.release_notes",
            target=notes.version,
            metadata={
                "added": len(notes.added),
                "changed": len(notes.changed),
                "removed": len(notes.removed),
                "trust_level": notes.trust_level,
            },
        )

    def get_release_notes(self, version: str = "") -> list[CorpusReleaseNotes]:
        if version:
            return [n for n in self._release_notes if n.version == version]
        return sorted(self._release_notes, key=lambda n: n.released_at, reverse=True)

    def validate_trust(self, source_name: str, min_trust: str = "") -> dict[str, Any]:
        source = self._sources.get(source_name)
        if not source:
            return {
                "valid": False,
                "reason": f"Source not registered: {source_name}",
                "source": source_name,
            }

        min_trust_level = min_trust or CorpusTrustLevel.min_for_production()
        comparison = CorpusTrustLevel.compare(source.trust_level, min_trust_level)

        if comparison < 0:
            return {
                "valid": False,
                "reason": f"Source trust level ({source.trust_level}) below minimum ({min_trust_level})",
                "source": source_name,
                "trust_level": source.trust_level,
                "min_trust": min_trust_level,
            }

        if source.trust_level == CorpusTrustLevel.QUARANTINED:
            return {
                "valid": False,
                "reason": "Source is quarantined and cannot be used in production",
                "source": source_name,
                "trust_level": source.trust_level,
            }

        return {
            "valid": True,
            "source": source_name,
            "trust_level": source.trust_level,
            "reviewed_at": source.reviewed_at,
        }
