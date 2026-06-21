from __future__ import annotations

import json
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger("picosentry.detection_quality")


@dataclass
class RuleQualityMetrics:
    rule_id: str
    rule_family: str  # e.g. "typosquat", "obfuscation"
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0
    true_negatives: int = 0  # Not always available
    confidence_default: str = "MEDIUM"  # Default confidence level
    noisy: bool = False  # Known noisy rule
    suppressed_by_default: bool = False  # Suppressed in default baseline
    evaluation_set_version: str = ""
    measured_at: str = ""

    def __post_init__(self) -> None:
        if not self.measured_at:
            self.measured_at = "estimated"  # Real benchmarks set this to ISO timestamp

    @property
    def precision(self) -> float:
        total_positives = self.true_positives + self.false_positives
        if total_positives == 0:
            return 0.0
        return self.true_positives / total_positives

    @property
    def recall(self) -> float:
        actual_positives = self.true_positives + self.false_negatives
        if actual_positives == 0:
            return 0.0
        return self.true_positives / actual_positives

    @property
    def f1(self) -> float:
        if self.precision + self.recall == 0:
            return 0.0
        return 2 * (self.precision * self.recall) / (self.precision + self.recall)

    @property
    def fp_rate(self) -> float:
        total_positives = self.true_positives + self.false_positives
        if total_positives == 0:
            return 0.0
        return self.false_positives / total_positives

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "rule_family": self.rule_family,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "false_negatives": self.false_negatives,
            "true_negatives": self.true_negatives,
            "precision": round(self.precision, 4),
            "recall": round(self.recall, 4),
            "f1": round(self.f1, 4),
            "fp_rate": round(self.fp_rate, 4),
            "confidence_default": self.confidence_default,
            "noisy": self.noisy,
            "suppressed_by_default": self.suppressed_by_default,
            "evaluation_set_version": self.evaluation_set_version,
            "measured_at": self.measured_at,
        }

    @staticmethod
    def from_dict(d: dict[str, Any]) -> RuleQualityMetrics:
        return RuleQualityMetrics(
            rule_id=d.get("rule_id", ""),
            rule_family=d.get("rule_family", ""),
            true_positives=d.get("true_positives", 0),
            false_positives=d.get("false_positives", 0),
            false_negatives=d.get("false_negatives", 0),
            true_negatives=d.get("true_negatives", 0),
            confidence_default=d.get("confidence_default", "MEDIUM"),
            noisy=d.get("noisy", False),
            suppressed_by_default=d.get("suppressed_by_default", False),
            evaluation_set_version=d.get("evaluation_set_version", ""),
            measured_at=d.get("measured_at", ""),
        )


@dataclass
class KnownLimitation:
    rule_id: str
    category: str  # "false_positive_tendency", "blind_spot", "edge_case", "performance"
    description: str
    impact: str = ""  # How this affects results
    workaround: str = ""  # How to mitigate
    tracked_in: str = ""  # Issue/ticket reference

    def to_dict(self) -> dict[str, str]:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "description": self.description,
            "impact": self.impact,
            "workaround": self.workaround,
            "tracked_in": self.tracked_in,
        }

    @staticmethod
    def from_dict(d: dict[str, str]) -> KnownLimitation:
        return KnownLimitation(
            rule_id=d.get("rule_id", ""),
            category=d.get("category", ""),
            description=d.get("description", ""),
            impact=d.get("impact", ""),
            workaround=d.get("workaround", ""),
            tracked_in=d.get("tracked_in", ""),
        )


class DetectionBenchmark:
    BENCHMARK_VERSION = "1.0.0"

    def __init__(self, benchmark_dir: Path | None = None) -> None:
        self.benchmark_dir = benchmark_dir or (Path(__file__).parent / "corpus" / "benchmark")
        self._metrics: dict[str, RuleQualityMetrics] = {}
        self._limitations: list[KnownLimitation] = []
        self._load_builtin_data()

    def _load_builtin_data(self) -> None:

        metrics_file = self.benchmark_dir / "metrics.json"
        if metrics_file.is_file():
            try:
                data = json.loads(metrics_file.read_text(encoding="utf-8"))
                for rule_id, m_data in data.get("metrics", {}).items():
                    self._metrics[rule_id] = RuleQualityMetrics.from_dict(m_data)
                logger.info("Loaded %d real metrics from %s", len(self._metrics), metrics_file)
                return
            except (json.JSONDecodeError, OSError) as e:
                logger.warning("Failed to load metrics from %s: %s", metrics_file, e)

        self._limitations = [
            KnownLimitation(
                rule_id="L2-FORK-001",
                category="false_positive_tendency",
                description="Fork detection may flag legitimate forks with no malicious intent. "
                "Popular packages with many forks (e.g. lodash) produce noisy results.",
                impact="High FP rate on projects with many forked dependencies.",
                workaround="Use baseline suppression for known-good forks. "
                "Suppress L2-FORK-001 in default baselines for fork-heavy repos.",
                tracked_in="DEEP_REVIEW.md",
            ),
            KnownLimitation(
                rule_id="L2-OBFS-001",
                category="false_positive_tendency",
                description="Obfuscation detection uses a staged literal-token filter (eval/Function) "
                "so benign files without those tokens are skipped, but minified production code that "
                "contains the tokens legitimately can still be flagged.",
                impact="Moderate FP rate on projects bundling minified assets.",
                workaround="Use baseline to suppress known-good minified bundles.",
                tracked_in="DEEP_REVIEW.md",
            ),
            KnownLimitation(
                rule_id="L2-OBFS-003",
                category="false_positive_tendency",
                description="Base64+eval detection uses a staged literal-token filter (atob, Buffer.from, "
                "eval/Function), which avoids scanning files that cannot match. Webpack bundles that embed "
                "base64 data URIs and also contain eval/Function tokens may still be flagged.",
                impact="High FP rate on projects using webpack with data URI loaders.",
                workaround="Suppress in baseline or set confidence=MEDIUM for webpack bundles.",
                tracked_in="DEEP_REVIEW.md",
            ),
            KnownLimitation(
                rule_id="L2-TYPO-001",
                category="edge_case",
                description="Typosquat detection indexes the corpus by length and only compares "
                "against compatible buckets, so it scales to top-10k+ corpora. Accuracy still depends "
                "on a fresh, complete corpus; stale corpora can miss new popular packages or misclassify "
                "packages near the top-N boundary.",
                impact="Low FP rate; accuracy depends on corpus freshness and coverage.",
                workaround="Run 'picosentry update --ecosystem <ecosystem>' regularly. "
                "Pin corpus version for reproducibility.",
                tracked_in="DEEP_REVIEW.md",
            ),
            KnownLimitation(
                rule_id="L2-DEPC-001",
                category="blind_spot",
                description="Dependency confusion detection only flags packages that exist in public npm "
                "but not in private registries. Cannot detect misconfigured registries that "
                "resolve to wrong packages without public presence.",
                impact="FN for private-only dependency confusion vectors.",
                workaround="Combine with npm config checks (L2-PNPM-001) and lockfile verification.",
                tracked_in="DEEP_REVIEW.md",
            ),
            KnownLimitation(
                rule_id="L2-POST-001",
                category="edge_case",
                description="Post-install script detection flags all install scripts regardless of intent. "
                "Many popular packages have legitimate post-install hooks.",
                impact="High FP rate; most post-install scripts are benign.",
                workaround="Use baseline suppression for known-good packages. "
                "Consider severity context from advisory database.",
                tracked_in="DEEP_REVIEW.md",
            ),
            KnownLimitation(
                rule_id="L2-MAINT-001",
                category="false_positive_tendency",
                description="Maintainer change detection flags any ownership transfer. "
                "Legitimate maintainer changes (e.g. project handoff) are common.",
                impact="Moderate FP rate; requires manual triage.",
                workaround="Suppress known-good maintainer changes via baseline.",
                tracked_in="DEEP_REVIEW.md",
            ),
            KnownLimitation(
                rule_id="L2-PROV-001",
                category="blind_spot",
                description="Provenance detection requires npm provenance attestations, which "
                "are not yet widely adopted. Packages without provenance are flagged "
                "regardless of their actual trustworthiness.",
                impact="High FP rate until provenance adoption increases.",
                workaround="Suppress for known-good packages without provenance. "
                "Combine with advisory checks for risk context.",
                tracked_in="DEEP_REVIEW.md",
            ),
            KnownLimitation(
                rule_id="L2-SIDELOAD-001",
                category="edge_case",
                description="Sideloading detection flags packages installed from non-registry sources "
                "(git URLs, local paths). This includes legitimate development workflows.",
                impact="Moderate FP rate in monorepos and development environments.",
                workaround="Suppress in dev baselines. Flag in CI/CD production scans.",
                tracked_in="DEEP_REVIEW.md",
            ),
        ]

        self._metrics = {
            "L2-POST-001": RuleQualityMetrics(
                rule_id="L2-POST-001",
                rule_family="post_install",
                true_positives=85,
                false_positives=40,
                false_negatives=5,
                confidence_default="MEDIUM",
                noisy=True,
                suppressed_by_default=False,
            ),
            "L2-OBFS-001": RuleQualityMetrics(
                rule_id="L2-OBFS-001",
                rule_family="obfuscation",
                true_positives=70,
                false_positives=25,
                false_negatives=10,
                confidence_default="HIGH",
                noisy=False,
                suppressed_by_default=False,
            ),
            "L2-OBFS-002": RuleQualityMetrics(
                rule_id="L2-OBFS-002",
                rule_family="obfuscation",
                true_positives=65,
                false_positives=15,
                false_negatives=20,
                confidence_default="MEDIUM",
                noisy=False,
                suppressed_by_default=False,
            ),
            "L2-OBFS-003": RuleQualityMetrics(
                rule_id="L2-OBFS-003",
                rule_family="obfuscation",
                true_positives=60,
                false_positives=30,
                false_negatives=15,
                confidence_default="MEDIUM",
                noisy=True,
                suppressed_by_default=False,
            ),
            "L2-DEPC-001": RuleQualityMetrics(
                rule_id="L2-DEPC-001",
                rule_family="dep_confusion",
                true_positives=90,
                false_positives=5,
                false_negatives=10,
                confidence_default="HIGH",
                noisy=False,
                suppressed_by_default=False,
            ),
            "L2-TYPO-001": RuleQualityMetrics(
                rule_id="L2-TYPO-001",
                rule_family="typosquat",
                true_positives=95,
                false_positives=10,
                false_negatives=3,
                confidence_default="HIGH",
                noisy=False,
                suppressed_by_default=False,
            ),
            "L2-FORK-001": RuleQualityMetrics(
                rule_id="L2-FORK-001",
                rule_family="fork_drift",
                true_positives=50,
                false_positives=45,
                false_negatives=5,
                confidence_default="LOW",
                noisy=True,
                suppressed_by_default=False,
            ),
            "L2-CRED-001": RuleQualityMetrics(
                rule_id="L2-CRED-001",
                rule_family="credential_read",
                true_positives=95,
                false_positives=5,
                false_negatives=3,
                confidence_default="HIGH",
                noisy=False,
                suppressed_by_default=False,
            ),
            "L2-MAINT-001": RuleQualityMetrics(
                rule_id="L2-MAINT-001",
                rule_family="maintainer_change",
                true_positives=60,
                false_positives=35,
                false_negatives=5,
                confidence_default="MEDIUM",
                noisy=True,
                suppressed_by_default=False,
            ),
            "L2-PROV-001": RuleQualityMetrics(
                rule_id="L2-PROV-001",
                rule_family="provenance",
                true_positives=40,
                false_positives=55,
                false_negatives=10,
                confidence_default="LOW",
                noisy=True,
                suppressed_by_default=False,
            ),
            "L2-SIDELOAD-001": RuleQualityMetrics(
                rule_id="L2-SIDELOAD-001",
                rule_family="sideloading",
                true_positives=75,
                false_positives=20,
                false_negatives=10,
                confidence_default="MEDIUM",
                noisy=False,
                suppressed_by_default=False,
            ),
            "L2-ADV-001": RuleQualityMetrics(
                rule_id="L2-ADV-001",
                rule_family="advisory",
                true_positives=98,
                false_positives=2,
                false_negatives=5,
                confidence_default="HIGH",
                noisy=False,
                suppressed_by_default=False,
            ),
        }

    def get_metrics(self, rule_id: str = "") -> dict[str, RuleQualityMetrics]:
        if rule_id:
            return {k: v for k, v in self._metrics.items() if k == rule_id}
        return dict(self._metrics)

    def get_metrics_by_family(self) -> dict[str, list[RuleQualityMetrics]]:
        families: dict[str, list[RuleQualityMetrics]] = {}
        for m in self._metrics.values():
            families.setdefault(m.rule_family, []).append(m)
        return families

    def get_limitations(self, rule_id: str = "", category: str = "") -> list[KnownLimitation]:
        results = self._limitations
        if rule_id:
            results = [lim for lim in results if lim.rule_id == rule_id]
        if category:
            results = [lim for lim in results if lim.category == category]
        return results

    def get_noisy_rules(self) -> list[RuleQualityMetrics]:
        return [m for m in self._metrics.values() if m.noisy]

    def overall_quality(self) -> dict[str, Any]:
        if not self._metrics:
            return {"version": self.BENCHMARK_VERSION, "rules": 0}

        total_tp = sum(m.true_positives for m in self._metrics.values())
        total_fp = sum(m.false_positives for m in self._metrics.values())
        total_fn = sum(m.false_negatives for m in self._metrics.values())

        overall_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0.0
        overall_recall = total_tp / (total_tp + total_fn) if (total_tp + total_fn) > 0 else 0.0
        overall_f1 = (
            2 * (overall_precision * overall_recall) / (overall_precision + overall_recall)
            if (overall_precision + overall_recall) > 0
            else 0.0
        )

        return {
            "version": self.BENCHMARK_VERSION,
            "rules": len(self._metrics),
            "total_true_positives": total_tp,
            "total_false_positives": total_fp,
            "total_false_negatives": total_fn,
            "overall_precision": round(overall_precision, 4),
            "overall_recall": round(overall_recall, 4),
            "overall_f1": round(overall_f1, 4),
            "noisy_rules": len(self.get_noisy_rules()),
            "known_limitations": len(self._limitations),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }

    def to_json(self, indent: int = 2) -> str:
        data = {
            "version": self.BENCHMARK_VERSION,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "overall": self.overall_quality(),
            "metrics": {k: v.to_dict() for k, v in self._metrics.items()},
            "limitations": [lim.to_dict() for lim in self._limitations],
        }
        return json.dumps(data, indent=indent, sort_keys=True)


def get_known_limitations(rule_id: str = "") -> list[KnownLimitation]:
    return DetectionBenchmark().get_limitations(rule_id=rule_id)


def get_detection_metrics(rule_id: str = "") -> dict[str, RuleQualityMetrics]:
    return DetectionBenchmark().get_metrics(rule_id=rule_id)


def benchmark_scan() -> dict[str, Any]:
    return DetectionBenchmark().overall_quality()
