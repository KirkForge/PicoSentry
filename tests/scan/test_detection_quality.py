"""Tests for detection quality benchmark module."""

from picosentry.scan.detection_quality import (
    DetectionBenchmark,
    KnownLimitation,
    RuleQualityMetrics,
    benchmark_scan,
    get_detection_metrics,
    get_known_limitations,
)


class TestRuleQualityMetrics:
    def test_precision(self):
        m = RuleQualityMetrics(rule_id="TEST", rule_family="test", true_positives=80, false_positives=20)
        assert m.precision == 0.8

    def test_recall(self):
        m = RuleQualityMetrics(rule_id="TEST", rule_family="test", true_positives=80, false_negatives=20)
        assert m.recall == 0.8

    def test_f1(self):
        m = RuleQualityMetrics(
            rule_id="TEST", rule_family="test", true_positives=80, false_positives=20, false_negatives=20
        )
        assert 0 < m.f1 < 1

    def test_zero_metrics(self):
        m = RuleQualityMetrics(rule_id="TEST", rule_family="test")
        assert m.precision == 0.0
        assert m.recall == 0.0
        assert m.f1 == 0.0
        assert m.fp_rate == 0.0

    def test_serialization(self):
        m = RuleQualityMetrics(rule_id="L2-POST-001", rule_family="post_install", true_positives=85)
        d = m.to_dict()
        assert d["rule_id"] == "L2-POST-001"
        restored = RuleQualityMetrics.from_dict(d)
        assert restored.rule_id == "L2-POST-001"
        assert restored.true_positives == 85


class TestKnownLimitation:
    def test_serialization(self):
        lim = KnownLimitation(
            rule_id="L2-FORK-001",
            category="false_positive_tendency",
            description="Fork detection flags legitimate forks",
        )
        d = lim.to_dict()
        restored = KnownLimitation.from_dict(d)
        assert restored.rule_id == "L2-FORK-001"


class TestDetectionBenchmark:
    def test_loads_builtin(self):
        bench = DetectionBenchmark()
        metrics = bench.get_metrics()
        assert len(metrics) > 0

    def test_get_metrics_by_family(self):
        bench = DetectionBenchmark()
        families = bench.get_metrics_by_family()
        assert "typosquat" in families
        assert "obfuscation" in families

    def test_noisy_rules(self):
        bench = DetectionBenchmark()
        noisy = bench.get_noisy_rules()
        noisy_ids = [m.rule_id for m in noisy]
        assert "L2-FORK-001" in noisy_ids
        assert "L2-DEPC-001" not in noisy_ids

    def test_get_limitations(self):
        bench = DetectionBenchmark()
        all_lims = bench.get_limitations()
        assert len(all_lims) > 0

        fork_lims = bench.get_limitations(rule_id="L2-FORK-001")
        assert len(fork_lims) > 0

        fp_lims = bench.get_limitations(category="false_positive_tendency")
        assert len(fp_lims) > 0

    def test_overall_quality(self):
        bench = DetectionBenchmark()
        quality = bench.overall_quality()
        assert quality["version"] == "1.0.0"
        assert quality["rules"] > 0
        assert 0 < quality["overall_precision"] <= 1.0
        assert 0 < quality["overall_recall"] <= 1.0
        assert 0 < quality["overall_f1"] <= 1.0

    def test_to_json(self):
        bench = DetectionBenchmark()
        json_str = bench.to_json()
        import json

        data = json.loads(json_str)
        assert "version" in data
        assert "metrics" in data
        assert "limitations" in data


class TestConvenienceFunctions:
    def test_benchmark_scan(self):
        result = benchmark_scan()
        assert result["rules"] > 0
        assert "overall_precision" in result

    def test_get_known_limitations(self):
        lims = get_known_limitations()
        assert len(lims) > 0

    def test_get_detection_metrics(self):
        metrics = get_detection_metrics()
        assert len(metrics) > 0
