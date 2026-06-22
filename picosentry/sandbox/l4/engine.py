from __future__ import annotations

import inspect
import logging
import time
from collections.abc import Callable, Sequence

from picosentry.sandbox.l4.baseline import load_all_baselines
from picosentry.sandbox.l4.differ import find_best_baseline
from picosentry.sandbox.l4.models import (
    AnalysisResult,
    Baseline,
    BehavioralProfile,
    BehavioralVerdict,
    DriftResult,
    Finding,
    ScanStats,
)
from picosentry.sandbox.models import Severity, _generate_finding_id

logger = logging.getLogger("picodome.l4.engine")

DetectorRule = Callable[..., list[Finding]]


class L4Engine:
    def __init__(self) -> None:
        self._rules: dict[str, DetectorRule] = {}

    def register(self, rule_id: str, rule: DetectorRule) -> L4Engine:
        self._rules[rule_id] = rule
        return self

    def unregister(self, rule_id: str) -> None:
        self._rules.pop(rule_id, None)

    def list_rules(self) -> list[str]:
        return sorted(self._rules.keys())

    def analyze(
        self,
        profile: BehavioralProfile,
        baselines: dict[str, Baseline] | None = None,
        rules: Sequence[str] | None = None,
        deterministic: bool = True,
    ) -> AnalysisResult:
        if baselines is None:
            baselines = load_all_baselines()

        selected = {k: v for k, v in self._rules.items() if k in rules} if rules else dict(self._rules)

        if not selected:
            logger.warning("No detector rules selected for L4 analysis")
            return AnalysisResult(
                target=profile.package,
                profile=profile,
                overall_verdict=BehavioralVerdict.CLEAN,
            )

        logger.info(
            "Starting L4 analysis: target=%s rules=%s",
            profile.package,
            list(selected.keys()),
        )

        start_ms = _now_ms()
        all_findings: list[Finding] = []

        for rule_id, rule_fn in selected.items():
            try:
                sig = inspect.signature(rule_fn)
                param_count = len(sig.parameters)
                findings = rule_fn(profile, baselines) if param_count >= 2 else rule_fn(profile)
                all_findings.extend(findings)
                logger.debug("L4 rule %s: %d findings", rule_id, len(findings))
            except Exception:
                logger.exception("L4 rule")

        if not deterministic:
            filled_findings = []
            for finding in all_findings:
                if not finding.finding_id:
                    f = Finding(
                        rule_id=finding.rule_id,
                        severity=finding.severity,
                        message=finding.message,
                        location=finding.location,
                        evidence=finding.evidence,
                        finding_id=_generate_finding_id(),
                    )
                else:
                    f = finding
                filled_findings.append(f)
            all_findings = filled_findings

        duration = int(_now_ms() - start_ms)

        drift_results: list[DriftResult] = []
        best_match = find_best_baseline(profile, baselines)
        if best_match:
            _, drift = best_match
            drift_results.append(drift)

        overall = _compute_verdict(all_findings)

        by_severity: dict[str, int] = {}
        by_rule: dict[str, int] = {}
        for f in all_findings:
            by_severity[f.severity.value] = by_severity.get(f.severity.value, 0) + 1
            by_rule[f.rule_id] = by_rule.get(f.rule_id, 0) + 1

        stats = ScanStats(
            duration_ms=duration,
            findings_by_severity=by_severity,
            findings_by_rule=by_rule,
        )

        result = AnalysisResult(
            target=profile.package,
            findings=all_findings,
            profile=profile,
            drift_results=drift_results,
            overall_verdict=overall,
            stats=stats,
        )

        logger.info(
            "L4 analysis complete: %d findings, verdict=%s, %dms",
            len(all_findings),
            overall.value,
            duration,
        )

        return result


def create_default_engine() -> L4Engine:
    from picosentry.sandbox.l4.rules.baseline_drift import detect_baseline_drift
    from picosentry.sandbox.l4.rules.container_escape import detect_container_escape
    from picosentry.sandbox.l4.rules.crypto_mining import detect_crypto_mining
    from picosentry.sandbox.l4.rules.dependency_confusion import detect_dependency_confusion
    from picosentry.sandbox.l4.rules.entropy import detect_entropy_anomalies
    from picosentry.sandbox.l4.rules.env_leak import detect_env_leak
    from picosentry.sandbox.l4.rules.exfil import detect_exfiltration
    from picosentry.sandbox.l4.rules.filesystem import detect_filesystem_anomalies
    from picosentry.sandbox.l4.rules.honeypot import detect_honeypot_touches
    from picosentry.sandbox.l4.rules.network import detect_network_anomalies
    from picosentry.sandbox.l4.rules.persistence import detect_persistence
    from picosentry.sandbox.l4.rules.privilege_escalation import detect_privilege_escalation
    from picosentry.sandbox.l4.rules.process_anomaly import detect_process_anomalies
    from picosentry.sandbox.l4.rules.supply_chain import detect_supply_chain_patterns
    from picosentry.sandbox.l4.rules.timing import detect_timing_anomalies

    engine = L4Engine()
    engine.register("L4-TIME", detect_timing_anomalies)
    engine.register("L4-EXFIL", detect_exfiltration)
    engine.register("L4-ENTROPY", detect_entropy_anomalies)
    engine.register("L4-HONEY", detect_honeypot_touches)
    engine.register("L4-BASE", detect_baseline_drift)
    engine.register("L4-ENV", detect_env_leak)
    engine.register("L4-PROC", detect_process_anomalies)
    engine.register("L4-FS", detect_filesystem_anomalies)
    engine.register("L4-NET", detect_network_anomalies)
    engine.register("L4-SC", detect_supply_chain_patterns)
    engine.register("L4-PRIVESC", detect_privilege_escalation)
    engine.register("L4-PERSIST", detect_persistence)
    engine.register("L4-CRYPTO", detect_crypto_mining)
    engine.register("L4-CONTAINER", detect_container_escape)
    engine.register("L4-DEP", detect_dependency_confusion)
    return engine


def analyze(
    profile: BehavioralProfile,
    baselines: dict[str, Baseline] | None = None,
    rules: Sequence[str] | None = None,
    deterministic: bool = True,
) -> AnalysisResult:
    engine = create_default_engine()
    return engine.analyze(profile, baselines=baselines, rules=rules, deterministic=deterministic)


def _compute_verdict(findings: list[Finding]) -> BehavioralVerdict:
    if not findings:
        return BehavioralVerdict.CLEAN
    for f in findings:
        if f.severity in (Severity.CRITICAL, Severity.HIGH):
            return BehavioralVerdict.MALICIOUS
    for f in findings:
        if f.severity == Severity.MEDIUM:
            return BehavioralVerdict.SUSPICIOUS
    return BehavioralVerdict.CLEAN


def _now_ms() -> float:
    return time.monotonic() * 1000
