"""L4 baseline drift detector."""

from picosentry.sandbox.l4.models import Baseline, BehavioralProfile, Finding
from picosentry.sandbox.models import Severity


def detect_baseline_drift(
    profile: BehavioralProfile,
    baselines: dict[str, Baseline] | None = None,
) -> list[Finding]:
    """Detect significant drift from known baselines."""
    findings: list[Finding] = []

    if not baselines:
        return findings

    from picosentry.sandbox.l4.differ import find_best_baseline

    best = find_best_baseline(profile, baselines)

    if best is None:
        # No matching baseline — not necessarily bad, but notable
        findings.append(
            Finding(
                rule_id="L4-BASE-001",
                severity=Severity.INFO,
                message=f"No baseline match found for package '{profile.package}'",
                location=profile.package,
                evidence={"package": profile.package},
            )
        )
        return findings

    baseline, drift = best

    if drift.score >= 0.8:
        findings.append(
            Finding(
                rule_id="L4-BASE-002",
                severity=Severity.CRITICAL,
                message=f"Severe baseline drift ({drift.score:.0%}) from '{baseline.name}': {drift.details}",
                location=profile.package,
                evidence={"baseline": baseline.name, "drift_score": drift.score, "details": drift.details},
            )
        )
    elif drift.score >= 0.4:
        findings.append(
            Finding(
                rule_id="L4-BASE-003",
                severity=Severity.MEDIUM,
                message=f"Moderate baseline drift ({drift.score:.0%}) from '{baseline.name}': {drift.details}",
                location=profile.package,
                evidence={"baseline": baseline.name, "drift_score": drift.score, "details": drift.details},
            )
        )

    return findings
