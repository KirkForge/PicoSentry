
from picosentry.sandbox.l4.models import Baseline, BehavioralProfile, Finding
from picosentry.sandbox.models import Severity


def detect_timing_anomalies(
    profile: BehavioralProfile,
    baselines: dict[str, Baseline] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []


    if profile.total_runtime_ms < 5 and profile.exit_code == 0:
        findings.append(
            Finding(
                rule_id="L4-TIME-001",
                severity=Severity.MEDIUM,
                message=f"Execution completed in {profile.total_runtime_ms}ms — unusually fast, possible no-op",
                location=profile.package,
                evidence={"runtime_ms": profile.total_runtime_ms},
            )
        )


    for tp in profile.timing_points:
        if tp.elapsed_ms > 60000:  # >60s on a single operation
            findings.append(
                Finding(
                    rule_id="L4-TIME-002",
                    severity=Severity.MEDIUM,
                    message=f"Timing point '{tp.label}' took {tp.elapsed_ms}ms — potential busy-wait or sleep",
                    location=tp.label,
                    evidence={"label": tp.label, "elapsed_ms": tp.elapsed_ms},
                )
            )


    if baselines:
        from picosentry.sandbox.l4.differ import find_best_baseline

        best = find_best_baseline(profile, baselines)
        if best and best[1].timing_drift:
            findings.append(
                Finding(
                    rule_id="L4-TIME-003",
                    severity=Severity.HIGH,
                    message=f"Timing drift from baseline '{best[1].baseline_name}': {best[1].details}",
                    location=profile.package,
                    evidence={"drift_score": best[1].score, "details": best[1].details},
                )
            )

    return findings
