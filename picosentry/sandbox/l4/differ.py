
from __future__ import annotations

from picosentry.sandbox.l4.models import Baseline, BehavioralProfile, DriftResult


def compare_profile_to_baseline(
    profile: BehavioralProfile,
    baseline: Baseline,
) -> DriftResult:
    drift_flags: list = []
    drift_count = 0
    total_checks = 5


    network_drift = False
    if baseline.expected_network_calls >= 0 and len(profile.network_calls) > baseline.expected_network_calls:
        network_drift = True
        drift_count += 1
        drift_flags.append(
            f"Network: {len(profile.network_calls)} calls (expected ≤{baseline.expected_network_calls})"
        )


    dns_drift = False
    if baseline.expected_dns_queries >= 0 and len(profile.dns_queries) > baseline.expected_dns_queries:
        dns_drift = True
        drift_count += 1
        drift_flags.append(f"DNS: {len(profile.dns_queries)} queries (expected ≤{baseline.expected_dns_queries})")


    fs_drift = False
    if baseline.expected_fs_ops >= 0 and len(profile.fs_ops) > baseline.expected_fs_ops:
        fs_drift = True
        drift_count += 1
        drift_flags.append(f"FS: {len(profile.fs_ops)} operations (expected ≤{baseline.expected_fs_ops})")


    spawn_drift = False
    if baseline.expected_spawns >= 0 and len(profile.spawns) > baseline.expected_spawns:
        spawn_drift = True
        drift_count += 1
        drift_flags.append(f"Spawns: {len(profile.spawns)} processes (expected ≤{baseline.expected_spawns})")


    timing_drift = False
    low, high = baseline.expected_runtime_ms_range
    if (low > 0 or high > 0) and (profile.total_runtime_ms < low or profile.total_runtime_ms > high):
        timing_drift = True
        drift_count += 1
        drift_flags.append(f"Timing: {profile.total_runtime_ms}ms (expected {low}-{high}ms)")


    if baseline.allowed_domains and "*" not in baseline.allowed_domains:
        for call in profile.network_calls:


            if not call.address.replace(".", "").replace(":", "").isdigit():

                if call.address not in baseline.allowed_domains:
                    if not network_drift:
                        network_drift = True
                        drift_count += 1
                    drift_flags.append(f"Unexpected domain: {call.address}")
                    break


    if baseline.allowed_paths and "**" not in baseline.allowed_paths:
        for op in profile.fs_ops:
            allowed = any(_path_matches(op.path, p) for p in baseline.allowed_paths)
            if not allowed:
                if not fs_drift:
                    fs_drift = True
                    drift_count += 1
                drift_flags.append(f"Unexpected path: {op.path}")
                break

    score = drift_count / total_checks
    details = "; ".join(drift_flags) if drift_flags else "No drift detected"

    return DriftResult(
        baseline_name=baseline.name,
        score=round(score, 2),
        network_drift=network_drift,
        dns_drift=dns_drift,
        fs_drift=fs_drift,
        spawn_drift=spawn_drift,
        timing_drift=timing_drift,
        details=details,
    )


def find_best_baseline(
    profile: BehavioralProfile,
    baselines: dict[str, Baseline],
) -> tuple[Baseline, DriftResult] | None:
    best: tuple[Baseline, DriftResult] | None = None
    best_score = 1.0

    for _name, baseline in baselines.items():

        if baseline.package not in ("*", profile.package, profile.entrypoint):
            continue

        drift = compare_profile_to_baseline(profile, baseline)
        if drift.score < best_score:
            best_score = drift.score
            best = (baseline, drift)

    return best


def _path_matches(path: str, pattern: str) -> bool:
    import fnmatch

    return fnmatch.fnmatch(path, pattern)
