"""L4 differ — compare behavioral profiles against baselines."""

from __future__ import annotations

from picosentry.sandbox.l4.models import Baseline, BehavioralProfile, DriftResult


def compare_profile_to_baseline(
    profile: BehavioralProfile,
    baseline: Baseline,
) -> DriftResult:
    """
    Compare a behavioral profile against a baseline.
    Returns a DriftResult with a score from 0.0 (identical) to 1.0 (completely different).
    """
    drift_flags: list = []
    drift_count = 0
    total_checks = 5

    # Network drift
    network_drift = False
    if baseline.expected_network_calls >= 0:
        if len(profile.network_calls) > baseline.expected_network_calls:
            network_drift = True
            drift_count += 1
            drift_flags.append(
                f"Network: {len(profile.network_calls)} calls (expected ≤{baseline.expected_network_calls})"
            )

    # DNS drift
    dns_drift = False
    if baseline.expected_dns_queries >= 0:
        if len(profile.dns_queries) > baseline.expected_dns_queries:
            dns_drift = True
            drift_count += 1
            drift_flags.append(f"DNS: {len(profile.dns_queries)} queries (expected ≤{baseline.expected_dns_queries})")

    # Filesystem drift
    fs_drift = False
    if baseline.expected_fs_ops >= 0:
        if len(profile.fs_ops) > baseline.expected_fs_ops:
            fs_drift = True
            drift_count += 1
            drift_flags.append(f"FS: {len(profile.fs_ops)} operations (expected ≤{baseline.expected_fs_ops})")

    # Spawn drift
    spawn_drift = False
    if baseline.expected_spawns >= 0:
        if len(profile.spawns) > baseline.expected_spawns:
            spawn_drift = True
            drift_count += 1
            drift_flags.append(f"Spawns: {len(profile.spawns)} processes (expected ≤{baseline.expected_spawns})")

    # Timing drift
    timing_drift = False
    low, high = baseline.expected_runtime_ms_range
    if low > 0 or high > 0:
        if profile.total_runtime_ms < low or profile.total_runtime_ms > high:
            timing_drift = True
            drift_count += 1
            drift_flags.append(f"Timing: {profile.total_runtime_ms}ms (expected {low}-{high}ms)")

    # Domain checks — compare hostname if available, skip if only an IP address
    if baseline.allowed_domains and "*" not in baseline.allowed_domains:
        for call in profile.network_calls:
            # NetworkCall.address is typically an IP; check if it looks like a domain
            # (contains letters, not just digits/dots/colns)
            if not call.address.replace(".", "").replace(":", "").isdigit():
                # Address looks like a domain name
                if call.address not in baseline.allowed_domains:
                    if not network_drift:
                        network_drift = True
                        drift_count += 1
                    drift_flags.append(f"Unexpected domain: {call.address}")
                    break

    # Path checks
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
    """
    Find the best-matching baseline for a profile.
    Returns (baseline, drift_result) for the lowest-drift match, or None.
    """
    best: tuple[Baseline, DriftResult] | None = None
    best_score = 1.0

    for _name, baseline in baselines.items():
        # Skip if package doesn't match at all
        if baseline.package not in ("*", profile.package, profile.entrypoint):
            continue

        drift = compare_profile_to_baseline(profile, baseline)
        if drift.score < best_score:
            best_score = drift.score
            best = (baseline, drift)

    return best


def _path_matches(path: str, pattern: str) -> bool:
    """Simple glob matching for paths."""
    import fnmatch

    return fnmatch.fnmatch(path, pattern)
