"""L4 entropy anomaly detector."""

import math
from collections import Counter

from picosentry.sandbox.l4.models import Baseline, BehavioralProfile, Finding
from picosentry.sandbox.models import Severity


def detect_entropy_anomalies(
    profile: BehavioralProfile,
    baselines: dict[str, Baseline] | None = None,
) -> list[Finding]:
    """Detect high-entropy strings indicative of encoded/encrypted payloads."""
    findings: list[Finding] = []

    # Check file paths for high-entropy names
    for op in profile.fs_ops:
        name = op.path.split("/")[-1] if "/" in op.path else op.path
        ent = _shannon_entropy(name)
        if ent > 4.5 and len(name) > 10:  # High entropy, long name = suspicious
            findings.append(
                Finding(
                    rule_id="L4-ENTROPY-001",
                    severity=Severity.MEDIUM,
                    message=f"High-entropy filename ({ent:.1f} bits): {name}",
                    location=op.path,
                    evidence={"entropy": round(ent, 2), "path": op.path},
                )
            )

    # Check DNS hostnames for high entropy
    for dns in profile.dns_queries:
        host_part = dns.hostname.split(".")[0]
        if len(host_part) > 20:
            ent = _shannon_entropy(host_part)
            if ent > 3.5:
                findings.append(
                    Finding(
                        rule_id="L4-ENTROPY-002",
                        severity=Severity.HIGH,
                        message=f"High-entropy DNS query ({ent:.1f} bits): {dns.hostname} — possible DGA or encoded C2",
                        location=dns.hostname,
                        evidence={"entropy": round(ent, 2), "hostname": dns.hostname},
                    )
                )

    return findings


def _shannon_entropy(data: str) -> float:
    """Calculate Shannon entropy of a string."""
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    entropy = 0.0
    for count in counts.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy
