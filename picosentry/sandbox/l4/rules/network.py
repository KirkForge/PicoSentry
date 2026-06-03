"""L4 network anomaly detector.

Detects suspicious network behavior: connections to private IPs from unexpected
contexts, unusual port numbers, high data volumes, and DNS tunneling indicators.
"""

import re

from picosentry.sandbox.l4.models import Baseline, BehavioralProfile, Finding
from picosentry.sandbox.models import Severity

# Private IP ranges (RFC 1918)
_PRIVATE_IP_RE = re.compile(
    r"^(10\.\d+\.\d+\.\d+|"
    r"172\.(1[6-9]|2\d|3[01])\.\d+\.\d+|"
    r"192\.168\.\d+\.\d+|"
    r"127\.\d+\.\d+\.\d+|"
    r"0\.0\.0\.0)$"
)

# Ports commonly used for C2 and data exfiltration
SUSPICIOUS_PORTS = {4444, 5555, 6666, 6667, 8888, 31337, 12345, 4443, 1337}

# DNS labels that look like encoded data (DNS tunneling)
_DNS_TUNNELING_RE = re.compile(r"^[a-z0-9]{32,}\.[a-z0-9-]+\.[a-z]{2,}$", re.IGNORECASE)

# Known malicious / suspicious TLDs
SUSPICIOUS_TLDS = {".xyz", ".tk", ".ml", ".cf", ".ga", ".gq", ".top", ".pw", ".cc", ".buzz"}


def detect_network_anomalies(
    profile: BehavioralProfile,
    baselines: dict[str, Baseline] | None = None,
) -> list[Finding]:
    """Detect anomalous network behavior in sandboxed execution."""
    findings: list[Finding] = []

    # L4-NET-001: Connections to suspicious ports
    for call in profile.network_calls:
        if call.port in SUSPICIOUS_PORTS:
            findings.append(
                Finding(
                    rule_id="L4-NET-001",
                    severity=Severity.HIGH,
                    message=f"Connection to suspicious port: {call.address}:{call.port}",
                    location=f"{call.address}:{call.port}",
                    evidence={"address": call.address, "port": call.port},
                )
            )

    # L4-NET-002: DNS tunneling indicators
    for dns in profile.dns_queries:
        hostname = dns.hostname
        # Check for very long subdomain labels (encoded data)
        parts = hostname.split(".")
        for part in parts:
            if len(part) > 30 and re.match(r"^[a-zA-Z0-9]+$", part):
                findings.append(
                    Finding(
                        rule_id="L4-NET-002",
                        severity=Severity.HIGH,
                        message=f"DNS tunneling indicator — long encoded subdomain: {hostname}",
                        location=hostname,
                        evidence={"hostname": hostname, "label_length": len(part)},
                    )
                )
                break

        # Check for suspicious TLDs
        for tld in SUSPICIOUS_TLDS:
            if hostname.endswith(tld):
                findings.append(
                    Finding(
                        rule_id="L4-NET-003",
                        severity=Severity.MEDIUM,
                        message=f"DNS query to suspicious TLD: {hostname}",
                        location=hostname,
                        evidence={"hostname": hostname, "tld": tld},
                    )
                )

    # L4-NET-004: High volume of network calls
    if len(profile.network_calls) > 20:
        addresses = [c.address for c in profile.network_calls]
        findings.append(
            Finding(
                rule_id="L4-NET-004",
                severity=Severity.MEDIUM,
                message=f"High volume of network connections: {len(profile.network_calls)}",
                location=profile.package,
                evidence={"network_call_count": len(profile.network_calls), "addresses": addresses[:10]},
            )
        )

    # L4-NET-005: Connection to private IPs (unexpected in package install)
    if baselines:
        from picosentry.sandbox.l4.differ import find_best_baseline

        best = find_best_baseline(profile, baselines)
        if best and best[0].expected_network_calls == 0:
            private_calls = [
                c for c in profile.network_calls
                if _PRIVATE_IP_RE.match(c.address) and c.address not in ("127.0.0.1", "0.0.0.0")
            ]
            for call in private_calls:
                findings.append(
                    Finding(
                        rule_id="L4-NET-005",
                        severity=Severity.MEDIUM,
                        message=f"Connection to private IP in zero-network baseline: {call.address}",
                        location=call.address,
                        evidence={"address": call.address, "port": call.port},
                    )
                )

    return findings
