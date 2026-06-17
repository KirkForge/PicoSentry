
import re

from picosentry.sandbox.l4.models import BehavioralProfile, Finding
from picosentry.sandbox.models import Severity


def detect_exfiltration(
    profile: BehavioralProfile,
) -> list[Finding]:
    findings: list[Finding] = []


    suspicious_tlds = {".xyz", ".tk", ".ml", ".cf", ".ga", ".gq", ".top", ".pw", ".cc"}
    private_ips = re.compile(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.)")

    for call in profile.network_calls:

        for tld in suspicious_tlds:
            if call.address.endswith(tld):
                findings.append(
                    Finding(
                        rule_id="L4-EXFIL-001",
                        severity=Severity.HIGH,
                        message=f"Network call to suspicious TLD: {call.address}",
                        location=call.address,
                        evidence={"address": call.address, "port": call.port, "tld": tld},
                    )
                )


        if call.port not in (0, 80, 443, 8080, 8443) and not private_ips.match(call.address):
            findings.append(
                Finding(
                    rule_id="L4-EXFIL-002",
                    severity=Severity.MEDIUM,
                    message=f"Network call to non-standard port: {call.address}:{call.port}",
                    location=f"{call.address}:{call.port}",
                    evidence={"address": call.address, "port": call.port},
                )
            )


    total_sent = sum(c.bytes_sent for c in profile.network_calls)
    if total_sent > 1000000:  # 1MB
        findings.append(
            Finding(
                rule_id="L4-EXFIL-003",
                severity=Severity.HIGH,
                message=f"Large outbound data transfer: {total_sent} bytes sent",
                location=profile.package,
                evidence={"bytes_sent": total_sent},
            )
        )


    for dns in profile.dns_queries:
        for tld in suspicious_tlds:
            if dns.hostname.endswith(tld):
                findings.append(
                    Finding(
                        rule_id="L4-EXFIL-004",
                        severity=Severity.MEDIUM,
                        message=f"DNS query to suspicious domain: {dns.hostname}",
                        location=dns.hostname,
                        evidence={"hostname": dns.hostname},
                    )
                )


    sensitive_patterns = [
        ".env",
        ".npmrc",
        "credentials",
        "secrets",
        "tokens",
        ".aws/",
        ".ssh/",
        "id_rsa",
        "id_ed25519",
    ]
    sensitive_reads = [
        op.path for op in profile.fs_ops if op.operation == "read" and any(p in op.path for p in sensitive_patterns)
    ]
    if sensitive_reads and len(profile.network_calls) > 0:
        findings.append(
            Finding(
                rule_id="L4-EXFIL-005",
                severity=Severity.CRITICAL,
                message=(
                    f"Sensitive files read ({len(sensitive_reads)} files)"
                    f" followed by {len(profile.network_calls)}"
                    " network calls — possible credential exfiltration"
                ),
                location=", ".join(sensitive_reads[:3]),
                evidence={
                    "sensitive_files": sensitive_reads[:5],
                    "network_calls": len(profile.network_calls),
                },
            )
        )

    return findings
