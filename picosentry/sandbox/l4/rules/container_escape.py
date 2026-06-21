from picosentry.sandbox.l4.models import BehavioralProfile, Finding
from picosentry.sandbox.models import Severity


ESCAPE_PATHS: list[tuple[str, str, Severity]] = [
    ("/proc/1/", "host PID 1 access — container escape probe", Severity.CRITICAL),
    ("/proc/1/cgroup", "container cgroup escape via PID 1", Severity.CRITICAL),
    ("/proc/1/mountinfo", "host mount info via PID 1", Severity.HIGH),
    ("/proc/1/environ", "host environment via PID 1", Severity.CRITICAL),
    ("/proc/1/cmdline", "host cmdline via PID 1", Severity.MEDIUM),
    ("/var/run/docker.sock", "Docker socket access", Severity.CRITICAL),
    ("/run/docker.sock", "Docker socket access", Severity.CRITICAL),
    ("/.dockerenv", "Docker environment detection", Severity.INFO),
    ("/etc/hosts", "hosts file modification — container escape", Severity.HIGH),
    ("/etc/resolv.conf", "DNS configuration modification", Severity.MEDIUM),
    ("/etc/hostname", "hostname modification", Severity.MEDIUM),
    ("/sys/fs/cgroup/", "cgroup filesystem manipulation", Severity.HIGH),
    ("/var/run/containerd/", "containerd socket access", Severity.CRITICAL),
    ("/run/containerd/", "containerd socket access", Severity.CRITICAL),
    ("/var/run/crio/", "CRI-O socket access", Severity.CRITICAL),
    ("/run/crio/", "CRI-O socket access", Severity.CRITICAL),
    ("/var/run/secrets/kubernetes.io/", "Kubernetes service account token access", Severity.HIGH),
    ("/meta-data", "cloud metadata access attempt", Severity.MEDIUM),
]


ESCAPE_BINARIES = {
    "docker",
    "podman",
    "ctr",
    "crictl",
    "kubectl",
    "runc",
    "nsenter",
    "unshare",
    "chroot",
}


def detect_container_escape(
    profile: BehavioralProfile,
) -> list[Finding]:
    findings: list[Finding] = []

    for op in profile.fs_ops:
        for esc_path, description, severity in ESCAPE_PATHS:
            if op.path == esc_path or op.path.startswith(esc_path):
                final_severity = severity
                if op.operation == "read" and esc_path == "/.dockerenv":
                    final_severity = Severity.INFO
                elif (
                    op.operation in ("write", "create", "delete", "chmod", "chown")
                    and final_severity.value < Severity.HIGH.value
                ):
                    final_severity = Severity.HIGH

                findings.append(
                    Finding(
                        rule_id="L4-CONTAINER-001",
                        severity=final_severity,
                        message=f"Container escape path access ({op.operation}): {op.path} — {description}",
                        location=op.path,
                        evidence={"operation": op.operation, "path": op.path, "description": description},
                    )
                )

    for spawn in profile.spawns:
        exe_base = spawn.executable.split("/")[-1].lower() if "/" in spawn.executable else spawn.executable.lower()
        if exe_base in ESCAPE_BINARIES:
            findings.append(
                Finding(
                    rule_id="L4-CONTAINER-002",
                    severity=Severity.CRITICAL,
                    message=f"Container escape binary spawned: {spawn.executable}",
                    location=spawn.executable,
                    evidence={"executable": spawn.executable, "args": spawn.args[:5]},
                )
            )

    cloud_metadata_addresses = {
        "169.254.169.254",  # AWS/GCP/Azure metadata
        "100.100.100.200",  # Alibaba Cloud metadata
        "fd00:ec2::254",  # AWS IPv6 metadata
    }
    findings.extend(
        Finding(
            rule_id="L4-CONTAINER-003",
            severity=Severity.CRITICAL,
            message=f"Cloud metadata endpoint access: {call.address}:{call.port}",
            location=f"{call.address}:{call.port}",
            evidence={"address": call.address, "port": call.port, "protocol": call.protocol},
        )
        for call in profile.network_calls
        if call.address in cloud_metadata_addresses
    )

    for op in profile.fs_ops:
        path_lower = op.path.lower()
        if "/proc/self/mountinfo" in path_lower or "/proc/self/cgroup" in path_lower:
            findings.append(
                Finding(
                    rule_id="L4-CONTAINER-004",
                    severity=Severity.MEDIUM,
                    message=f"Container fingerprinting via /proc/self: {op.path}",
                    location=op.path,
                    evidence={"operation": op.operation, "path": op.path},
                )
            )

    namespace_keywords = {"nsenter", "unshare", "ip netns", "pivot_root"}
    for spawn in profile.spawns:
        all_args = " ".join(spawn.args).lower()
        exe_lower = spawn.executable.lower()
        findings.extend(
            Finding(
                rule_id="L4-CONTAINER-005",
                severity=Severity.HIGH,
                message=f"Namespace manipulation command: {spawn.executable} {' '.join(spawn.args[:5])}",
                location=spawn.executable,
                evidence={"executable": spawn.executable, "args": spawn.args[:5], "keyword": kw},
            )
            for kw in namespace_keywords
            if kw in exe_lower or kw in all_args
        )

    metadata_dns_patterns = ("metadata.google", "metadata.azure", "169.254.169.254")
    findings.extend(
        Finding(
            rule_id="L4-CONTAINER-006",
            severity=Severity.HIGH,
            message=f"DNS query to cloud metadata hostname: {dns.hostname}",
            location=dns.hostname,
            evidence={"hostname": dns.hostname, "pattern": pattern},
        )
        for dns in profile.dns_queries
        for pattern in metadata_dns_patterns
        if pattern in dns.hostname.lower()
    )

    return findings
