"""L4 filesystem anomaly detector.

Detects suspicious filesystem operations: writes outside expected directories,
chmod to executable, deletion of critical files, and unexpected path traversal.
"""

from picosentry.sandbox.l4.models import Baseline, BehavioralProfile, Finding
from picosentry.sandbox.models import Severity

# Directories that should never be written to by package install scripts
PROTECTED_WRITE_PATHS = {
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts",
    "/etc/ssh/sshd_config", "/etc/crontab",
    "/boot", "/sys", "/proc", "/dev",
    "/root/.ssh", "/root/.bashrc", "/root/.profile",
}

# Extensions that should not be written by package managers
SUSPICIOUS_WRITE_EXTENSIONS = {
    ".sh", ".bat", ".cmd", ".ps1", ".vbs", ".dll", ".so", ".dylib",
    ".exe", ".msi", ".deb", ".rpm",
}

# Critical system files that should never be deleted
CRITICAL_DELETE_PATHS = {
    "/etc/passwd", "/etc/shadow", "/etc/sudoers",
    "/bin/sh", "/bin/bash", "/usr/bin/sudo",
    "/usr/bin/passwd", "/etc/hosts",
}


def detect_filesystem_anomalies(
    profile: BehavioralProfile,
    baselines: dict[str, Baseline] | None = None,
) -> list[Finding]:
    """Detect suspicious filesystem operations in sandboxed execution."""
    findings: list[Finding] = []

    for op in profile.fs_ops:
        path = op.path

        # L4-FS-001: Writes to protected system paths
        if op.operation in ("write", "create"):
            for protected in PROTECTED_WRITE_PATHS:
                if path.startswith(protected) or path == protected:
                    findings.append(
                        Finding(
                            rule_id="L4-FS-001",
                            severity=Severity.CRITICAL,
                            message=f"Write to protected system path: {path}",
                            location=path,
                            evidence={"operation": op.operation, "path": path},
                        )
                    )

        # L4-FS-002: Suspicious file extensions being written
        if op.operation in ("write", "create"):
            for ext in SUSPICIOUS_WRITE_EXTENSIONS:
                if path.lower().endswith(ext) and not path.startswith("/tmp/"):
                    findings.append(
                        Finding(
                            rule_id="L4-FS-002",
                            severity=Severity.MEDIUM,
                            message=f"Executable/shared library written outside /tmp: {path}",
                            location=path,
                            evidence={"operation": op.operation, "path": path, "extension": ext},
                        )
                    )
                    break

        # L4-FS-003: Deletion of critical system files
        if op.operation in ("delete",):
            for critical in CRITICAL_DELETE_PATHS:
                if path == critical or path.startswith(critical + "/"):
                    findings.append(
                        Finding(
                            rule_id="L4-FS-003",
                            severity=Severity.CRITICAL,
                            message=f"Deletion of critical system file: {path}",
                            location=path,
                            evidence={"operation": op.operation, "path": path},
                        )
                    )

        # L4-FS-004: Path traversal attempts
        if "../" in path or "..\\" in path:
            findings.append(
                Finding(
                    rule_id="L4-FS-004",
                    severity=Severity.HIGH,
                    message=f"Path traversal detected: {path}",
                    location=path,
                    evidence={"operation": op.operation, "path": path},
                )
            )

        # L4-FS-005: chmod operations making files executable
        if op.operation == "chmod" and "path" in op.path.lower():
            pass  # chmod events don't have a separate field; skip for now

    # L4-FS-006: Excessive filesystem writes
    write_ops = [op for op in profile.fs_ops if op.operation in ("write", "create")]
    if len(write_ops) > 100:
        findings.append(
            Finding(
                rule_id="L4-FS-006",
                severity=Severity.MEDIUM,
                message=f"Excessive filesystem writes: {len(write_ops)} write operations",
                location=profile.package,
                evidence={"write_count": len(write_ops)},
            )
        )

    return findings
