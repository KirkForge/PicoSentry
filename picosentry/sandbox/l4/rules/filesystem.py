from picosentry.sandbox.l4.models import BehavioralProfile, Finding
from picosentry.sandbox.models import Severity


PROTECTED_WRITE_PATHS = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/etc/hosts",
    "/etc/ssh/sshd_config",
    "/etc/crontab",
    "/boot",
    "/sys",
    "/proc",
    "/dev",
    "/root/.ssh",
    "/root/.bashrc",
    "/root/.profile",
}


SUSPICIOUS_WRITE_EXTENSIONS = {
    ".sh",
    ".bat",
    ".cmd",
    ".ps1",
    ".vbs",
    ".dll",
    ".so",
    ".dylib",
    ".exe",
    ".msi",
    ".deb",
    ".rpm",
}


CRITICAL_DELETE_PATHS = {
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/bin/sh",
    "/bin/bash",
    "/usr/bin/sudo",
    "/usr/bin/passwd",
    "/etc/hosts",
}


def detect_filesystem_anomalies(
    profile: BehavioralProfile,
) -> list[Finding]:
    findings: list[Finding] = []

    for op in profile.fs_ops:
        path = op.path

        if op.operation in ("write", "create"):
            findings.extend(
                Finding(
                    rule_id="L4-FS-001",
                    severity=Severity.CRITICAL,
                    message=f"Write to protected system path: {path}",
                    location=path,
                    evidence={"operation": op.operation, "path": path},
                )
                for protected in PROTECTED_WRITE_PATHS
                if path.startswith(protected) or path == protected
            )

        if op.operation in ("write", "create"):
            matched_ext = next(
                (
                    ext
                    for ext in SUSPICIOUS_WRITE_EXTENSIONS
                    if path.lower().endswith(ext) and not path.startswith("/tmp/")
                ),
                None,
            )
            if matched_ext:
                findings.append(
                    Finding(
                        rule_id="L4-FS-002",
                        severity=Severity.MEDIUM,
                        message=f"Executable/shared library written outside /tmp: {path}",
                        location=path,
                        evidence={"operation": op.operation, "path": path, "extension": matched_ext},
                    )
                )

        if op.operation == "delete":
            findings.extend(
                Finding(
                    rule_id="L4-FS-003",
                    severity=Severity.CRITICAL,
                    message=f"Deletion of critical system file: {path}",
                    location=path,
                    evidence={"operation": op.operation, "path": path},
                )
                for critical in CRITICAL_DELETE_PATHS
                if path == critical or path.startswith(critical + "/")
            )

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

        if op.operation == "chmod" and "path" in op.path.lower():
            pass  # chmod events don't have a separate field; skip for now

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
