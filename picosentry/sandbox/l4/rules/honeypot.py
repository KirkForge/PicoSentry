"""L4 honeypot touch detector."""

from picosentry.sandbox.l4.models import Baseline, BehavioralProfile, Finding
from picosentry.sandbox.models import Severity

# Paths that no legitimate package should access
HONEYPOT_PATHS = [
    "/etc/passwd",
    "/etc/shadow",
    "/etc/sudoers",
    "/root/.ssh",
    "/root/.bashrc",
    "/home/*/.ssh/id_rsa",
    "/home/*/.ssh/id_ed25519",
    "/proc/sys/kernel",
    "/sys/kernel",
    "/boot",
    "/etc/ssl/private",
    "/var/log/auth.log",
    "/var/log/secure",
]


def detect_honeypot_touches(
    profile: BehavioralProfile,
    baselines: dict[str, Baseline] | None = None,
) -> list[Finding]:
    """Detect access to honeypot paths — files no package should touch."""
    findings: list[Finding] = []
    import fnmatch

    for op in profile.fs_ops:
        for honeypot in HONEYPOT_PATHS:
            if fnmatch.fnmatch(op.path, honeypot):
                findings.append(
                    Finding(
                        rule_id="L4-HONEY-001",
                        severity=Severity.CRITICAL,
                        message=f"Honeypot path accessed ({op.operation}): {op.path}",
                        location=op.path,
                        evidence={"operation": op.operation, "path": op.path, "honeypot_rule": honeypot},
                    )
                )
                break

    # Check for process spawns that look like privilege escalation
    priv_esc_binaries = {"sudo", "su", "pkexec", "doas", "chown", "chmod"}
    for spawn in profile.spawns:
        exe_base = spawn.executable.split("/")[-1]
        if exe_base in priv_esc_binaries:
            findings.append(
                Finding(
                    rule_id="L4-HONEY-002",
                    severity=Severity.CRITICAL,
                    message=f"Privilege escalation binary spawned: {spawn.executable}",
                    location=spawn.executable,
                    evidence={"executable": spawn.executable, "args": spawn.args},
                )
            )

    return findings
