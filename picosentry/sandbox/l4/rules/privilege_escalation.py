"""L4 privilege escalation detector.

Detects attempts to escalate privileges: setuid/setgid file creation,
sudoers manipulation, shadow/passwd writes, chmod 4xxx, cron abuse,
and capabilities manipulation.
"""

from picosentry.sandbox.l4.models import Baseline, BehavioralProfile, Finding
from picosentry.sandbox.models import Severity

# Paths that should never be written to by sandboxed code
PRIV_ESC_PATHS: dict[str, Severity] = {
    "/etc/sudoers": Severity.CRITICAL,
    "/etc/sudoers.d/": Severity.CRITICAL,
    "/etc/shadow": Severity.CRITICAL,
    "/etc/gshadow": Severity.CRITICAL,
    "/etc/passwd": Severity.CRITICAL,
    "/etc/group": Severity.HIGH,
    "/etc/pam.d/": Severity.CRITICAL,
    "/etc/polkit-1/": Severity.HIGH,
    "/etc/sudo.conf": Severity.HIGH,
    "/etc/security/": Severity.HIGH,
    "/etc/ssh/sshd_config": Severity.HIGH,
}

# Executables commonly used for privilege escalation
PRIV_ESC_BINARIES = {
    "sudo",
    "su",
    "pkexec",
    "chroot",
    "chfn",
    "chsh",
    "passwd",
    "newgrp",
    "gpasswd",
    "chage",
}

# chmod operations indicating setuid/setgid attempts
SETUID_PATTERNS = ("chmod 4", "chmod 2", "chmod 6", "chmod 47", "chmod 27", "chmod 67")


def detect_privilege_escalation(
    profile: BehavioralProfile,
    baselines: dict[str, Baseline] | None = None,
) -> list[Finding]:
    """Detect privilege escalation attempts during sandboxed execution."""
    findings: list[Finding] = []

    # L4-PRIVESC-001: Writes to privilege-critical paths
    for op in profile.fs_ops:
        if op.operation not in ("write", "create", "chmod", "chown", "delete"):
            continue
        for priv_path, severity in PRIV_ESC_PATHS.items():
            if op.path == priv_path or op.path.startswith(priv_path):
                findings.append(
                    Finding(
                        rule_id="L4-PRIVESC-001",
                        severity=severity,
                        message=f"Write to privilege-critical path ({op.operation}): {op.path}",
                        location=op.path,
                        evidence={"operation": op.operation, "path": op.path},
                    )
                )

    # L4-PRIVESC-002: Spawning privilege-escalation binaries
    for spawn in profile.spawns:
        exe_base = spawn.executable.split("/")[-1].lower() if "/" in spawn.executable else spawn.executable.lower()
        if exe_base in PRIV_ESC_BINARIES:
            findings.append(
                Finding(
                    rule_id="L4-PRIVESC-002",
                    severity=Severity.HIGH,
                    message=f"Privilege escalation binary spawned: {spawn.executable}",
                    location=spawn.executable,
                    evidence={"executable": spawn.executable, "args": spawn.args[:5]},
                )
            )

    # L4-PRIVESC-003: setuid/setgid chmod attempts
    for op in profile.fs_ops:
        if op.operation == "chmod":
            for pattern in SETUID_PATTERNS:
                if pattern in op.path:
                    findings.append(
                        Finding(
                            rule_id="L4-PRIVESC-003",
                            severity=Severity.CRITICAL,
                            message=f"setuid/setgid chmod attempt: {op.path}",
                            location=op.path,
                            evidence={"operation": "chmod", "path": op.path},
                        )
                    )
                    break

    # L4-PRIVESC-004: Capabilities manipulation
    cap_keywords = {"setcap", "getcap", "cap_setuid", "cap_net_raw", "cap_sys_admin", "cap_dac_override"}
    for spawn in profile.spawns:
        exe_lower = spawn.executable.lower()
        all_args = " ".join(spawn.args).lower()
        if any(kw in exe_lower or kw in all_args for kw in cap_keywords):
            findings.append(
                Finding(
                    rule_id="L4-PRIVESC-004",
                    severity=Severity.HIGH,
                    message=f"Linux capabilities manipulation: {spawn.executable} {spawn.args[:3]}",
                    location=spawn.executable,
                    evidence={"executable": spawn.executable, "args": spawn.args[:5]},
                )
            )

    # L4-PRIVESC-005: /etc/cron manipulation (persistence via cron)
    for op in profile.fs_ops:
        path_lower = op.path.lower()
        if op.operation in ("write", "create") and (
            "/etc/cron" in path_lower
            or path_lower.startswith("/var/spool/cron")
            or path_lower.startswith("/var/cron")
        ):
            findings.append(
                Finding(
                    rule_id="L4-PRIVESC-005",
                    severity=Severity.HIGH,
                    message=f"Cron job manipulation ({op.operation}): {op.path}",
                    location=op.path,
                    evidence={"operation": op.operation, "path": op.path},
                )
            )

    return findings
