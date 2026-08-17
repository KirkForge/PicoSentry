from picosentry.sandbox.l4.models import BehavioralProfile, SandboxFinding
from picosentry.sandbox.models import Severity


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
) -> list[SandboxFinding]:
    findings: list[SandboxFinding] = []
    import fnmatch

    for op in profile.fs_ops:
        for honeypot in HONEYPOT_PATHS:
            if fnmatch.fnmatch(op.path, honeypot):
                findings.append(
                    SandboxFinding(
                        rule_id="L4-HONEY-001",
                        severity=Severity.CRITICAL,
                        message=f"Honeypot path accessed ({op.operation}): {op.path}",
                        location=op.path,
                        evidence={"operation": op.operation, "path": op.path, "honeypot_rule": honeypot},
                    )
                )
                break

    # FP fix (WO4.0.0-018): privilege BROKERS stay CRITICAL; chmod/chown are
    # routine install steps (every benign postinstall chmods its bin shims)
    # and got their own LOW-severity rule so a benign postinstall is not
    # verdicted MALICIOUS. Setuid-style chmod is still caught by L4-PRIVESC-003.
    privilege_brokers = {"sudo", "su", "pkexec", "doas"}
    ownership_tools = {"chmod", "chown", "chgrp"}
    for spawn in profile.spawns:
        exe_base = spawn.executable.split("/")[-1]
        if exe_base in privilege_brokers:
            findings.append(
                SandboxFinding(
                    rule_id="L4-HONEY-002",
                    severity=Severity.CRITICAL,
                    message=f"Privilege escalation binary spawned: {spawn.executable}",
                    location=spawn.executable,
                    evidence={"executable": spawn.executable, "args": spawn.args},
                )
            )
        elif exe_base in ownership_tools:
            findings.append(
                SandboxFinding(
                    rule_id="L4-HONEY-003",
                    severity=Severity.LOW,
                    message=f"File ownership/permission tool spawned: {spawn.executable}",
                    location=spawn.executable,
                    evidence={"executable": spawn.executable, "args": spawn.args},
                )
            )

    return findings
