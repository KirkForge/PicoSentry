from picosentry.sandbox.l4.models import BehavioralProfile, SandboxFinding
from picosentry.sandbox.models import Severity


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


# Setuid/setgid bits live in the chmod MODE argument ("4755", "6755", ...),
# not in the file path. The rule used to substring-match command prefixes
# ("chmod 4") against op.path — a FILE PATH — so it never fired on real data
# (WO9.0.0-002). These are the bit masks: 04000 setuid, 02000 setgid.
_SETUID_BIT = 0o4000
_SETGID_BIT = 0o2000


def _is_setuid_mode(mode: str) -> bool:
    """True when a chmod mode carries the setuid and/or setgid bit.

    Only numeric (octal) modes are considered: a symbolic mode like "+x" says
    nothing about setuid, and guessing would produce false CRITICALs.
    """
    mode = (mode or "").strip()
    if not mode or not mode.isdigit():
        return False
    try:
        value = int(mode, 8)
    except ValueError:
        return False
    return bool(value & (_SETUID_BIT | _SETGID_BIT))


def detect_privilege_escalation(
    profile: BehavioralProfile,
) -> list[SandboxFinding]:
    findings: list[SandboxFinding] = []

    for op in profile.fs_ops:
        if op.operation not in ("write", "create", "chmod", "chown", "delete"):
            continue
        for priv_path, severity in PRIV_ESC_PATHS.items():
            if op.path == priv_path or op.path.startswith(priv_path):
                findings.append(
                    SandboxFinding(
                        rule_id="L4-PRIVESC-001",
                        severity=severity,
                        message=f"Write to privilege-critical path ({op.operation}): {op.path}",
                        location=op.path,
                        evidence={"operation": op.operation, "path": op.path},
                    )
                )

    for spawn in profile.spawns:
        exe_base = spawn.executable.split("/")[-1].lower() if "/" in spawn.executable else spawn.executable.lower()
        if exe_base in PRIV_ESC_BINARIES:
            findings.append(
                SandboxFinding(
                    rule_id="L4-PRIVESC-002",
                    severity=Severity.HIGH,
                    message=f"Privilege escalation binary spawned: {spawn.executable}",
                    location=spawn.executable,
                    evidence={"executable": spawn.executable, "args": spawn.args[:5]},
                )
            )

    for op in profile.fs_ops:
        if op.operation == "chmod" and _is_setuid_mode(op.mode):
            findings.append(
                SandboxFinding(
                    rule_id="L4-PRIVESC-003",
                    severity=Severity.CRITICAL,
                    message=f"setuid/setgid chmod attempt: chmod {op.mode} {op.path}",
                    location=op.path,
                    evidence={"operation": "chmod", "path": op.path, "mode": op.mode},
                )
            )

    cap_keywords = {"setcap", "getcap", "cap_setuid", "cap_net_raw", "cap_sys_admin", "cap_dac_override"}
    for spawn in profile.spawns:
        exe_lower = spawn.executable.lower()
        all_args = " ".join(spawn.args).lower()
        if any(kw in exe_lower or kw in all_args for kw in cap_keywords):
            findings.append(
                SandboxFinding(
                    rule_id="L4-PRIVESC-004",
                    severity=Severity.HIGH,
                    message=f"Linux capabilities manipulation: {spawn.executable} {spawn.args[:3]}",
                    location=spawn.executable,
                    evidence={"executable": spawn.executable, "args": spawn.args[:5]},
                )
            )

    for op in profile.fs_ops:
        path_lower = op.path.lower()
        if op.operation in ("write", "create") and (
            "/etc/cron" in path_lower or path_lower.startswith(("/var/spool/cron", "/var/cron"))
        ):
            findings.append(
                SandboxFinding(
                    rule_id="L4-PRIVESC-005",
                    severity=Severity.HIGH,
                    message=f"Cron job manipulation ({op.operation}): {op.path}",
                    location=op.path,
                    evidence={"operation": op.operation, "path": op.path},
                )
            )

    return findings
