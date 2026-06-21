from picosentry.sandbox.l4.models import BehavioralProfile, Finding
from picosentry.sandbox.models import Severity


PERSISTENCE_PATHS: list[tuple[str, str, Severity]] = [
    ("/etc/profile", "shell profile modification", Severity.HIGH),
    ("/etc/profile.d/", "shell profile.d drop-in", Severity.HIGH),
    ("/etc/bash.bashrc", "system-wide bashrc modification", Severity.HIGH),
    ("/etc/zsh/zshrc", "system-wide zshrc modification", Severity.HIGH),
    ("/.ssh/authorized_keys", "SSH authorized_keys write", Severity.CRITICAL),
    ("/.ssh/config", "SSH config modification", Severity.HIGH),
    ("/root/.ssh/", "root SSH directory write", Severity.CRITICAL),
    ("/etc/systemd/system/", "systemd unit creation", Severity.HIGH),
    ("/etc/systemd/user/", "systemd user unit creation", Severity.HIGH),
    ("/lib/systemd/system/", "systemd library unit write", Severity.MEDIUM),
    ("/etc/init.d/", "init.d script creation", Severity.HIGH),
    ("/etc/rc.local", "rc.local modification", Severity.HIGH),
    ("/Library/LaunchAgents/", "macOS LaunchAgent creation", Severity.HIGH),
    ("/Library/LaunchDaemons/", "macOS LaunchDaemon creation", Severity.HIGH),
    ("~/Library/LaunchAgents/", "user LaunchAgent creation", Severity.HIGH),
    ("/etc/login.defs", "login.defs modification", Severity.MEDIUM),
    ("/etc/pam.d/", "PAM configuration modification", Severity.HIGH),
    ("/var/spool/at/", "at job creation", Severity.MEDIUM),
]


def detect_persistence(
    profile: BehavioralProfile,
) -> list[Finding]:
    findings: list[Finding] = []

    for op in profile.fs_ops:
        if op.operation not in ("write", "create", "chmod", "chown"):
            continue
        for path_prefix, description, severity in PERSISTENCE_PATHS:
            if op.path == path_prefix or op.path.startswith(path_prefix) or op.path.endswith(path_prefix):
                findings.append(
                    Finding(
                        rule_id="L4-PERSIST-001",
                        severity=severity,
                        message=f"Persistence path written ({op.operation}): {op.path} — {description}",
                        location=op.path,
                        evidence={"operation": op.operation, "path": op.path, "mechanism": description},
                    )
                )

    cron_binaries = {"crontab", "at", "atq", "atrm", "batch"}
    for spawn in profile.spawns:
        exe_base = spawn.executable.split("/")[-1].lower() if "/" in spawn.executable else spawn.executable.lower()
        if exe_base in cron_binaries:
            findings.append(
                Finding(
                    rule_id="L4-PERSIST-002",
                    severity=Severity.HIGH,
                    message=f"Persistence command spawned: {spawn.executable}",
                    location=spawn.executable,
                    evidence={"executable": spawn.executable, "args": spawn.args[:5]},
                )
            )

    for spawn in profile.spawns:
        exe_base = spawn.executable.split("/")[-1].lower() if "/" in spawn.executable else spawn.executable.lower()
        if exe_base == "systemctl":
            all_args = " ".join(spawn.args).lower()
            if any(kw in all_args for kw in ("enable", "start", "mask")):
                findings.append(
                    Finding(
                        rule_id="L4-PERSIST-003",
                        severity=Severity.HIGH,
                        message=f"systemctl persistence command: {spawn.executable} {' '.join(spawn.args[:5])}",
                        location=spawn.executable,
                        evidence={"executable": spawn.executable, "args": spawn.args[:5]},
                    )
                )

    profile_editors = {"chsh", "chfn", "usermod", "passwd"}
    for spawn in profile.spawns:
        exe_base = spawn.executable.split("/")[-1].lower() if "/" in spawn.executable else spawn.executable.lower()
        if exe_base in profile_editors:
            findings.append(
                Finding(
                    rule_id="L4-PERSIST-004",
                    severity=Severity.MEDIUM,
                    message=f"User/profile modification command: {spawn.executable}",
                    location=spawn.executable,
                    evidence={"executable": spawn.executable, "args": spawn.args[:5]},
                )
            )

    for spawn in profile.spawns:
        exe_base = spawn.executable.split("/")[-1].lower() if "/" in spawn.executable else spawn.executable.lower()
        if exe_base == "launchctl":
            all_args = " ".join(spawn.args).lower()
            if any(kw in all_args for kw in ("load", "enable")):
                findings.append(
                    Finding(
                        rule_id="L4-PERSIST-005",
                        severity=Severity.HIGH,
                        message=f"macOS launchctl persistence: {spawn.executable} {' '.join(spawn.args[:5])}",
                        location=spawn.executable,
                        evidence={"executable": spawn.executable, "args": spawn.args[:5]},
                    )
                )

    return findings
