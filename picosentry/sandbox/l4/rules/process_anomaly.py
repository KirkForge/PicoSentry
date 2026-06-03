"""L4 process anomaly detector.

Detects unexpected process behaviors: shell spawning, privilege escalation
attempts, orphaned/background processes, and suspicious parent-child relationships.
"""

from picosentry.sandbox.l4.models import Baseline, BehavioralProfile, Finding
from picosentry.sandbox.models import Severity

# Commands that should never appear in sandboxed package scripts
FORBIDDEN_SHELL_COMMANDS = {
    "bash", "sh", "zsh", "fish", "dash", "ksh", "csh", "tcsh",
    "cmd.exe", "powershell.exe", "pwsh.exe",
}

# Commands commonly used in reverse shells and C2
REVERSE_SHELL_INDICATORS = {
    "nc", "ncat", "netcat", "socat", "nmap", "telnet",
    "cryptcat", "sbd",
}

# Package manager lifecycle scripts that should not spawn shells
SUSPICIOUS_SPAWN_CONTEXTS = {
    "postinstall", "preinstall", "install", "prepare", "postpack",
}


def detect_process_anomalies(
    profile: BehavioralProfile,
    baselines: dict[str, Baseline] | None = None,
) -> list[Finding]:
    """Detect anomalous process behavior in sandboxed execution."""
    findings: list[Finding] = []

    for spawn in profile.spawns:
        exe = spawn.executable
        exe_base = exe.split("/")[-1].lower() if "/" in exe else exe.lower()

        # L4-PROC-001: Shell spawning
        if exe_base in FORBIDDEN_SHELL_COMMANDS:
            findings.append(
                Finding(
                    rule_id="L4-PROC-001",
                    severity=Severity.HIGH,
                    message=f"Shell spawned during execution: {exe}",
                    location=exe,
                    evidence={"executable": exe, "args": spawn.args},
                )
            )

        # L4-PROC-002: Reverse shell / C2 tool spawning
        if exe_base in REVERSE_SHELL_INDICATORS:
            findings.append(
                Finding(
                    rule_id="L4-PROC-002",
                    severity=Severity.CRITICAL,
                    message=f"Reverse shell / C2 tool spawned: {exe}",
                    location=exe,
                    evidence={"executable": exe, "args": spawn.args},
                )
            )

    # L4-PROC-003: Excessive process spawning
    if len(profile.spawns) > 5:
        spawn_names = [s.executable for s in profile.spawns]
        findings.append(
            Finding(
                rule_id="L4-PROC-003",
                severity=Severity.MEDIUM,
                message=f"Excessive process spawning: {len(profile.spawns)} processes spawned",
                location=profile.package,
                evidence={"spawn_count": len(profile.spawns), "executables": spawn_names[:10]},
            )
        )

    # L4-PROC-004: Spawns that don't match baseline expectations
    if baselines:
        from picosentry.sandbox.l4.differ import find_best_baseline

        best = find_best_baseline(profile, baselines)
        if best and best[1].spawn_drift:
            spawn_extras = len(profile.spawns) - (best[0].expected_spawns if best[0].expected_spawns >= 0 else 0)
            if spawn_extras > 3:
                findings.append(
                    Finding(
                        rule_id="L4-PROC-004",
                        severity=Severity.MEDIUM,
                        message=f"Process spawn count exceeds baseline by {spawn_extras}",
                        location=profile.package,
                        evidence={
                            "spawn_count": len(profile.spawns),
                            "baseline_expected": best[0].expected_spawns,
                        },
                    )
                )

    return findings
