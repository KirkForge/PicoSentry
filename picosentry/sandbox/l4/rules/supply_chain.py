
import re

from picosentry.sandbox.l4.models import Baseline, BehavioralProfile, Finding
from picosentry.sandbox.models import Severity


_OBFUSCATION_PATTERNS: list[tuple[str, str]] = [
    (r"\\x[0-9a-f]{2}", "hex-escape sequence"),
    (r"\\u[0-9a-f]{4}", "unicode-escape sequence"),
    (r"atob\(", "base64 decode (browser)"),
    (r"Buffer\.from\(.+,\s*['\"]base64['\"]", "Node.js base64 decode"),
    (r"eval\(atob\(", "eval of base64-decoded string"),
    (r"Function\(.{20,}\)", "Function constructor with long body"),
    (r"\\x[0-9a-f]{2}.+\\x[0-9a-f]{2}.+\\x[0-9a-f]{2}", "multiple hex escapes"),
]


_INSTALL_EXEC_PATTERNS: list[tuple[str, str]] = [
    (r"curl\s+\S+\s*\|\s*(?:sh|bash|zsh)", "pipelined remote script execution"),
    (r"wget\s+\S+\s*-O\s*\S+\s*&&\s*(?:sh|bash)", "download-and-execute"),
    (r"python\s+-c\s+['\"]import\s+urllib", "inline Python HTTP fetch"),
    (r"node\s+-e\s+['\"]require\(['\"]https?['\"]", "inline Node.js HTTP fetch"),
    (r"npm\s+publish", "npm publish from sandbox"),
    (r"pip\s+upload", "pip upload from sandbox"),
    (r"git\s+push", "git push from sandbox"),
]


def detect_supply_chain_patterns(
    profile: BehavioralProfile,
    baselines: dict[str, Baseline] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []


    for spawn in profile.spawns:
        args_str = " ".join(spawn.args)
        for pattern, description in _OBFUSCATION_PATTERNS:
            if re.search(pattern, args_str):
                findings.append(
                    Finding(
                        rule_id="L4-SC-001",
                        severity=Severity.HIGH,
                        message=f"Obfuscated payload in spawn args ({description}): {spawn.executable}",
                        location=spawn.executable,
                        evidence={"executable": spawn.executable, "args": spawn.args[:5], "pattern": description},
                    )
                )
                break


        for pattern, description in _INSTALL_EXEC_PATTERNS:
            if re.search(pattern, args_str):
                findings.append(
                    Finding(
                        rule_id="L4-SC-002",
                        severity=Severity.CRITICAL,
                        message=f"Remote code execution pattern: {description}",
                        location=spawn.executable,
                        evidence={"executable": spawn.executable, "args": spawn.args[:5], "pattern": description},
                    )
                )


    if baselines:
        from picosentry.sandbox.l4.differ import find_best_baseline

        best = find_best_baseline(profile, baselines)
        if best and best[0].expected_network_calls == 0 and len(profile.network_calls) > 0:
            findings.append(
                Finding(
                    rule_id="L4-SC-003",
                    severity=Severity.HIGH,
                    message=(
                        f"Network activity in zero-network baseline: "
                        f"{len(profile.network_calls)} connections detected"
                    ),
                    location=profile.package,
                    evidence={
                        "network_call_count": len(profile.network_calls),
                        "baseline": best[0].name,
                        "baseline_expected_network_calls": 0,
                    },
                )
            )


    if baselines:
        from picosentry.sandbox.l4.differ import find_best_baseline

        best = find_best_baseline(profile, baselines)
        if best and best[0].expected_spawns == 0 and len(profile.spawns) > 0:
            findings.append(
                Finding(
                    rule_id="L4-SC-004",
                    severity=Severity.HIGH,
                    message=(
                        f"Process spawning in zero-spawn baseline: "
                        f"{len(profile.spawns)} spawns detected"
                    ),
                    location=profile.package,
                    evidence={
                        "spawn_count": len(profile.spawns),
                        "baseline": best[0].name,
                        "baseline_expected_spawns": 0,
                    },
                )
            )


    suspicious_keywords = {"pastebin", "webhook", "ipify", "ifconfig", "whatismyip", "checkip"}
    for dns in profile.dns_queries:
        hostname_lower = dns.hostname.lower()
        for keyword in suspicious_keywords:
            if keyword in hostname_lower:
                findings.append(
                    Finding(
                        rule_id="L4-SC-005",
                        severity=Severity.HIGH,
                        message=f"Suspicious DNS query during execution: {dns.hostname}",
                        location=dns.hostname,
                        evidence={"hostname": dns.hostname, "keyword": keyword},
                    )
                )

    return findings
