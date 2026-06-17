
from picosentry.sandbox.l4.models import Baseline, BehavioralProfile, Finding
from picosentry.sandbox.models import Severity


SUSPICIOUS_REGISTRY_HOSTS = {
    "npm.company", "npm.internal", "npm.local",
    "pypi.company", "pypi.internal", "pypi.local",
    "artifactory.internal", "nexus.internal", "gems.internal",
}


SUSPICIOUS_REGISTRY_ARG_PATTERNS = (
    "--registry=",
    "--registry ",
    "--index-url=",
    "--index-url ",
    "--extra-index-url=",
    "--extra-index-url ",
    "npm_config_registry",
    "PYPI_INDEX_URL",
    "pip.conf",
)


PUBLISH_BINARIES = {
    "npm publish",
    "npm-deprecate",
    "twine",
    "gem push",
    "nuget push",
    "cargo publish",
}


SUSPICIOUS_INSTALL_PATTERNS = (
    "git+http://",
    "git+https://github.com/",
    "http://",
    "ftp://",
    "file:///",
    "/tmp/",
    "dev/null",
)


def detect_dependency_confusion(
    profile: BehavioralProfile,
    baselines: dict[str, Baseline] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []


    for dns in profile.dns_queries:
        hostname_lower = dns.hostname.lower()
        for pattern in SUSPICIOUS_REGISTRY_HOSTS:
            if pattern in hostname_lower:
                findings.append(
                    Finding(
                        rule_id="L4-DEP-001",
                        severity=Severity.HIGH,
                        message=f"DNS query to suspicious registry: {dns.hostname}",
                        location=dns.hostname,
                        evidence={"hostname": dns.hostname, "pattern": pattern},
                    )
                )


        if hostname_lower.endswith((".local", ".internal")):
            findings.append(
                Finding(
                    rule_id="L4-DEP-001",
                    severity=Severity.HIGH,
                    message=f"DNS query to internal TLD: {dns.hostname}",
                    location=dns.hostname,
                    evidence={"hostname": dns.hostname},
                )
            )


    for spawn in profile.spawns:
        exe_base = spawn.executable.split("/")[-1].lower() if "/" in spawn.executable else spawn.executable.lower()
        all_args_str = " ".join(spawn.args).lower()


        if exe_base in ("twine", "gem", "cargo") and ("upload" in all_args_str or "publish" in all_args_str):
            findings.append(
                Finding(
                    rule_id="L4-DEP-002",
                    severity=Severity.CRITICAL,
                    message=f"Package publish command during install: {spawn.executable} {' '.join(spawn.args[:5])}",
                    location=spawn.executable,
                    evidence={"executable": spawn.executable, "args": spawn.args[:5]},
                )
            )


        if exe_base == "npm" and "publish" in all_args_str:
            findings.append(
                Finding(
                    rule_id="L4-DEP-002",
                    severity=Severity.CRITICAL,
                    message=f"npm publish command during install: {spawn.executable} {' '.join(spawn.args[:5])}",
                    location=spawn.executable,
                    evidence={"executable": spawn.executable, "args": spawn.args[:5]},
                )
            )


    for spawn in profile.spawns:
        exe_base = spawn.executable.split("/")[-1].lower() if "/" in spawn.executable else spawn.executable.lower()
        all_args_str = " ".join(spawn.args)

        if exe_base in ("pip", "pip3", "python", "python3"):
            for pattern in SUSPICIOUS_INSTALL_PATTERNS:
                if pattern in all_args_str:
                    findings.append(
                        Finding(
                            rule_id="L4-DEP-003",
                            severity=Severity.HIGH,
                            message=f"Suspicious package install URL: {pattern.rstrip('=')} in {spawn.executable}",
                            location=spawn.executable,
                            evidence={"executable": spawn.executable, "args": spawn.args[:5], "pattern": pattern},
                        )
                    )
                    break

        if exe_base == "npm" and "http://" in all_args_str:
            findings.append(
                Finding(
                    rule_id="L4-DEP-003",
                    severity=Severity.MEDIUM,
                    message=f"npm install over HTTP (insecure): {spawn.executable}",
                    location=spawn.executable,
                    evidence={"executable": spawn.executable, "args": spawn.args[:5]},
                )
            )


    for spawn in profile.spawns:
        all_args_str = " ".join(spawn.args)
        for pattern in SUSPICIOUS_REGISTRY_ARG_PATTERNS:
            if pattern.lower() in all_args_str.lower():
                findings.append(
                    Finding(
                        rule_id="L4-DEP-004",
                        severity=Severity.HIGH,
                        message=f"Registry override attempt: {pattern} in {spawn.executable}",
                        location=spawn.executable,
                        evidence={"executable": spawn.executable, "args": spawn.args[:5], "pattern": pattern},
                    )
                )


    standard_ports = {0, 22, 80, 443}
    for call in profile.network_calls:
        if call.port not in standard_ports and call.port > 0:

            addr_lower = call.address.lower()
            registry_keywords = ("pypi", "npmjs", "npm", "registry", "rubygems", "crates", "maven", "nuget", "packagist")
            if any(kw in addr_lower for kw in registry_keywords):
                findings.append(
                    Finding(
                        rule_id="L4-DEP-005",
                        severity=Severity.MEDIUM,
                        message=f"Registry connection on non-standard port: {call.address}:{call.port}",
                        location=f"{call.address}:{call.port}",
                        evidence={"address": call.address, "port": call.port},
                    )
                )


    for op in profile.fs_ops:
        path_lower = op.path.lower()
        if op.operation in ("read", "write", "create"):
            if path_lower.endswith((".npmrc", "pip.conf")) or "pip.ini" in path_lower:
                if op.operation in ("write", "create"):
                    findings.append(
                        Finding(
                            rule_id="L4-DEP-006",
                            severity=Severity.HIGH,
                            message=f"Package registry config modification ({op.operation}): {op.path}",
                            location=op.path,
                            evidence={"operation": op.operation, "path": op.path},
                        )
                    )
                elif op.operation == "read":
                    findings.append(
                        Finding(
                            rule_id="L4-DEP-006",
                            severity=Severity.LOW,
                            message=f"Package registry config read: {op.path}",
                            location=op.path,
                            evidence={"operation": op.operation, "path": op.path},
                        )
                    )

    return findings
