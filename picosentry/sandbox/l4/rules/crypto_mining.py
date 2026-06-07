
from picosentry.sandbox.l4.models import Baseline, BehavioralProfile, Finding
from picosentry.sandbox.models import Severity


MINING_PORTS = {
    3333,   # Default Stratum
    4444,   # Alternative Stratum
    45558,  # NiceHash
    45700,  # Mining pool
    5555,   # Mining pool alt
    8888,   # Mining pool alt
    14433,  # Stratum alt
    14444,  # Stratum alt
    34444,  # Mining pool
}


MINING_BINARIES = {
    "xmrig",
    "minerd",
    "cgminer",
    "bfgminer",
    "cpuminer",
    "ccminer",
    "claymore",
    "ethminer",
    "phoenixminer",
    "nbminer",
    "t-rex",
    "trex",
    "cryptonight",
    "xmr-stak",
    "wildrig",
    "nanominer",
    "gminer",
    "lolminer",
    "teamredminer",
    "progpowminer",
}


MINING_DNS_PATTERNS = (
    "pool.",
    "stratum.",
    "mining.",
    "miner.",
    "xmr.",
    "eth.",
    "monero.",
    "nicehash.",
)


def detect_crypto_mining(
    profile: BehavioralProfile,
    baselines: dict[str, Baseline] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []


    for call in profile.network_calls:
        if call.port in MINING_PORTS:
            findings.append(
                Finding(
                    rule_id="L4-CRYPTO-001",
                    severity=Severity.CRITICAL,
                    message=f"Connection to known mining pool port {call.port}: {call.address}:{call.port}",
                    location=f"{call.address}:{call.port}",
                    evidence={"address": call.address, "port": call.port, "protocol": call.protocol},
                )
            )


    for spawn in profile.spawns:
        exe_base = spawn.executable.split("/")[-1].lower() if "/" in spawn.executable else spawn.executable.lower()
        if exe_base in MINING_BINARIES:
            findings.append(
                Finding(
                    rule_id="L4-CRYPTO-002",
                    severity=Severity.CRITICAL,
                    message=f"Crypto mining binary spawned: {spawn.executable}",
                    location=spawn.executable,
                    evidence={"executable": spawn.executable, "args": spawn.args[:5]},
                )
            )


    for dns in profile.dns_queries:
        hostname_lower = dns.hostname.lower()
        for pattern in MINING_DNS_PATTERNS:
            if pattern in hostname_lower:
                findings.append(
                    Finding(
                        rule_id="L4-CRYPTO-003",
                        severity=Severity.HIGH,
                        message=f"DNS query to mining-related domain: {dns.hostname}",
                        location=dns.hostname,
                        evidence={"hostname": dns.hostname, "pattern": pattern},
                    )
                )


    has_mining_port = any(call.port in MINING_PORTS for call in profile.network_calls)
    has_network = len(profile.network_calls) > 0
    long_execution = profile.total_runtime_ms > 60000  # > 60s
    if long_execution and has_network and not has_mining_port:

        findings.append(
            Finding(
                rule_id="L4-CRYPTO-004",
                severity=Severity.MEDIUM,
                message=f"Suspiciously long execution ({profile.total_runtime_ms}ms) with network activity",
                location=profile.package,
                evidence={
                    "runtime_ms": profile.total_runtime_ms,
                    "network_calls": len(profile.network_calls),
                },
            )
        )


    mining_config_patterns = (
        "config.json",  # XMRig config
        "pools.txt",
        "pool.conf",
    )
    mining_config_dirs = (".xmrig", ".minerd", ".cgminer", ".bfgminer")
    for op in profile.fs_ops:
        path_lower = op.path.lower()
        for pattern in mining_config_patterns:
            if pattern in path_lower and any(d in path_lower for d in mining_config_dirs):
                findings.append(
                    Finding(
                        rule_id="L4-CRYPTO-005",
                        severity=Severity.HIGH,
                        message=f"Mining configuration file access: {op.path}",
                        location=op.path,
                        evidence={"operation": op.operation, "path": op.path},
                    )
                )


    mining_arg_patterns = {"--url=stratum", "--pool", "--algo=cryptonight", "--coin", "--donate-level"}
    for spawn in profile.spawns:
        all_args_str = " ".join(spawn.args).lower()
        for pattern in mining_arg_patterns:
            if pattern in all_args_str:
                findings.append(
                    Finding(
                        rule_id="L4-CRYPTO-006",
                        severity=Severity.HIGH,
                        message=f"Process spawned with mining arguments: {spawn.executable}",
                        location=spawn.executable,
                        evidence={"executable": spawn.executable, "args": spawn.args[:5], "pattern": pattern},
                    )
                )

    return findings
