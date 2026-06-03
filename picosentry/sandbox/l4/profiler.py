"""L4 profiler — extract behavioral profiles from L3 sandbox results."""

from __future__ import annotations

import re

from picosentry.sandbox.l3.models import SandboxResult
from picosentry.sandbox.l4.models import (
    BehavioralProfile,
    DnsQuery,
    FileOperation,
    NetworkCall,
    ProcessSpawn,
    TimingPoint,
)


def profile_from_sandbox_result(result: SandboxResult) -> BehavioralProfile:
    """
    Build a behavioral profile from a sandbox execution result.

    Extracts network calls, DNS queries, filesystem operations,
    process spawns, and timing data from stdout/stderr output.
    """
    combined = result.stdout + "\n" + result.stderr
    package = (
        ".".join(result.command[:2]) if len(result.command) >= 2 else result.command[0] if result.command else "unknown"
    )

    return BehavioralProfile(
        package=package,
        entrypoint=result.command[0] if result.command else "",
        timing_points=_extract_timing_points(combined),
        network_calls=_extract_network_calls(combined),
        dns_queries=_extract_dns_queries(combined),
        fs_ops=_extract_file_operations(combined),
        spawns=_extract_spawns(combined),
        total_runtime_ms=result.duration_ms,
        exit_code=result.exit_code,
        stdout_len=len(result.stdout),
        stderr_len=len(result.stderr),
    )


def profile_from_trace(trace_text: str, package: str = "unknown") -> BehavioralProfile:
    """Build a behavioral profile from raw trace output (strace/dtruss)."""
    return BehavioralProfile(
        package=package,
        timing_points=_extract_timing_points(trace_text),
        network_calls=_extract_network_calls(trace_text),
        dns_queries=_extract_dns_queries(trace_text),
        fs_ops=_extract_file_operations(trace_text),
        spawns=_extract_spawns(trace_text),
    )


def _extract_timing_points(output: str) -> list[TimingPoint]:
    """Extract timing annotations from output."""
    points: list[TimingPoint] = []
    pattern = re.compile(r"\[TIMING\]\s+(\S+)\s+(\d+)\s*ms", re.IGNORECASE)

    for match in pattern.finditer(output):
        points.append(
            TimingPoint(
                label=match.group(1),
                elapsed_ms=int(match.group(2)),
            )
        )
    return points


def _extract_network_calls(output: str) -> list[NetworkCall]:
    """Extract network call indicators from output."""
    calls: list[NetworkCall] = []
    ip_pattern = re.compile(
        r"(?:connect|send|recv).*?"
        r"((?:(?:25[0-5]|2[0-4]\d|1\d\d|\d{1,2})\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|\d{1,2}))"
        r"(?::(\d+))?",
        re.IGNORECASE,
    )

    seen = set()
    for match in ip_pattern.finditer(output):
        ip = match.group(1)
        port = int(match.group(2)) if match.group(2) else 0
        key = f"{ip}:{port}"
        if key not in seen and ip not in ("0.0.0.0", "127.0.0.1", "255.255.255.255"):
            seen.add(key)
            calls.append(NetworkCall(address=ip, port=port))

    return calls


def _extract_dns_queries(output: str) -> list[DnsQuery]:
    """Extract DNS query indicators from output."""
    queries: list[DnsQuery] = []
    dns_pattern = re.compile(
        r"(?:getaddrinfo|gethostbyname|DNS|resolve).*?"
        r"([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?"
        r"\.(?:[a-zA-Z]{2,}))",
        re.IGNORECASE,
    )

    seen = set()
    for match in dns_pattern.finditer(output):
        hostname = match.group(1).lower()
        if hostname not in seen and hostname != "localhost":
            seen.add(hostname)
            queries.append(DnsQuery(hostname=hostname))

    return queries


def _extract_file_operations(output: str) -> list[FileOperation]:
    """Extract filesystem operation indicators from output."""
    ops: list[FileOperation] = []
    fs_patterns = [
        (re.compile(r'(?:open|reading|read)\s+"?([^\s"]+)"?', re.IGNORECASE), "read"),
        (re.compile(r'(?:write|writing|wrote|saving|saved)\s+(?:to\s+)?\s*"?([^\s"]+)"?', re.IGNORECASE), "write"),
        (re.compile(r'(?:create|creating|mkdir)\s+"?([^\s"]+)"?', re.IGNORECASE), "create"),
        (re.compile(r'(?:delete|deleting|remove|removing|rm|unlink)\s+"?([^\s"]+)"?', re.IGNORECASE), "delete"),
        (re.compile(r'chmod\s+\S+\s+"?([^\s"]+)"?', re.IGNORECASE), "chmod"),
    ]

    seen = set()
    for pattern, op_type in fs_patterns:
        for match in pattern.finditer(output):
            path = match.group(1)
            if path not in seen and not path.startswith("/dev/"):
                seen.add(path)
                ops.append(FileOperation(path=path, operation=op_type))

    return ops


def _extract_spawns(output: str) -> list[ProcessSpawn]:
    """Extract process spawn indicators from output."""
    spawns: list[ProcessSpawn] = []
    spawn_patterns = [
        re.compile(r'exec(?:uting)?:\s*"?([^\s"]+)"?', re.IGNORECASE),
        re.compile(r'spawn(?:ing|ed)?:?\s*"?([^\s"]+)"?', re.IGNORECASE),
        re.compile(r'subprocess\.(?:run|Popen)\s*\(\s*\[?"([^\]]+)"\]?', re.IGNORECASE),
        re.compile(r'os\.system\s*\(\s*"([^"]+)"', re.IGNORECASE),
    ]

    seen = set()
    for pattern in spawn_patterns:
        for match in pattern.finditer(output):
            exe = match.group(1).strip()
            if exe not in seen:
                seen.add(exe)
                spawns.append(ProcessSpawn(executable=exe, args=[exe]))

    return spawns
