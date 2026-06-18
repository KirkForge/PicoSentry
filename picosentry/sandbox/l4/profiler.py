
from __future__ import annotations

import ipaddress
import re

from picosentry.sandbox.l3.models import SandboxEvent, SandboxResult
from picosentry.sandbox.l4.models import (
    BehavioralProfile,
    DnsQuery,
    FileOperation,
    NetworkCall,
    ProcessSpawn,
    TimingPoint,
)


_NETWORK_OPS = frozenset({"network_outbound"})
_FILE_OPS = frozenset({"file_write_indicator", "file_write_bytes", "file_save", "file_export", "file_read"})
_SPAWN_OPS = frozenset({"process_spawn"})


def _is_not_loopback(address: str) -> bool:
    try:
        addr = ipaddress.ip_address(address)
        return not (
            addr.is_loopback
            or addr.is_multicast
            or addr.is_link_local
            or addr.is_unspecified
            or addr == ipaddress.IPv4Address("255.255.255.255")
        )
    except ValueError:
        return True  # non-IP (URL, hostname) — keep for further analysis


def _extract_network_from_events(events: list[SandboxEvent]) -> list[NetworkCall]:
    seen: set[str] = set()
    calls: list[NetworkCall] = []
    for ev in events:
        if ev.operation not in _NETWORK_OPS or not ev.address:
            continue
        addr = ev.address.strip()
        if not _is_not_loopback(addr):
            continue
        if addr not in seen:
            seen.add(addr)
            calls.append(NetworkCall(address=addr, port=0))
    return calls


def _extract_fs_from_events(events: list[SandboxEvent]) -> list[FileOperation]:
    seen: set[str] = set()
    ops: list[FileOperation] = []
    for ev in events:
        if ev.operation not in _FILE_OPS or not ev.path:
            continue
        path = ev.path.strip()
        if path in seen or path.startswith("/dev/"):
            continue
        seen.add(path)
        op_type = "read" if ev.operation == "file_read" else "write"
        ops.append(FileOperation(path=path, operation=op_type))
    return ops


def _extract_spawns_from_events(events: list[SandboxEvent]) -> list[ProcessSpawn]:
    seen: set[str] = set()
    spawns: list[ProcessSpawn] = []
    for ev in events:
        if ev.operation not in _SPAWN_OPS or not ev.detail:
            continue

        exe = ev.detail.rsplit(":", 1)[-1].strip()
        if not exe or exe in seen:
            continue
        seen.add(exe)
        spawns.append(ProcessSpawn(executable=exe, args=[exe]))
    return spawns


def profile_from_sandbox_result(result: SandboxResult) -> BehavioralProfile:
    combined = result.stdout + "\n" + result.stderr
    package = (
        ".".join(result.command[:2]) if len(result.command) >= 2
        else result.command[0] if result.command else "unknown"
    )

    has_events = bool(result.events)


    network_calls = _extract_network_from_events(result.events) if has_events else _extract_network_calls(combined)


    fs_ops = _extract_fs_from_events(result.events) if has_events else _extract_file_operations(combined)


    spawns = _extract_spawns_from_events(result.events) if has_events else _extract_spawns(combined)


    dns_queries = _extract_dns_queries(combined)
    timing_points = _extract_timing_points(combined)

    return BehavioralProfile(
        package=package,
        entrypoint=result.command[0] if result.command else "",
        timing_points=timing_points,
        network_calls=network_calls,
        dns_queries=dns_queries,
        fs_ops=fs_ops,
        spawns=spawns,
        total_runtime_ms=result.duration_ms,
        exit_code=result.exit_code,
        stdout_len=len(result.stdout),
        stderr_len=len(result.stderr),
    )


def profile_from_trace(trace_text: str, package: str = "unknown") -> BehavioralProfile:
    return BehavioralProfile(
        package=package,
        timing_points=_extract_timing_points(trace_text),
        network_calls=_extract_network_calls(trace_text),
        dns_queries=_extract_dns_queries(trace_text),
        fs_ops=_extract_file_operations(trace_text),
        spawns=_extract_spawns(trace_text),
    )


def _extract_timing_points(output: str) -> list[TimingPoint]:
    pattern = re.compile(r"\[TIMING\]\s+(\S+)\s+(\d+)\s*ms", re.IGNORECASE)
    return [
        TimingPoint(
            label=match.group(1),
            elapsed_ms=int(match.group(2)),
        )
        for match in pattern.finditer(output)
    ]


def _parse_ip_port(output: str) -> list[tuple[str, int]]:
    results: list[tuple[str, int]] = []


    _strace_intervals: list[tuple[int, int]] = []


    strace_block = re.compile(
        r"(?:^|\n)\s*(getaddrinfo|connect|bind|sendto|sendmsg|recvfrom|recvmsg)\s*\(",
        re.MULTILINE,
    )
    for block_match in strace_block.finditer(output):

        block_start = block_match.start()
        depth, cursor = 0, block_match.end()
        while cursor < len(output):
            ch = output[cursor]
            if ch == "(":
                depth += 1
            elif ch == ")":
                if depth == 0:
                    break
                depth -= 1
            cursor += 1
        block_end = cursor
        _strace_intervals.append((block_start, block_end))
        block_text = output[block_start:block_end]


        port = 0
        port_match = re.search(r"sin(?:6|_6|)_port\s*=\s*(?:htons\s*\()?(\d+)", block_text)
        if port_match:
            port = int(port_match.group(1))


        addr: str | None = None


        v4_raw = re.search(
            r"sa_family=AF_INET(?:$|[^6])\D.*?sin_addr\s*=\s*\{?\s*s_addr=([^}\s]+)",
            block_text,
        )
        if v4_raw:
            raw_val = v4_raw.group(1).strip()
            ip_m = re.search(
                r"(?:(?:25[0-5]|2[0-4]\d|1\d\d|\d{1,2})\.){3}"
                r"(?:25[0-5]|2[0-4]\d|1\d\d|\d{1,2})",
                raw_val,
            )
            if ip_m:
                addr = ip_m.group(0)


        if addr is None:
            v4_inet = re.search(
                r'sin_addr\s*=\s*inet_addr\s*\(\s*"([^"]+)"\s*\)',
                block_text,
            )
            if v4_inet:
                addr = v4_inet.group(1)


        if addr is None:
            v6_pton = re.search(
                r'inet_pton\s*\([^,]+,\s*"([^"]+)"',
                block_text,
            )
            if v6_pton:
                candidate = v6_pton.group(1)
                try:
                    ipaddress.IPv6Address(candidate)
                    addr = candidate
                except ipaddress.AddressValueError:
                    pass


        if addr is None:
            v6_raw = re.search(
                r"sa_family=AF_INET6.*?sin6_addr\s*=\s*([^}\s,]+)",
                block_text,
            )
            if v6_raw:
                raw = v6_raw.group(1).strip()
                if raw not in ("", "in6addr_any"):
                    v6_literal = re.search(
                        r'"((?:[0-9a-f]{0,4}:){1,7}[0-9a-f]{0,4})"', raw, re.IGNORECASE,
                    )
                    if v6_literal:
                        try:
                            ipaddress.IPv6Address(v6_literal.group(1))
                            addr = v6_literal.group(1)
                        except ipaddress.AddressValueError:
                            pass

        if addr and _is_not_loopback(addr):
            results.append((addr, port))


    for match in re.finditer(
        r"((?:(?:25[0-5]|2[0-4]\d|1\d\d|\d{1,2})\.){3}"
        r"(?:25[0-5]|2[0-4]\d|1\d\d|\d{1,2}))"
        r"(?::(\d+))?",
        output,
    ):

        if any(start <= match.start() < end for start, end in _strace_intervals):
            continue
        ip = match.group(1)
        port = int(match.group(2)) if match.group(2) else 0
        if _is_not_loopback(ip):
            results.append((ip, port))


    for match in re.finditer(
        r"\[([0-9a-f:]+(?:%[\w.]+)?)\](?::(\d+))?",
        output,
        re.IGNORECASE,
    ):
        if any(start <= match.start() < end for start, end in _strace_intervals):
            continue
        addr = match.group(1)
        try:
            ipaddress.IPv6Address(addr.split("%")[0])
            port = int(match.group(2)) if match.group(2) else 0
            if _is_not_loopback(addr):
                results.append((addr, port))
        except ipaddress.AddressValueError:
            pass

    return results


def _extract_network_calls(output: str) -> list[NetworkCall]:
    calls: list[NetworkCall] = []
    seen: set[str] = set()
    for ip, port in _parse_ip_port(output):
        key = f"{ip}:{port}"
        if key not in seen:
            seen.add(key)
            calls.append(NetworkCall(address=ip, port=port))
    return calls


def _extract_dns_queries(output: str) -> list[DnsQuery]:
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
    ops: list[FileOperation] = []
    fs_patterns: list[tuple[re.Pattern, str]] = [
        (re.compile(r'\b(?:open|reading|read)\b(?!\s*\()\s*"?([^\s"()]+)"?', re.IGNORECASE), "read"),
        (re.compile(r'\b(?:write|writing|wrote|saving|saved)\s+(?:to\s+)?\s*"?([^\s"()]+)"?', re.IGNORECASE), "write"),
        (re.compile(r'\b(?:create|creating|mkdir)\s*"?([^\s"()]+)"?', re.IGNORECASE), "create"),
        (re.compile(r'\b(?:delete|deleting|remove|removing|rm|unlink)\s*"?([^\s"()]+)"?', re.IGNORECASE), "delete"),
        (re.compile(r'\bchmod\s+\S+\s*"?([^\s"()]+)"?', re.IGNORECASE), "chmod"),
    ]

    seen: set[str] = set()

    for pattern, op_type in fs_patterns:
        for match in pattern.finditer(output):
            path = match.group(1)
            if path not in seen and not path.startswith("/dev/"):
                seen.add(path)
                ops.append(FileOperation(path=path, operation=op_type))


    strace_read = re.compile(
        r"(?:openat|open|read)\s*\([^)]*\"([^\"]+)\"",
    )
    strace_write = re.compile(
        r"write\s*\([^)]*\"([^\"]+)\"",
    )
    strace_creat = re.compile(
        r"(?:creat|create)\s*\([^)]*\"([^\"]+)\"",
    )

    for match in strace_read.finditer(output):
        path = match.group(1)
        if path not in seen and not path.startswith("/dev/") and not path.startswith("/proc/"):
            seen.add(path)
            ops.append(FileOperation(path=path, operation="read"))
    for match in strace_write.finditer(output):
        path = match.group(1)
        if path not in seen and not path.startswith("/dev/") and not path.startswith("/proc/"):
            seen.add(path)
            ops.append(FileOperation(path=path, operation="write"))
    for match in strace_creat.finditer(output):
        path = match.group(1)
        if path not in seen and not path.startswith("/dev/"):
            seen.add(path)
            ops.append(FileOperation(path=path, operation="create"))

    return ops


def _extract_spawns(output: str) -> list[ProcessSpawn]:
    spawns: list[ProcessSpawn] = []
    spawn_patterns: list[re.Pattern] = [
        re.compile(r'exec(?:uting)?:\s*"?([^\s"()]+)"?', re.IGNORECASE),
        re.compile(r'spawn(?:ing|ed)?:?\s*"?([^\s"()]+)"?', re.IGNORECASE),
        re.compile(r'subprocess\.(?:run|Popen)\s*\(\s*\[?"([^\]]+)"\]?', re.IGNORECASE),
        re.compile(r'os\.system\s*\(\s*"([^"]+)"', re.IGNORECASE),
    ]

    seen: set[str] = set()

    for pattern in spawn_patterns:
        for match in pattern.finditer(output):
            exe = match.group(1).strip()
            if exe not in seen:
                seen.add(exe)
                spawns.append(ProcessSpawn(executable=exe, args=[exe]))


    for match in re.finditer(r'execve(?:at)?\s*\(\s*"([^"]+)"', output):
        exe = match.group(1).strip()
        if exe not in seen:
            seen.add(exe)
            spawns.append(ProcessSpawn(executable=exe, args=[exe]))

    return spawns
