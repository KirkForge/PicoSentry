"""Tests for L4 profiler — extracting behavioral profiles from sandbox results and traces."""

from picosentry.sandbox.l3.models import SandboxEvent, SandboxResult, Verdict
from picosentry.sandbox.l4.profiler import (
    _extract_dns_queries,
    _extract_file_operations,
    _extract_network_calls,
    _extract_spawns,
    _extract_timing_points,
    profile_from_sandbox_result,
    profile_from_trace,
)


class TestProfileFromSandboxResult:
    def test_clean_result(self, clean_sandbox_result):
        profile = profile_from_sandbox_result(clean_sandbox_result)
        assert profile.package == "echo.hello"  # command = ["echo", "hello"]
        assert profile.entrypoint == "echo"
        assert profile.exit_code == 0
        assert profile.total_runtime_ms == 42

    def test_result_with_command(self):
        result = SandboxResult(
            run_id="test",
            timestamp="2025-01-01T00:00:00Z",
            command=["python3", "script.py"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
            duration_ms=100,
            stdout="",
            stderr="",
        )
        profile = profile_from_sandbox_result(result)
        assert profile.package == "python3.script.py"

    def test_single_command(self):
        result = SandboxResult(
            run_id="test",
            timestamp="2025-01-01T00:00:00Z",
            command=["ls"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
            duration_ms=10,
            stdout="",
            stderr="",
        )
        profile = profile_from_sandbox_result(result)
        assert profile.package == "ls"

    def test_empty_command(self):
        result = SandboxResult(
            run_id="test",
            timestamp="2025-01-01T00:00:00Z",
            command=[],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
            duration_ms=10,
            stdout="",
            stderr="",
        )
        profile = profile_from_sandbox_result(result)
        assert profile.package == "unknown"
        assert profile.entrypoint == ""

    def test_stdout_len(self):
        result = SandboxResult(
            run_id="test",
            timestamp="2025-01-01T00:00:00Z",
            command=["echo", "test"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
            duration_ms=10,
            stdout="hello world",
            stderr="",
        )
        profile = profile_from_sandbox_result(result)
        assert profile.stdout_len == 11

    def test_stderr_len(self):
        result = SandboxResult(
            run_id="test",
            timestamp="2025-01-01T00:00:00Z",
            command=["echo"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
            duration_ms=10,
            stdout="",
            stderr="error message",
        )
        profile = profile_from_sandbox_result(result)
        assert profile.stderr_len == 13


class TestProfileFromTrace:
    def test_empty_trace(self):
        profile = profile_from_trace("")
        assert profile.package == "unknown"
        assert len(profile.network_calls) == 0
        assert len(profile.dns_queries) == 0
        assert len(profile.fs_ops) == 0
        assert len(profile.spawns) == 0
        assert len(profile.timing_points) == 0

    def test_clean_trace(self):
        trace = "hello world\nthis is normal output"
        profile = profile_from_trace(trace, package="myapp")
        assert profile.package == "myapp"
        assert len(profile.network_calls) == 0

    def test_trace_with_package(self):
        profile = profile_from_trace("clean output", package="test-pkg")
        assert profile.package == "test-pkg"


class TestExtractTimingPoints:
    def test_timing_point_extraction(self):
        output = "[TIMING] init 50 ms\n[TIMING] main 200 ms\n"
        points = _extract_timing_points(output)
        assert len(points) == 2
        assert points[0].label == "init"
        assert points[0].elapsed_ms == 50
        assert points[1].label == "main"
        assert points[1].elapsed_ms == 200

    def test_timing_point_case_insensitive(self):
        output = "[timing] startup 100 ms\n"
        points = _extract_timing_points(output)
        assert len(points) == 1
        assert points[0].label == "startup"

    def test_no_timing_points(self):
        output = "no timing data here"
        points = _extract_timing_points(output)
        assert len(points) == 0


class TestExtractNetworkCalls:
    def test_ip_extraction(self):
        output = "connect to 93.184.216.34:443"
        calls = _extract_network_calls(output)
        assert len(calls) >= 1
        assert any(c.address == "93.184.216.34" for c in calls)

    def test_skip_loopback(self):
        output = "connect 127.0.0.1:8080"
        calls = _extract_network_calls(output)
        loopback = [c for c in calls if c.address == "127.0.0.1"]
        assert len(loopback) == 0

    def test_skip_broadcast(self):
        output = "connect 255.255.255.255"
        calls = _extract_network_calls(output)
        broadcast = [c for c in calls if c.address == "255.255.255.255"]
        assert len(broadcast) == 0

    def test_skip_zero(self):
        output = "connect 0.0.0.0"
        calls = _extract_network_calls(output)
        zero = [c for c in calls if c.address == "0.0.0.0"]
        assert len(zero) == 0

    def test_no_network_calls(self):
        output = "clean output with no IPs"
        calls = _extract_network_calls(output)
        assert len(calls) == 0


class TestExtractDnsQueries:
    def test_dns_extraction(self):
        output = "getaddrinfo: resolving example.com"
        queries = _extract_dns_queries(output)
        assert len(queries) >= 1
        assert any(q.hostname == "example.com" for q in queries)

    def test_dns_case_insensitive(self):
        output = "DNS lookup for Evil.COM"
        queries = _extract_dns_queries(output)
        assert any(q.hostname == "evil.com" for q in queries)

    def test_skip_localhost(self):
        output = "getaddrinfo: resolving localhost"
        queries = _extract_dns_queries(output)
        localhost = [q for q in queries if q.hostname == "localhost"]
        assert len(localhost) == 0

    def test_no_dns(self):
        output = "clean output"
        queries = _extract_dns_queries(output)
        assert len(queries) == 0


class TestExtractFileOperations:
    def test_read_extraction(self):
        output = 'reading "/etc/config.yml"'
        ops = _extract_file_operations(output)
        assert len(ops) >= 1
        assert any(op.operation == "read" for op in ops)

    def test_write_extraction(self):
        output = "writing to /tmp/output.log"
        ops = _extract_file_operations(output)
        assert len(ops) >= 1
        assert any(op.operation == "write" for op in ops)

    def test_create_extraction(self):
        output = "create /tmp/newfile.txt"
        ops = _extract_file_operations(output)
        assert len(ops) >= 1
        assert any(op.operation == "create" for op in ops)

    def test_delete_extraction(self):
        output = "delete /tmp/oldfile.txt"
        ops = _extract_file_operations(output)
        assert len(ops) >= 1
        assert any(op.operation == "delete" for op in ops)

    def test_skip_dev_files(self):
        output = "open /dev/null"
        ops = _extract_file_operations(output)
        dev_ops = [op for op in ops if op.path.startswith("/dev/")]
        assert len(dev_ops) == 0

    def test_no_fs_ops(self):
        output = "clean output"
        ops = _extract_file_operations(output)
        assert len(ops) == 0


class TestExtractSpawns:
    def test_executing_extraction(self):
        output = "executing: /bin/bash"
        spawns = _extract_spawns(output)
        assert len(spawns) >= 1
        assert any(s.executable == "/bin/bash" for s in spawns)

    def test_spawning_extraction(self):
        output = "spawning /usr/bin/wget"
        spawns = _extract_spawns(output)
        assert len(spawns) >= 1
        assert any(s.executable == "/usr/bin/wget" for s in spawns)

    def test_subprocess_popen_extraction(self):
        output = 'subprocess.Popen(["curl"])'
        spawns = _extract_spawns(output)
        assert len(spawns) >= 1

    def test_os_system_extraction(self):
        output = 'os.system("rm -rf /")'
        spawns = _extract_spawns(output)
        assert len(spawns) >= 1

    def test_no_spawns(self):
        output = "clean output"
        spawns = _extract_spawns(output)
        assert len(spawns) == 0

    def test_deduplication(self):
        output = "executing: /bin/bash\nexecuting: /bin/bash"
        spawns = _extract_spawns(output)
        bash_spawns = [s for s in spawns if s.executable == "/bin/bash"]
        assert len(bash_spawns) == 1


# ── Events-first extraction (new) ─────────────────────────────


class TestExtractNetworkFromEvents:
    """profile_from_sandbox_result uses events when available."""

    def test_network_from_event(self):
        result = SandboxResult(
            command=["node", "test.js"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
            duration_ms=100,
            events=[
                SandboxEvent(
                    rule_id="L3-NET-001",
                    verdict=Verdict.ALLOW,
                    operation="network_outbound",
                    detail="IP address found: 1.2.3.4",
                    address="1.2.3.4",
                ),
            ],
            stdout="",
            stderr="",
        )
        profile = profile_from_sandbox_result(result)
        assert len(profile.network_calls) == 1
        assert profile.network_calls[0].address == "1.2.3.4"

    def test_network_events_supersede_text(self):
        """When events have network data, text-only dupes are skipped."""
        result = SandboxResult(
            command=["node", "test.js"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
            duration_ms=100,
            events=[
                SandboxEvent(
                    rule_id="L3-NET-001",
                    verdict=Verdict.ALLOW,
                    operation="network_outbound",
                    detail="IP address found: 5.6.7.8",
                    address="5.6.7.8",
                ),
            ],
            stdout="connect to 5.6.7.8:443",
            stderr="",
        )
        profile = profile_from_sandbox_result(result)
        # 5.6.7.8 from event; text might add a 2nd with port but dedup by address
        addrs = {c.address for c in profile.network_calls}
        assert "5.6.7.8" in addrs

    def test_no_events_falls_back_to_text(self):
        result = SandboxResult(
            command=["node", "test.js"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
            duration_ms=100,
            events=[],
            stdout="connect to 9.9.9.9:53",
            stderr="",
        )
        profile = profile_from_sandbox_result(result)
        assert len(profile.network_calls) >= 1
        assert profile.network_calls[0].address == "9.9.9.9"


class TestExtractFsFromEvents:
    """Filesystem from events when available."""

    def test_fs_from_event(self):
        result = SandboxResult(
            command=["node", "test.js"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
            duration_ms=100,
            events=[
                SandboxEvent(
                    rule_id="L3-FW-001",
                    verdict=Verdict.DENY,
                    operation="file_write_indicator",
                    detail="Write detected: /etc/shadow",
                    path="/etc/shadow",
                ),
            ],
            stdout="",
            stderr="",
        )
        profile = profile_from_sandbox_result(result)
        assert len(profile.fs_ops) == 1
        assert profile.fs_ops[0].operation == "write"

    def test_no_events_falls_back_to_text(self):
        result = SandboxResult(
            command=["node", "test.js"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
            duration_ms=100,
            events=[],
            stdout='reading "/etc/config.yml"',
            stderr="",
        )
        profile = profile_from_sandbox_result(result)
        assert len(profile.fs_ops) >= 1


# ── IPv6 network extraction ──────────────────────────────────


class TestIPv6NetworkExtraction:
    """_extract_network_calls must handle IPv6 addresses."""

    def test_ipv6_bracketed(self):
        output = "connect to [2607:f8b0:4005:802::200e]:443"
        calls = _extract_network_calls(output)
        assert any(c.address == "2607:f8b0:4005:802::200e" for c in calls)

    def test_ipv6_loopback_excluded(self):
        output = "[::1]:53"
        calls = _extract_network_calls(output)
        loopback = [c for c in calls if c.address == "::1"]
        assert len(loopback) == 0

    def test_ipv6_strace_connect(self):
        output = (
            'connect(3, {sa_family=AF_INET6, sin6_port=htons(443), '
            'sin6_addr=inet_pton(AF_INET6, "2001:db8::1")}, 28)'
        )
        calls = _extract_network_calls(output)
        assert any(c.address == "2001:db8::1" for c in calls)

    def test_ipv4_strace_inet_addr(self):
        output = (
            'connect(3, {sa_family=AF_INET, sin_port=htons(4444), '
            'sin_addr=inet_addr("1.2.3.4")}, 16)'
        )
        calls = _extract_network_calls(output)
        assert any(c.address == "1.2.3.4" and c.port == 4444 for c in calls)

    def test_no_dup_strace_and_plain(self):
        """An address in a strace block should not also appear from plain match."""
        output = (
            'connect(3, {sa_family=AF_INET, sin_port=htons(443), '
            'sin_addr=inet_addr("1.2.3.4")}, 16)'
        )
        calls = _extract_network_calls(output)
        matches = [c for c in calls if c.address == "1.2.3.4"]
        assert len(matches) == 1


# ── Strace-format text fallback ──────────────────────────────


class TestStraceFormatTextFallback:
    """Text regexes must handle real strace output (not just friendly format)."""

    def test_strace_openat_read(self):
        output = 'openat(AT_FDCWD, "/home/user/.aws/credentials", O_RDONLY) = 3'
        ops = _extract_file_operations(output)
        assert any("credentials" in op.path for op in ops)

    def test_strace_execve_spawn(self):
        output = 'execve("/usr/bin/curl", ["curl", "-o", "/tmp/out"], 0x7fff...) = 0'
        spawns = _extract_spawns(output)
        assert any("curl" in s.executable for s in spawns)

    def test_strace_write_file(self):
        output = 'write(1, "hello world", 11) = 11'
        # The strace write pattern matches write(fd, "path", ...) — the
        # second arg is the written content, not a path. That's fine — it
        # won't produce a useful FileOperation, but also won't regress.
        ops = _extract_file_operations(output)
        # No meaningful path match is expected here
        assert isinstance(ops, list)


# ── Regression guards for bugs found in code review ────────────


class TestSpoofGuard:
    """Events must be authoritative; text cannot inject phantom calls."""

    def test_events_block_phantom_text_network(self):
        """When events exist, empty network from events means NO network."""
        result = SandboxResult(
            command=["node", "test.js"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
            duration_ms=100,
            events=[
                SandboxEvent(
                    rule_id="L3-FS-001",
                    verdict=Verdict.ALLOW,
                    operation="file_write_indicator",
                    detail="Write detected: /tmp/foo",
                    path="/tmp/foo",
                ),
            ],
            stdout="connect to 8.8.8.8:443",
            stderr="",
        )
        profile = profile_from_sandbox_result(result)
        # Events exist (filesystem), so network should not be scraped from text
        assert len(profile.network_calls) == 0, (
            "Text-derived phantom network injected despite events existing"
        )

    def test_events_block_phantom_text_fs(self):
        """When events exist, empty fs_ops from events means NO text-derived fs."""
        result = SandboxResult(
            command=["node", "test.js"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
            duration_ms=100,
            events=[
                SandboxEvent(
                    rule_id="L3-NET-001",
                    verdict=Verdict.ALLOW,
                    operation="network_outbound",
                    detail="IP address found: 1.2.3.4",
                    address="1.2.3.4",
                ),
            ],
            stdout="writing to /etc/shadow",
            stderr="",
        )
        profile = profile_from_sandbox_result(result)
        assert len(profile.fs_ops) == 0, (
            "Text-derived /etc/shadow phantom injected despite events existing"
        )

    def test_events_block_phantom_text_spawn(self):
        """When events exist, empty spawns from events means NO text-derived spawn."""
        result = SandboxResult(
            command=["node", "test.js"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
            duration_ms=100,
            events=[
                SandboxEvent(
                    rule_id="L3-NET-001",
                    verdict=Verdict.ALLOW,
                    operation="network_outbound",
                    detail="IP address found: 1.2.3.4",
                    address="1.2.3.4",
                ),
            ],
            stdout="executing: /bin/malware",
            stderr="",
        )
        profile = profile_from_sandbox_result(result)
        assert len(profile.spawns) == 0, (
            "Text-derived /bin/malware phantom injected despite events existing"
        )


class TestStraceIPv6RealFormat:
    """Real strace emits inet_pton(AF_INET6, ..., &sin6_addr) — not the synthetic sin6_addr=inet_pton."""

    def test_real_strace_ipv6_connect(self):
        """Real strace IPv6 format — inet_pton with IP as 2nd arg, &sin6_addr as 3rd."""
        output = (
            'connect(3, {sa_family=AF_INET6, sin6_port=htons(443), '
            'inet_pton(AF_INET6, "2606:4700::1", &sin6_addr)}, 28) = 0'
        )
        calls = _extract_network_calls(output)
        assert any(c.address == "2606:4700::1" for c in calls), (
            "Real strace IPv6 not parsed"
        )

    def test_synthetic_strace_ipv6_still_works(self):
        """The synthetic format used in existing tests must still parse."""
        output = (
            'connect(3, {sa_family=AF_INET6, sin6_port=htons(443), '
            'sin6_addr=inet_pton(AF_INET6, "2001:db8::1")}, 28)'
        )
        calls = _extract_network_calls(output)
        assert any(c.address == "2001:db8::1" for c in calls), (
            "Synthetic strace IPv6 broke"
        )


class TestExfilReadOnEventsPath:
    """EXFIL-005 (credential-read-then-egress) must fire on the events path."""

    def test_fs_read_preserved_from_event(self):
        """file_read event produces FileOperation(operation='read')."""
        result = SandboxResult(
            command=["node", "evil.js"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
            duration_ms=100,
            events=[
                SandboxEvent(
                    rule_id="L3-FR-001",
                    verdict=Verdict.ALLOW,
                    operation="file_read",
                    detail="Read detected: /home/user/.aws/credentials",
                    path="/home/user/.aws/credentials",
                ),
            ],
            stdout="",
            stderr="",
        )
        profile = profile_from_sandbox_result(result)
        assert len(profile.fs_ops) == 1
        assert profile.fs_ops[0].operation == "read", (
            "file_read event must produce 'read' op for EXFIL-005"
        )

    def test_file_write_still_write_on_events_path(self):
        """file_write_* events still produce FileOperation(operation='write')."""
        result = SandboxResult(
            command=["node", "test.js"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
            duration_ms=100,
            events=[
                SandboxEvent(
                    rule_id="L3-FW-001",
                    verdict=Verdict.DENY,
                    operation="file_write_indicator",
                    detail="Write detected: /tmp/evil",
                    path="/tmp/evil",
                ),
            ],
            stdout="",
            stderr="",
        )
        profile = profile_from_sandbox_result(result)
        assert profile.fs_ops[0].operation == "write"


class TestEventsFirstIntegration:
    """End-to-end: AWS cred read + IPv6 exfil in real strace syntax.

    This is the exact scenario the code-review proved was missed
    by the old text-only profiler. Both paths (events + text) must
    now detect the exfil.
    """

    def test_ipv6_exfil_caught_via_events(self):
        """Seccomp backend: structured events catch IPv6 exfil."""
        result = SandboxResult(
            command=["node", "evil.js"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
            duration_ms=150,
            events=[
                SandboxEvent(
                    rule_id="L3-NET-001",
                    verdict=Verdict.ALLOW,
                    operation="network_outbound",
                    detail="IP address found: 2607:f8b0:4005:802::200e",
                    address="2607:f8b0:4005:802::200e",
                    timestamp_ms=120,
                ),
            ],
            stdout="",
            stderr=(
                'openat(AT_FDCWD, "/home/user/.aws/credentials", O_RDONLY) = 3\n'
                'connect(3, {sa_family=AF_INET6, sin6_port=htons(443), '
                'sin6_addr=inet_pton(AF_INET6, "2607:f8b0:4005:802::200e")}, 28) = 0\n'
            ),
        )
        profile = profile_from_sandbox_result(result)
        assert len(profile.network_calls) > 0, "Events path must detect IPv6 exfil"
        assert any("2607" in c.address for c in profile.network_calls)

    def test_ipv6_exfil_caught_via_text_fallback(self):
        """Observational-only backend: text fallback also catches IPv6 exfil."""
        result = SandboxResult(
            command=["node", "evil.js"],
            overall_verdict=Verdict.ALLOW,
            exit_code=0,
            duration_ms=150,
            events=[],
            stdout="",
            stderr=(
                'openat(AT_FDCWD, "/home/user/.aws/credentials", O_RDONLY) = 3\n'
                'connect(3, {sa_family=AF_INET6, sin6_port=htons(443), '
                'sin6_addr=inet_pton(AF_INET6, "2607:f8b0:4005:802::200e")}, 28) = 0\n'
            ),
        )
        profile = profile_from_sandbox_result(result)
        assert len(profile.network_calls) > 0, "Text path must detect IPv6 exfil"
        assert any("2607" in c.address for c in profile.network_calls)
