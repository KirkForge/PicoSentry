"""Tests for L4 profiler — extracting behavioral profiles from sandbox results and traces."""

from picosentry.sandbox.l3.models import SandboxResult, Verdict
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
