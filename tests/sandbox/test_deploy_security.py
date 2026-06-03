"""Tests for the deployment security checker.

Verifies that check_deploy_security.py correctly detects insecure
deployment defaults and doesn't produce false positives.
"""

from __future__ import annotations

import textwrap
from pathlib import Path
from unittest.mock import patch

from .check_deploy_security import (
    Finding,
    check_dockerfile,
    check_gitignore_secrets,
    check_helm_templates,
    check_helm_values,
    check_k8s_deployment,
    check_source_hardcoded_secrets,
    main,
)

# ── Helpers ─────────────────────────────────────────────────────────────


def _write_tmp_file(tmp_path: Path, name: str, content: str) -> Path:
    """Write content to a temp file and return the path."""
    f = tmp_path / name
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text(content, encoding="utf-8")
    return f


def _find_by_check(findings: list[Finding], check: str) -> list[Finding]:
    """Filter findings by check name."""
    return [f for f in findings if f.check == check]


# ── K8s Deployment Checks ─────────────────────────────────────────────


class TestK8sDeployment:
    """Tests for check_k8s_deployment."""

    def test_dev_mode_detected(self, tmp_path: Path) -> None:
        content = textwrap.dedent("""\
            env:
              - name: PICODOME_DEV_MODE
                value: "1"
        """)
        deploy_dir = tmp_path / "kubernetes"
        deploy_dir.mkdir()
        _write_tmp_file(deploy_dir, "deployment.yaml", content)

        findings: list[Finding] = []
        with patch("tests.sandbox.check_deploy_security.K8S_DIR", deploy_dir):
            check_k8s_deployment(findings)

        critical = _find_by_check(findings, "dev-mode-k8s")
        assert len(critical) == 1
        assert critical[0].severity == "CRITICAL"

    def test_tls_dev_detected(self, tmp_path: Path) -> None:
        content = textwrap.dedent("""\
            env:
              - name: PICODOME_TLS_DEV
                value: "1"
        """)
        deploy_dir = tmp_path / "kubernetes"
        deploy_dir.mkdir()
        _write_tmp_file(deploy_dir, "deployment.yaml", content)

        findings: list[Finding] = []
        with patch("tests.sandbox.check_deploy_security.K8S_DIR", deploy_dir):
            check_k8s_deployment(findings)

        tls_findings = _find_by_check(findings, "tls-dev-k8s")
        assert len(tls_findings) == 1
        assert tls_findings[0].severity == "HIGH"

    def test_placeholder_secret_detected(self, tmp_path: Path) -> None:
        content = textwrap.dedent("""\
            apiVersion: v1
            kind: Secret
            stringData:
              api-tokens: "REPLACE_WITH_STRONG_TOKEN"
        """)
        deploy_dir = tmp_path / "kubernetes"
        deploy_dir.mkdir()
        _write_tmp_file(deploy_dir, "deployment.yaml", content)

        findings: list[Finding] = []
        with patch("tests.sandbox.check_deploy_security.K8S_DIR", deploy_dir):
            check_k8s_deployment(findings)

        placeholder = _find_by_check(findings, "placeholder-secret-k8s")
        assert len(placeholder) == 1
        assert placeholder[0].severity == "CRITICAL"

    def test_root_user_detected(self, tmp_path: Path) -> None:
        content = textwrap.dedent("""\
            securityContext:
              runAsUser: 0
        """)
        deploy_dir = tmp_path / "kubernetes"
        deploy_dir.mkdir()
        _write_tmp_file(deploy_dir, "deployment.yaml", content)

        findings: list[Finding] = []
        with patch("tests.sandbox.check_deploy_security.K8S_DIR", deploy_dir):
            check_k8s_deployment(findings)

        root = _find_by_check(findings, "root-user-k8s")
        assert len(root) == 1
        assert root[0].severity == "HIGH"

    def test_privilege_escalation_detected(self, tmp_path: Path) -> None:
        content = textwrap.dedent("""\
            securityContext:
              allowPrivilegeEscalation: true
        """)
        deploy_dir = tmp_path / "kubernetes"
        deploy_dir.mkdir()
        _write_tmp_file(deploy_dir, "deployment.yaml", content)

        findings: list[Finding] = []
        with patch("tests.sandbox.check_deploy_security.K8S_DIR", deploy_dir):
            check_k8s_deployment(findings)

        priv = _find_by_check(findings, "privilege-escalation-k8s")
        assert len(priv) == 1
        assert priv[0].severity == "HIGH"

    def test_clean_manifest_passes(self, tmp_path: Path) -> None:
        content = textwrap.dedent("""\
            apiVersion: apps/v1
            kind: Deployment
            metadata:
              name: picodome
            spec:
              template:
                spec:
                  securityContext:
                    runAsNonRoot: true
                    runAsUser: 1000
                  containers:
                    - name: picodome
                      env:
                        - name: PICODOME_ENTERPRISE_MODE
                          value: "1"
                        - name: PICODOME_API_TOKENS
                          valueFrom:
                            secretKeyRef:
                              name: picodome-tokens
                              key: api-tokens
                      securityContext:
                        readOnlyRootFilesystem: true
                        allowPrivilegeEscalation: false
        """)
        deploy_dir = tmp_path / "kubernetes"
        deploy_dir.mkdir()
        _write_tmp_file(deploy_dir, "deployment.yaml", content)

        findings: list[Finding] = []
        with patch("tests.sandbox.check_deploy_security.K8S_DIR", deploy_dir):
            check_k8s_deployment(findings)

        # Should have no CRITICAL or HIGH findings
        critical_high = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
        assert len(critical_high) == 0


# ── Helm Values Checks ──────────────────────────────────────────────


class TestHelmValues:
    """Tests for check_helm_values."""

    def test_enterprise_disabled(self, tmp_path: Path) -> None:
        content = textwrap.dedent("""\
            enterprise:
              enabled: false
        """)
        helm_dir = tmp_path / "picodome"
        helm_dir.mkdir(parents=True)
        _write_tmp_file(helm_dir, "values.yaml", content)

        findings: list[Finding] = []
        with patch("tests.sandbox.check_deploy_security.HELM_DIR", helm_dir):
            check_helm_values(findings)

        ent = _find_by_check(findings, "enterprise-disabled-helm")
        assert len(ent) >= 1

    def test_mtls_disabled(self, tmp_path: Path) -> None:
        content = textwrap.dedent("""\
            mtls:
              enabled: false
        """)
        helm_dir = tmp_path / "picodome"
        helm_dir.mkdir(parents=True)
        _write_tmp_file(helm_dir, "values.yaml", content)

        findings: list[Finding] = []
        with patch("tests.sandbox.check_deploy_security.HELM_DIR", helm_dir):
            check_helm_values(findings)

        mtls = _find_by_check(findings, "mtls-disabled-helm")
        assert len(mtls) >= 1

    def test_dev_mode_detected(self, tmp_path: Path) -> None:
        content = textwrap.dedent("""\
            mtls:
              devMode: true
        """)
        helm_dir = tmp_path / "picodome"
        helm_dir.mkdir(parents=True)
        _write_tmp_file(helm_dir, "values.yaml", content)

        findings: list[Finding] = []
        with patch("tests.sandbox.check_deploy_security.HELM_DIR", helm_dir):
            check_helm_values(findings)

        dev = _find_by_check(findings, "dev-mode-helm")
        assert len(dev) == 1
        assert dev[0].severity == "HIGH"

    def test_metrics_on_main_port(self, tmp_path: Path) -> None:
        content = textwrap.dedent("""\
            metrics:
              separatePort: false
        """)
        helm_dir = tmp_path / "picodome"
        helm_dir.mkdir(parents=True)
        _write_tmp_file(helm_dir, "values.yaml", content)

        findings: list[Finding] = []
        with patch("tests.sandbox.check_deploy_security.HELM_DIR", helm_dir):
            check_helm_values(findings)

        metrics = _find_by_check(findings, "metrics-main-port-helm")
        assert len(metrics) == 1
        assert metrics[0].severity == "LOW"


# ── Helm Template Checks ────────────────────────────────────────────


class TestHelmTemplates:
    """Tests for check_helm_templates."""

    def test_dev_mode_in_template(self, tmp_path: Path) -> None:
        content = textwrap.dedent("""\
            env:
              - name: PICODOME_DEV_MODE
                value: "1"
        """)
        helm_dir = tmp_path / "picodome"
        templates_dir = helm_dir / "templates"
        templates_dir.mkdir(parents=True)
        _write_tmp_file(templates_dir, "deployment.yaml", content)

        findings: list[Finding] = []
        with patch("tests.sandbox.check_deploy_security.HELM_DIR", helm_dir):
            check_helm_templates(findings)

        dev = _find_by_check(findings, "dev-mode-template")
        assert len(dev) == 1
        assert dev[0].severity == "CRITICAL"

    def test_privilege_escalation_in_template(self, tmp_path: Path) -> None:
        content = textwrap.dedent("""\
            securityContext:
              allowPrivilegeEscalation: true
        """)
        helm_dir = tmp_path / "picodome"
        templates_dir = helm_dir / "templates"
        templates_dir.mkdir(parents=True)
        _write_tmp_file(templates_dir, "deployment.yaml", content)

        findings: list[Finding] = []
        with patch("tests.sandbox.check_deploy_security.HELM_DIR", helm_dir):
            check_helm_templates(findings)

        priv = _find_by_check(findings, "privilege-escalation-template")
        assert len(priv) == 1
        assert priv[0].severity == "HIGH"


# ── Dockerfile Checks ────────────────────────────────────────────────


class TestDockerfile:
    """Tests for check_dockerfile."""

    def test_no_user_directive(self, tmp_path: Path) -> None:
        content = textwrap.dedent("""\
            FROM python:3.12-slim
            COPY . /app
            CMD ["python", "-m", "picodome"]
        """)
        _write_tmp_file(tmp_path, "Dockerfile", content)

        findings: list[Finding] = []
        with patch("tests.sandbox.check_deploy_security.REPO_ROOT", tmp_path):
            check_dockerfile(findings)

        no_user = _find_by_check(findings, "docker-no-user")
        assert len(no_user) == 1
        assert no_user[0].severity == "HIGH"

    def test_root_user_explicit(self, tmp_path: Path) -> None:
        content = textwrap.dedent("""\
            FROM python:3.12-slim
            USER root
            CMD ["python", "-m", "picodome"]
        """)
        _write_tmp_file(tmp_path, "Dockerfile", content)

        findings: list[Finding] = []
        with patch("tests.sandbox.check_deploy_security.REPO_ROOT", tmp_path):
            check_dockerfile(findings)

        root = _find_by_check(findings, "docker-root-user")
        assert len(root) == 1
        assert root[0].severity == "HIGH"

    def test_non_root_user_passes(self, tmp_path: Path) -> None:
        content = textwrap.dedent("""\
            FROM python:3.12-slim
            COPY . /app
            USER picodome
            CMD ["python", "-m", "picodome"]
        """)
        _write_tmp_file(tmp_path, "Dockerfile", content)

        findings: list[Finding] = []
        with patch("tests.sandbox.check_deploy_security.REPO_ROOT", tmp_path):
            check_dockerfile(findings)

        critical_high = [f for f in findings if f.severity in ("CRITICAL", "HIGH")]
        assert len(critical_high) == 0


# ── Source Hardcoded Secrets ────────────────────────────────────────


class TestSourceHardcodedSecrets:
    """Tests for check_source_hardcoded_secrets."""

    def test_hardcoded_password_detected(self, tmp_path: Path) -> None:
        src_dir = tmp_path / "picodome"
        src_dir.mkdir(parents=True)
        (src_dir / "__init__.py").write_text("")
        (src_dir / "bad.py").write_text('DEFAULT_PASSWORD = "supersecret12345"\n')

        findings: list[Finding] = []
        check_source_hardcoded_secrets(findings, src_dir=src_dir)

        assert any(f.check == "hardcoded-secret-source" for f in findings)

    def test_env_var_not_flagged(self, tmp_path: Path) -> None:
        src_dir = tmp_path / "picodome"
        src_dir.mkdir(parents=True)
        (src_dir / "__init__.py").write_text("")
        (src_dir / "good.py").write_text('token = os.environ.get("PICODOME_API_TOKENS", "")\n')

        findings: list[Finding] = []
        check_source_hardcoded_secrets(findings, src_dir=src_dir)

        assert not any(f.check == "hardcoded-secret-source" for f in findings)

    def test_docstring_example_not_flagged(self, tmp_path: Path) -> None:
        src_dir = tmp_path / "picodome"
        src_dir.mkdir(parents=True)
        (src_dir / "__init__.py").write_text("")
        (src_dir / "example.py").write_text('"""Example: secret="my-signing-secret"\n"""\n')

        findings: list[Finding] = []
        check_source_hardcoded_secrets(findings, src_dir=src_dir)

        assert not any(f.check == "hardcoded-secret-source" for f in findings)


# ── Gitignore Checks ────────────────────────────────────────────────


class TestGitignore:
    """Tests for check_gitignore_secrets."""

    def test_missing_gitignore(self, tmp_path: Path) -> None:
        findings: list[Finding] = []
        with patch("tests.sandbox.check_deploy_security.REPO_ROOT", tmp_path):
            check_gitignore_secrets(findings)

        no_git = _find_by_check(findings, "no-gitignore")
        assert len(no_git) == 1

    def test_incomplete_gitignore(self, tmp_path: Path) -> None:
        gitignore = tmp_path / ".gitignore"
        gitignore.write_text("__pycache__/\n*.pyc\n")

        findings: list[Finding] = []
        with patch("tests.sandbox.check_deploy_security.REPO_ROOT", tmp_path):
            check_gitignore_secrets(findings)

        missing = _find_by_check(findings, "gitignore-missing")
        # Should find .env, *.pem, *.key, *token*
        assert len(missing) >= 2

    def test_complete_gitignore(self, tmp_path: Path) -> None:
        gitignore = tmp_path / ".gitignore"
        gitignore.write_text(
            "\n".join(
                [
                    "__pycache__/",
                    ".env",
                    ".env.*",
                    "*.pem",
                    "*.key",
                    "*token*",
                ]
            )
        )

        findings: list[Finding] = []
        with patch("tests.sandbox.check_deploy_security.REPO_ROOT", tmp_path):
            check_gitignore_secrets(findings)

        missing = _find_by_check(findings, "gitignore-missing")
        assert len(missing) == 0


# ── Main Exit Codes ──────────────────────────────────────────────────


class TestMainExitCode:
    """Tests for the main() function exit codes."""

    def test_clean_repo_exits_zero(self) -> None:
        """The real repo should only have MEDIUM/LOW findings (no CRITICAL/HIGH)."""
        exit_code = main(["--quiet"])
        assert exit_code == 0

    def test_strict_mode_exits_nonzero_on_any_finding(self) -> None:
        """In strict mode, any finding should cause failure."""
        # After fixing Helm defaults (enterprise, mTLS, separatePort), the real repo
        # is clean. Inject a synthetic MEDIUM finding to verify strict mode behavior.
        with patch("tests.sandbox.check_deploy_security.check_helm_values") as mock_check:

            def inject_finding(findings):
                findings.append(Finding("MEDIUM", "test-strict", "synthetic finding for test", "test.yaml"))

            mock_check.side_effect = inject_finding
            exit_code = main(["--strict"])
        assert exit_code == 1


# ── Finding NamedTuple ──────────────────────────────────────────────


class TestFinding:
    """Test Finding construction."""

    def test_finding_fields(self) -> None:
        f = Finding("CRITICAL", "test-check", "test message", "file.yaml", 42)
        assert f.severity == "CRITICAL"
        assert f.check == "test-check"
        assert f.message == "test message"
        assert f.file == "file.yaml"
        assert f.line == 42

    def test_finding_optional_line(self) -> None:
        f = Finding("HIGH", "test-check", "test message", "file.yaml")
        assert f.line is None
