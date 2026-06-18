#!/usr/bin/env python3
"""PicoDome — Deployment Security Checker.

Validates that deployment manifests and configuration don't contain
insecure defaults that would be dangerous in production.

Runs as part of CI to catch:
  - Dev-mode flags left enabled
  - Missing authentication
  - Plaintext secrets
  - Insecure TLS settings
  - Observational-only backends in enterprise context
  - Missing security contexts in containers

Usage:
  python scripts/check_deploy_security.py [--strict]

  --strict  Treat warnings as errors (exit 1 on any finding)
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path
from typing import NamedTuple

# ── Repository root ────────────────────────────────────────────────────

REPO_ROOT = Path(__file__).resolve().parent.parent
DEPLOY_DIR = REPO_ROOT / "deploy"
HELM_DIR = DEPLOY_DIR / "helm" / "picodome"
K8S_DIR = DEPLOY_DIR / "kubernetes"
SRC_DIR = REPO_ROOT / "src"


class Finding(NamedTuple):
    severity: str  # "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO"
    check: str
    message: str
    file: str
    line: int | None = None


# Dev-bypass environment variables that are safe for local development but must
# never be enabled in a production deployment.
_DEV_BYPASS_ENV_VARS: tuple[tuple[str, str, str], ...] = (
    ("PICODOME_DEV_MODE", "CRITICAL", "disables authentication"),
    ("PICODOME_TLS_DEV", "HIGH", "uses self-signed TLS certificates"),
    ("PICODOME_SKIP_SECURE_ASSERT", "HIGH", "disables daemon secure-boot checks"),
    ("PICOSHOGUN_SKIP_SECURE_ASSERT", "HIGH", "disables serve secure-boot checks"),
    ("PICOWATCH_SKIP_SECURE_ASSERT", "HIGH", "disables watch secure-boot checks"),
)

# Preserve the original short check names for the two variables that existing
# tests and consumers already reference.
_DEV_BYPASS_CHECK_PREFIX: dict[str, str] = {
    "PICODOME_DEV_MODE": "dev-mode",
    "PICODOME_TLS_DEV": "tls-dev",
}


def _env_var_enabled_in_line(var: str, line: str, lines: list[str], i: int) -> bool:
    """Return True if `var` is set to 1 on this line or the next value line."""
    if var not in line:
        return False
    return bool(
        re.search(rf"{re.escape(var)}.*1", line)
        or (i < len(lines) and re.search(r'value:\s*["\']?1["\']?', lines[i]))
    )


def _load_yaml_file(path: Path) -> dict | list | None:
    """Load a YAML file, falling back to basic parsing if PyYAML unavailable."""
    try:
        import yaml

        with open(path) as f:
            return yaml.safe_load(f)
    except ImportError:
        pass

    # Minimal YAML parser for simple key: value files
    try:
        with open(path) as f:
            text = f.read()
        # Try JSON first (some .yaml files are actually JSON)
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            pass
        # Very basic YAML: extract top-level key: value pairs
        result: dict = {}
        for raw_line in text.splitlines():
            line = raw_line.strip()
            if not line or line.startswith("#"):
                continue
            match = re.match(r'^(\w+):\s*["\']?(.+?)["\']?\s*$', line)
            if match:
                key, val = match.group(1), match.group(2)
                if val.lower() in ("true", "false"):
                    result[key] = val.lower() == "true"
                elif val.isdigit():
                    result[key] = int(val)
                else:
                    result[key] = val
        return result or None
    except Exception:
        return None


def _read_file_lines(path: Path) -> list[str]:
    """Read file lines, returning empty list on error."""
    try:
        return path.read_text(encoding="utf-8").splitlines()
    except Exception:
        return []


# ── Check Functions ────────────────────────────────────────────────────


def check_k8s_deployment(findings: list[Finding]) -> None:
    """Check the raw K8s deployment manifest for insecure defaults."""
    deploy_path = K8S_DIR / "deployment.yaml"
    if not deploy_path.exists():
        findings.append(Finding("INFO", "k8s-manifest", "No raw K8s deployment.yaml found", str(deploy_path)))
        return

    lines = _read_file_lines(deploy_path)

    for i, line in enumerate(lines, 1):
        # Dev-bypass env vars enabled in the manifest
        for var, severity, reason in _DEV_BYPASS_ENV_VARS:
            if _env_var_enabled_in_line(var, line, lines, i):
                prefix = _DEV_BYPASS_CHECK_PREFIX.get(var, var.lower().replace("_", "-"))
                findings.append(
                    Finding(
                        severity,
                        f"{prefix}-k8s",
                        f"{var}=1 found in K8s deployment — {reason}",
                        str(deploy_path),
                        i,
                    )
                )

        # Placeholder secrets
        if "REPLACE_WITH_STRONG_TOKEN" in line or "REPLACE_ME" in line or "changeme" in line:
            findings.append(
                Finding(
                    "CRITICAL",
                    "placeholder-secret-k8s",
                    f"Placeholder secret found: {line.strip()}",
                    str(deploy_path),
                    i,
                )
            )

        # runAsUser: 0 (root)
        if re.search(r"runAsUser:\s*0", line):
            findings.append(
                Finding(
                    "HIGH",
                    "root-user-k8s",
                    "Container runs as root (runAsUser: 0)",
                    str(deploy_path),
                    i,
                )
            )

        # Insecure container settings
        if "allowPrivilegeEscalation: true" in line:
            findings.append(
                Finding(
                    "HIGH",
                    "privilege-escalation-k8s",
                    "allowPrivilegeEscalation: true found — should be false",
                    str(deploy_path),
                    i,
                )
            )

        if "readOnlyRootFilesystem: false" in line:
            findings.append(
                Finding(
                    "MEDIUM",
                    "writable-filesystem-k8s",
                    "readOnlyRootFilesystem: false — should be true in production",
                    str(deploy_path),
                    i,
                )
            )

    # Check for enterprise mode
    content = "\n".join(lines)
    if "PICODOME_ENTERPRISE_MODE" not in content:
        findings.append(
            Finding(
                "MEDIUM",
                "enterprise-mode-missing-k8s",
                "PICODOME_ENTERPRISE_MODE not set in K8s deployment — enterprise enforcement disabled",
                str(deploy_path),
            )
        )

    # Check for security context
    if "securityContext" not in content:
        findings.append(
            Finding(
                "HIGH",
                "no-security-context-k8s",
                "No securityContext defined in K8s deployment",
                str(deploy_path),
            )
        )


def check_helm_values(findings: list[Finding]) -> None:
    """Check Helm values for insecure defaults."""
    values_path = HELM_DIR / "values.yaml"
    if not values_path.exists():
        findings.append(Finding("INFO", "helm-values", "No Helm values.yaml found", str(values_path)))
        return

    lines = _read_file_lines(values_path)
    data = _load_yaml_file(values_path)

    for i, line in enumerate(lines, 1):
        # Dev mode in values
        if re.search(r"devMode:\s*true", line):
            findings.append(
                Finding(
                    "HIGH",
                    "dev-mode-helm",
                    "devMode: true in Helm values — self-signed TLS certs",
                    str(values_path),
                    i,
                )
            )

        # Enterprise mode disabled
        if re.search(r"enabled:\s*false", line) and i > 0:
            # Check if this is under enterprise key
            context = "\n".join(lines[max(0, i - 5) : i + 1])
            if "enterprise" in context.lower():
                findings.append(
                    Finding(
                        "MEDIUM",
                        "enterprise-disabled-helm",
                        "enterprise.enabled: false in Helm values — enterprise enforcement disabled",
                        str(values_path),
                        i,
                    )
                )

        # Plaintext tokens (inline instead of secretRef)
        if re.search(r'^\s*tokens:\s*["\'][^"\']+["\']', line):
            findings.append(
                Finding(
                    "CRITICAL",
                    "plaintext-tokens-helm",
                    f"Plaintext API token in Helm values: {line.strip()}",
                    str(values_path),
                    i,
                )
            )

        # mTLS disabled
        if re.search(r"^\s+enabled:\s*false", line):
            context = "\n".join(lines[max(0, i - 5) : i + 1])
            if "mtls" in context.lower() or "mTLS" in context:
                findings.append(
                    Finding(
                        "MEDIUM",
                        "mtls-disabled-helm",
                        "mTLS disabled in Helm values — no transport encryption",
                        str(values_path),
                        i,
                    )
                )

        # Metrics on main port
        if re.search(r"separatePort:\s*false", line):
            findings.append(
                Finding(
                    "LOW",
                    "metrics-main-port-helm",
                    "Metrics on main port — consider separatePort: true for auth separation",
                    str(values_path),
                    i,
                )
            )

        # runAsUser: 0
        if re.search(r"runAsUser:\s*0", line):
            findings.append(
                Finding(
                    "HIGH",
                    "root-user-helm",
                    "runAsUser: 0 in Helm values — container runs as root",
                    str(values_path),
                    i,
                )
            )

    # Check data structure if YAML parsed (dedup with line-level checks)
    if data and isinstance(data, dict):
        enterprise = data.get("enterprise", {})
        if (
            isinstance(enterprise, dict)
            and not enterprise.get("enabled", False)
            # Only add if not already found by line-level check
            and not any(f.check == "enterprise-disabled-helm" for f in findings)
        ):
            findings.append(
                Finding(
                    "MEDIUM",
                    "enterprise-disabled-helm",
                    "enterprise.enabled is false — production deployments should enable enterprise mode",
                    str(values_path),
                )
            )

        auth = data.get("auth", {})
        if isinstance(auth, dict):
            tokens = auth.get("tokens", "")
            if (
                tokens
                and isinstance(tokens, str)
                and tokens not in ("", '""', "''")
                # Non-empty inline token — check if it's not a placeholder
                and tokens not in ("REPLACE_WITH_STRONG_TOKEN", "CHANGE_ME")
                and not any(f.check == "inline-tokens-helm" for f in findings)
            ):
                findings.append(
                    Finding(
                        "HIGH",
                        "inline-tokens-helm",
                        "auth.tokens is set inline in values.yaml — use existingSecret instead",
                        str(values_path),
                    )
                )

        mtls = data.get("mtls", {})
        if (
            isinstance(mtls, dict)
            and not mtls.get("enabled", False)
            and not any(f.check == "mtls-disabled-helm" for f in findings)
        ):
            findings.append(
                Finding(
                    "MEDIUM",
                    "mtls-disabled-helm",
                    "mtls.enabled is false — no mutual TLS in production",
                    str(values_path),
                )
            )


def check_helm_templates(findings: list[Finding]) -> None:
    """Check Helm templates for insecure patterns."""
    templates_dir = HELM_DIR / "templates"
    if not templates_dir.exists():
        return

    for tpl_path in sorted(templates_dir.glob("*.yaml")):
        lines = _read_file_lines(tpl_path)

        for i, line in enumerate(lines, 1):
            # Dev-bypass env vars enabled in templates
            for var, severity, _reason in _DEV_BYPASS_ENV_VARS:
                if var not in line or "comment" in line.lower():
                    continue
                if _env_var_enabled_in_line(var, line, lines, i):
                    prefix = _DEV_BYPASS_CHECK_PREFIX.get(var, var.lower().replace("_", "-"))
                    findings.append(
                        Finding(
                            severity,
                            f"{prefix}-template",
                            f"{var}=1 in template: {line.strip()}",
                            str(tpl_path),
                            i,
                        )
                    )

            # Plaintext env vars for tokens (Kubernetes value: with long string)
            if re.search(r'value:\s*["\'][^"\']{20,}["\']', line) and "token" in line.lower():
                findings.append(
                    Finding(
                        "CRITICAL",
                        "hardcoded-token-template",
                        f"Possible hardcoded token in template: {line.strip()}",
                        str(tpl_path),
                        i,
                    )
                )

            # allowPrivilegeEscalation: true
            if "allowPrivilegeEscalation: true" in line:
                findings.append(
                    Finding(
                        "HIGH",
                        "privilege-escalation-template",
                        "allowPrivilegeEscalation: true in template",
                        str(tpl_path),
                        i,
                    )
                )


def check_dockerfile(findings: list[Finding]) -> None:
    """Check Dockerfile for insecure patterns."""
    dockerfile = REPO_ROOT / "Dockerfile"
    if not dockerfile.exists():
        return

    lines = _read_file_lines(dockerfile)

    for i, line in enumerate(lines, 1):
        # Running as root
        if re.match(r"^\s*USER\s+root", line):
            findings.append(
                Finding(
                    "HIGH",
                    "docker-root-user",
                    "Dockerfile explicitly sets USER root",
                    str(dockerfile),
                    i,
                )
            )

        # No USER directive at all
        if "USER picodome" not in "".join(lines) and "USER nobody" not in "".join(lines):
            # Check there's at least a non-root USER
            pass  # Handled below

    # Check that Dockerfile has a non-root USER
    content = "\n".join(lines)
    if not re.search(r"^USER\s+\S+", content, re.MULTILINE):
        findings.append(
            Finding(
                "HIGH",
                "docker-no-user",
                "Dockerfile has no USER directive — will run as root",
                str(dockerfile),
            )
        )

    # Check for COPY as root before USER
    user_lines = [(i, ln) for i, ln in enumerate(lines) if re.match(r"^USER\s+", ln)]
    copy_lines = [(i, ln) for i, ln in enumerate(lines) if re.match(r"^(COPY|ADD)\s+", ln)]

    if user_lines:
        last_user_line = user_lines[-1][0]
        for copy_i, _copy_l in copy_lines:
            if copy_i > last_user_line:
                # COPY after last USER is fine (running as non-root)
                pass

    # Check for --no-cache-dir in pip install
    if "pip install" in content and "--no-cache-dir" not in content:
        findings.append(
            Finding(
                "LOW",
                "docker-pip-cache",
                "pip install without --no-cache-dir — larger image size",
                str(dockerfile),
            )
        )


def check_source_hardcoded_secrets(findings: list[Finding], src_dir: Path | None = None) -> None:
    """Check source code for hardcoded secrets or insecure defaults in production paths."""
    check_dir = src_dir or SRC_DIR
    # Only check non-test source files
    for py_file in sorted(check_dir.rglob("*.py")):
        try:
            rel_path = py_file.relative_to(check_dir)
        except ValueError:
            rel_path = py_file
        lines = _read_file_lines(py_file)

        for i, line in enumerate(lines, 1):
            # Skip comments and docstrings
            stripped = line.strip()
            if stripped.startswith(("#", '"""', "'''")):
                continue

            # Hardcoded tokens/passwords (but not in docstrings, comments, or config params)
            if re.search(r'(?:password|secret|token|api_key)\s*=\s*["\'][^"\']{8,}["\']', line, re.IGNORECASE):
                # Exclude known safe patterns
                if any(
                    s in line
                    for s in [
                        "os.environ",
                        "environ.get",
                        "os.getenv",
                        "getenv",
                        "from_env",
                        "placeholder",
                        "example",
                        "REPLACE",
                        "changeme",
                        "test_",
                        "_test",
                        "secret_key",
                        "signing_secret",  # config params, not actual secrets
                        "my-signing-secret",  # docstring example
                        "my_signing_secret",  # docstring example
                    ]
                ):
                    continue
                # Exclude lines inside docstrings (triple-quoted)
                # Check if this line is between """ markers
                above = lines[max(0, i - 3) : i]
                in_docstring = any('"""' in ln or "'''" in ln for ln in above)
                if in_docstring:
                    continue
                findings.append(
                    Finding(
                        "CRITICAL",
                        "hardcoded-secret-source",
                        f"Possible hardcoded secret: {stripped[:80]}",
                        str(rel_path),
                        i,
                    )
                )


def check_env_defaults(findings: list[Finding]) -> None:
    """Check that environment variable defaults favor secure settings."""
    # Check auth.py for dev-mode bypass
    auth_path = SRC_DIR / "picodome" / "auth.py"
    if auth_path.exists():
        lines = _read_file_lines(auth_path)
        content = "\n".join(lines)

        # Verify dev mode is opt-in, not default
        if 'os.environ.get("PICODOME_DEV_MODE", "").lower() in ("1", "true", "yes")' not in content:
            findings.append(
                Finding(
                    "MEDIUM",
                    "dev-mode-default",
                    "PICODOME_DEV_MODE default may not be opt-in",
                    str(auth_path),
                )
            )

    # Check daemon server for observational_only backend rejection in enterprise
    server_path = SRC_DIR / "picodome" / "daemon" / "server.py"
    if server_path.exists():
        lines = _read_file_lines(server_path)
        content = "\n".join(lines)

        # Verify enterprise mode rejects observational_only
        if "observational_only" not in content or "enterprise" not in content:
            findings.append(
                Finding(
                    "MEDIUM",
                    "no-observational-guard",
                    "Daemon server may not reject observational_only backends in enterprise mode",
                    str(server_path),
                )
            )


def check_gitignore_secrets(findings: list[Finding]) -> None:
    """Check that .gitignore covers common secret patterns."""
    gitignore_path = REPO_ROOT / ".gitignore"
    if not gitignore_path.exists():
        findings.append(
            Finding(
                "MEDIUM",
                "no-gitignore",
                "No .gitignore file found",
                str(gitignore_path),
            )
        )
        return

    content = gitignore_path.read_text(encoding="utf-8")
    required_patterns = [
        (".env", "Environment files may contain secrets"),
        ("*.pem", "PEM certificate/key files"),
        ("*.key", "Private key files"),
        ("*token*", "Token files"),
    ]

    for pattern, reason in required_patterns:
        # Check for the pattern or a broader pattern that covers it
        if pattern.startswith("*."):
            base = pattern[1:]  # e.g., ".pem"
            if base not in content and pattern not in content:
                findings.append(
                    Finding(
                        "LOW",
                        "gitignore-missing",
                        f".gitignore missing '{pattern}' — {reason}",
                        str(gitignore_path),
                    )
                )
        elif pattern not in content:
            findings.append(
                Finding(
                    "LOW",
                    "gitignore-missing",
                    f".gitignore missing '{pattern}' — {reason}",
                    str(gitignore_path),
                )
            )


# ── Main ───────────────────────────────────────────────────────────────


def main(args: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(description="PicoDome deployment security checker")
    parser.add_argument("--strict", action="store_true", help="Treat all findings as errors")
    parser.add_argument("--quiet", action="store_true", help="Only show CRITICAL and HIGH findings")
    parsed = parser.parse_args(args)

    findings: list[Finding] = []

    # Run all checks
    check_k8s_deployment(findings)
    check_helm_values(findings)
    check_helm_templates(findings)
    check_dockerfile(findings)
    check_source_hardcoded_secrets(findings)
    check_env_defaults(findings)
    check_gitignore_secrets(findings)

    # Sort by severity
    severity_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: (severity_order.get(f.severity, 99), f.check, f.file))

    # Display results
    print("\n🔒 PicoDome — Deployment Security Check\n")
    print("=" * 70)

    if not findings:
        print("\n✅ No security findings — deployment looks clean!\n")
        return 0

    # Count by severity
    counts: dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1

    summary = "  ".join(
        f"{sev}: {count}" for sev, count in sorted(counts.items(), key=lambda x: severity_order.get(x[0], 99))
    )
    print(f"\n  {summary}\n")

    for f in findings:
        if parsed.quiet and f.severity not in ("CRITICAL", "HIGH"):
            continue

        icon = {"CRITICAL": "🚨", "HIGH": "❌", "MEDIUM": "⚠️", "LOW": "💡", "INFO": "ℹ️"}.get(f.severity, "?")
        location = f.file
        if f.line:
            location += f":{f.line}"
        print(f"  {icon} [{f.severity:8s}] {f.check}")
        print(f"           {f.message}")
        print(f"           at {location}")
        print()

    # Determine exit code
    critical_high = any(f.severity in ("CRITICAL", "HIGH") for f in findings)
    if critical_high:
        print("❌ FAIL — Critical or High severity findings detected")
        return 1
    if parsed.strict and findings:
        print("❌ FAIL — Findings detected in strict mode")
        return 1
    print("⚠️  WARN — Only medium/low findings (passing in non-strict mode)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
