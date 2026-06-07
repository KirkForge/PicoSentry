
from __future__ import annotations

import logging
from pathlib import Path

from ..models import Confidence, Finding, Severity
from .pypi_utils import detect_pypi_project, iter_site_packages, load_pyproject_toml

logger = logging.getLogger("picosentry.pypi_post_install")

__all__ = ["detect_pypi_post_install"]


NETWORK_PATTERNS = (
    "curl",
    "wget",
    "fetch",
    "urllib.request",
    "requests.get",
    "http.client",
    "http://",
    "https://",
    "ftp://",
)


EXEC_PATTERNS = (
    "subprocess.call",
    "subprocess.run",
    "subprocess.Popen",
    "subprocess.check_output",
    "os.system",
    "os.popen",
    "os.exec",
    "os.execl",
    "os.execle",
    "os.execlp",
    "os.execv",
    "os.execve",
    "os.execvp",
    "os.execvpe",
    "os.spawn",
    "eval(",
    "exec(",
    "__import__(",
    "compile(",
)


CREDENTIAL_PATTERNS = (
    ".env",
    ".pypirc",
    ".netrc",
    "~/.ssh",
    "os.environ",
    "environ.get",
)


def _scan_setup_py(setup_path: Path) -> list[Finding]:
    findings: list[Finding] = []

    if not setup_path.is_file():
        return findings

    try:
        content = setup_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return findings


    has_suspicious_code = False
    risk_tags: list[str] = []
    evidence_lines: list[str] = []

    lines = content.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()


        if stripped.startswith("#") or stripped.startswith(('"""', "'''", '"', "'")):
            continue

        for pattern in EXEC_PATTERNS:
            if pattern in stripped:
                has_suspicious_code = True
                risk_tags.append("code execution")
                evidence_lines.append(f"line {i + 1}: {stripped[:100]}")
                break

        for pattern in NETWORK_PATTERNS:
            if pattern in stripped:
                has_suspicious_code = True
                risk_tags.append("network access")
                if f"line {i + 1}: {stripped[:100]}" not in evidence_lines:
                    evidence_lines.append(f"line {i + 1}: {stripped[:100]}")
                break

        for pattern in CREDENTIAL_PATTERNS:
            if pattern in stripped:
                has_suspicious_code = True
                risk_tags.append("credential reading")
                if f"line {i + 1}: {stripped[:100]}" not in evidence_lines:
                    evidence_lines.append(f"line {i + 1}: {stripped[:100]}")
                break

    if has_suspicious_code:
        risk_tags = list(dict.fromkeys(risk_tags))  # Deduplicate preserving order
        severity = Severity.CRITICAL if "network access" in risk_tags or "credential reading" in risk_tags else Severity.HIGH

        findings.append(
            Finding(
                rule_id="L2-PYPI-POST-001",
                severity=severity,
                confidence=Confidence.EXACT,
                package=setup_path.parent.name,
                file=str(setup_path),
                message="setup.py contains code execution during installation",
                evidence="; ".join(evidence_lines[:5]),
                remediation=(
                    f"CRITICAL: setup.py in {setup_path.parent.name} has "
                    + ", ".join(risk_tags)
                    + ". Audit before installing. Prefer pyproject.toml with static metadata."
                ),
                references=[
                    "https://pip.pypa.io/en/stable/topics/secure-installation/",
                    "https://blog.pypi.org/posts/2023-05-23-securing-package-installs/",
                ],
                ecosystem="pypi",
            )
        )

    return findings


def _scan_pyproject_build(pyproject_path: Path) -> list[Finding]:
    findings: list[Finding] = []

    if not pyproject_path.is_file():
        return findings

    project_data = load_pyproject_toml(pyproject_path.parent)
    if not project_data:
        return findings


    build_system = project_data.get("build-system", {})
    build_backend = build_system.get("build-backend", "")

    if "setuptools" in build_backend:

        setup_py = pyproject_path.parent / "setup.py"
        if setup_py.is_file():
            findings.extend(_scan_setup_py(setup_py))


    poetry_tool = project_data.get("tool", {}).get("poetry", {})
    if "scripts" in poetry_tool:
        scripts = poetry_tool["scripts"]
        if isinstance(scripts, dict):
            for script_name, script_value in scripts.items():
                if isinstance(script_value, str) and any(
                    p in str(script_value).lower() for p in ("subprocess", "os.system", "exec", "eval")
                ):
                    findings.append(
                        Finding(
                            rule_id="L2-PYPI-POST-001",
                            severity=Severity.HIGH,
                            confidence=Confidence.HIGH,
                            package=pyproject_path.parent.name,
                            file=str(pyproject_path),
                            message=f"PyPI package defines post-install script: '{script_name}'",
                            evidence=f"tool.poetry.scripts.{script_name} = {script_value!r}",
                            remediation=(
                                f"Review the '{script_name}' script. "
                                "Ensure it does not execute arbitrary code during install."
                            ),
                            references=[
                                "https://python-poetry.org/docs/pyproject/#scripts",
                            ],
                            ecosystem="pypi",
                        )
                    )

    return findings


def detect_pypi_post_install(target: Path, corpus_dir: Path) -> list[Finding]:
    findings: list[Finding] = []

    if not detect_pypi_project(target):
        return findings


    setup_py = target / "setup.py"
    if setup_py.is_file():
        findings.extend(_scan_setup_py(setup_py))

    pyproject = target / "pyproject.toml"
    if pyproject.is_file():
        findings.extend(_scan_pyproject_build(pyproject))


    for meta_path, metadata in iter_site_packages(target):
        metadata.get("name", "") if metadata else meta_path.parent.name
        pkg_dir = meta_path.parent


        setup_py_path = pkg_dir / "setup.py"
        if setup_py_path.is_file():
            findings.extend(_scan_setup_py(setup_py_path))

    return findings
