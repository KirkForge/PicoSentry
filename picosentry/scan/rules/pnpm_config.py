
import contextlib
import json
from pathlib import Path

from ..models import Confidence, Finding, Severity
from .utils import load_package_json

__all__ = ["detect_pnpm_config"]


def detect_pnpm_config(target_path: Path) -> list[Finding]:
    findings: list[Finding] = []

    target = Path(target_path)
    has_pnpm_lock = (target / "pnpm-lock.yaml").exists()
    has_npmrc = (target / ".npmrc").exists()
    pkg_path = target / "package.json"

    if not has_pnpm_lock:
        return findings


    pkg_data = {}
    if pkg_path.exists():
        with contextlib.suppress(json.JSONDecodeError, UnicodeDecodeError):
            pkg_data = load_package_json(pkg_path)

    pnpm_config = pkg_data.get("pnpm", {})
    pnpm_overrides = pnpm_config.get("overrides", {})
    pnpm_patches = pnpm_config.get("patchedDependencies", {})


    if has_npmrc:
        npmrc_path = target / ".npmrc"
        try:
            npmrc_content = npmrc_path.read_text(encoding="utf-8", errors="ignore")
        except (UnicodeDecodeError, OSError):
            npmrc_content = ""

        for line_no, line in enumerate(npmrc_content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if "dangerouslyallowallbuilds" in stripped.lower().replace("-", "").replace("_", ""):
                findings.append(
                    Finding(
                        rule_id="L2-PNPM-001",
                        package="pnpm-config",
                        severity=Severity.CRITICAL,
                        confidence=Confidence.EXACT,
                        file=str(npmrc_path),
                        line=line_no,
                        message=".npmrc enables dangerouslyAllowAllBuilds — all install scripts run without allowlist",
                        evidence=f"Config line: {stripped}",
                        remediation="Remove dangerouslyAllowAllBuilds and use onlyBuiltDependencies to allowlist specific packages with build scripts.",
                        references=[
                            "https://pnpm.io/settings#dangerouslyallowallbuilds",
                            "https://pnpm.io/package_json#pnpmonlybuiltdependencies",
                        ],
                    )
                )


    if pnpm_config.get("dangerouslyAllowAllBuilds"):
        findings.append(
            Finding(
                rule_id="L2-PNPM-001",
                package=pkg_data.get("name", "unknown"),
                severity=Severity.CRITICAL,
                confidence=Confidence.EXACT,
                file=str(pkg_path),
                line=None,
                message="package.json enables dangerouslyAllowAllBuilds — all install scripts run without allowlist",
                evidence="pnpm.dangerouslyAllowAllBuilds: true",
                remediation="Remove dangerouslyAllowAllBuilds and use onlyBuiltDependencies to allowlist specific packages.",
                references=[
                    "https://pnpm.io/settings#dangerouslyallowallbuilds",
                    "https://pnpm.io/package_json#pnpmonlybuiltdependencies",
                ],
            )
        )


    if has_pnpm_lock and not has_npmrc:
        findings.append(
            Finding(
                rule_id="L2-PNPM-001",
                package="pnpm-config",
                severity=Severity.MEDIUM,
                confidence=Confidence.HIGH,
                file=str(target / "pnpm-lock.yaml"),
                line=None,
                message="pnpm-lock.yaml exists without .npmrc — no build script allowlist is configured",
                evidence="pnpm-lock.yaml present, .npmrc absent",
                remediation="Add .npmrc with onlyBuiltDependencies to control which packages can run install scripts.",
                references=["https://pnpm.io/npmrc#only-built-dependencies"],
            )
        )


    if pnpm_overrides:
        for override_key in pnpm_overrides:

            override_val = pnpm_overrides[override_key]
            findings.append(
                Finding(
                    rule_id="L2-PNPM-001",
                    package=pkg_data.get("name", "unknown"),
                    severity=Severity.LOW,
                    confidence=Confidence.HIGH,
                    file=str(pkg_path),
                    line=None,
                    message=f"pnpm override detected: {override_key} → {override_val}",
                    evidence=f"pnpm.overrides.{override_key} = {override_val}",
                    remediation="Review pnpm overrides regularly. Overrides bypass resolution and may introduce unverified code.",
                    references=["https://pnpm.io/package_json#pnpmoverrides"],
                )
            )


    if pnpm_patches:
        findings.append(
            Finding(
                rule_id="L2-PNPM-001",
                package=pkg_data.get("name", "unknown"),
                severity=Severity.MEDIUM,
                confidence=Confidence.EXACT,
                file=str(pkg_path),
                line=None,
                message=f"pnpm patchedDependencies modifies {len(pnpm_patches)} package(s) — patches bypass npm audit",
                evidence=f"patchedDependencies: {list(pnpm_patches.keys())}",
                remediation="Minimize pnpm patches. Each patch modifies third-party code and is invisible to npm audit. Prefer upstream fixes.",
                references=["https://pnpm.io/package_json#pnpmpatcheddependencies"],
            )
        )

    return findings
