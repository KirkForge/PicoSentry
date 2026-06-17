
from __future__ import annotations

import re
from pathlib import Path
from typing import cast

from ..models import Confidence, Finding, Severity
from .utils import iter_node_modules, load_package_json

__all__ = ["detect_fork_drift"]

FORK_INDICATORS = (
    "fork",
    "mirror",
    "patch",
    "patched",
    "fix",
    "fixed",
    "custom",
    "local",
    "private",
    "backup",
    "mirror-",
)


AUTHORITATIVE_PREFIXES = (
    "https://github.com/npm/",
    "https://github.com/facebook/",
    "https://github.com/microsoft/",
    "https://github.com/google/",
    "https://github.com/nodejs/",
    "https://github.com/babel/",
    "https://github.com/webpack/",
    "https://github.com/mozilla/",
    "https://github.com/angular/",
    "https://github.com/vuejs/",
    "https://github.com/expressjs/",
    "https://github.com/lodash/",
    "https://github.com/axios/",
    "https://github.com/jestjs/",
    "https://github.com/mochajs/",
    "https://github.com/pugjs/",
    "https://github.com/DefinitelyTyped/",
)


AUTHORITATIVE_SCOPES = frozenset(
    {
        "@angular",
        "@babel",
        "@emotion",
        "@eslint",
        "@google",
        "@microsoft",
        "@mozilla",
        "@nestjs",
        "@nodejs",
        "@npm",
        "@react-spring",
        "@sentry",
        "@types",
        "@vue",
        "@webpack",
        "@typescript-eslint",
    }
)


_GITHUB_URL_RE = re.compile(r"github\.com/([^/]+)", re.IGNORECASE)


def _extract_repo_url(pkg: dict) -> str | None:
    repo = pkg.get("repository")
    if isinstance(repo, str):
        return repo
    if isinstance(repo, dict):
        url = cast(str, repo.get("url", ""))
        if url:
            return url
    homepage = cast(str, pkg.get("homepage", ""))
    if homepage and "github.com" in homepage:
        return homepage
    return None


def _is_fork_repo(url: str, pkg_name: str, author: str = "") -> bool:
    url_lower = url.lower()


    for prefix in AUTHORITATIVE_PREFIXES:
        if url_lower.startswith(prefix.lower()):
            return False


    match = _GITHUB_URL_RE.search(url)
    if match:
        org = match.group(1).lower()


        normalized_name = pkg_name.lower().replace("@", "").split("/")[0]
        if org == normalized_name:
            return False


        author_str = str(author).strip().lower() if author else ""
        if author_str and (org in author_str or author_str in org):
            return False


        for prefix in AUTHORITATIVE_PREFIXES:

            prefix_org = prefix.split("/")[-2].lower() if "/" in prefix else ""
            if normalized_name == prefix_org and org != prefix_org:
                return True


        org_aliases = {
            "fb": "facebook",
            "facebookincubator": "facebook",
            "googlecloud": "google",
            "aws": "amazon",
            "web-projects": "w3c",
            "jquery": "jquery",
        }
        resolved_org = org_aliases.get(org, org)


        for prefix in AUTHORITATIVE_PREFIXES:
            prefix_org = prefix.split("/")[-2].lower()
            if resolved_org == prefix_org or org == prefix_org:
                return False


    url_path = url_lower.split(".com/")[-1] if ".com/" in url_lower else url_lower
    for indicator in FORK_INDICATORS:
        if indicator in url_path:
            return True


    if match:
        repo_path = url_lower.split(match.group(0).lower())[-1]
        normalized_name = pkg_name.lower().replace("@", "").replace("/", "-")
        if normalized_name in repo_path and match.group(1).lower() != normalized_name:


            author_str = str(author).strip().lower() if author else ""
            org_lower = match.group(1).lower()
            if not author_str:

                pass
            elif org_lower not in author_str and author_str not in org_lower:
                return True


    return False


def detect_fork_drift(target: Path) -> list[Finding]:
    findings: list[Finding] = []


    root_pkg = target / "package.json"
    if root_pkg.is_file():
        pkg = load_package_json(root_pkg)
        if pkg:
            findings.extend(_check_fork(pkg, root_pkg))


    for pkg_json, pkg in iter_node_modules(target):
        findings.extend(_check_fork(pkg, pkg_json))

    return findings


def _check_fork(pkg: dict, pkg_json: Path) -> list[Finding]:
    findings: list[Finding] = []
    pkg_name = pkg.get("name", pkg_json.parent.name)
    pkg_version = pkg.get("version", "unknown")
    pkg_label = f"{pkg_name}@{pkg_version}"

    repo_url = _extract_repo_url(pkg)
    if not repo_url:
        findings.append(
            Finding(
                rule_id="L2-FORK-001",
                severity=Severity.LOW,
                confidence=Confidence.LOW,
                package=pkg_label,
                file=str(pkg_json),
                message=f"Package '{pkg_name}' has no repository URL — provenance cannot be verified",
                evidence="repository field missing or empty",
                remediation=(
                    f"Check the npm page for '{pkg_name}' to verify the canonical repository. "
                    "Packages without repository URLs may be forks or abandoned packages."
                ),
                references=[
                    "https://docs.npmjs.com/cli/v10/configuring-npm/package-json#repository",
                ],
            )
        )
        return findings


    author = pkg.get("author", "")
    if isinstance(author, dict):
        author = author.get("name", "")
    if _is_fork_repo(repo_url, pkg_name, str(author)):
        description = str(pkg.get("description", "")).lower()
        name_lower = pkg_name.lower()
        fork_indicators_found = [ind for ind in FORK_INDICATORS if ind in name_lower or ind in description]

        evidence_parts = [f"repository: {repo_url}"]
        if fork_indicators_found:
            evidence_parts.append(f"indicators: {', '.join(fork_indicators_found)}")

        findings.append(
            Finding(
                rule_id="L2-FORK-001",
                severity=Severity.MEDIUM,
                confidence=Confidence.MEDIUM if fork_indicators_found else Confidence.LOW,
                package=pkg_label,
                file=str(pkg_json),
                message=(f"Package '{pkg_name}' appears to be a fork — repo URL suggests a non-canonical source"),
                evidence=", ".join(evidence_parts),
                remediation=(
                    f"Verify '{pkg_name}' is from the canonical source. "
                    "Forks may contain unreviewed modifications. "
                    "Consider replacing with the upstream package."
                ),
                references=[
                    "https://blog.npmjs.org/post/162780572570/how-to-avoid-npm-version-range-typos",
                ],
            )
        )


    if pkg_name.startswith("@") and "/" in pkg_name:
        scope = pkg_name.split("/")[0]
        if scope.lower() not in AUTHORITATIVE_SCOPES:

            match = _GITHUB_URL_RE.search(repo_url)
            if match:
                org = match.group(1).lower()
                scope_without_at = scope.lower().lstrip("@")
                if org != scope_without_at:
                    findings.append(
                        Finding(
                            rule_id="L2-FORK-001",
                            severity=Severity.LOW,
                            confidence=Confidence.LOW,
                            package=pkg_label,
                            file=str(pkg_json),
                            message=(f"Scoped package '{pkg_name}' from non-authoritative scope '{scope}'"),
                            evidence=f"scope: {scope}, repository: {repo_url}",
                            remediation=(
                                f"Verify that '{pkg_name}' is the canonical package, "
                                f"not a fork published under scope '{scope}'."
                            ),
                            references=[
                                "https://docs.npmjs.com/cli/v10/using-npm/scope",
                            ],
                        )
                    )

    return findings
