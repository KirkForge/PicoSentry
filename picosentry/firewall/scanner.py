from __future__ import annotations

import json
import logging
import re
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import unquote, urlsplit

from picosentry.firewall.cache import VerdictCache as _VerdictCache
from picosentry.firewall.cache import VerdictCache as _CacheForPut

if TYPE_CHECKING:
    from picosentry.scan.engine import ScanEngine

logger = logging.getLogger("picosentry.firewall.scanner")

_NPM_PACKAGE_RE = re.compile(r"^/(@[^/]+/[^/]+|[^/]+)(?:/([^/]+))?$")
_PYPI_PACKAGE_RE = re.compile(r"^/pypi/([^/]+)(?:/([^/]+))?/json$")
_STATIC_EXT_RE = re.compile(r"\.(ico|png|jpg|jpeg|gif|svg|css|js|woff|woff2|ttf|eot|map)$", re.IGNORECASE)

# Rules that require local artifacts (lockfiles, pnpm workspace files, private
# registry config) which registry metadata documents never contain — they
# structurally false-positive on every manifest with dependencies (e.g. "no
# lockfile" HIGH on any package with deps). The firewall is a *metadata*
# firewall; artifact scanning is picosentry scan's job on the downloaded
# tarball.
_ARTIFACT_RULE_EXCLUSIONS = frozenset({"L2-LOCK-001", "L2-PNPM-001", "L2-DEPC-001", "L2-PYPI-DEPC-001"})

# WO7-009: UNRESOLVED gets a short TTL so a version published during the
# negative-cache window is re-resolved quickly instead of blocked for an hour.
_UNRESOLVED_TTL_SECONDS = 30


def extract_version_manifest(metadata: dict, version: str) -> dict | None:
    """Return the requested version's manifest slice from a registry document.

    npm ``GET /pkg`` returns the whole-catalog doc with every version nested
    under ``versions``; the scan engine's rules only read root-level manifest
    fields, so scanning the raw doc would be blind to all version content.
    PyPI nests the requested version's metadata under ``info``. Single-manifest
    docs (npm ``GET /pkg/1.2.3``) pass through unchanged.

    Returns ``None`` when a whole-catalog doc does not contain the requested
    version — the caller must refuse (400/502) rather than scan root fields,
    which would report a false ALLOW by inspecting non-version content
    (WO6-017).
    """
    versions = metadata.get("versions")
    if isinstance(versions, dict):
        resolved: str | None = version
        if version == "latest":
            dist_tags = metadata.get("dist-tags")
            resolved = dist_tags.get("latest") if isinstance(dist_tags, dict) else None
        slice_manifest = versions.get(resolved) if resolved else None
        if isinstance(slice_manifest, dict):
            return slice_manifest
        return None
    info = metadata.get("info")
    if isinstance(info, dict):
        return info
    return metadata


class FirewallVerdict:
    ALLOW = "allow"
    QUARANTINE = "quarantine"
    BLOCK = "block"
    # Requested version could not be resolved from the upstream doc — the proxy
    # maps this to 502 so a missing version is never silently ALLOW-scanned
    # against root catalog fields (WO6-017).
    UNRESOLVED = "unresolved"


def classify_path(path: str) -> tuple[str, str, str] | None:
    # Classify on the query-less path: $-anchored regexes must never see
    # '?refresh=1' — query-decorated metadata URLs get SCANNED, and the
    # query never pollutes the name used for scanning/cache keys.
    path = urlsplit(path).path.rstrip("/")
    if _STATIC_EXT_RE.search(path):
        return None
    # Percent-decode BEFORE regex match: npm clients send scopes as %40 (@)
    # and the slash inside a scoped name as %2F. Decoding up front makes
    # /%40scope/pkg classify identically to /@scope/pkg (WO6-017). Decoding
    # before _STATIC_EXT_RE is safe — static extensions never arrive encoded.
    path = unquote(path)
    m = _PYPI_PACKAGE_RE.match(path)
    if m:
        name = m.group(1)
        version = m.group(2) or "latest"
        return ("pypi", name, version)
    m = _NPM_PACKAGE_RE.match(path)
    if m:
        name = m.group(1)
        version = m.group(2) or "latest"
        return ("npm", name, version)
    return None


def _sanitize_pypi_name(name: str) -> str | None:
    """Escape a URL-path package name for safe interpolation into TOML.

    ``classify_path`` percent-decodes the path before regex match, so a
    path like ``/pypi/evil%27%0a[tool.evil]%0acmd/json`` yields a name with
    single quotes and newlines. Interpolating that into ``name = '{name}'``
    closes the TOML string and starts a new section — TOML injection
    (WO7-008). Strip the characters that break out of a single-quoted TOML
    basic string (``'``, ``\\n``, ``\\r``, ``]``, ``#``); reject names that
    still contain anything non-printable or empty after sanitization.
    """
    safe = name.replace("'", "").replace("\n", "").replace("\r", "").replace("]", "").replace("#", "")
    safe = safe.strip()
    if not safe or not safe.isprintable():
        return None
    return safe


def _pypi_to_npm_manifest(name: str, version: str, info: dict) -> dict | None:
    """Map PyPI ``info`` metadata into an npm ``package.json`` shape.

    WO7-013: the firewall writes pypi_metadata.json but no rule reads it.
    Writing a package.json lets the existing npm rules (L2-MAINT, L2-FORK,
    L2-PROV) fire on PyPI packages, giving PyPI the same metadata firewall
    coverage as npm. Only fields the existing rules read are mapped.
    """
    manifest: dict = {"name": name, "version": version}

    author_name = info.get("author") or ""
    author_email = info.get("author_email") or ""
    if author_name:
        if author_email:
            manifest["author"] = {"name": str(author_name), "email": str(author_email)}
        else:
            manifest["author"] = str(author_name)

    maintainer_name = info.get("maintainer") or ""
    maintainer_email = info.get("maintainer_email") or ""
    if maintainer_name:
        m: dict = {"name": str(maintainer_name)}
        if maintainer_email:
            m["email"] = str(maintainer_email)
        manifest["maintainers"] = [m]

    repo_url = info.get("home_page") or ""
    project_urls = info.get("project_urls")
    if isinstance(project_urls, dict):
        for key in ("Repository", "repository", "Source", "source", "Homepage", "homepage"):
            val = project_urls.get(key)
            if val and isinstance(val, str):
                repo_url = val
                break
    if repo_url:
        manifest["repository"] = {"type": "git", "url": str(repo_url)}
        manifest["homepage"] = str(repo_url)

    description = info.get("summary") or info.get("description") or ""
    if description:
        manifest["description"] = str(description)

    license_val = info.get("license") or ""
    if license_val and isinstance(license_val, str):
        manifest["license"] = license_val

    requires_dist = info.get("requires_dist") or []
    if isinstance(requires_dist, list) and requires_dist:
        deps: dict[str, str] = {}
        for req in requires_dist:
            if isinstance(req, str) and req:
                dep_name = _sanitize_pypi_name(
                    req.split(">")[0].split("<")[0].split("=")[0].split("!")[0].split(";")[0].strip()
                )
                if dep_name:
                    deps[dep_name] = "*"
        if deps:
            manifest["dependencies"] = deps

    if info.get("yanked"):
        manifest["_npmUser"] = {"name": str(info.get("author", "unknown"))}

    return manifest


class FirewallScanner:
    def __init__(
        self,
        block_severities: list[str] | None = None,
        quarantine_severities: list[str] | None = None,
        scan_timeout_seconds: int = 30,
        cache_ttl_seconds: int = 3600,
        cache_max_entries: int = 10_000,
    ) -> None:
        # Default posture: hard-BLOCK only on CRITICAL metadata findings
        # (verified typosquat, dep-confusion, worm patterns). HIGH/MEDIUM
        # (install scripts, sparse maintainers) quarantine-tag instead —
        # blocking on HIGH metadata alone breaks every benign package that
        # ships an install script (WO4.0.0-022). Override via config.
        self._block_sevs = {s.upper() for s in (block_severities or ["CRITICAL"])}
        self._quarantine_sevs = {s.upper() for s in (quarantine_severities or ["HIGH", "MEDIUM"])}
        self._scan_timeout = scan_timeout_seconds
        self._cache = _CacheForPut(ttl_seconds=cache_ttl_seconds, max_entries=cache_max_entries)
        self._engine: ScanEngine | None = None

    def _get_engine(self) -> ScanEngine:
        if self._engine is None:
            from picosentry.scan.engine import create_default_engine

            self._engine = create_default_engine()
            # Unregister (not scan(rules=...)): the engine post-filters explicit
            # rule selections to REGISTERED ids, which would silently drop
            # fan-out-emitted ids like L2-PYPI-TYPO-001.
            for rule_id in _ARTIFACT_RULE_EXCLUSIONS:
                self._engine.unregister(rule_id)
        return self._engine

    def verdict_from_findings(self, findings: list) -> str:
        if not findings:
            return FirewallVerdict.ALLOW
        for f in findings:
            sev = f.severity.value.upper() if hasattr(f.severity, "value") else str(f.severity).upper()
            if sev in self._block_sevs:
                return FirewallVerdict.BLOCK
        for f in findings:
            sev = f.severity.value.upper() if hasattr(f.severity, "value") else str(f.severity).upper()
            if sev in self._quarantine_sevs:
                return FirewallVerdict.QUARANTINE
        return FirewallVerdict.ALLOW

    def scan_metadata(self, ecosystem: str, name: str, version: str, metadata: dict) -> tuple[str, list]:
        cached = self._cache.get(ecosystem, name, version)
        if cached is not None:
            return cached

        manifest = extract_version_manifest(metadata, version)
        if manifest is None:
            # Whole-catalog doc without the requested version: refuse instead of
            # scanning root fields (which would report a false ALLOW). The proxy
            # maps UNRESOLVED to 502 (WO6-017).
            # WO7-009: short TTL (30s) so a version published during the window
            # is re-resolved instead of blocked for up to an hour.
            self._cache.put(
                ecosystem, name, version, (FirewallVerdict.UNRESOLVED, []), ttl_override=_UNRESOLVED_TTL_SECONDS
            )
            return FirewallVerdict.UNRESOLVED, []
        with tempfile.TemporaryDirectory(prefix="picosentry_fw_") as tmp:
            tmp_path = Path(tmp)
            if ecosystem == "npm":
                pkg_file = tmp_path / "package.json"
                pkg_file.write_text(json.dumps(manifest, indent=2))
            elif ecosystem == "pypi":
                safe_name = _sanitize_pypi_name(name)
                if safe_name is None:
                    return FirewallVerdict.BLOCK, []
                pkg_file = tmp_path / "pyproject.toml"
                pkg_file.write_text(f"[project]\nname = '{safe_name}'\n")
                req_file = tmp_path / "requirements.txt"
                req_file.write_text(f"{safe_name}=={version}")
                meta_file = tmp_path / "pypi_metadata.json"
                meta_file.write_text(json.dumps(manifest, indent=2))
                # WO7-013: write a package.json under node_modules/<name>/ so
                # the existing npm rules (L2-MAINT, L2-FORK, L2-PROV) fire on
                # PyPI packages too — the firewall was blind to author/repo/
                # provenance because no PyPI rule read pypi_metadata.json. The
                # node_modules path makes has_execution_risk() return True so
                # the informational rules fire (they skip clean root manifests).
                npm_manifest = _pypi_to_npm_manifest(safe_name, version, manifest)
                if npm_manifest:
                    nm_dir = tmp_path / "node_modules" / safe_name
                    nm_dir.mkdir(parents=True)
                    (nm_dir / "package.json").write_text(json.dumps(npm_manifest, indent=2))
            else:
                return FirewallVerdict.ALLOW, []

            try:
                engine = self._get_engine()
                result = engine.scan(str(tmp_path))
            except Exception:
                logger.exception("Firewall scan failed for %s/%s@%s", ecosystem, name, version)
                return FirewallVerdict.BLOCK, []  # ponytail: default-deny on scan failure

            verdict = self.verdict_from_findings(result.findings)
            self._cache.put(ecosystem, name, version, (verdict, result.findings))
            return verdict, result.findings

    @property
    def cache(self) -> _VerdictCache:
        return self._cache
