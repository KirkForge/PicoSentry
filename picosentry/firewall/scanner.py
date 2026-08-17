from __future__ import annotations

import json
import logging
import re
import tempfile
from pathlib import Path
from typing import TYPE_CHECKING

from picosentry.firewall.cache import VerdictCache as _VerdictCache
from picosentry.firewall.cache import VerdictCache as _CacheForPut

if TYPE_CHECKING:
    from picosentry.scan.engine import ScanEngine

logger = logging.getLogger("picosentry.firewall.scanner")

_NPM_PACKAGE_RE = re.compile(r"^/(@[^/]+/[^/]+|[^/]+)(?:/([^/]+))?$")
_PYPI_PACKAGE_RE = re.compile(r"^/pypi/([^/]+)(?:/([^/]+))?/json$")
_STATIC_EXT_RE = re.compile(r"\.(ico|png|jpg|jpeg|gif|svg|css|js|woff|woff2|ttf|eot|map)$", re.IGNORECASE)

# Rules that require local artifacts (lockfiles, pnpm workspace files) which
# registry metadata documents never contain — they structurally false-positive
# on every manifest with dependencies (e.g. "no lockfile" HIGH on any package
# with deps). The firewall is a *metadata* firewall; artifact scanning is
# picosentry scan's job on the downloaded tarball.
_ARTIFACT_RULE_EXCLUSIONS = frozenset({"L2-LOCK-001", "L2-PNPM-001"})


def extract_version_manifest(metadata: dict, version: str) -> dict:
    """Return the requested version's manifest slice from a registry document.

    npm ``GET /pkg`` returns the whole-catalog doc with every version nested
    under ``versions``; the scan engine's rules only read root-level manifest
    fields, so scanning the raw doc would be blind to all version content.
    PyPI nests the requested version's metadata under ``info``. Single-manifest
    docs (npm ``GET /pkg/1.2.3``) pass through unchanged.
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
        return {k: v for k, v in metadata.items() if k != "versions"}
    info = metadata.get("info")
    if isinstance(info, dict):
        return info
    return metadata


class FirewallVerdict:
    ALLOW = "allow"
    QUARANTINE = "quarantine"
    BLOCK = "block"


def classify_path(path: str) -> tuple[str, str, str] | None:
    if _STATIC_EXT_RE.search(path):
        return None
    m = _PYPI_PACKAGE_RE.match(path)
    if m:
        name = m.group(1)
        version = m.group(2) or "latest"
        return ("pypi", name, version)
    m = _NPM_PACKAGE_RE.match(path)
    if m:
        name = m.group(1).replace("%2F", "/")
        version = m.group(2) or "latest"
        return ("npm", name, version)
    return None


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
        with tempfile.TemporaryDirectory(prefix="picosentry_fw_") as tmp:
            tmp_path = Path(tmp)
            if ecosystem == "npm":
                pkg_file = tmp_path / "package.json"
                pkg_file.write_text(json.dumps(manifest, indent=2))
            elif ecosystem == "pypi":
                pkg_file = tmp_path / "pyproject.toml"
                pkg_file.write_text(f"[project]\nname = '{name}'\n")
                req_file = tmp_path / "requirements.txt"
                req_file.write_text(f"{name}=={version}")
                meta_file = tmp_path / "pypi_metadata.json"
                meta_file.write_text(json.dumps(manifest, indent=2))
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
