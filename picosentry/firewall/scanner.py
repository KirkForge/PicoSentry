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
    ) -> None:
        self._block_sevs = {s.upper() for s in (block_severities or ["CRITICAL", "HIGH"])}
        self._quarantine_sevs = {s.upper() for s in (quarantine_severities or ["MEDIUM"])}
        self._scan_timeout = scan_timeout_seconds
        self._cache = _CacheForPut(ttl_seconds=cache_ttl_seconds)
        self._engine: ScanEngine | None = None

    def _get_engine(self) -> ScanEngine:
        if self._engine is None:
            from picosentry.scan.engine import create_default_engine

            self._engine = create_default_engine()
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

        with tempfile.TemporaryDirectory(prefix="picosentry_fw_") as tmp:
            tmp_path = Path(tmp)
            if ecosystem == "npm":
                pkg_file = tmp_path / "package.json"
                pkg_file.write_text(json.dumps(metadata, indent=2))
            elif ecosystem == "pypi":
                pkg_file = tmp_path / "pyproject.toml"
                pkg_file.write_text(f"[project]\nname = '{name}'\n")
                req_file = tmp_path / "requirements.txt"
                req_file.write_text(f"{name}=={version}")
                meta_file = tmp_path / "pypi_metadata.json"
                meta_file.write_text(json.dumps(metadata, indent=2))
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
