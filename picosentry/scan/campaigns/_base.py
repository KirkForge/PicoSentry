from __future__ import annotations

import json
import logging
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from ..models import Confidence, Finding, Severity
from ..rules.utils import iter_node_modules

__all__ = [
    "CampaignPackage",
    "IndicatorSet",
    "iter_campaigns",
    "list_campaigns",
]

logger = logging.getLogger("picosentry.campaigns")


@dataclass(frozen=True)
class IndicatorSet:
    named_signatures: tuple[str, ...] = ()
    c2_domains: tuple[str, ...] = ()
    phishing_domains: tuple[str, ...] = ()
    payload_filenames: tuple[str, ...] = ()
    bundle_hashes_sha256: dict[str, str] = field(default_factory=dict)

    @property
    def has_named_signatures(self) -> bool:
        return bool(self.named_signatures)

    @property
    def has_payload_filenames(self) -> bool:
        return bool(self.payload_filenames)

    @property
    def has_c2_domains(self) -> bool:
        return bool(self.c2_domains)


_CONTENT_EXTENSIONS = frozenset(
    {
        ".js",
        ".mjs",
        ".cjs",
        ".ts",
        ".tsx",
        ".jsx",
        ".json",
        ".yaml",
        ".yml",
        ".toml",
        ".py",
        ".sh",
        ".bash",
        ".rb",
        ".go",
        ".rs",
        ".md",
        ".txt",
        ".env",
        ".cfg",
        ".ini",
    }
)
_SKIP_DIRS = frozenset(
    {
        ".git",
        "__pycache__",
        ".cache",
        ".hg",
        ".svn",
        "node_modules/.cache",
        "dist",
        "build",
        "out",
    }
)
_MAX_FILE_BYTES = 512_000  # 512 KB — same budget as network_exfil rule


class CampaignPackage:
    campaign_id: str = ""
    rule_id: str = ""
    iocs_path: Path = Path()

    ecosystems: tuple[str, ...] = ()

    def __init_subclass__(cls, **kwargs: object) -> None:

        super().__init_subclass__(**kwargs)

    def __init__(self) -> None:
        if not self.campaign_id:
            raise ValueError(f"{type(self).__name__} must define campaign_id")
        if not self.rule_id or not self.rule_id.startswith("L2-CAMP-"):
            raise ValueError(
                f"{type(self).__name__}.rule_id must start with L2-CAMP- "
                f"(see scan/rules/__init__.py taxonomy); got {self.rule_id!r}"
            )
        if not self.iocs_path or not Path(self.iocs_path).is_file():
            raise FileNotFoundError(f"{type(self).__name__}: iocs.json not found at {self.iocs_path!r}")
        self._data: dict = self._load_iocs(self.iocs_path)
        self._indicators = self._compile_indicators(self._data.get("indicators", {}))

    @staticmethod
    def _load_iocs(path: Path) -> dict:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for required in ("campaign_id", "schema_version", "severity", "description", "ecosystem", "rule_id"):
            if required not in data:
                raise ValueError(f"iocs.json {path}: missing required field {required!r}")
        if data["rule_id"] != data.get("rule_id"):
            pass
        return data

    @staticmethod
    def _compile_indicators(raw: dict) -> IndicatorSet:
        return IndicatorSet(
            named_signatures=tuple(raw.get("named_signatures", ())),
            c2_domains=tuple(raw.get("c2_domains", ())),
            phishing_domains=tuple(raw.get("phishing_domains", ())),
            payload_filenames=tuple(raw.get("payload_filenames", ())),
            bundle_hashes_sha256=dict(raw.get("bundle_hashes_sha256", {})),
        )

    def iocs(self) -> dict:
        return self._data

    def indicators(self) -> IndicatorSet:
        return self._indicators

    def severity(self) -> Severity:
        return _parse_severity(self._data.get("severity", "HIGH"))

    def description(self) -> str:
        return self._data.get("description", "")

    def references(self) -> list[str]:
        return list(self._data.get("references", []))

    def expected_rule_ids(self) -> list[str]:
        return list(self._data.get("expected_rule_ids", []))

    def compromised_packages(self) -> list[dict]:
        return list(self._data.get("indicators", {}).get("compromised_packages", []))

    def detect_named_signatures(self, target: Path, *, confidence: Confidence = Confidence.HIGH) -> list[Finding]:
        if not self._indicators.has_named_signatures:
            return []

        findings: list[Finding] = []
        signatures: tuple[str, ...] = self._indicators.named_signatures
        sev = Severity.CRITICAL
        target_prefix = str(target.resolve()) + "/"

        for file_path in _iter_scannable_files(target):
            if file_path.is_symlink():
                continue
            try:
                if file_path.stat().st_size > _MAX_FILE_BYTES:
                    continue
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for sig in signatures:
                if sig in content:
                    file_display = str(file_path)
                    file_display = file_display.removeprefix(target_prefix)
                    findings.append(
                        Finding(
                            rule_id=self.rule_id,
                            severity=sev,
                            confidence=confidence,
                            package=self.campaign_id,
                            file=file_display,
                            message=(f"Named-signature match for {self.campaign_id}: literal {sig!r} found in source"),
                            evidence=(
                                f"named_signature={sig!r}, "
                                f"campaign={self.campaign_id}, "
                                f"scan_strategy=literal_string_substring"
                            ),
                            remediation=(
                                f"This file matches a literal indicator for the "
                                f"{self.campaign_id} supply-chain attack. "
                                f"Quarantine the package, audit its dependencies, "
                                f"and check the IoC references for full scope."
                            ),
                            references=self.references(),
                            ecosystem="npm",
                        )
                    )

                    break
        return findings

    def detect_payload_filenames(self, target: Path) -> list[Finding]:
        if not self._indicators.has_payload_filenames:
            return []
        names = set(self._indicators.payload_filenames)
        findings: list[Finding] = []
        target_prefix = str(target.resolve()) + "/"
        for file_path in target.rglob("*"):
            if not file_path.is_file() or file_path.is_symlink():
                continue
            if any(part in _SKIP_DIRS for part in file_path.parts):
                continue
            if file_path.name in names:
                file_display = str(file_path)
                file_display = file_display.removeprefix(target_prefix)
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=self.severity(),
                        confidence=Confidence.MEDIUM,
                        package=self.campaign_id,
                        file=file_display,
                        message=(f"Payload filename {file_path.name!r} matches known indicator for {self.campaign_id}"),
                        evidence=(f"payload_filename={file_path.name!r}, campaign={self.campaign_id}"),
                        remediation=(
                            f"Verify whether this file is part of the "
                            f"{self.campaign_id} attack chain or a legitimate "
                            f"file that happens to share the name."
                        ),
                        references=self.references(),
                        ecosystem="npm",
                    )
                )
        return findings

    def detect_packages(self, target: Path) -> list[Finding]:
        from ..rules.ioc_detection import _semver_matches  # local import — circular otherwise

        compromised = self.compromised_packages()
        if not compromised:
            return []

        findings: list[Finding] = []
        for pkg_json, pkg in iter_node_modules(target):
            pkg_name = pkg.get("name", pkg_json.parent.name)
            pkg_version = pkg.get("version", "unknown")
            for ioc in compromised:
                if ioc.get("package_name") != pkg_name:
                    continue
                constraint = str(ioc.get("version_range", "*"))
                if constraint != "*" and not _semver_matches(pkg_version, constraint):
                    continue
                try:
                    sev = _parse_severity(ioc.get("severity", self._data.get("severity", "HIGH")))
                except ValueError:
                    sev = self.severity()
                findings.append(
                    Finding(
                        rule_id=self.rule_id,
                        severity=sev,
                        confidence=Confidence.EXACT,
                        package=f"{pkg_name}@{pkg_version}",
                        file=str(pkg_json),
                        message=(
                            f"Package {pkg_name}@{pkg_version} matches a known "
                            f"compromised version from the {self.campaign_id} campaign"
                        ),
                        evidence=(
                            f"campaign={self.campaign_id}, package={pkg_name}, "
                            f"installed_version={pkg_version}, "
                            f"compromised_version_range={constraint}"
                        ),
                        remediation=(
                            f"This package is on the {self.campaign_id} compromise "
                            f"list. Upgrade to a clean version, remove the dependency, "
                            f"or replace with an alternative."
                        ),
                        references=self.references(),
                        ecosystem=(
                            pkg_json.parent.parent.name if pkg_json.parent.parent.name == "node_modules" else "npm"
                        ),
                    )
                )
        return findings

    def detect(self, target: Path) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self.detect_named_signatures(target))
        findings.extend(self.detect_payload_filenames(target))
        findings.extend(self.detect_packages(target))
        return findings

    def register(self, engine: object) -> None:

        engine.register(self.rule_id, self.detect)  # type: ignore[attr-defined]
        logger.debug("Registered campaign %s as rule %s", self.campaign_id, self.rule_id)


def _parse_severity(s: str) -> Severity:
    return Severity(s.upper())


def _iter_scannable_files(target: Path) -> Iterable[Path]:
    if target.is_file():
        yield target
        return
    if not target.is_dir():
        return
    for file in target.rglob("*"):
        if not file.is_file() or file.is_symlink():
            continue
        if any(part in _SKIP_DIRS for part in file.parts):
            continue
        if file.suffix in _CONTENT_EXTENSIONS or file.name in {
            "package.json",
            "package-lock.json",
            "pnpm-lock.yaml",
            "yarn.lock",
            ".npmrc",
            "pnpm-workspace.yaml",
            "requirements.txt",
            "pyproject.toml",
            "setup.py",
            "Pipfile",
            "go.mod",
            "go.sum",
            "Cargo.toml",
            "Cargo.lock",
            "pom.xml",
            "build.gradle",
            "Gemfile",
            "Gemfile.lock",
            "Makefile",
        }:
            yield file


def list_campaigns() -> list[Path]:
    campaigns_root = Path(__file__).parent
    found: list[Path] = []
    for entry in sorted(campaigns_root.iterdir()):
        if not entry.is_dir() or entry.name.startswith(("_", ".")):
            continue
        if (entry / "iocs.json").is_file() and (entry / "detector.py").is_file():
            found.append(entry)
    return found


def iter_campaigns() -> Iterable[CampaignPackage]:
    import importlib

    subclasses: list[type[CampaignPackage]] = list(CampaignPackage.__subclasses__())
    for camp_path in list_campaigns():
        module_name = f"picosentry.scan.campaigns.{camp_path.name}"
        try:
            importlib.import_module(module_name)
        except Exception as exc:
            logger.warning("Failed to import campaign %s: %s", camp_path.name, exc)
            continue

        for sub in CampaignPackage.__subclasses__():
            if sub not in subclasses:
                subclasses.append(sub)

    for sub in subclasses:
        try:
            yield sub()
        except Exception as exc:
            logger.warning("Failed to instantiate campaign %s: %s", sub.__name__, exc)
