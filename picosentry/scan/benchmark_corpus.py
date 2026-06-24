"""Real-world malware dataset loaders for benchmark corpus expansion.

Public datasets wired here:
- DataDog malicious-software-packages-dataset (manifest.json + directory tree)
- OSV malicious-package entries (MAL-* IDs via GCS bulk dump or API)
- Backstabber's Knife Collection (user-provided JSON; authors require email request)

The module exposes normalized ``Advisory``-like records that can be written in
OSV format and loaded by ``picosentry.scan.advisory.AdvisoryDB``.
"""

from __future__ import annotations

import json
import logging
import urllib.request
import zipfile
from dataclasses import dataclass
from io import BytesIO
from pathlib import Path
from typing import Any

logger = logging.getLogger("picosentry.benchmark_corpus")


# Dataset ecosystem names -> PicoSentry advisory ecosystem names.
_ECOSYSTEM_MAP = {
    "npm": "npm",
    "pypi": "pypi",
    "go": "go",
    "golang": "go",
    "cargo": "cargo",
    "crates.io": "cargo",
    "rust": "cargo",
    "maven": "maven",
    "rubygems": "rubygems",
    "nuget": "nuget",
    "pip": "pypi",
    "python": "pypi",
}

# PicoSentry ecosystem -> OSV GCS dump bucket name.
_OSV_DUMP_NAME = {
    "npm": "npm",
    "pypi": "PyPI",
    "go": "Go",
    "cargo": "crates.io",
    "maven": "Maven",
    "rubygems": "RubyGems",
    "nuget": "NuGet",
}


@dataclass(frozen=True)
class MalwareRecord:
    """Normalized malware record from any public dataset."""

    source: str  # "datadog", "osv", "backstabber"
    source_id: str
    ecosystem: str
    package_name: str
    versions: tuple[str, ...]
    summary: str
    published: str = ""
    references: tuple[str, ...] = ()
    categories: tuple[str, ...] = ()  # e.g. "typosquat", "compromised"

    def to_osv(self) -> dict[str, Any]:
        """Convert to an OSV record that ``Advisory.from_osv`` understands."""
        affected: dict[str, Any] = {
            "package": {"name": self.package_name, "ecosystem": self.ecosystem},
            "ranges": [
                {
                    "type": "SEMVER",
                    "events": [{"introduced": "0.0.0"}],
                }
            ],
        }
        if self.versions:
            affected["versions"] = list(self.versions)
        return {
            "id": f"MAL-{self.source.upper()}-{self.source_id}",
            "summary": self.summary,
            "published": self.published,
            "affected": [affected],
            "references": [{"url": url} for url in self.references],
            "database_specific": {
                "severity": "CRITICAL",
                "categories": list(self.categories),
                "source_dataset": self.source,
            },
        }


def _safe_get(url: str, timeout: int = 60) -> bytes:
    """Fetch URL with a user-agent, return body bytes."""
    req = urllib.request.Request(
        url,
        headers={"User-Agent": "picosentry-benchmark-corpus-sync"},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _github_api_get(path: str) -> Any:
    """GET a GitHub API path and decode JSON."""
    url = f"https://api.github.com/{path}"
    body = _safe_get(url, timeout=60)
    return json.loads(body.decode("utf-8"))


def _github_file(owner: str, repo: str, path: str, ref: str = "main") -> bytes:
    """Fetch raw file contents from GitHub."""
    url = f"https://raw.githubusercontent.com/{owner}/{repo}/{ref}/{path}"
    return _safe_get(url, timeout=60)


def _normalize_ecosystem(raw: str) -> str:
    return _ECOSYSTEM_MAP.get(raw.lower(), raw.lower())


def _parse_datadog_manifest(data: dict[str, Any], ecosystem: str) -> list[MalwareRecord]:
    """Parse a Datadog manifest.json mapping package names to versions/null."""
    records: list[MalwareRecord] = []
    for pkg_name, versions in data.items():
        if not isinstance(pkg_name, str) or not pkg_name:
            continue
        version_list: tuple[str, ...] = ()
        if isinstance(versions, list):
            version_list = tuple(str(v) for v in versions if v)
        records.append(
            MalwareRecord(
                source="datadog",
                source_id=pkg_name.replace("/", "_"),
                ecosystem=ecosystem,
                package_name=pkg_name,
                versions=version_list,
                summary="Malicious package reported by DataDog malicious-software-packages-dataset",
                categories=("malicious_intent",),
                references=("https://github.com/DataDog/malicious-software-packages-dataset",),
            )
        )
    return records


def _parse_datadog_tree_paths(paths: list[str], ecosystem: str) -> list[MalwareRecord]:
    """Parse Datadog sample paths of form samples/{eco}/{category}/{pkg}/{version}/file.zip.

    Scoped npm packages are encoded as ``@scope/name`` directories, so the package
    name is reconstructed by joining all path segments between the category and
    the version.
    """
    records: dict[str, MalwareRecord] = {}
    prefix = f"samples/{ecosystem}/"
    for path in paths:
        if not path.startswith(prefix):
            continue
        parts = path[len(prefix) :].split("/")
        # Need at least: category, package, version, filename
        if len(parts) < 4:
            continue
        category = parts[0]
        version = parts[-2]
        pkg_name = "/".join(parts[1:-2])
        # DataDog encodes scoped npm packages as ``@scope@name`` in directory
        # names (``/`` is not used). Convert the first ``@`` after the leading
        # ``@`` into ``/`` so the name matches npm's canonical form.
        if ecosystem == "npm" and pkg_name.startswith("@") and "@" in pkg_name[1:]:
            idx = pkg_name.index("@", 1)
            pkg_name = pkg_name[:idx] + "/" + pkg_name[idx + 1 :]
        if not pkg_name or not version:
            continue
        key = (ecosystem, pkg_name)
        existing = records.get(key)
        versions = existing.versions if existing else ()
        if version not in versions:
            versions = (*versions, version)
        records[key] = MalwareRecord(
            source="datadog",
            source_id=pkg_name.replace("/", "_"),
            ecosystem=ecosystem,
            package_name=pkg_name,
            versions=versions,
            summary=f"Malicious package reported by DataDog ({category})",
            categories=(category,),
            references=("https://github.com/DataDog/malicious-software-packages-dataset",),
        )
    return list(records.values())


def load_datadog_malware(ecosystems: tuple[str, ...] = ("npm", "pypi")) -> list[MalwareRecord]:
    """Load malicious package records from DataDog dataset.

    Tries manifest.json first; falls back to parsing the published Git tree for
    ecosystems that store samples as zip archives without a top-level manifest.
    """
    records: list[MalwareRecord] = []
    owner, repo = "DataDog", "malicious-software-packages-dataset"
    tree = _github_api_get(f"repos/{owner}/{repo}/git/trees/main?recursive=true")
    all_paths = [t["path"] for t in tree.get("tree", []) if t.get("type") == "blob"]

    for eco in ecosystems:
        manifest_path = f"samples/{eco}/manifest.json"
        if any(p == manifest_path for p in all_paths):
            raw = _github_file(owner, repo, manifest_path)
            data = json.loads(raw.decode("utf-8"))
            records.extend(_parse_datadog_manifest(data, _normalize_ecosystem(eco)))
        else:
            records.extend(_parse_datadog_tree_paths(all_paths, eco))

    logger.info("Loaded %d DataDog malware records for %s", len(records), ecosystems)
    return records


def load_backstabber_malware(path: Path | str) -> list[MalwareRecord]:
    """Load Backstabber's Knife Collection from a user-provided local file.

    The authors require an email request for access; this loader does not
    auto-fetch. Supported formats: JSON list or CSV with columns
    [ecosystem, package_name, versions, category, date].
    """
    p = Path(path)
    if not p.is_file():
        logger.warning("Backstabber dataset not found at %s; skipping", p)
        return []

    text = p.read_text(encoding="utf-8")
    records: list[MalwareRecord] = []
    if p.suffix.lower() == ".csv":
        import csv

        for row in csv.reader(text.splitlines()):
            if not row or row[0].lower() in ("ecosystem", ""):
                continue
            ecosystem = _normalize_ecosystem(row[0])
            pkg_name = row[1]
            versions = tuple(v.strip() for v in row[2].split(",") if v.strip()) if len(row) > 2 else ()
            category = row[3] if len(row) > 3 else "malicious_intent"
            published = row[4] if len(row) > 4 else ""
            records.append(
                MalwareRecord(
                    source="backstabber",
                    source_id=pkg_name.replace("/", "_"),
                    ecosystem=ecosystem,
                    package_name=pkg_name,
                    versions=versions,
                    summary="Malicious package from Backstabber's Knife Collection",
                    published=published,
                    categories=(category,),
                    references=("https://arxiv.org/abs/2005.09535",),
                )
            )
    else:
        data = json.loads(text)
        if isinstance(data, dict):
            data = data.get("packages", data.get("data", []))
        for entry in data:
            ecosystem = _normalize_ecosystem(entry.get("ecosystem", "npm"))
            pkg_name = entry.get("package", entry.get("package_name", ""))
            versions = entry.get("versions", entry.get("version", ()))
            if isinstance(versions, str):
                versions = (versions,) if versions else ()
            records.append(
                MalwareRecord(
                    source="backstabber",
                    source_id=pkg_name.replace("/", "_"),
                    ecosystem=ecosystem,
                    package_name=pkg_name,
                    versions=tuple(str(v) for v in versions if v),
                    summary="Malicious package from Backstabber's Knife Collection",
                    published=entry.get("published", ""),
                    categories=(entry.get("category", "malicious_intent"),),
                    references=("https://arxiv.org/abs/2005.09535",),
                )
            )

    logger.info("Loaded %d Backstabber malware records from %s", len(records), p)
    return records


def load_osv_malicious(
    ecosystems: tuple[str, ...] = ("npm", "pypi", "go", "cargo", "maven", "rubygems", "nuget"),
    ids_only: tuple[str, ...] = (),
    limit_per_ecosystem: int = 5_000,
) -> list[MalwareRecord]:
    """Load OSV malicious-package entries (MAL-* IDs) for requested ecosystems.

    Downloads the public OSV bulk dump per ecosystem and filters for records whose
    id starts with ``MAL-``. If *ids_only* is provided, only those IDs are kept.
    When *limit_per_ecosystem* is set, the most recently published records are kept.
    """
    records: list[MalwareRecord] = []
    for eco in ecosystems:
        dump_name = _OSV_DUMP_NAME.get(eco, eco)
        url = f"https://osv-vulnerabilities.storage.googleapis.com/{dump_name}/all.zip"
        try:
            body = _safe_get(url, timeout=180)
        except Exception as exc:
            logger.warning("Failed to download OSV dump for %s (bucket=%s): %s", eco, dump_name, exc)
            continue

        eco_records: list[MalwareRecord] = []
        try:
            with zipfile.ZipFile(BytesIO(body)) as zf:
                for name in zf.namelist():
                    if not name.endswith(".json"):
                        continue
                    data = json.loads(zf.read(name).decode("utf-8"))
                    vuln_id = data.get("id", "")
                    if not vuln_id.startswith("MAL-"):
                        continue
                    if ids_only and vuln_id not in ids_only:
                        continue

                    pkg_name = ""
                    for affected in data.get("affected", []):
                        pkg = affected.get("package", {})
                        if _normalize_ecosystem(pkg.get("ecosystem", "")) == eco:
                            pkg_name = pkg.get("name", "")
                            break
                    if not pkg_name:
                        continue

                    versions: list[str] = []
                    for affected in data.get("affected", []):
                        versions.extend(affected.get("versions", []))

                    eco_records.append(
                        MalwareRecord(
                            source="osv",
                            source_id=vuln_id,
                            ecosystem=eco,
                            package_name=pkg_name,
                            versions=tuple(sorted(set(versions))),
                            summary=data.get("summary")
                            or data.get("details", "")[:200]
                            or "Malicious package reported by OSV",
                            published=data.get("published", ""),
                            categories=("malicious",),
                            references=tuple(ref.get("url", "") for ref in data.get("references", []))
                            or ("https://osv.dev/",),
                        )
                    )
        except Exception as exc:
            logger.warning("Failed to parse OSV dump for %s: %s", eco, exc)
            continue

        # Keep the most recent records to bound repo size while staying fresh.
        eco_records.sort(key=lambda r: r.published or "", reverse=True)
        if limit_per_ecosystem > 0:
            eco_records = eco_records[:limit_per_ecosystem]
        records.extend(eco_records)
        logger.info("Loaded %d OSV malicious records for %s", len(eco_records), eco)

    logger.info("Loaded %d OSV malicious records total for %s", len(records), ecosystems)
    return records


def build_malware_advisory_db(
    output_dir: Path,
    datadog_ecosystems: tuple[str, ...] = ("npm", "pypi"),
    osv_ecosystems: tuple[str, ...] = ("npm", "pypi", "go", "cargo", "maven", "rubygems", "nuget"),
    osv_limit_per_ecosystem: int = 5_000,
    backstabber_path: Path | str | None = None,
) -> int:
    """Sync public malware datasets into OSV-format advisory JSON files.

    Returns the number of advisory records written. Files are written as a flat
    list of OSV records per ecosystem under *output_dir* so that
    ``AdvisoryDB.load`` can consume them directly, plus a ``.meta.json`` file
    with provenance metadata.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    records: list[MalwareRecord] = []
    records.extend(load_datadog_malware(datadog_ecosystems))
    records.extend(load_osv_malicious(osv_ecosystems, limit_per_ecosystem=osv_limit_per_ecosystem))
    if backstabber_path:
        records.extend(load_backstabber_malware(backstabber_path))

    grouped: dict[str, list[dict[str, Any]]] = {}
    for rec in records:
        grouped.setdefault(rec.ecosystem, []).append(rec.to_osv())

    count = 0
    for eco, advisories in sorted(grouped.items()):
        out_file = output_dir / f"{eco}-malware.json"
        out_file.write_text(
            json.dumps(advisories, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        meta_file = output_dir / f"{eco}-malware.meta.json"
        meta_file.write_text(
            json.dumps(
                {
                    "source": "PicoSentry real-world malware benchmark corpus",
                    "datasets": ["datadog", "osv", "backstabber"],
                    "generated_at": "",
                    "advisory_count": len(advisories),
                    "description": "Known malicious package names from public datasets, converted to OSV format.",
                },
                indent=2,
                sort_keys=True,
            )
            + "\n",
            encoding="utf-8",
        )
        count += len(advisories)
        logger.info("Wrote %d malware advisories to %s", len(advisories), out_file)

    return count
