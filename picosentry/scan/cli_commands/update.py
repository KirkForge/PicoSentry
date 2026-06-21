from __future__ import annotations

import argparse
import contextlib
import datetime
import hashlib
import json
import sys
import urllib.request
from pathlib import Path
from typing import Any

from picosentry.scan._network import InsecureURLError, ResponseTooLargeError, safe_urlopen
from picosentry.scan.engine import user_corpus_dir
from picosentry.scan.rules.corpus_index import save_indexed_corpus
from picosentry.scan.rules.typosquat_utils import (
    BUILTIN_CARGO_TOP_100,
    BUILTIN_GO_TOP_100,
    BUILTIN_MAVEN_TOP_100,
    BUILTIN_NUGET_TOP_100,
    BUILTIN_PYPI_TOP_100,
    BUILTIN_RUBYGEMS_TOP_100,
    BUILTIN_TOP_100,
)

NAME = "update"

_SUPPORTED_ECOSYSTEMS = [
    "npm",
    "pypi",
    "go",
    "cargo",
    "maven",
    "rubygems",
    "nuget",
]

_BUILTIN_FALLBACK: dict[str, list[str]] = {
    "npm": BUILTIN_TOP_100,
    "pypi": BUILTIN_PYPI_TOP_100,
    "go": BUILTIN_GO_TOP_100,
    "cargo": BUILTIN_CARGO_TOP_100,
    "maven": BUILTIN_MAVEN_TOP_100,
    "rubygems": BUILTIN_RUBYGEMS_TOP_100,
    "nuget": BUILTIN_NUGET_TOP_100,
}


def add_arguments(subparsers: argparse._SubParsersAction) -> None:
    parser = subparsers.add_parser(
        NAME,
        help="Download or refresh the typosquat/dep-confusion package corpus (requires network for some ecosystems)",
    )
    parser.add_argument(
        "--ecosystem",
        "-e",
        choices=[*_SUPPORTED_ECOSYSTEMS, "all"],
        default="npm",
        help="Ecosystem corpus to update (default: npm; 'all' fetches every supported ecosystem)",
    )
    parser.add_argument(
        "--top",
        "-n",
        type=int,
        default=1000,
        help="Number of top packages to download (default: 1000)",
    )
    parser.add_argument(
        "--output",
        "-o",
        type=str,
        default=None,
        help=(
            "Output path. For a single ecosystem this is the JSON file to write "
            "(default: <user-corpus-dir>/<ecosystem>_top_packages.json). "
            "For 'all' this is the output directory (default: user corpus directory)."
        ),
    )
    parser.add_argument(
        "--source-url",
        type=str,
        default=None,
        help="Override the default corpus source URL for ecosystems without a built-in fetcher.",
    )
    parser.add_argument(
        "--no-merge",
        dest="merge",
        action="store_false",
        default=True,
        help="Replace the existing corpus instead of merging new names into it.",
    )


def _load_existing(path: Path) -> set[str]:
    if path.is_file():
        with contextlib.suppress(json.JSONDecodeError, OSError):
            data = json.loads(path.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return set(data)
    return set()


def _write_manifest(output_dir: Path, entries: dict[str, dict[str, Any]]) -> None:
    manifest_path = output_dir / "corpus.json"
    manifest: dict[str, Any] = {
        "version": 1,
        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "ecosystems": entries,
    }
    manifest_path.write_text(json.dumps(manifest, indent=4, ensure_ascii=False), encoding="utf-8")


def _fetch_npm(top_n: int) -> tuple[list[str], str, bool]:
    """Fetch top npm packages from the npm-rank community dataset.

    npm does not expose a public "top by downloads" API, so we use the
    community-maintained npm-rank release which ranks packages by popularity.
    """
    url = "https://github.com/LeoDog896/npm-rank/releases/download/latest/raw.json"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        resp, body = safe_urlopen(req, timeout=60)
    except (InsecureURLError, ResponseTooLargeError) as e:
        raise RuntimeError(f"npm-rank fetch failed: {e}") from e

    try:
        data = json.loads(body.decode("utf-8"))
    finally:
        resp.close()

    if not isinstance(data, list):
        raise RuntimeError("unexpected npm-rank response format")

    names: list[str] = []
    for pkg in data:
        if isinstance(pkg, dict) and isinstance(pkg.get("name"), str):
            name = pkg["name"]
            if not name.startswith("@"):
                names.append(name)
            if len(names) >= top_n:
                break

    return names[:top_n], url, False


def _fetch_pypi(top_n: int) -> tuple[list[str], str, bool]:
    """Fetch top PyPI packages from the public hugovk leaderboard."""
    url = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.json"
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        resp, body = safe_urlopen(req, timeout=30)
    except (InsecureURLError, ResponseTooLargeError) as e:
        raise RuntimeError(f"PyPI corpus fetch failed: {e}") from e

    try:
        data = json.loads(body.decode("utf-8"))
    finally:
        resp.close()

    rows = data.get("rows", []) if isinstance(data, dict) else []
    names: list[str] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        project = row.get("project")
        if isinstance(project, str) and project:
            names.append(project)
        if len(names) >= top_n:
            break

    return names[:top_n], url, False


def _fetch_cargo(top_n: int) -> tuple[list[str], str, bool]:
    """Fetch top Rust crates from crates.io sorted by all-time downloads."""
    source_url = "https://crates.io/api/v1/crates"
    names: list[str] = []
    per_page = 100
    page = 1
    while len(names) < top_n:
        url = f"{source_url}?page={page}&per_page={per_page}&sort=downloads"
        req = urllib.request.Request(
            url, headers={"Accept": "application/json", "User-Agent": "picosentry-corpus-fetcher"}
        )
        try:
            resp, body = safe_urlopen(req, timeout=60)
        except (InsecureURLError, ResponseTooLargeError) as e:
            raise RuntimeError(f"crates.io fetch failed: {e}") from e

        try:
            data = json.loads(body.decode("utf-8"))
        finally:
            resp.close()

        crates = data.get("crates", []) if isinstance(data, dict) else []
        if not crates:
            break
        for c in crates:
            if isinstance(c, dict) and isinstance(c.get("id"), str):
                names.append(c["id"])
        if len(crates) < per_page:
            break
        page += 1
        if page > 50:
            break

    return names[:top_n], source_url, False


def _fetch_go(top_n: int) -> tuple[list[str], str, bool]:
    """Fetch popular Go modules from the mvdan/corpus top-1000 TSV."""
    url = "https://raw.githubusercontent.com/mvdan/corpus/master/top-1000.tsv"
    req = urllib.request.Request(url, headers={"User-Agent": "picosentry-corpus-fetcher"})
    try:
        _resp, body = safe_urlopen(req, timeout=60)
    except (InsecureURLError, ResponseTooLargeError) as e:
        raise RuntimeError(f"mvdan/corpus fetch failed: {e}") from e

    try:
        import csv

        rows = list(csv.reader(body.decode("utf-8").splitlines(), delimiter="\t"))
    finally:
        _resp.close()

    if not rows:
        return [], url, False
    # First row is a header.
    names = [r[0] for r in rows[1:] if r]
    return names[:top_n], url, False


def _fetch_maven(top_n: int) -> tuple[list[str], str, bool]:
    """Fetch important Maven packages from Ecosyste.ms ranked by dependents."""
    source_url = "https://packages.ecosyste.ms/api/v1/registries/repo1.maven.org/packages"
    names: list[str] = []
    page = 1
    while len(names) < top_n:
        url = f"{source_url}?order=desc&sort=dependent_repos_count&per_page=100&page={page}"
        req = urllib.request.Request(
            url, headers={"Accept": "application/json", "User-Agent": "picosentry-corpus-fetcher"}
        )
        try:
            resp, body = safe_urlopen(req, timeout=60)
        except (InsecureURLError, ResponseTooLargeError) as e:
            raise RuntimeError(f"Ecosyste.ms Maven fetch failed: {e}") from e

        try:
            data = json.loads(body.decode("utf-8"))
        finally:
            resp.close()

        if not isinstance(data, list):
            break
        page_names = [p.get("name") for p in data if isinstance(p, dict)]
        page_names = [n for n in page_names if isinstance(n, str)]
        if not page_names:
            break
        names.extend(page_names)
        if len(page_names) < 100:
            break
        page += 1
        if page > 20:
            break

    return names[:top_n], source_url, False


def _fetch_rubygems(top_n: int) -> tuple[list[str], str, bool]:
    """Fetch important RubyGems from Ecosyste.ms ranked by dependents."""
    source_url = "https://packages.ecosyste.ms/api/v1/registries/rubygems.org/packages"
    names: list[str] = []
    page = 1
    while len(names) < top_n:
        url = f"{source_url}?order=desc&sort=dependent_repos_count&per_page=100&page={page}"
        req = urllib.request.Request(
            url, headers={"Accept": "application/json", "User-Agent": "picosentry-corpus-fetcher"}
        )
        try:
            resp, body = safe_urlopen(req, timeout=60)
        except (InsecureURLError, ResponseTooLargeError) as e:
            raise RuntimeError(f"Ecosyste.ms RubyGems fetch failed: {e}") from e

        try:
            data = json.loads(body.decode("utf-8"))
        finally:
            resp.close()

        if not isinstance(data, list):
            break
        page_names = [p.get("name") for p in data if isinstance(p, dict)]
        page_names = [n for n in page_names if isinstance(n, str)]
        if not page_names:
            break
        names.extend(page_names)
        if len(page_names) < 100:
            break
        page += 1
        if page > 20:
            break

    return names[:top_n], source_url, False


def _fetch_nuget(top_n: int) -> tuple[list[str], str, bool]:
    """Fetch top NuGet packages from the NuGet V3 search endpoint.

    The public search endpoint does not guarantee download ordering, so we
    fetch a large result set and sort locally by ``totalDownloads``.
    """
    source_url = "https://azuresearch-usnc.nuget.org/query"
    names_with_downloads: list[tuple[str, int]] = []
    skip = 0
    take = 100
    target_fetches = max(top_n * 2, 2000)
    while len(names_with_downloads) < target_fetches:
        url = f"{source_url}?q=&skip={skip}&take={take}&prerelease=false&semVerLevel=2.0.0"
        req = urllib.request.Request(url, headers={"Accept": "application/json"})
        try:
            resp, body = safe_urlopen(req, timeout=60)
        except (InsecureURLError, ResponseTooLargeError) as e:
            raise RuntimeError(f"NuGet fetch failed: {e}") from e

        try:
            data = json.loads(body.decode("utf-8"))
        finally:
            resp.close()

        items = data.get("data", []) if isinstance(data, dict) else []
        if not items:
            break
        for item in items:
            if isinstance(item, dict) and isinstance(item.get("id"), str):
                names_with_downloads.append((item["id"], int(item.get("totalDownloads", 0) or 0)))
        if len(items) < take:
            break
        skip += take
        if skip > 5000:
            break

    names_with_downloads.sort(key=lambda x: (-x[1], x[0]))
    return [n for n, _ in names_with_downloads[:top_n]], source_url, False


def _fetch_builtin(ecosystem: str, top_n: int) -> tuple[list[str], str, bool]:
    """Fall back to the built-in curated list when no live fetcher exists."""
    builtin = _BUILTIN_FALLBACK.get(ecosystem, [])
    return builtin[:top_n], "builtin", True


def _fetch_ecosystem(
    ecosystem: str,
    top_n: int,
    source_url: str | None,
) -> tuple[list[str], str, bool]:
    if source_url:
        # Generic JSON list fetch for ecosystems without a dedicated fetcher.
        return _fetch_json_list(source_url, top_n)
    if ecosystem == "npm":
        return _fetch_npm(top_n)
    if ecosystem == "pypi":
        return _fetch_pypi(top_n)
    if ecosystem == "cargo":
        return _fetch_cargo(top_n)
    if ecosystem == "go":
        return _fetch_go(top_n)
    if ecosystem == "maven":
        return _fetch_maven(top_n)
    if ecosystem == "rubygems":
        return _fetch_rubygems(top_n)
    if ecosystem == "nuget":
        return _fetch_nuget(top_n)
    return _fetch_builtin(ecosystem, top_n)


def _fetch_json_list(url: str, top_n: int) -> tuple[list[str], str, bool]:
    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        resp, body = safe_urlopen(req, timeout=30)
    except (InsecureURLError, ResponseTooLargeError) as e:
        raise RuntimeError(f"Corpus fetch failed for {url}: {e}") from e

    try:
        data = json.loads(body.decode("utf-8"))
    finally:
        resp.close()

    names: list[str] = []
    if isinstance(data, list):
        for item in data[:top_n]:
            if isinstance(item, str):
                names.append(item)
            elif isinstance(item, dict) and isinstance(item.get("name"), str):
                names.append(item["name"])
    elif isinstance(data, dict):
        # Accept a flat object of {name: count}; sort by count descending.
        for name, _count in sorted(data.items(), key=lambda kv: kv[1], reverse=True):
            if isinstance(name, str):
                names.append(name)
            if len(names) >= top_n:
                break

    return names[:top_n], url, False


def _hash_corpus(names: list[str]) -> str:
    return hashlib.sha256(json.dumps(names, sort_keys=True).encode()).hexdigest()[:16]


def cmd(args: argparse.Namespace) -> int:
    top_n = getattr(args, "top", 1000)
    merge = getattr(args, "merge", True)
    ecosystem_arg = getattr(args, "ecosystem", "npm")
    ecosystems = _SUPPORTED_ECOSYSTEMS if ecosystem_arg == "all" else [ecosystem_arg]
    single_ecosystem = len(ecosystems) == 1

    output_arg = getattr(args, "output", None)
    if output_arg:
        output_path = Path(output_arg)
        output_dir = output_path if ecosystem_arg == "all" else output_path.parent
    else:
        output_dir = user_corpus_dir()
        output_path = None

    output_dir.mkdir(parents=True, exist_ok=True)

    manifest_entries: dict[str, dict[str, Any]] = {}
    failed: list[str] = []

    for ecosystem in ecosystems:
        try:
            names, source_url, used_builtin = _fetch_ecosystem(ecosystem, top_n, getattr(args, "source_url", None))
        except Exception as e:
            print(f"Error fetching {ecosystem}: {e}", file=sys.stderr)
            failed.append(ecosystem)
            continue

        corpus_file = output_path if output_path and single_ecosystem else output_dir / f"{ecosystem}_top_packages.json"

        existing: set[str] = set()
        if merge:
            existing = _load_existing(corpus_file)

        builtin = set(_BUILTIN_FALLBACK.get(ecosystem, []))
        # Always merge built-in names and drop obscure fetched short names
        # (<4 chars) that are not already in the curated built-in list.
        filtered = {n for n in names if isinstance(n, str) and n and (len(n) >= 4 or n in builtin)}
        merged = sorted(existing | filtered | builtin)
        save_indexed_corpus(corpus_file.parent, ecosystem, merged)

        if used_builtin:
            print(
                f"{ecosystem}: refreshed from built-in fallback ({len(merged)} names, "
                f"{len(names)} from builtin, {len(existing)} existing)"
            )
        else:
            print(
                f"{ecosystem}: downloaded {len(names)} names, merged corpus now {len(merged)} names "
                f"({len(existing)} existing)"
            )
        print(f"  saved: {corpus_file}")

        manifest_entries[ecosystem] = {
            "count": len(merged),
            "source_url": source_url,
            "fetched_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "top_n": top_n,
            "sha256": _hash_corpus(merged),
            "used_builtin": used_builtin,
        }

    if manifest_entries:
        _write_manifest(output_dir, manifest_entries)
        print(f"Manifest written: {output_dir / 'corpus.json'}")

    if failed:
        print(f"Failed ecosystems: {', '.join(failed)}", file=sys.stderr)
        return 1

    return 0


_cmd_update = cmd

__all__ = ["NAME", "_cmd_update", "add_arguments", "cmd"]
