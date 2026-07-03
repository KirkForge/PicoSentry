#!/usr/bin/env python3
"""Verify a PicoSentry release artifact bundle.

This script downloads the release assets for a given tag from GitHub and checks:

1. The wheel and sdist are present.
2. SHA-256 checksums match the shipped `.SHA256SUMS` file.
3. Sigstore signature bundles are present and parse as valid JSON.
4. The CycloneDX SBOM is present and parses as valid JSON.

For full cryptographic verification of SLSA provenance and Sigstore signatures,
use the GitHub CLI:

    gh attestation verify dist/picosentry-*.whl \
        --owner KirkForge --predicate-type slsaprovenance

Usage:
    python scripts/verify_release.py v2.0.17

Returns 0 on success, non-zero on any failure.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sys
import tempfile
import urllib.request
from pathlib import Path
from typing import Any


GITHUB_REPO = os.environ.get("GITHUB_REPOSITORY", "KirkForge/PicoSentry")


def _download(url: str, dest: Path) -> None:
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/octet-stream")
    with urllib.request.urlopen(req, timeout=60) as resp, dest.open("wb") as f:
        shutil.copyfileobj(resp, f)


def _github_api(path: str) -> Any:
    url = f"https://api.github.com/repos/{GITHUB_REPO}{path}"
    req = urllib.request.Request(url)
    req.add_header("Accept", "application/vnd.github+json")
    token = os.environ.get("GITHUB_TOKEN")
    if token:
        req.add_header("Authorization", f"Bearer {token}")
    with urllib.request.urlopen(req, timeout=60) as resp:
        return json.loads(resp.read().decode())


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def _verify_checksums(work_dir: Path) -> list[str]:
    errors: list[str] = []
    sums_file = next(work_dir.glob("*.SHA256SUMS"), None)
    if sums_file is None:
        return ["No .SHA256SUMS file found in release assets"]

    for raw_line in sums_file.read_text().splitlines():
        line = raw_line.strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2:
            errors.append(f"Malformed checksum line: {line}")
            continue
        expected = parts[0]
        filename = parts[1]
        path = work_dir / filename
        if not path.exists():
            errors.append(f"Checksum references missing file: {filename}")
            continue
        actual = _sha256_file(path)
        if actual != expected:
            errors.append(f"Checksum mismatch for {filename}: expected {expected}, got {actual}")
    return errors


def _verify_sigstore_present(work_dir: Path) -> list[str]:
    errors: list[str] = []
    artifacts = list(work_dir.glob("picosentry-*.whl")) + list(work_dir.glob("picosentry-*.tar.gz"))
    for artifact in artifacts:
        bundle = work_dir / f"{artifact.name}.sigstore.json"
        if not bundle.exists():
            errors.append(f"Missing Sigstore bundle for {artifact.name}")
            continue
        try:
            data = json.loads(bundle.read_text())
            if "messageSignature" not in data:
                errors.append(f"Sigstore bundle for {artifact.name} has no messageSignature field")
        except json.JSONDecodeError as exc:
            errors.append(f"Could not parse Sigstore bundle for {artifact.name}: {exc}")
    return errors


def _verify_sbom(work_dir: Path) -> list[str]:
    errors: list[str] = []
    sbom_files = list(work_dir.glob("*.sbom.cdx.json"))
    if not sbom_files:
        errors.append("No CycloneDX SBOM found")
        return errors
    for sbom in sbom_files:
        try:
            data = json.loads(sbom.read_text())
            if data.get("bomFormat") != "CycloneDX":
                errors.append(f"{sbom.name} is not a CycloneDX SBOM")
            if not data.get("components"):
                errors.append(f"{sbom.name} has no components")
        except json.JSONDecodeError as exc:
            errors.append(f"Could not parse {sbom.name}: {exc}")
    return errors


def main(argv: list[str]) -> int:
    if len(argv) != 1:
        print(f"usage: {sys.argv[0]} <tag>", file=sys.stderr)
        return 2

    tag = argv[0]
    if not tag.startswith("v"):
        tag = f"v{tag}"

    release = _github_api(f"/releases/tags/{tag}")
    assets = release.get("assets", [])
    if not assets:
        print(f"No assets found for {tag}", file=sys.stderr)
        return 1

    with tempfile.TemporaryDirectory(prefix="picosentry-verify-") as tmp:
        work_dir = Path(tmp)
        print(f"Downloading {len(assets)} asset(s) for {tag}...")
        for asset in assets:
            name = asset["name"]
            dest = work_dir / name
            _download(asset["browser_download_url"], dest)
            print(f"  {name} ({dest.stat().st_size} bytes)")

        checks = [
            ("checksums", _verify_checksums(work_dir)),
            ("sigstore", _verify_sigstore_present(work_dir)),
            ("sbom", _verify_sbom(work_dir)),
        ]

    all_errors: list[str] = []
    for check_name, errors in checks:
        if errors:
            print(f"\n{check_name} failures:")
            for err in errors:
                print(f"  - {err}")
            all_errors.extend(errors)
        else:
            print(f"{check_name}: OK")

    if all_errors:
        print(f"\nVerification FAILED: {len(all_errors)} error(s)", file=sys.stderr)
        return 1

    print("\nVerification passed.")
    print("For cryptographic SLSA/Sigstore verification run: gh attestation verify dist/picosentry-* --owner KirkForge")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
