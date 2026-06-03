# L2-PYPI-ADV-001: PyPI Advisory Vulnerability Detection

**Severity:** HIGH (dynamic — matches advisory severity)  
**Category:** vulnerability  
**Since:** v1.1.0

## What It Detects

Known CVEs and security advisories affecting installed Python packages, checked against a local OSV-format advisory database.

## How It Works

1. Loads a local OSV-format advisory database (same as the npm advisory check)
2. Collects installed Python packages from site-packages, lockfiles, and pyproject.toml
3. For each package with a matching advisory, generates a finding with the CVE ID, severity, and fix version

## Requirements

An advisory database must be available. Without one, this rule produces no findings. Use `picosentry advisories fetch` to download the latest advisories.