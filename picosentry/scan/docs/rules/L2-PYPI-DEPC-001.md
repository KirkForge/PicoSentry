# L2-PYPI-DEPC-001: PyPI Dependency Confusion Detection

**Severity:** CRITICAL  
**Category:** dependency  
**Since:** v1.1.0

## What It Detects

Internal/private package names declared without a private PyPI index configuration. Attackers register internal-looking package names on public PyPI to inject malicious code when pip resolution picks the public package.

## Why It Matters

Dependency confusion is the highest-severity supply chain risk for organisations with internal Python packages. If `internal-auth-token` is used internally but also exists on PyPI, pip can resolve to the public (attacker-controlled) version.

## How It Works

1. Checks for a configured private index in pip.conf, .pypirc, or pyproject.toml
2. Identifies internal-looking package names (matching patterns like `internal-`, `private-`, `my-`)
3. Flags these names when no private index is configured

## Remediation

Add a private PyPI index URL in pip.conf or pyproject.toml before installing internal-looking packages. Use `--index-url <private-repo>` for individual installs.