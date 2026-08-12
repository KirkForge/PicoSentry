# L2-VCONF-001: Version Confusion / Version-Squatting

**Severity:** MEDIUM  
**Category:** supply-chain  
**Since:** v3.0.0

## What It Detects

A package that is **popular and established** but declares a placeholder
version (`0.0.0` or `1.0.0`) — the classic version-squatting profile:

| Signal | Threshold | Description |
|--------|-----------|-------------|
| Download count | `>= 1000` in the last month | Real adoption (popular) |
| Package age | `>= 30` days since first release | Published long enough to be established |
| Declared version | exactly `0.0.0` or `1.0.0` | Placeholder / squat marker |

All three conditions must hold. A brand-new or low-download package at
`1.0.0` is a normal first release and is **not** flagged.

## Why It Matters

Version-confusion is distinct from name-based typosquatting and
registry-based dependency-confusion. An attacker publishes a package at a
placeholder version that shadows the "real" version of a popular package,
hoping a dependency pin or a naive resolver resolves to the squat. A
popular, established package that is still pinned at `0.0.0`/`1.0.0` is a
strong signal that the resolved artifact is not the genuine one.

## How It Works

This rule requires **registry intelligence** (download counts + first-release
date), fetched from the package registry when the scanner runs in `connected`
mode. In **offline** mode there is no registry intel, so this rule never
fires — it degrades gracefully (no intel, no crash, no false positives).

## How to Fix

1. **Verify the package source**: Check the repository URL and publisher identity
2. **Pin the real version**: Resolve the genuine published version and pin it
3. **Check for squatting**: Compare the resolved artifact against the package it may be impersonating

## Configuration

```yaml
# .picosentry.yml
severity_overrides:
  L2-VCONF-001: HIGH  # upgrade if you ingest many dependencies
```

## References

- [npm: package spec](https://docs.npmjs.com/cli/v10/using-npm/package-specification-npm)
- [PyPI JSON API](https://warehouse.pypa.io/api-reference/json.html)
