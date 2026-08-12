# L2-INTEL-001: Suspicious New Package

**Severity:** MEDIUM  
**Category:** supply-chain  
**Since:** v2.1.0

## What It Detects

A package that is both very young and has almost no downloads — the classic
profile of a freshly-published typosquat or supply-chain lure:

| Signal | Threshold | Description |
|--------|-----------|-------------|
| Download count | `< 100` in the last month | Almost nobody has installed it |
| Package age | `< 30` days since first release | It was published very recently |

Both conditions must hold. An old package with few downloads, or a young
package with many downloads, is not flagged.

## Why It Matters

Attackers publish lookalike packages (typosquats, dependency-confusion
lures) that are brand new and have essentially zero adoption. Established
packages accumulate downloads and age over time; a package that is both
brand-new and unadopted has no track record to trust.

## How It Works

This rule requires **registry intelligence** (download counts + first-release
date), which is fetched from the package registry when the scanner runs in
`connected` mode:

- **PyPI**: `https://pypi.org/pypi/{name}/json` — first release is the
  earliest `upload_time` across all releases.
- **npm**: `https://registry.npmjs.org/{name}` for `time.created`, plus the
  npm downloads API for a 30-day count.

In **offline** mode there is no registry intel, so this rule never fires —
it degrades gracefully (no intel, no crash, no false positives).

## How to Fix

1. **Verify the package source**: Check the repository URL and publisher identity
2. **Check for typosquatting**: Compare the name against the package it may be impersonating
3. **Prefer established packages**: If the functionality is available from a
   well-known, widely-downloaded package, use that instead
4. **Pin and audit**: If you must use a new package, pin the exact version and
   review its install scripts

## Configuration

```yaml
# .picosentry.yml
severity_overrides:
  L2-INTEL-001: HIGH  # upgrade if you ingest many new dependencies
```

## References

- [npm: package spec](https://docs.npmjs.com/cli/v10/using-npm/package-specification-npm)
- [PyPI JSON API](https://warehouse.pypa.io/api-reference/json.html)
