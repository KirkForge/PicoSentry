# L2-FORK-001: Fork Drift Detection

**Severity:** MEDIUM  
**Category:** provenance  
**Since:** v0.1.0

## What It Detects

Packages with missing or suspicious repository URLs, or indicators that the package is a fork rather than the canonical source:

- **Missing `repository` field**: No way to verify the source code
- **No `homepage` or `bugs.url`**: No reference to the upstream project
- **Fork indicators**: URL patterns suggesting a fork (e.g., different org, "fork" in name)

## Why It Matters

Fork drift is a subtle supply chain risk:

- When a package is forked, the fork may diverge from the original in ways that aren't immediately visible
- Forks may add malicious code that doesn't exist in the upstream
- Missing repository URLs make it impossible to audit the source code
- The `event-stream@3.3.6` attack involved a maintainer transferring the package to an unknown developer — effectively a "friendly fork"

## How to Fix

1. **Verify the source**: Check that the `repository` URL points to an active, maintained project
2. **Use the canonical package**: If this is a fork, prefer the original package unless you need specific fork changes
3. **Add missing `repository` field**: If you maintain the package, add a proper `repository` field to `package.json`

## Configuration

```yaml
# .picosentry.yml
severity_overrides:
  L2-FORK-001: LOW  # if your project tolerates forks
```

## References

- [npm: package.json repository field](https://docs.npmjs.com/cli/v10/configuring-npm/package-json#repository)