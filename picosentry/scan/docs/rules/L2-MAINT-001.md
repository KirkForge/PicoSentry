# L2-MAINT-001: Maintainer Change Detection

**Severity:** MEDIUM / HIGH  
**Category:** maintainer  
**Since:** v0.1.0

## What It Detects

Offline signals that a package's maintainer identity has changed or is suspicious:

| Signal | Severity | Description |
|--------|----------|-------------|
| `_npmUser` ≠ `author` mismatch | HIGH | Publisher doesn't match declared author — like event-stream takeover |
| No author + install scripts | HIGH | Unaccountable package running code at install time |
| Single maintainer + scripts | MEDIUM | Bus factor + attack surface (one person controls the RCE) |
| Maintainers from different domains | MEDIUM | Possible org transfer or account compromise |
| No author/maintainer at all | MEDIUM | Completely anonymous package |
| Short author names | LOW | Pseudonymous risk (1-2 character names, e.g., "a", "x") |

## Why It Matters

The **event-stream@3.3.6** attack is the canonical example:

1. The original maintainer (dominictarr) transferred the package to a new developer
2. The new maintainer added `flatmap-stream` as a dependency
3. The new dependency contained Bitcoin wallet-stealing code
4. The `_npmUser` (publisher) didn't match the `author` field
5. The attack was only discovered when a developer noticed the unfamiliar dependency

Maintainer changes are a leading indicator of account compromise or malicious takeover.

## How to Fix

1. **Verify the maintainer**: Check npmjs.com for the package's publish history
2. **Check for recent ownership transfers**: Look for sudden changes in who publishes versions
3. **Pin to trusted versions**: If the current maintainer is unknown, pin to the last version published by the original maintainer
4. **Use `npm info <package> maintainers`**: See who has publish access

## Configuration

```yaml
# .picosentry.yml
severity_overrides:
  L2-MAINT-001: HIGH  # upgrade if your project handles financial data
```

## References

- [event-stream incident](https://github.com/dominictarr/event-stream/issues/116)
- [npm: package maintainers](https://docs.npmjs.com/cli/v10/commands/npm-owner)