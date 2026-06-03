# L2-MANI-001: Dangerous Version Ranges

**Severity:** MEDIUM  
**Category:** manifest  
**Since:** v0.1.0

## What It Detects

Dependency version ranges that are overly permissive or dangerous:

| Pattern | Risk | Example |
|---------|------|---------|
| `*` or empty | Any version, including malicious publishes | `"lodash": "*"` |
| `latest` | Always resolves to newest, may be compromised | `"express": "latest"` |
| `x` ranges | Major or minor wildcard ranges | `"react": "18.x"` |
| `>=0.0.0` | Semantically equivalent to `*` | `"moment": ">=0.0.0"` |

## Why It Matters

Broad version ranges undermine reproducibility and security:

- `*` or `latest` means every `npm install` can pull a different package version
- An attacker who compromises a package's npm account can publish a malicious version that automatically gets installed
- `x` ranges (`18.x`) allow minor version updates that may introduce breaking changes or vulnerabilities
- Lockfiles mitigate this, but only if they're committed and not regenerated

## How to Fix

1. **Pin exact versions**: Use `"lodash": "4.17.21"` instead of ranges
2. **Use caret ranges carefully**: `"express": "^4.18.2"` allows patch+minor updates (usually safe)
3. **Commit your lockfile**: `package-lock.json` or `pnpm-lock.yaml` should be in version control
4. **Use `npm ci`**: Installs exactly what's in the lockfile, ignoring ranges

## Configuration

```yaml
# .picosentry.yml
severity_overrides:
  L2-MANI-001: LOW  # if your team uses lockfiles and npm ci
```

## References

- [npm: semantic versioning](https://docs.npmjs.com/about-semantic-versioning)
- [npm ci vs npm install](https://docs.npmjs.com/cli/v10/commands/npm-ci)