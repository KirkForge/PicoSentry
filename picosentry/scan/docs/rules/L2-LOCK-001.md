# L2-LOCK-001: Lockfile Drift Detection

**Severity:** MEDIUM / HIGH  
**Category:** lockfile  
**Since:** v0.1.0

## What It Detects

Issues with `package-lock.json` or `pnpm-lock.yaml` files:

| Finding | Severity | Description |
|---------|----------|-------------|
| Missing lockfile | HIGH | No lockfile found — every install resolves versions independently |
| Missing dependencies | HIGH | Lockfile doesn't include all declared dependencies |
| Weak integrity hashes | MEDIUM | Lockfile uses `sha1` instead of `sha512` for integrity checks |
| pnpm `dangerouslyAllowAllBuilds` | CRITICAL | `pnpm` config allows all packages to run install scripts without review |

## Why It Matters

Lockfiles are your primary defense against supply chain attacks:

- Without a lockfile, `npm install` resolves versions fresh every time — a compromised registry can serve a different version
- Missing dependencies in the lockfile mean some packages are resolved at install time, creating windows for attacks
- Weak integrity hashes (sha1) are vulnerable to collision attacks
- `dangerouslyAllowAllBuilds` in pnpm is exactly what it sounds like — it bypasses pnpm's built-in protection against install scripts

## How to Fix

1. **Commit your lockfile**: `package-lock.json` or `pnpm-lock.yaml` must be in version control
2. **Use `npm ci` or `pnpm install --frozen-lockfile`**: Install exactly what's in the lockfile
3. **Remove `dangerouslyAllowAllBuilds`**: Use `.npmrc` with specific `onlyBuiltDependencies` allowlist instead
4. **Upgrade to sha512**: Modern npm generates sha512 hashes by default

## Configuration

```yaml
# .picosentry.yml
severity_overrides:
  L2-LOCK-001: LOW  # only if you have other controls in place
```

## References

- [npm: package-lock.json](https://docs.npmjs.com/cli/v10/configuring-npm/package-lock-json)
- [pnpm: dangerouslyAllowAllBuilds](https://pnpm.io/settings#dangerouslyallowallbuilds)