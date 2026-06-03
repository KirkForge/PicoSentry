# L2-PNPM-001: pnpm Configuration Risks

**Severity:** MEDIUM / CRITICAL  
**Category:** lockfile  
**Since:** v0.1.0

## What It Detects

Dangerous or missing pnpm configuration in `.npmrc` or `pnpm-lock.yaml`:

| Finding | Severity | Description |
|---------|----------|-------------|
| `dangerouslyAllowAllBuilds=true` | CRITICAL | All packages can run install scripts without review |
| Missing `.npmrc` | MEDIUM | No pnpm configuration file found |
| `overrides` with scripts | HIGH | Dependency overrides that include packages with install scripts |
| `patchedDependencies` | MEDIUM | Local patches applied to dependencies (supply chain risk) |

## Why It Matters

pnpm has stronger security defaults than npm, but they can be bypassed:

- **`dangerouslyAllowAllBuilds`** disables pnpm's built-in protection against untrusted install scripts — this is equivalent to running `npm install` with no script protection
- **`overrides`** let you replace any dependency, but if the override itself has install scripts, you've introduced a new attack surface
- **`patchedDependencies`** apply local patches to third-party code, which means the patch author (you) becomes part of the supply chain
- **Missing `.npmrc`** means pnpm uses defaults, which may or may not be appropriate for your security posture

## How to Fix

1. **Remove `dangerouslyAllowAllBuilds`**: Use `onlyBuiltDependencies` allowlist instead
2. **Audit overrides**: Verify that override packages don't have install scripts
3. **Review patches**: Ensure `patchedDependencies` patches are minimal and reviewed
4. **Add `.npmrc`**: Configure pnpm security settings explicitly

```ini
# .npmrc — pnpm security best practices
shamefully-hoist=false
strict-peer-dependencies=true
onlyBuiltDependencies[]=esbuild
```

## Configuration

```yaml
# .picosentry.yml
severity_overrides:
  L2-PNPM-001: HIGH  # upgrade dangerouslyAllowAllBuilds to CRITICAL
```

## References

- [pnpm: settings](https://pnpm.io/settings)
- [pnpm: onlyBuiltDependencies](https://pnpm.io/package_json#onlybuiltdependencies)