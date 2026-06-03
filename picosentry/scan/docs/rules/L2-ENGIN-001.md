# L2-ENGIN-001: Engine Constraint Detection

**Severity:** MEDIUM  
**Category:** compatibility  
**Since:** v0.2.0

## What It Detects

Problematic `engines` fields in `package.json`:

| Finding | Severity | Description |
|---------|----------|-------------|
| Missing `engines` field | LOW | No Node.js version constraint declared |
| Overly permissive ranges | MEDIUM | `>=0.0.0`, `*`, or `>=0.10.0` — allows any Node.js version |
| Suspicious constraints | MEDIUM | Unusually narrow ranges or patterns that may indicate targeted attacks |

## Why It Matters

Engine constraints affect reproducibility and security:

- **Missing engines**: The package may break on different Node.js versions, and you won't know until runtime
- **Overly permissive**: `>=0.0.0` means the package claims to work on any Node.js version — unlikely and untested
- **Suspicious constraints**: Extremely narrow ranges (e.g., `>=18.19.0 <18.19.1`) may indicate the package is designed to fail or behave differently on specific versions

For ML pipelines, engine constraints matter because:
- Training and inference environments may use different Node.js versions
- Inconsistent engine constraints across dependencies can cause runtime failures
- ML pipeline reproducibility requires deterministic environments

## How to Fix

1. **Add `engines` field**: If you maintain the package, specify supported Node.js versions
2. **Use `volta` or `nvm`**: Pin your project's Node.js version in development
3. **Check compatibility**: Verify that all dependencies support your target Node.js version

```json
{
  "engines": {
    "node": ">=18.0.0 <23.0.0"
  }
}
```

## Configuration

```yaml
# .picosentry.yml
severity_overrides:
  L2-ENGIN-001: INFO  # if your project has other Node.js version controls
```

## References

- [npm: engines field](https://docs.npmjs.com/cli/v10/configuring-npm/package-json#engines)
- [Node.js releases](https://nodejs.org/en/about/previous-releases)