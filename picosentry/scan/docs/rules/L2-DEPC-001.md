# L2-DEPC-001: Dependency Confusion

**Severity:** HIGH  
**Category:** dependency  
**Since:** v0.1.0

## What It Detects

Packages that declare dependencies using internal/private package names (e.g., `@mycompany/internal-lib`) without a corresponding private npm registry configuration (`.npmrc` with `registry=` or `@scope:registry=`).

## Why It Matters

Dependency confusion (aka "substitution attack") is one of the most effective supply chain attacks:

- If you declare `@myorg/utils` as a dependency but don't configure a private registry, npm will look for it on the public npm registry
- An attacker can publish a package with that name on npm and it will be installed instead
- This has been used to steal credentials from Apple, Microsoft, PayPal, and others
- The attack is silent — the malicious package runs during `npm install` before you even import it

## How to Fix

1. **Configure `.npmrc`**: Add `@myorg:registry=https://registry.myorg.com/` for each private scope
2. **Use `--registry` flag**: Point npm/pnpm to your private registry
3. **Verify `.npmrc` is committed**: Your registry config should be in version control, not just local

## Configuration

```yaml
# .picosentry.yml
severity_overrides:
  L2-DEPC-001: CRITICAL  # upgrade if your org is a high-value target
```

## References

- [Alex Birsan: Dependency Confusion](https://medium.com/@alex.birsan/dependency-confusion-4a5d60fec610)
- [npm: preventing dependency confusion](https://docs.npmjs.com/cli/v10/using-npm/configuring-your-registry-settings)