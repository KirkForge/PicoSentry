# L2-BUND-001: Bundled Dependency Shadows

**Severity:** HIGH  
**Category:** dependency  
**Since:** v0.1.0

## What It Detects

Packages that declare `bundledDependencies` (or `bundleDependencies`) in their `package.json`. This feature allows a package to include its dependencies inside its own tarball, overriding whatever versions the consumer has installed.

## Why It Matters

This is the exact attack vector used in the **event-stream@3.3.6** incident:

1. The attacker gained maintainer access to `event-stream`
2. They added `flatmap-stream` as a bundled dependency
3. The bundled version of `flatmap-stream` contained malicious code that stole Bitcoin wallets
4. Because it was bundled, the malicious code was invisible to normal dependency audits
5. The attack went undetected for weeks because `bundledDependencies` bypasses normal resolution

### How bundledDependencies enable attacks:

- **Shadowing**: The bundled version replaces whatever the consumer has installed, even if they have a different version
- **Invisibility**: Bundled deps don't appear in `npm ls` or most dependency scanners
- **No integrity check**: The bundled tarball's contents are controlled by the package publisher
- **Persistence**: Even if the upstream package is fixed, the bundled version remains

## How to Fix

1. **Remove bundledDependencies**: If you maintain the package, remove `bundledDependencies` and use normal dependency resolution
2. **Audit bundled contents**: If you must use a package with bundled deps, inspect the bundled tarball contents
3. **Use an alternative package**: Prefer packages that don't bundle their dependencies
4. **Freeze your lockfile**: `npm ci` with a committed lockfile reduces the risk of shadowed versions

## Configuration

```yaml
# .picosentry.yml
severity_overrides:
  L2-BUND-001: MEDIUM  # only if you've audited the bundled contents
```

## References

- [event-stream incident analysis](https://github.com/dominictarr/event-stream/issues/116)
- [npm: bundledDependencies](https://docs.npmjs.com/cli/v10/configuring-npm/package-json#bundledependencies)