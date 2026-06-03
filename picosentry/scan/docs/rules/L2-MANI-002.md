# L2-MANI-002: Optional Dependencies with Install Scripts

**Severity:** HIGH  
**Category:** manifest  
**Since:** v0.1.0

## What It Detects

Packages declared in `optionalDependencies` that also have install scripts (`install`, `postinstall`, `preinstall`).

## Why It Matters

Optional dependencies with install scripts are a dangerous combination:

- Optional dependencies are installed when they can be, and silently skipped when they fail
- This means a malicious install script in an optional dependency might execute on some machines but not others
- The "optional" label creates a false sense of security — the install script still runs with full system access
- If the optional dependency fails to install, npm silently continues, making it hard to detect in CI logs

## How to Fix

1. **Audit the install script**: Read what the script actually does
2. **Move to regular dependencies**: If you need the package, declare it as a regular dependency so failures are visible
3. **Use `--ignore-scripts`**: Skip optional dependency scripts during install
4. **Remove the dependency**: If it's truly optional, consider removing it entirely

## Configuration

```yaml
# .picosentry.yml
severity_overrides:
  L2-MANI-002: MEDIUM  # if you've audited the specific packages
```

## References

- [npm: optionalDependencies](https://docs.npmjs.com/cli/v10/configuring-npm/package-json#optionaldependencies)