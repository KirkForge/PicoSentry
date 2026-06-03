# L2-POST-001: Post-Install Script Detection

**Severity:** CRITICAL / HIGH  
**Category:** execution  
**Since:** v0.1.0

## What It Detects

Packages that declare `install`, `postinstall`, or `preinstall` scripts in their `package.json`. These scripts execute automatically during `npm install` or `pnpm install` with full system access.

## Why It Matters

Post-install scripts are the #1 attack vector in npm supply chain attacks:

- **event-stream@3.3.6** (2018): Post-install script injected cryptocurrency wallet-stealing code
- **ua-parser-js@7.7.8** (2021): Compromised post-install script ran `curl|bash` to install cryptominers
- **colors.js@1.4.2** (2022): Protestware — infinite loop in post-install

Any package with a post-install script has arbitrary code execution on your machine during `npm install`.

## Severity Levels

| Level | Condition |
|-------|-----------|
| CRITICAL | Script accesses network (`curl`, `wget`, `http`, `fetch`, `request`) or credentials (`$HOME`, `.ssh`, `.npmrc`, `.aws`, `process.env`) |
| HIGH | Script exists but no network/credential indicators detected |

## How to Fix

1. **Audit the script**: Read the install script contents before installing
2. **Use `--ignore-scripts`**: Run `npm install --ignore-scripts` to skip all lifecycle scripts
3. **Allowlist specific scripts**: In `.npmrc` or `.pnpmrc`, only allow trusted scripts
4. **Remove the dependency**: If the script isn't necessary, find an alternative package

## Configuration

```yaml
# .picosentry.yml
severity_overrides:
  L2-POST-001: HIGH  # downgrade from CRITICAL if your team allows post-install scripts
```

## References

- [npm docs: lifecycle scripts](https://docs.npmjs.com/cli/v10/using-npm/scripts)
- [Snyk: npm script injection](https://snyk.io/blog/npm-script-injection/)
- [event-stream incident analysis](https://github.com/dominictarr/event-stream/issues/116)