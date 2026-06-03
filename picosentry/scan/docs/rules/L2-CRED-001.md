# L2-CRED-001: Credential-Reading Install Scripts

**Severity:** HIGH  
**Category:** credential  
**Since:** v0.1.0

## What It Detects

Install scripts that access credential files or environment variables:

- **`.npmrc`**: May contain auth tokens
- **`.ssh/`**: SSH private keys
- **`.aws/`**: AWS credentials
- **`.env` / `process.env`**: Environment variables that often contain secrets
- **`.gitconfig`**: Git credentials and tokens

## Why It Matters

This is the exact attack pattern used in multiple real-world supply chain incidents:

- An install script runs with full system access during `npm install`
- It can read your credential files and exfiltrate them via network requests
- This happens before you even `import` the package — the attack runs at install time
- The `crossenv` typosquatting attack used this pattern to steal npm credentials
- CI/CD environments are especially vulnerable — they often contain deployment keys, API tokens, and cloud credentials

## How to Fix

1. **Do not install**: This is a critical risk — any package reading credentials during install is suspicious
2. **Use `--ignore-scripts`**: Prevent all install scripts from running
3. **Audit the script**: If you must use the package, read the install script contents
4. **Use `.npmrc` auth**: Prefer registry-level auth tokens over credential files
5. **Rotate compromised credentials**: If a package has already been installed, rotate any credentials that were accessible

## Configuration

```yaml
# .picosentry.yml
severity_overrides:
  L2-CRED-001: CRITICAL  # upgrade in CI/CD environments
```

## References

- [npm: securing your credentials](https://docs.npmjs.com/cli/v10/configuring-npm/npmrc#auth-related-configuration)
- [Crossenv attack analysis](https://snyk.io/blog/crossenv-malicious-package/)