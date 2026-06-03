# L2-PROV-001: Provenance Issues

**Severity:** LOW / MEDIUM  
**Category:** provenance  
**Since:** v0.1.0

## What It Detects

Packages with missing provenance signals — indicators that the package's origin and integrity can't be verified:

| Finding | Severity | Description |
|---------|----------|-------------|
| Missing repository URL | MEDIUM | No way to view or audit the source code |
| No integrity hash | MEDIUM | Package tarball can't be verified against tampering |
| Scripts without provenance | LOW | Install scripts run without npm provenance attestation |

## Why It Matters

Provenance is about being able to answer "where did this code come from?":

- Without a repository URL, you can't audit the source code
- Without integrity hashes, you can't verify the tarball hasn't been tampered with
- npm's provenance attestation feature (2023+) lets package publishers cryptographically sign their builds
- Packages without provenance signals are harder to trust in automated CI/CD pipelines

This rule has a lower default severity because provenance is a best-practice signal, not an active attack indicator. Many legitimate packages don't have provenance yet.

## How to Fix

1. **Check the repository**: If the package has a repo URL, verify it's active and maintained
2. **Prefer packages with provenance**: When choosing between similar packages, prefer ones with npm provenance attestation
3. **Add provenance to your own packages**: Use `npm publish --provenance` to sign your packages
4. **Add repository URL**: If you maintain the package, add the `repository` field to `package.json`

## Configuration

```yaml
# .picosentry.yml
severity_overrides:
  L2-PROV-001: INFO  # provenance is a best practice, not a vulnerability
```

## References

- [npm: provenance attestation](https://docs.npmjs.com/generating-provenance-statements)
- [OpenSSF: SLSA framework](https://slsa.dev/)