# L2-NSCOL-001: Namespace/Scope Collision

**Severity:** MEDIUM  
**Category:** supply-chain  
**Since:** v3.0.0

## What It Detects

A package whose name claims a well-known namespace/scope prefix (e.g. an npm
`@scope` like `@google`/`@aws-sdk`/`@types`, or a PyPI namespace like
`google-`/`aws-`/`django-`) while being both new and low-download — the
signature of a namespace/scope-squatting supply-chain lure.

| Signal | Threshold | Description |
|--------|-----------|-------------|
| Download count | `< 100` in the last month | Almost nobody has installed it |
| Package age | `< 30` days since first release | It was published very recently |

Both conditions must hold along with a well-known prefix claim. An established
scoped package with downloads (or an old one) is not flagged.

## Why It Matters

Attackers squat a well-known scope or namespace to ride on the trust of a
legitimate org — e.g. publishing `@aws-sdk/something-new` or a `google-foo`
package that looks like it belongs to the official namespace. A brand-new,
unadopted package making that claim has no track record to justify it.

## How It Works

This rule requires **registry intelligence** (download counts + first-release
date), fetched in `connected` mode. In **offline** mode there is no registry
intel, so the rule never fires (no intel, no crash, no false positives).

For npm, scoped names (`@scope/pkg`) are matched by their `@scope` prefix. For
unscoped names, the well-known namespace prefix is matched directly.

## How to Fix

1. **Verify scope ownership**: Confirm the publisher genuinely owns the claimed
   scope/namespace (e.g. an official GitHub org).
2. **Prefer the official package**: If functionality is available from the
   well-known package, use that instead.
3. **Pin and audit**: If you must use the package, pin the version and review
   its install scripts and publisher identity.

## Configuration

```yaml
# .picosentry.yml
severity_overrides:
  L2-NSCOL-001: HIGH  # upgrade if you ingest many new scoped dependencies
```

## References

- [npm: package spec](https://docs.npmjs.com/cli/v10/using-npm/package-specification-npm)
- [PyPI JSON API](https://warehouse.pypa.io/api-reference/json.html)
