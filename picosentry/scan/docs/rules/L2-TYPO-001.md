# L2-TYPO-001: Typosquatting Detection

**Severity:** HIGH (normal-length names) / MEDIUM-LOW (short names ≤4 chars)  
**Category:** typosquat  
**Since:** v0.1.0

## What It Detects

Package names within edit distance ≤2 of the top 327 most-downloaded npm packages. This includes both the package's own `name` field and its declared dependencies.

The corpus is loaded from `corpus/npm_top_packages.json` (327 packages) and is versioned via SHA-256 hash for determinism.

## Why It Matters

Typosquatting is the most common npm supply chain attack vector:

- Attackers publish packages with names like `lodassh`, `expres`, `reacat` — one or two characters off from popular packages
- A single typo in your `package.json` or `npm install` command can install malware
- The `crossenv` attack (2017) used a typosquat of `cross-env`
- Typosquatted packages often contain install scripts that steal credentials or install cryptominers

## Edit Distance Algorithm

PicoSentry uses Levenshtein edit distance with the following thresholds:

| Distance | Name Length | Severity | Example |
|----------|-------------|----------|---------|
| 0 | — | — | Exact match (not flagged — it IS the popular package) |
| 1 | ≥5, ratio ≥0.8 | HIGH | `reqct` → `react` |
| 1 | ≤4 | MEDIUM | `ky` → `cpy` |
| 2 | ≥5, ratio ≥0.6 | MEDIUM | `nx1` → `next` |
| 2 | ≤4 | LOW | `swr` → `tar` |
| 2 | Low ratio | LOW | Coincidental similarity |

**Short package names (≤4 chars) are extremely prone to false positives**
because almost any short string is within edit distance 2 of another short name.
Matches on short names are capped at LOW/MEDIUM severity to prevent
typosquat noise from breaking CI pipelines with `--fail-on high`.

## How to Fix

1. **Verify the package name**: Check that you typed it correctly
2. **Check npm for the intended package**: Search npmjs.com for the correct name
3. **Pin exact versions**: Use `package@exact.version` instead of ranges

## Configuration

```yaml
# .picosentry.yml
ignore_packages:
  - my-internal-package  # if it's legitimately named similar to a top package
```

## References

- [npm: typosquatting detection](https://blog.npmjs.org/post/180565024790/detecting-npm-typosquatting-packages)
- [Snyk: typosquatting attacks](https://snyk.io/blog/typosquatting-attacks/)