# PicoSentry Rule Documentation

All 19 detector rules for deterministic npm/pnpm supply-chain scanning.

## Rule Catalog

| ID | Rule | Detects | Default Severity |
|----|------|---------|-----------------|
| [L2-POST-001](L2-POST-001.md) | post_install | Install scripts with network/credential access | CRITICAL/HIGH |
| [L2-OBFS-001](L2-OBFS-001.md) | obfuscation_eval | eval() calls in install scripts | CRITICAL |
| [L2-OBFS-002](L2-OBFS-002.md) | obfuscation_hex | Hex-encoded strings in install scripts | HIGH |
| [L2-OBFS-003](L2-OBFS-003.md) | obfuscation_base64 | Base64 + exec patterns in install scripts | CRITICAL |
| [L2-OBFS-004](L2-OBFS-004.md) | obfuscation_unicode | Unicode escape sequences in install scripts | HIGH |
| [L2-DEPC-001](L2-DEPC-001.md) | dep_confusion | Internal dependencies without private registry | HIGH |
| [L2-TYPO-001](L2-TYPO-001.md) | typosquat | Package names within edit distance ≤2 of top-500 npm packages | HIGH |
| [L2-MANI-001](L2-MANI-001.md) | manifest_version_range | Dangerous version ranges (*, latest, x ranges) | MEDIUM |
| [L2-MANI-002](L2-MANI-002.md) | manifest_optional_scripts | Optional dependencies with install scripts | HIGH |
| [L2-FORK-001](L2-FORK-001.md) | fork_drift | Missing repository URL or fork indicators | LOW/MEDIUM |
| [L2-CRED-001](L2-CRED-001.md) | credential_read | Install scripts reading .npmrc, .aws/, .ssh/, env vars | MEDIUM/CRITICAL |
| [L2-LOCK-001](L2-LOCK-001.md) | lockfile_drift | Missing lockfile, missing deps, weak integrity | MEDIUM |
| [L2-BUND-001](L2-BUND-001.md) | bundled_shadow | bundledDependencies shadows (event-stream attack vector) | HIGH |
| [L2-PROV-001](L2-PROV-001.md) | provenance | Missing repo, no integrity hash, scripts without provenance | LOW/MEDIUM |
| [L2-MAINT-001](L2-MAINT-001.md) | maintainer_change | Publisher/author mismatch, anonymous scripts, bus factor | MEDIUM/HIGH |
| [L2-PNPM-001](L2-PNPM-001.md) | pnpm_config | dangerouslyAllowAllBuilds, missing .npmrc, overrides, patchedDependencies | MEDIUM/CRITICAL |
| [L2-LICENSE-001](L2-LICENSE-001.md) | license | Missing, UNLICENSED, copyleft (GPL/AGPL/LGPL), unrecognized license | MEDIUM/HIGH/LOW |
| [L2-ENGIN-001](L2-ENGIN-001.md) | engine_constraints | Missing, overly permissive, or suspicious Node.js engine constraints | MEDIUM |
| [L2-SIDELOAD-001](L2-SIDELOAD-001.md) | protocol_sideloading | git://, file:, link: dependencies bypassing registry integrity | HIGH |

**Note:** 21 rule IDs are produced from 15 detector functions. Sub-rules L2-OBFS-002/003/004 share `detect_obfuscation()` and L2-MANI-002 shares `detect_manifest_issues()`.

## By Category

### Execution Risk
- L2-POST-001 (post-install scripts)
- L2-OBFS-001..004 (obfuscation)
- L2-CRED-001 (credential reading)

### Dependency Risk
- L2-DEPC-001 (dependency confusion)
- L2-TYPO-001 (typosquatting)
- L2-BUND-001 (bundled dependency shadows)
- L2-SIDELOAD-001 (protocol sideloading)

### Manifest Risk
- L2-MANI-001 (version ranges)
- L2-MANI-002 (optional deps with scripts)

### Lockfile Risk
- L2-LOCK-001 (lockfile drift)
- L2-PNPM-001 (pnpm configuration)

### Provenance Risk
- L2-FORK-001 (fork drift)
- L2-PROV-001 (provenance)
- L2-MAINT-001 (maintainer changes)

### Compliance Risk
- L2-LICENSE-001 (license compliance)
- L2-ENGIN-001 (engine constraints)

## Design Principles

1. **Deterministic**: Same input + same corpus = same output. Every time.
2. **Offline**: No HTTP calls at scan time. Corpus is local and versioned.
3. **Pure functions**: `(target_path, corpus_dir) → List[Finding]`. No global state, no randomness.
4. **No narrative**: Findings are structured data, not prose.

## Severity Override

All rule severities can be overridden in `.picosentry.yml`:

```yaml
severity_overrides:
  L2-PROV-001: INFO
  L2-POST-001: HIGH
```

## CLI Usage

```bash
# Scan with all rules
picosentry scan ./project

# Scan with specific rules only
picosentry scan ./project --rules L2-POST-001 L2-TYPO-001 L2-CRED-001

# List all 21 rules
picosentry rules

# List rules as JSON (includes helpUri)
picosentry rules --json
```
