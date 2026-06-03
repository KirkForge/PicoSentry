# L2-SIDELOAD-001: Protocol Sideloading Detection

**Severity:** HIGH  
**Category:** dependency  
**Since:** v0.3.0

## What It Detects

Dependencies declared using protocols that bypass the npm registry's integrity guarantees:

| Protocol | Example | Risk |
|----------|---------|------|
| `git://` | `"pkg": "git://github.com/user/pkg.git"` | Unencrypted, no integrity, MITM-vulnerable |
| `git+ssh://` | `"pkg": "git+ssh://git@github.com/user/pkg.git"` | No registry integrity check |
| `git+http://` | `"pkg": "git+http://github.com/user/pkg.git"` | Unencrypted + no integrity |
| `git+https://` | `"pkg": "git+https://github.com/user/pkg.git"` | No registry integrity check |
| `github:` | `"pkg": "github:user/pkg"` | Shorthand git, no integrity |
| `file:` | `"pkg": "file:../local-pkg"` | Local path, not reproducible |
| `link:` | `"pkg": "link:../local-pkg"` | Symlink, not reproducible |

## Why It Matters

Protocol sideloading bypasses the npm registry's security model:

- **No integrity hash**: Registry packages have `integrity` hashes (sha512). Git/file dependencies don't.
- **No version pinning**: `git://` dependencies resolve to whatever HEAD is, making builds non-reproducible
- **MITM attacks**: `git://` and `git+http://` are unencrypted — an attacker can intercept and modify the code
- **Non-reproducible builds**: `file:` and `link:` dependencies resolve differently on each machine
- **Supply chain gap**: These dependencies are invisible to most npm audit tools

For ML pipelines, non-reproducible dependencies mean `sha256(scan_a) != sha256(scan_b)` — your determinism guarantee breaks.

## How to Fix

1. **Use registry versions**: Replace git/file dependencies with published npm versions
2. **Use `https://` git URLs**: If you must use git, at least use encrypted transport
3. **Pin to commit hashes**: `git+https://github.com/user/pkg.git#abc123` pins to a specific commit
4. **Publish to private registry**: For internal packages, use a private npm registry (Verdaccio, GitHub Packages, etc.)

```json
// BEFORE (sideloading — HIGH risk)
"my-lib": "git+ssh://git@github.com/myorg/my-lib.git"

// AFTER (registry — safe)
"my-lib": "^1.2.3"
```

## Configuration

```yaml
# .picosentry.yml
severity_overrides:
  L2-SIDELOAD-001: MEDIUM  # if you control the git repos being referenced
```

## References

- [npm: git URLs as dependencies](https://docs.npmjs.com/cli/v10/commands/npm-install#git-urls-as-dependencies)
- [npm: local paths](https://docs.npmjs.com/cli/v10/commands/npm-install#local-paths)