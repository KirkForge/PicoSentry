# L2-WORM-001: Self-Propagating Worm Detection

**Severity:** CRITICAL / HIGH  
**Category:** supply-chain  
**Since:** v0.16.0

## What It Detects

Self-propagating npm worm patterns in install scripts and source code. Catches the Shai-Hulud worm family (2025-2026) and similar self-replicating postinstall attacks.

Specific patterns detected:
- **npm publish/whoami in install scripts** — worm self-propagation
- **curl/wget piped to shell** — remote payload download+execute (Shai-Hulud v1)
- **node -e one-liners** — inline payload execution
- **Shai-Hulud 2.0 Bun payloads** — `setup_bun.js`, `bun_environment.js`
- **Bun runtime execution in install/lifecycle scripts** — `bun run`/`bun x`/`bun exec`, the Mini Shai-Hulud (TanStack, May 2026) evasion that bypasses Node `--require` monitoring hooks
- **Git-resolved dependency + install lifecycle script** — the Mini Shai-Hulud delivery vector (a `github:`/git URL dependency whose `prepare` script runs the payload)
- **Forced exit after execution** — `&& exit 1` / `|| exit 0` appended so npm treats the dependency as failed and hides the install after the payload already ran
- **CI secrets exfiltration** — `toJSON(secrets)` dumping CI secrets to workflow output
- **Bun-only decompression API** — `Bun.gunzipSync`/`Bun.inflateSync` payload trait (evades Node monitoring)
- **Campaign identifiers** — `MUT-8694`, `s1ngularity/Nx`, `firedalazer`
- **GitHub repo creation/exfiltration** — `makeRepo`, `Shai-Hulud` strings
- **git config manipulation** — `git config --unset core.bare` (repo hijacking)
- **Workflow file injection** — `.github/workflows` deletion/injection
- **Destructive fallback** — `rm -rf ~` / `rm -rf $HOME`
- **Self-modifying package.json** — `writeFileSync` targeting package.json
- **node_modules scanning** — `glob` scanning for propagation targets

## Why It Matters

The Shai-Hulud worm (September 2025) compromised 1193+ package versions across 691 npm packages including CrowdStrike, @ctrl, @nativescript-community, and @things-factory. It propagated by cloning itself into new npm packages via postinstall scripts. Shai-Hulud 2.0 (November 2025) added Bun-based payloads that exfiltrate credentials to GitHub repositories.

## Severity Levels

| Level | Condition |
|-------|-----------|
| CRITICAL | npm publish, curl|bash, Bun payloads, campaign identifiers, destructive patterns, git-dep+lifecycle delivery, CI secrets exfil |
| HIGH | node -e one-liners, glob scanning, Bun runtime execution, forced exit after exec, Bun-only decompression API |
| MEDIUM | Git-resolved dependency without lifecycle script (provenance flag) |

## How to Fix

1. **Remove immediately**: Any package matching worm propagation patterns should be uninstalled
2. **Rotate all credentials**: If Shai-Hulud was installed, assume all env vars and npm tokens were exfiltrated
3. **Audit GitHub**: Check for unauthorized "Shai-Hulud" repositories in your org
4. **Use `--ignore-scripts`**: Prevent all future postinstall execution
5. **Pin dependencies**: Use lockfiles and pin exact versions

## References

- [Phylum: Shai-Hulud the npm worm is still crawling](https://blog.phylum.io/shai-hulud-the-npm-worm-is-still-crawling/)
- [SafeDep: Mini Shai-Hulud strikes again](https://safedep.io/mini-shai-hulud-strikes-again-314-npm-packages-compromised/)
- [Unit42: Shai-Hulud 2.0](https://unit42.paloaltonetworks.com/npm-supply-chain-attack-shai-hulud-2-0/)
