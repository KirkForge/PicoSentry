# WO6.0.0-007 — Scan: `deny_packages` policy SUPPRESSES security findings for the banned packages (inverted semantics)

**Series:** WO6.0.0 (exploration round 2026-08-18 evening)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/6.0.0/policy-deny-inversion`)
**Priority:** P0 · Effort S · Risk L
**Scope:** `picosentry/scan/cli_service.py`, `tests/scan/`

**Gate:** `bash scripts/test.sh fast` + test: banned package's findings SURVIVE (or escalate) with the policy violation present; exit code computed from the full finding set.

## Objective
An org bans a package precisely because it's suspicious — today adding it to `deny_packages` REMOVES its findings from the result (and the cached shape), flipping fail-exit to 0.

## Evidence (verified 2026-08-18, explorer SA-AP; live, `--no-cache`, eval+hex payload in node_modules/evil-pkg)
- No policy: 11 findings incl. L2-OBFS-001×2, L2-OBFS-002. With `--policy` (`deny_packages: ["evil-pkg"]`): 8 findings — all three OBFS gone; exit decisions (`cli_service.py:689-698`, from findings only) can flip 1→0.
- `cli_service.py:357-360`; policy semantics are the OPPOSITE (`policy_pkg/engine.py:189-209`: deny-list → ERROR violation). Matching inconsistent: `evil-pkg` findings dropped, `evil-pkg@1.0.0` survive (policy engine strips `@version`; this filter doesn't). Suppressed shape persisted by `_save_cache`. Pre-existing (git-blamed to the original CLI split), not a WO5 regression.
- Adjacent dead code: `deny_licenses` filter (`:361-369`) — `f.licenses` doesn't exist on Finding → never drops anything.

## Deliverables
1. Delete the `deny_packages` finding-suppression block (violations already surface via `_apply_policy`) or invert to escalate severity; delete the dead `deny_licenses` block.
2. Regression test per the gate.
