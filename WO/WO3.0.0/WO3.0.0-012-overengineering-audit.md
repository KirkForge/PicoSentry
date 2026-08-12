# WO3.0.0-012 — Over-engineering audit (READ-ONLY report)

**Series:** WO3.0.0 (improvement loop, 7→9)
**Status:** COMPLETE (report delivered; findings #2/#3 acted on in commit `42520317`; #1 flagged for dedicated WO; #5-#8 deferred)
**Owner:** subagent (research/explore — NO code changes)
**Scope:** READ across `picosentry/` (67K LOC). Do not modify any file.

**Gate:** N/A (read-only). Deliverable = this report, filled in.

## Objective
Find concrete over-engineering to trim. This is the highest-leverage 9/10 work: a clean
codebase with deliberate cuts beats one that grew by accretion. Report ONLY — the brain
decides what to cut after reviewing your findings.

## What to hunt (one finding per line, file:line + what to cut + what replaces it)
1. **Reinvented stdlib:** custom cache/backoff/lru/json-walk/deep-merge where `functools`,
   `itertools`, `collections`, `json`, `pathlib` already do it. Search for hand-rolled
   retry loops (vs `tenacity` already a dep? check), manual LRU dicts (vs `@lru_cache`),
   custom deep-copy/merge (vs `copy`/`dict |=`).
2. **Unneeded dependencies:** check `pyproject.toml` deps against actual imports. Any dep
   imported in <3 files or wrapping a trivial stdlib call is a candidate. List with usage count.
3. **Speculative abstraction:** interfaces/ABCs with a single implementation, factories with
   one product, config knobs that never vary from default, `Protocol` classes used once.
4. **Dead flexibility:** parameters/args no caller passes (verify by grep across the repo),
   feature flags always on or always off, `Optional[X]` that's never None at any call site.
5. **Boilerplate scaffolding:** "for later" hooks, stub methods returning NotImplementedError
   with no plugin contract, generic `Base*` classes nothing extends.

## Method (mandatory)
- Use Grep + Read + Glob. Do NOT run impact/context on everything — pick the top 5 largest
  source files first (`picosentry/serve/database/_schema.py` 829, `serve/services/auth.py` 726,
  `scan/cli_service.py` 651, `serve/api/models.py` 636, `serve/services/orchestrator.py` 612).
- For each dep candidate, count import sites across `picosentry/` before flagging.
- Verify every "no caller passes X" claim with a repo-wide grep before writing it down
  (false positives waste review cycles).

## Deliverable format (paste into your final message)
```
## Over-engineering findings (ranked by cut value)

### 1. [HIGH] <one-line title>
- Location: picosentry/path/file.py:LINE
- What to cut: <specific — function/class/param/deps>
- What replaces it: <stdlib call / inline / existing helper at X / nothing>
- Usage count: <N callers; verified by grep on <pattern>>
- Risk: <LOW|MEDIUM|HIGH> + why

### 2. [HIGH/MED/LOW] ...
(max 12 findings; quality over quantity. 3 strong findings beat 12 weak ones.)

## Verdict
- Top 3 cuts worth doing: ...
- Anything that LOOKS over-engineered but is actually load-bearing (don't cut): ...
```

## Notes
- Do NOT recommend cuts to security/validation/trust-boundary code. Those are never lazy-eligible.
- Do NOT recommend adding a dependency to remove one.
- Respect `ponytail:` comments — they already document deliberate simplifications; don't re-report them.
- An empty report ("everything looks fine") is acceptable ONLY if you genuinely checked the top 5
  files. Say so explicitly. Do not pad with weak findings.
