# WO3.0.0-013 — `_core` consolidation audit + safe dedup

**Series:** WO3.0.0 (improvement loop, 7→9)
**Status:** COMPLETE (merge `50248aec` on `dev`; 11 call sites → `constant_time_compare`; +22/-14)
**Owner:** subagent (own worktree off `origin/dev`)
**Scope:** `picosentry/_core/` (read + edit) and the specific call sites you consolidate (edit).
Do NOT touch test files, docs, or unrelated source.

**Gate:** `uv run ruff check picosentry/_core/ && uv run ruff format --check picosentry/_core/ && uv run mypy picosentry/_core/ && uv run pytest tests/_core/ tests/scan/ -m "not slow" --timeout=120`
(if `tests/_core/` doesn't exist, run `uv run pytest tests/ -k "core or config or guards or doctor" -m "not slow"` instead)

## Objective
`picosentry/_core/` was created as the shared utility layer (config.py 201, guards.py 207,
doctor.py 355, security_check.py 154, models.py 66, tracing.py 59, time.py 7, policy.py 18).
There is likely duplicated logic OUTSIDE `_core` (in scan/, serve/, sandbox/, watch/) that
should be calling `_core` instead. Find the top concrete dedup opportunities and consolidate
the highest-value one or two.

## Root cause being addressed
The shared layer exists but isn't fully used — modules reinvent config loading, guard helpers,
or security checks that `_core` already provides. Consolidation reduces surface area and
guarantees the security-critical paths go through one place.

## Specific work
1. Read every file in `picosentry/_core/`. Build a mental inventory of what each public
   function/class does.
2. For each public helper in `_core`, Grep the rest of `picosentry/` for likely re-implementations:
   - `config.py`: search for `os.environ.get` / `load_dotenv` / manual env parsing outside `_core`.
   - `guards.py`: search for `isinstance` checks / validation patterns / `assert` chains that
     mirror guard logic.
   - `security_check.py`: search for duplicated security validation (path checks, secret checks).
   - `doctor.py`: health-check patterns duplicated in serve/health or sandbox.
   - `time.py` / `tracing.py` / `models.py`: small utils often copy-pasted.
3. Pick the **ONE or TWO highest-value consolidations** where:
   - The duplicate is clearly the same logic (not a coincidentally similar name).
   - The `_core` version is correct and complete (don't route through an incomplete helper).
   - Consolidation is safe (the call site's behavior is preserved exactly).
4. Make the edits: replace the duplicate with an import + call to `_core`. Run the gate after EACH file.
5. Do NOT force consolidation where the "duplicate" is actually a different abstraction that
   happens to look similar. Note these in your report as "considered, rejected because <reason>".

## Done-condition
- 1–2 real consolidations made (or a clear report that `_core` is already fully used — verify
  with grep counts before claiming this).
- Every edit preserves behavior: same test count, all passing.
- Gate output pasted with head SHA.
- Report lists: what you consolidated, what you rejected and why.

## Notes
- Security/validation paths are NEVER lazy-eligible for cuts — but routing them through ONE
  `_core` implementation (instead of N copies) is a security WIN. Prefer those consolidations.
- You MUST produce a real diff if any dedup target exists. Empty report only if verified clean.
- Preserve honest-doc annotations. Match existing style.
- If a consolidation would require changing `_core`'s signature, STOP — note it and leave the
  duplicate in place. Changing shared signatures is out of scope (separate WO).
