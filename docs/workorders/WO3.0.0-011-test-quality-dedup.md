# WO3.0.0-011 — Test-quality dedup on the two largest test files

**Series:** WO3.0.0 (improvement loop, 7→9)
**Status:** COMPLETE (merge `54a8b25f` on `dev`; 1593→1378 + 1530→1349; 210 tests passing)
**Owner:** subagent (own worktree off `origin/dev`)
**Scope:** ONLY these two files — do not touch any other file:
- `tests/serve/test_integration.py` (1593 lines)
- `tests/sandbox/test_cluster.py` (1530 lines)

**Gate:** `uv run ruff check tests/serve/test_integration.py tests/sandbox/test_cluster.py && uv run ruff format --check tests/serve/test_integration.py tests/sandbox/test_cluster.py && uv run pytest tests/serve/test_integration.py tests/sandbox/test_cluster.py -m "not slow" --timeout=120`

## Objective
Reduce the two largest test files in the repo to a maintainable size without losing coverage.
Target: each file <1200 lines, same number of passing tests (or more), no helper duplicated
within or across the two files.

## Root cause being addressed
These two files grew to 1500+ lines by accretion. That is a maintainability and flake-surface
smell, not a correctness bug. The fix is consolidation: extract shared fixtures/helpers into
the nearest conftest, delete dead helpers, and collapse repeated setup into parametrized cases.

## Specific work
1. Read both files fully. Inventory: every fixture, helper function, and `@pytest.fixture`
   defined *inside* the file. Note which are used once vs many times.
2. For each helper used <2 times: inline it if it's shorter than its definition (YAGNI).
3. For fixtures duplicated in both files OR in a sibling conftest: move to the nearest
   `conftest.py` (`tests/serve/conftest.py` or `tests/sandbox/conftest.py`) and delete the
   local copy. Do NOT move fixtures that are genuinely file-specific.
4. Collapse repeated test functions that differ only in input data into `@pytest.mark.parametrize`.
   Only collapse when the body is identical or near-identical; do not force-fit divergent assertions.
5. Delete dead code: helpers/fixtures/imports nothing references (verify with the gate —
   collection will fail if you break a reference).
6. Do NOT: rewrite tests to pass, weaken assertions, skip tests, add `|| true`, or delete
   tests for "coverage". Every test that passes today must pass after your change.

## Done-condition
- Both files <1200 lines (or a one-line justification in your final report if a specific
  file genuinely can't shrink without losing coverage).
- Same test count or more, all passing.
- No helper defined twice within or across the two files.
- Gate output pasted in your final report, with the head SHA of your branch.

## Notes
- You MUST produce a real diff. An empty report is a failure (see lessons.md: subagents that
  return empty need a hard requirement to produce a change).
- Preserve honest-doc annotations (`ponytail:`, `ceiling:`, `upgrade path:`).
- Match existing style. No comments unless asked.
