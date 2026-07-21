# AGENTS.md — Worker Contract for KirkForge-PicoSeries-picosentry (PicoSentry)

*This file is the verifier contract for any AI agent working in this repo. Read it before starting. Follow it always. Violations are regressions.*

*Repo facts: Offline supply-chain security suite — scanner, sandbox, LLM defense, orchestration. Stack: Python ≥3.10, FastAPI, ruff, mypy, pytest. Uses `uv` for env/dep management. License: BUSL-1.1. Default branch: `main`.*

## 1. Plan mode default
- Before writing any code, write a plan to `workplan.md` (gitignored). The plan must list the files you will touch (full paths), state the root cause you're fixing (not the symptom), and state the gate you'll run to verify.
- Check `workplan.md` before implementation. Check `lessons.md` for lessons from prior sessions. Check `state.md` for current repo state.
- If the task is unclear, say so in `workplan.md` and escalate — do not guess.

## 2. Subagent strategy
- For complex multi-step tasks, break them into subtasks and dispatch subagents.
- Each subtask must have a clear scope (files to touch), a gate (command to run), and a done-condition.
- Do not dispatch a subagent for a task you can do in <5 minutes yourself.

## 3. Self-improving loop
- At session end, write `lessons.md` (gitignored) with: what you learned about this codebase (conventions, gotchas, patterns), what you tried that didn't work and why, what you'd do differently next time.
- Update `state.md` (tracked) with: what changed this session, what's pending, what's blocked.
- Lessons from `lessons.md` that are permanent conventions get folded into this `AGENTS.md` file — so the next worker reads them automatically.

## 4. Verification
- Run the gates before every commit. Paste the actual output (not paraphrased). A green claim requires the pasted output + the head SHA. "It passed" is not evidence.
- Gates for this repo:
  - Test: `uv run pytest` (addopts in `pyproject.toml`: `-ra --strict-markers --tb=short -n auto --dist=loadfile --timeout=60`; `slow` and `network` markers available — deselect with `-m "not slow"`)
  - Lint: `uv run ruff check` (`target-version py310`, `line-length 120`)
  - Fmt: `uv run ruff format --check` (double quotes, space indent; `uv run ruff format` to write)
  - Typecheck: `uv run mypy` (`python_version 3.10`, `strict=false` but `warn_unreachable`/`warn_unused_ignores`/`warn_redundant_casts` on)
- Do not rewrite tests to make them pass. Fix the root cause.
- Do not add `|| true`, `|| echo "non-fatal"`, `#[ignore]` to make red go green. `pytest` markers `slow`/`network` are for *categorizing* tests, not for hiding failures.
- Do not commit `picowatch_audit.db`, `*.corpus.json`, `.coverage`, `picosentry/serve/backups/temp_*/`, or runtime sandbox state (`.picodome/`).
- Malicious fixture files in `tests/scan/fixtures/` are intentionally invalid Python — don't "fix" them, and don't let ruff/mypy reformat them (they're excluded).

## 5. Demand elegance
- Small, pure, well-named functions. No dead code. No debug spam (`print(`) in committed code.
- Match the existing style. Ruff rules: `E, F, W, I, N, UP, B, A, C4, SIM, RUF, FURB, PIE, ...`. Naming `N` rules largely ignored (`N806/N818/N802/N812`); `I001` (isort) is suppressed for the minified shipped code — don't add isort-style blank-line churn.
- Preserve honest-doc annotations (`ponytail:`, `ceiling:`, `upgrade path:`) — they document known limitations. Removing them is a regression.
- Per-file ignores in `pyproject.toml` are deliberate (gRPC stubs, security output formatters, fixture files) — don't "clean them up".
- A change that adds 100 lines to fix a 3-line bug is probably wrong. Find the smaller change.

## 6. Autonomous bug fixing
- If a test fails, read the error. Find the root cause. Fix it.
- Do NOT: rewrite the test to pass, add `|| true`, lower a threshold, delete the assertion, add `#[ignore]` to make red go green.
- Do NOT: add debug logging to committed code. Use `workplan.md` for scratch notes.
- If you've attempted the same fix 3 times and it's still red, STOP. Write "ESCALATE: <root cause unknown>" in `lessons.md` and return. The brain takes over when the brawn is stuck.

## Task management
1. **Plan**: write `workplan.md` (gitignored) with files to touch + root cause + gate.
2. **Check before implementation**: read `workplan.md`, `lessons.md`, `state.md`, and this `AGENTS.md`.
3. **Check progression**: after each file edit, verify it compiles/lints. Don't batch 10 changes then discover the 3rd was wrong.
4. **Explain changes**: post a summary in `workplan.md` (what changed, why) and a one-liner in `CHANGELOG.md` (it exists, 73KB).
5. **Session close**: commit → write `lessons.md` (what I learned) → update `state.md` (what changed, what's pending) → `CHANGELOG.md` one-liner → verify clean tree → verify gates green → paste final gate output. Session is NOT done until all 6 are done.
6. **Worktree discipline**: work in an isolated worktree off `origin/main` (this repo's default branch is `main`). `git fetch && git reset --hard origin/main` before starting. Never touch `main` directly. Never force-push. Fix forward.
7. **Scope discipline**: touch only the files the task names. If you need to edit outside scope, note it in `lessons.md` as "scope creep: <file> because <reason>".
8. **Honesty over claim**: paste gate output, never say "green" without the run ID + head SHA. An ADR that overclaims is a regression. A "CI green" citation for the wrong run ID is a regression.

## Escalation
If you are stuck after 3 attempts, say so. Write "ESCALATE: <root cause unknown>" in `lessons.md`. The brain (frontier model) takes over. This is not a failure — it's the design: the Fiat knows when to call the tow truck.