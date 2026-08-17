# AGENTS.md — Worker Contract for KirkForge-PicoSeries-picosentry (PicoSentry)

*This file is the verifier contract for any AI agent working in this repo. Read it before starting. Follow it always. Violations are regressions.*

*Repo facts: Offline supply-chain security suite — scanner, sandbox, LLM defense, orchestration. Stack: Python ≥3.10, FastAPI, ruff, mypy, pytest. Uses `uv` for env/dep management. License: BUSL-1.1. Default branch: `main`; work lands on `dev`.*

## 0. Entry files (read on startup, in this order)

1. **AGENTS.md** (this file) — the workflow contract.
2. **state.md** — current state of the codebase: last session's changes, pending work, blocked items, backlog with fix sketches.
3. **CHANGELOG.md** (head, ~50 lines) — recently completed work. One section per landed batch.
4. **lessons.md** (gitignored) — gotchas and patterns from prior sessions. Permanent ones get folded into this file's "Permanent conventions".

**Single source of work-order truth: `docs/workorders/`.** `workplan.md` (gitignored) is per-session scratch — plans, notes, scratch output. It is NOT a record and never a second truth. The root `WO/` folder was consolidated into `docs/workorders/` on 2026-08-17 and deleted — do not recreate it.

## 1. Session flow

1. **Plan**: write `workplan.md` (scratch) — files to touch, root cause (not symptom), gate to run. Substantial named work gets a WO file in `docs/workorders/` (`WO<major>.<minor>.<patch>-NNN-slug.md`, headers: Series/Status/Owner/Scope/Gate/Objective). Active series: **WO4.0.0** (seeded 2026-08-17, 24 WOs — see `docs/workorders/README.md`); next free series: WO5.0.0.
2. **Before implementation**: re-read state.md (pending/backlog), lessons.md, this file. If the task is unclear, say so and escalate — do not guess.
3. **Check progression**: after each file edit, verify it lints/compiles. Don't batch 10 changes then discover the 3rd was wrong.
4. **Session close** (all required, in order): commit → `lessons.md` (what I learned / didn't work / would do differently) → `state.md` (what changed, pending, blocked) → `CHANGELOG.md` entry → verify clean tree → verify gates green → paste final gate output + head SHA. A session is NOT done until all are done.
5. **Commit target**: routine work commits directly to `dev`. Risky/disjoint parallel work runs in dedicated worktrees branched `wo/<series>/<slug>` off `origin/dev` (see §2); the orchestrator merges them into `dev` (`--no-ff`) and re-runs gates so `dev` CI is green after every merge. Never touch `main` directly. Never force-push. Fix forward.

## 2. Subagent strategy

- For complex multi-step tasks, dispatch subagents with **exclusive file ownership** (disjoint trees). Shared files (CHANGELOG/state/lessons/workplan) are orchestrator-only; subagents are told so explicitly.
- Each subtask must state: scope (files to touch), gate (command), done-condition, and report format (FIXED/FLAGGED/gate-tails/diff-stat).
- Subagents doing risky or merge-sensitive work get their **own worktree**: `git worktree add <path> origin/dev -b wo/<series>/<slug>`, commit there, orchestrator merges. Same-tree parallel work is acceptable only when ownership is provably disjoint.
- Do not dispatch a subagent for a task you can do in <5 minutes yourself.
- After all subagents return: re-verify cross-agent complaints against the final tree (in-flight states go stale), reconcile seams (mocks, wirings), run central gates once.

## 3. Tests & CI — keep the quality, watch the clock

The suite is the product's safety net AND a recurring time cost. Both matter; neither wins alone. Rules (learned the hard way, see lessons.md 2026-08-17):

- **Profiles, not ad-hoc flags**: `scripts/test.sh {fast,integration,full,nightly}` owns marker/timeout/durations policy. Default = `fast`. PR CI runs `fast`; push runs `integration` (4-python matrix); nightly runs everything + junit artifact. Never inline marker expressions in CI YAML or commands when a profile exists.
- **Local changed-path runs**: `scripts/test-changed.sh [base]` maps changed paths → test dirs → `scripts/test.sh fast <dirs>`.
- **Measurement-first**: never optimize test speed without numbers. `scripts/test.sh fast --junit -q` then `python3 scripts/check-test-budget.py .pytest-artifacts/junit-fast.xml --top 40`. Attack the top ~20 by wall time only; the hundreds of 0.2–2 ms unit tests are not the problem.
- **No wall-clock sleeps in tests**: inject/monkeypatch the clock the production code reads (`monkeypatch.setattr("picosentry.<mod>.time.monotonic", fake)` and advance it manually). Genuine timeout-mechanism tests shrink ALL scales together (rule sleep AND timebox), keeping the same margin at a fraction of the cost.
- **No global state in tests**: `monkeypatch.setenv/delenv`, never direct `os.environ[...] =`. Never accept `--dist=loadfile` long poles: check per-file junit sums; split giant files (bodies byte-identical) so workers balance.
- **Profile expensive config defaults**: crypto/KDF costs (bcrypt rounds, key sizes in test env) are a silent per-test tax — `tests/serve/conftest.py` sets `password_hash_rounds=4` for exactly this reason. Check for the class before micro-optimizing tests.
- **Budget guard**: `scripts/check-test-budget.py` runs warn-mode on PRs, enforced on push — slow-test regressions surface in CI, junit + top-20 report uploaded on push/nightly. When touching tests, keep the suite under budget; if a test legitimately needs more time, it belongs in a slower tier (`slow` marker), documented — not an inline exception.
- **CI structure** (`.github/workflows/ci.yml`): PR = lint + type-check + one pytest job (fast) + cli/determinism + scan-artifacts, path-gated by a `changes` job (docs-only PRs skip pytest); push(main/dev) = 4-python matrix + postgres-live + docker(amd64+arm64) + reproducible-build; nightly = full corpus incl. malicious-workload + coverage + dependency-audit + junit artifacts. Concurrency cancellation is on — never remove it. New validations get placed in the cheapest tier that still catches the regression.

## 4. Verification

- Run the gates before every commit. Paste the actual output (not paraphrased). A green claim requires the pasted output + the head SHA. "It passed" is not evidence.
- Gates for this repo:
  - Test: `bash scripts/test.sh fast` (wraps `uv run --extra all --extra dev pytest`; addopts in `pyproject.toml`: `-ra --strict-markers --tb=short -n auto --dist=loadfile --timeout=60`; markers: `slow`, `network`, `benchmark_realworld`, `malicious_workload`)
  - Lint: `uv run ruff check` (`target-version py310`, `line-length 120`)
  - Fmt: `uv run ruff format --check` (double quotes, space indent; `uv run ruff format` to write)
  - Typecheck: `uv run mypy picosentry/` (`python_version 3.10`, `strict=false` but `warn_unreachable`/`warn_unused_ignores`/`warn_redundant_casts` on)
- Do not rewrite tests to make them pass. Fix the root cause.
- Do not add `|| true`, `|| echo "non-fatal"`, `#[ignore]` to make red go green. Markers are for *categorizing* tests into tiers, not for hiding failures. Recalibrating a floor is legitimate ONLY when the measurement population changed (document why where the number lives) — never to hide a regression.
- Do not commit `picowatch_audit.db`, `*.corpus.json`, `.coverage`, `.pytest-artifacts/`, `picosentry/serve/backups/temp_*/`, or runtime sandbox state (`.picodome/`).
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

## 7. Release policy (dev → main → PyPI)

- **Trigger**: `dev` is ~20 commits ahead of `main`, OR a security-relevant fix has landed (sooner, as a patch release), whichever comes first.
- **Flow**: gates green on `dev` → ff `main` to `dev` → bump `version` in `pyproject.toml` (+ CHANGELOG section) → build reproducibly (`SOURCE_DATE_EPOCH` from the commit timestamp; two builds must hash identically) → publish.
- **Publishing config**: upload credentials/index live in `/home/henrik/madlab/Lockdown/.pypi` — read at runtime, NEVER print, NEVER commit. Regular pushes use SSH remote (`gh` over SSH). `/home/henrik/madlab/Lockdown/.github_pat` is only for comprehensive GitHub work that needs PAT auth — same rule: read at runtime, never echo, never commit.
- Tag the release (`v<version>`), push `main` + tag, verify the published artifact digests against the local build.

## Scope & honesty discipline

- Touch only the files the task names. Edit outside scope only with a `lessons.md` note ("scope creep: <file> because <reason>").
- Paste gate output; never say "green" without the head SHA. An ADR/doc that overclaims is a regression. Benchmark claims must be reproducible from a fresh clone — a validation harness that silently skips inputs manufactures stale claims.

## Escalation
If you are stuck after 3 attempts, say so. Write "ESCALATE: <root cause unknown>" in `lessons.md`. The brain (frontier model) takes over. This is not a failure — it's the design: the Fiat knows when to call the tow truck.

## Permanent conventions (from lessons.md)

- **FastAPI return types**: When an endpoint may return `JSONResponse` (error path) alongside a dict (happy path), use `response_model=None` on the decorator to prevent `FastAPIError` at route registration.
- **Pydantic v1/v2 compat**: Use `hasattr(obj, "model_dump")` guard or `pydantic.VERSION` check for model serialization. Never assume v2-only APIs.
- **CORS with credentials**: Never use `allow_methods=["*"]` or `allow_headers=["*"]` with `allow_credentials=True`. Use explicit method/header lists.
- **API key comparison**: Always use `hmac.compare_digest` for any secret/token comparison, even after DB lookup. Defense in depth.
- **Request ID propagation**: Use `contextvars.ContextVar` + `logging.Filter` to inject request IDs into all structured log lines, not just explicit `logger.info()` calls.
- **Database pool staleness**: Always add a `SELECT 1` liveness check in connection pool `acquire()`. Stale connections (deleted DB, WAL corruption) are a real production scenario.
- **Resource limits on subprocesses**: Set `RLIMIT_AS`, `RLIMIT_FSIZE`, `RLIMIT_NOFILE` in `preexec_fn` for sandbox subprocesses. Configurable via `PICODOME_MEMORY_LIMIT_MB` and `PICODOME_FILE_SIZE_LIMIT_MB`.
- **Websocket auth**: Never accept JWT tokens in query strings in production — they leak into proxy logs and browser history.
- **Pydantic models for API input**: Always use `extra="forbid"` on request models. Never accept `dict` or `dict[str, Any]` for user-supplied parameters.

<!-- gitnexus:start -->
# GitNexus — Code Intelligence

This project is indexed by GitNexus as **PicoSentry** (14856 symbols, 31204 relationships, 300 execution flows). Use the GitNexus MCP tools to understand code, assess impact, and navigate safely.

> Index stale? Run `node .gitnexus/run.cjs analyze` from the project root — it auto-selects an available runner. No `.gitnexus/run.cjs` yet? `npx gitnexus analyze` (npm 11 crash → `npm i -g gitnexus`; #1939).

## Always Do

- **MUST run impact analysis before editing any symbol.** Before modifying a function, class, or method, run `impact({target: "symbolName", direction: "upstream"})` and report the blast radius (direct callers, affected processes, risk level) to the user.
- **MUST run `detect_changes()` before committing** to verify your changes only affect expected symbols and execution flows. For regression review, compare against the default branch: `detect_changes({scope: "compare", base_ref: "main"})`.
- **MUST warn the user** if impact analysis returns HIGH or CRITICAL risk before proceeding with edits.
- When exploring unfamiliar code, use `query({search_query: "concept"})` to find execution flows instead of grepping. It returns process-grouped results ranked by relevance.
- When you need full context on a specific symbol — callers, callees, which execution flows it participates in — use `context({name: "symbolName"})`.
- For security review, `explain({target: "fileOrSymbol"})` lists taint findings (source→sink flows; needs `analyze --pdg`).

## Never Do

- NEVER edit a function, class, or method without first running `impact` on it.
- NEVER ignore HIGH or CRITICAL risk warnings from impact analysis.
- NEVER rename symbols with find-and-replace — use `rename` which understands the call graph.
- NEVER commit changes without running `detect_changes()` to check affected scope.

## Resources

| Resource | Use for |
|----------|---------|
| `gitnexus://repo/PicoSentry/context` | Codebase overview, check index freshness |
| `gitnexus://repo/PicoSentry/clusters` | All functional areas |
| `gitnexus://repo/PicoSentry/processes` | All execution flows |
| `gitnexus://repo/PicoSentry/process/{name}` | Step-by-step execution trace |

## CLI

| Task | Read this skill file |
|------|---------------------|
| Understand architecture / "How does X work?" | `.claude/skills/gitnexus/gitnexus-exploring/SKILL.md` |
| Blast radius / "What breaks if I change X?" | `.claude/skills/gitnexus/gitnexus-impact-analysis/SKILL.md` |
| Trace bugs / "Why is X failing?" | `.claude/skills/gitnexus/gitnexus-debugging/SKILL.md` |
| Rename / extract / split / refactor | `.claude/skills/gitnexus/gitnexus-refactoring/SKILL.md` |
| Tools, resources, schema reference | `.claude/skills/gitnexus/gitnexus-guide/SKILL.md` |
| Index, status, clean, wiki CLI commands | `.claude/skills/gitnexus/gitnexus-cli/SKILL.md` |

<!-- gitnexus:end -->
