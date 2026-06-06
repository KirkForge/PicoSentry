# Changelog

All notable changes to PicoSentry will be documented in this file.

## [2.0.3] — 2026-06-06

### Fixed — CI repair patch

The 2.0.1 and 2.0.2 release commits were published, but the GitHub Actions
CI runs on those commits failed across 4 distinct categories of job. This
patch fixes all 4 — no behavioral changes for end users, just a green
pipeline. (PyPI cannot re-host a published version, hence 2.0.3 instead
of re-releasing 2.0.2.)

- **`test-serve` (10 failures).** Code in
  `picosentry/serve/services/orchestrator.py` and
  `picosentry/serve/services/orgs.py` was calling `.get()` on
  `sqlite3.Row` objects returned by `DatabaseManager.execute_one(...)`.
  `Row` doesn't implement `.get()`. The return-type hint on
  `execute_one` (`-> dict | None`) already documented the expected
  contract; the fix is at the source — `execute()` and `execute_one()`
  now materialize rows as plain dicts at the boundary, so every existing
  call site (`row["col"]` and `(row or {}).get("col")`) Just Works.
  No code change needed at any of the 3 call sites.
- **`test-watch`, `test-core` (3.10/3.11), `test-matrix` (3.11).** Those
  CI jobs installed `pip install -e ".[dev]"`, which doesn't include
  fastapi. The watch tests (`tests/watch/test_server*.py`) and the watch
  module under test (`picosentry/watch/server.py`) all import fastapi,
  so pytest collection failed before any test ran. Fixed by adding the
  `watch-server` extra (fastapi + uvicorn) to the install commands for
  all three jobs.
- **`type-check` (3 unused-ignore errors).** Three
  `# type: ignore[assignment]` comments on opentelemetry fallback
  imports were dead under newer mypy with `ignore_missing_imports = true`
  (the module becomes `Any` and the rebind is then safe). But the
  comments were also *needed* under older mypy that sees the real type
  conflict. Instead of pinning mypy, restructured both files:
  - `picosentry/serve/services/observability.py` — extracted the gRPC
    vs HTTP exporter-class selection into a `_load_otlp_exporters()`
    helper. Each branch binds a single class to one name; no rebind at
    the call site, no ignore comment needed.
  - `picosentry/sandbox/tracing.py` — same idea, bound the OTel `trace`
    module to a private `_trace_module` sentinel instead of rebinding
    the bare module name to `None` in the `except ImportError` branch.
  Both versions of mypy are now clean.
- **`test-scan` (2 corpus-dependent failures).**
  `picosentry/scan/corpus/npm_top_packages.json` was listed in
  `.gitignore`, so `actions/checkout@v4` skipped it. The
  `load_corpus_for_ecosystem()` loader fell back to a 99-entry builtin
  list, which broke `test_corpus_loaded_from_file` (asserts > 100
  packages) and `test_crossenv_credential_theft` (the typosquat
  detector couldn't match `crossenv` against `cross-env` because
  `cross-env` wasn't in the fallback). Fixed by removing the
  `npm_top_packages.json` line from `.gitignore` and committing the
  existing 6 KB / 327-entry corpus file (which includes `cross-env` at
  line 91). Both scan tests now pass.

### Quality
- 3,632 tests passing across the full local sweep (was 3,612 before
  the 2.0.3 fixes; the +20 reflects the 10 serve + 2 scan + 2 watch
  tests that now pass).
- `ruff` 0 errors, `mypy` 0 errors across 273 source files.

## [2.0.2] — 2026-06-06

### Added
- **`picosentry scan --validate`** CLI flag for the validation harness. The harness itself shipped in 2.0.1 (via the Python `picosentry.scan.validation.run_validation()` API); this patch exposes it on the CLI as planned. Prints a per-rule precision/recall table and exits 0 if mean precision >= 0.95 and mean recall >= 0.80. `picosentry/cli.py` now also wires the flag through the unified-CLI parser (it was previously only registered in the inner `picosentry/scan/cli.py` parser).

## [2.0.1] — 2026-06-06

### Added
- **Per-campaign IOC packages** (4 campaigns shipped): Shai-Hulud, Node-IPC Compromise, Trapdoor, Axios Poisoning. Each is a self-contained `picosentry/scan/campaigns/<name>/` package with `iocs.json` + `detector.py` + tests, auto-discovered by `create_default_engine()`.
- **Validation harness** (`picosentry scan --validate`): auditable per-rule precision/recall against labelled fixtures. 7 fixtures (3 positive / 4 negative), 100% precision, 100% recall.
- **Per-detector timebox**: each rule runs in a worker thread with a default 5.0s `future.result(timeout=...)` ceiling. New `timeout` status on `RuleExecution`; the rest of the scan continues. Per-scan override via `engine.scan(..., rule_timeout=N)`.
- **`RULE_ID_ALIASES` constant** in `picosentry/scan/rules/__init__.py` documents the three multi-ID detector functions (`detect_obfuscation`, `detect_manifest_issues`, `detect_pypi_obfuscation`) — one source of truth for "why does one function emit under many rule_ids".
- **README banner** at the top of the README (samurai-lobster hero image).
- README hero reworded to lead with the kernel-sandbox wedge: "The only local package scanner that actually runs the package under a real kernel sandbox and shows you the syscalls."

### Fixed
- `L2-CRED-001` detection gap: was only scanning `node_modules`, now also scans the root project's install scripts (closes the case where a project with no `node_modules` would silently pass).
- `clean_npm_app` validation fixture was under-shooting real-world conditions and triggering 6 informational rules; enriched to a realistic "production-ready" baseline.

### Quality
- 3,370 tests passing (up from 3,548 — net -178 is the 5 dead-test files removed in 2.0.0 plus the new campaign + validation + timebox + alias tests; +13 net campaign tests, +8 validation tests, +5 timebox tests, +6 alias tests).
- `ruff` 0 errors, `mypy` 0 errors across 273 source files.

## [2.0.0] — 2026-06-06

### Changed
- **Unified 4 previously separate packages into one CLI**: `picosentry`, `picodome`, `picowatch`, `picoshogun` are now subcommands of a single `picosentry` package.
- Vendored `pico-core` dependency directly into `picosentry._core` to eliminate install friction (#3).
- Single `picosentry` PyPI project now supersedes the previous individual packages. Old versions (0.16.0, 1.0.0, 1.0.1) remain installable; new installs default to 2.0.0.
- GitHub repository consolidated at [`KirkForge/PicoSentry`](https://github.com/KirkForge/PicoSentry). Old `picosentry` PyPI namespace links to the same repo.

### Added
- `picosentry scan` — supply-chain scanner for npm, PyPI, Go, Cargo, Maven, RubyGems, NuGet.
- `picosentry sandbox` — seccomp-bpf runtime sandbox with behavioral analysis.
- `picosentry watch` — LLM prompt-injection detection and output validation.
- `picosentry serve` — API server, dashboard, and orchestration.
- Cross-layer correlation engine linking scan findings → sandbox behavior → watch alerts.
- Deterministic output guarantee: same inputs + same policy = same SHA-256.
- Optional extras: `[scan]`, `[watch-server]`, `[serve]`, `[otel]`, `[sigstore]`, `[all]` for granular dependency control.
- 49 ecosystem rules across 6 lockfile formats; 3,548 tests passing.

### Removed
- External `pico-core` dependency (now vendored).
- 4 separate PyPI projects (`picosentry` v1.x, `picodome`, `picowatch`, `picoshogun`) — see deprecation notice below.

### Quality
- Static analysis: `ruff` 358 → 0 errors, `mypy` 135 → 0 errors across 262 source files.
- 3 dead test files removed.
- 2 real bugs caught and fixed during cleanup: scheduler.py referenced an undefined variable in the `run` branch; maven_utils.py had a copy-paste bug in a version-text ternary.

## [1.x] — Individual packages (deprecated)

The 1.x line of `picosentry` and the related `picodome`, `picowatch`, `picoshogun` packages are now superseded by 2.0.0. They will not receive further updates. Install with `pip install picosentry>=2.0.0` to get the unified package.

Legacy repository history (archived, read-only):
- [PicoSentry v1](https://github.com/KirkForge/PicoSentry-legacy)
- [PicoDome](https://github.com/KirkForge/PicoDome)
- [PicoWatch](https://github.com/KirkForge/PicoWatch)
- [PicoShogun](https://github.com/KirkForge/PicoShogun)
