# Changelog

All notable changes to PicoSentry will be documented in this file.

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
