# Changelog

All notable changes to PicoSentry will be documented in this file.

## [2.0.0] — 2025-06-03

### Changed
- Unified 4 previously separate packages (picosentry, picodome, picowatch, picoshogun) into one CLI.
- Vendored pico-core dependency directly into `picosentry._core` to eliminate install friction (#3).

### Added
- `picosentry scan` — supply-chain scanner for npm, PyPI, Go, Cargo, Maven, RubyGems, NuGet.
- `picosentry sandbox` — seccomp-bpf runtime sandbox with behavioral analysis.
- `picosentry watch` — LLM prompt-injection detection and output validation.
- `picosentry serve` — API server, dashboard, and orchestration.
- Cross-layer correlation engine linking scan findings → sandbox behavior → watch alerts.
- Deterministic output guarantee: same inputs + same policy = same SHA-256.

### Removed
- External `pico-core` dependency (now vendored).

## [1.x] — Individual packages (deprecated)

See individual repos for history:
- [PicoSentry v1](https://github.com/KirkForge/picosentry)
- [PicoDome](https://github.com/KirkForge/picodome)
- [PicoWatch](https://github.com/KirkForge/picowatch)
- [PicoShogun](https://github.com/KirkForge/picoshogun)