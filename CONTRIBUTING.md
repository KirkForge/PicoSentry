# Contributing to PicoSentry

## Quick start

```bash
git clone https://github.com/KirkForge/PicoSentry.git
cd PicoSentry

# Create a venv and install in editable mode with dev deps
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,scan,serve]"

# Run the full CI-quality test suite in parallel
python scripts/test_doctor.py --workers 4

# Run only a subset of areas
python scripts/test_doctor.py --areas scan sandbox

# Reproduce a CI failure exactly (no pytest-xdist, same commands as CI)
python scripts/test_doctor.py --ci --areas serve

# Auto-fix lint/format issues before committing
python scripts/test_doctor.py --fix

# Save a JSON report for CI artifacts or debugging
python scripts/test_doctor.py --workers 4 --report doctor.json
```

## PicoSentry at a glance

The codebase is organized by product surface, not by layer:

```text
picosentry/
  cli.py            # top-level command dispatcher
  scan/             # supply-chain scanner (stable)
    engine.py
    rules/
    models.py
    validation.py
  watch/            # LLM prompt/output guard (beta)
    prompt_guard/
    output_guard/
    server.py
    telemetry/
  sandbox/          # runtime sandbox (beta)
    l3/             # syscall policy backends
    l4/             # behavioral analysis
    daemon/
  serve/            # API server, orchestrator, plugins (beta)
    server.py
    services/       # auth, orchestrator, plugin host, webhooks, correlation, cluster
    config/
  _core/            # cross-cutting utilities
```

Entry points for the most common changes:

| Task | Start here |
|------|------------|
| Add a scan rule | `docs/EXTENSION_GUIDE.md` → `picosentry/scan/rules/` |
| Add a watch rule | `docs/EXTENSION_GUIDE.md` → `picosentry/watch/rules/` |
| Add a sandbox backend | `docs/EXTENSION_GUIDE.md` → `picosentry/sandbox/l3/backends/` |
| Find an internal API | `docs/INTERNAL_API.md` |
| Understand trust boundaries | `docs/ARCHITECTURE.md` |
| Write a plugin | `docs/PLUGIN_DEVELOPMENT.md` |

## What we need help with

| Area | Skill needed | Complexity |
|------|-------------|------------|
| **New detection rules** | Python, package-ecosystem knowledge | Low |
| **Corpus and IoC packs** | Research, finding real malicious packages | Low |
| **Documentation** | Technical writing | Low |
| **Test coverage** | Python, pytest | Low |
| **Example projects** | Any ecosystem (npm, PyPI, Go, etc.) | Low |
| **Prompt injection patterns** | LLM security | Medium |
| **Detector improvements** | Python, security research | Medium |
| **Dashboard frontend** | HTML/CSS/JS | Medium |
| **Postgres migration** | SQL, asyncpg/psycopg | High |

## Guidelines

- **Determinism matters**: Don't introduce randomness, timing-dependent logic, or non-deterministic IDs into findings. Read `docs/determinism.md`.
- **Add tests**: New rules need test fixtures with known-good and known-bad examples.
- **Sort imports**: Run `ruff check picosentry/ --fix` before committing.
- **One feature per PR**: Small, focused PRs get reviewed faster.
- **Never commit secrets**: Run the pre-commit hooks (see below) so secret-scanning runs before every commit. Never commit credentials, tokens, or private keys — even in compiled build artifacts (the `target/` directory in Rust projects can embed env secrets).

## Pre-commit hooks

A `.pre-commit-config.yaml` is provided. Run manually before committing:

```bash
pip install pre-commit
pre-commit run --all-files
```

This runs `ruff` (lint + format) and `trufflehog` (secret scanning). Note that
this repository sets `core.hooksPath` to an external hooks directory, so
`pre-commit install` may refuse to overwrite it; use the manual run command
instead, or unset `core.hooksPath` first if you want git-triggered hooks.

## Code of conduct

Be respectful, assume good intent, and keep discussions technical. No harassment, no politics.

## License

By contributing, you agree that your contributions will be licensed under BUSL-1.1 (same as the project).