# Contributing to PicoSentry

## Quick start

```bash
git clone https://github.com/KirkForge/PicoSentry.git
cd PicoSentry

# Create a venv and install in editable mode with dev deps
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev,scan,serve]"

# Run the test suite
python -m pytest
```

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

## Code of conduct

Be respectful, assume good intent, and keep discussions technical. No harassment, no politics.

## License

By contributing, you agree that your contributions will be licensed under BUSL-1.1 (same as the project).