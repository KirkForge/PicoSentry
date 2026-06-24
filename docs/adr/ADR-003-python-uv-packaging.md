# ADR-003: Python with uv for packaging and dependency management

**Status:** Accepted  
**Date:** 2026-06

## Context

PicoSentry targets both CLI use (`pip install picosentry`) and server deployment (Docker). The toolchain must handle editable installs, lockfiles, and fast CI installs.

## Decision

Python 3.10+ with `pyproject.toml` (PEP 517/518). `uv` is the package manager for local dev and CI; `pip` installs work for end users. A `uv.lock` lockfile pins the full dependency tree.

## Rationale

- `uv` is 10–100× faster than pip for CI installs, cutting feedback loop significantly
- `pyproject.toml` is the modern standard; avoids `setup.py` / `requirements.txt` split
- Pure-Python distribution means no native build step for most users
- Rust components (if added later) can be compiled via maturin inside the same pyproject

## Consequences

- Contributors need `uv` installed for the dev workflow (`uv pip install -e ".[dev]"`)
- `uv.lock` must be committed and updated on dep changes
