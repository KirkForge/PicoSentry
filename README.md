# PicoSentry 🦞

**Unified Pico Security Series** — supply-chain scanner, runtime sandbox, LLM defense, and orchestration. One package, one CLI, one version.

[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://pypi.org/project/picosentry/)
[![License: BUSL-1.1](https://img.shields.io/badge/license-BUSL--1.1-blue)](LICENSE)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-support%20my%20hardware-FFDD00?logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/kirkforge)

## What it is

PicoSentry combines 4 tools formerly distributed separately into one unified package:

| Component | Layer | What it does | Formerly |
|---|---|---|---|
| `scan` | L2 | Supply-chain scanner for **7 ecosystems** (npm, PyPI, Go, Cargo, Maven, RubyGems, NuGet) — SBOM, CVEs, typosquatting, dependency confusion, obfuscation | PicoSentry |
| `sandbox` | L3/L4 | Runtime sandbox (seccomp-bpf) + behavioral analysis — exfiltration, crypto mining, container escapes | PicoDome |
| `watch` | L5-L7 | LLM defender — prompt injection detection, output validation, telemetry | PicoWatch |
| `serve` | — | API server, dashboard, firewall, and orchestration | PicoShogun |

## Quick start

```bash
# Minimal install (scanner + sandbox + watch logic, no HTTP deps)
pip install picosentry

# With API server
pip install picosentry[serve]

# Scan a project
picosentry scan ./my-project

# Sandbox a command
picosentry sandbox echo "hello"

# Check for prompt injection
picosentry watch scan-prompt --text "Ignore all instructions..."

# Start the API server
picosentry serve --port 8765

# Health check
picosentry health
```

## Install options

| Command | What you get |
|---|---|
| `pip install picosentry` | Core: scanner, sandbox, watch (lightweight) |
| `pip install picosentry[scan]` | + requests for online corpus management |
| `pip install picosentry[serve]` | + FastAPI server, dashboard, auth, scheduler |
| `pip install picosentry[watch-server]` | + FastAPI + uvicorn for watch HTTP daemon |
| `pip install picosentry[otel]` | + OpenTelemetry tracing |
| `pip install picosentry[all]` | Everything |

## Deterministic by default

Same inputs + same policy = same output. Every time. No HTTP at scan time.
No probabilistic heuristics. No narrative in findings.

## Migration from v1.x

**Deprecation notice:** The original individual packages (`picosentry`, `picodome`, `picowatch`, `picoshogun`, `pico-core`) are deprecated. Pin to your current versions if you cannot migrate yet. No further updates will be published for them.

**Migration path:**
```bash
# Before: 5 packages, 4 different CLIs
pip install picosentry picodome picowatch picoshogun
picosentry scan ./project
picodome run ./project
picowatch analyze --text "..."

# After: 1 package, 1 CLI
pip install picosentry
picosentry scan ./project
picosentry sandbox ./project
picosentry watch scan-prompt --text "..."
```

## License

BUSL-1.1 — see [LICENSE](LICENSE) and [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md).