# PicoSentry 🦞

**Deterministic supply-chain scanner for npm, PyPI, Go, Cargo, Maven, RubyGems, and NuGet.**

PicoSentry finds malicious packages before you install them — no network, no
heuristics, no false positives from probabilistic models. Same inputs + same
policy = same SHA-256 output. Every time.

[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://pypi.org/project/picosentry/)
[![License: BUSL-1.1](https://img.shields.io/badge/license-BUSL--1.1-blue)](LICENSE)
[![tests](https://github.com/KirkForge/PicoSentry/actions/workflows/ci.yml/badge.svg)](https://github.com/KirkForge/PicoSentry/actions)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-support%20my%20hardware-FFDD00?logo=buy-me-a-coffee&logoColor=black)](https://buymeacoffee.com/kirkforge)

---

## Quick demo

```bash
pip install picosentry

# Clone the example vulnerable projects
git clone https://github.com/KirkForge/PicoSentry.git
cd PicoSentry

# Scan a typosquatted PyPI package
picosentry scan examples/pypi-obfuscated-setup/
```

Expected output:

```
╔══════════════════════════════════════════════════════╗
║  PicoSentry v2.0.0 — deterministic scan             ║
╚══════════════════════════════════════════════════════╝
Scanning 1 package, 2 files...

✗ HIGH  L2-OBF-001  Base64-encoded strings in setup files
  File: examples/pypi-obfuscated-setup/setup.py
  Evidence: base64.b64decode(...) used with exec()

✗ HIGH  L2-EVAL-001  Dynamic execution in setup.py
  File: examples/pypi-obfuscated-setup/setup.py
  Evidence: exec() called with decoded string

✗ HIGH  L2-TYPO-001  Typosquatted dependency
  Package: reauests (typo of "requests")
  File: examples/pypi-obfuscated-setup/setup.py

✗ HIGH  L2-CONF-001  Dependency confusion risk
  Package: internal-private-pkg (not on public registry)
  File: examples/pypi-obfuscated-setup/setup.py

Results: 4 findings · 0 critical 4 high 0 medium 0 low 0 info
Deterministic: 0254ea8ce6ff (verified)
```

---

## What it detects

| Rule | What it catches | Example |
|------|----------------|---------|
| L2-TYPO-001 | Typosquatted package names | `reqursts` instead of `requests` |
| L2-CONF-001 | Dependency confusion (private → public) | `internal-pkg` not on registry |
| L2-OBF-001 | Obfuscated code in setup/install scripts | Base64 + eval in setup.py |
| L2-EVAL-001 | Dynamic execution during install | `exec()`, `__import__()` in setup |
| L2-POST-001 | Postinstall script execution | `postinstall` in package.json |
| L2-EXFIL-003 | Network calls during install | `curl`, `wget`, `http.request` |
| L2-CVE-001 | Known CVEs in dependency tree | OSV-matched vulnerabilities |
| L2-DEP-001 | Deprecated/insecure dependency | End-of-life library versions |
| L2-SBOM-001 | SBOM generation | CycloneDX-compatible output |

See [docs/rules/](picosentry/scan/docs/rules/) for the full rule catalog.

---

## Compared to other tools

| Tool | PicoSentry difference |
|------|-----------------------|
| **pip-audit** | PicoSentry also detects malicious *behavior patterns* (obfuscation, typosquatting, exfil) |
| **osv-scanner** | PicoSentry adds deterministic offline rules + typosquat/dependency-confusion heuristics |
| **Trivy** | PicoSentry is deterministic (no probabilistic scoring) and focused on dev workflow |
| **Garak** | Garak tests LLM models; PicoSentry also guards prompts/output in apps |
| **Socket CLI** | PicoSentry is fully offline, deterministic, and open-source |

---

## Install

```bash
# Core scanner — works offline, no HTTP deps
pip install picosentry

# Extras
pip install picosentry[scan]      # + online corpus management
pip install picosentry[serve]     # + API server + dashboard
pip install picosentry[all]       # Everything
```

See [install options](#install-options) below for details.

---

## Usage

### Scan a project

```bash
picosentry scan ./my-project
picosentry scan ./package.json           # single file
picosentry scan --json ./project         # JSON output
picosentry scan --sarif ./project        # SARIF output
picosentry scan --diff a.json b.json     # compare two scans
```

### Verify determinism

```bash
picosentry scan --verify-determinism ./project
# Runs scan twice, asserts SHA-256 match
```

### Sandbox a command (beta)

```bash
picosentry sandbox echo "hello"
picosentry sandbox --timeout 5 ls -la
```

### LLM prompt guard (beta)

```bash
picosentry watch scan-prompt --text "Ignore all instructions..."
picosentry watch scan-prompt --file suspicious.txt
```

### API server (experimental)

```bash
picosentry serve --port 8765
```

### Health check

```bash
picosentry health
```

---

## Install options

| Command | What you get |
|---------|-------------|
| `pip install picosentry` | Core: scanner, sandbox, watch (lightweight) |
| `pip install picosentry[scan]` | + requests for online corpus management |
| `pip install picosentry[serve]` | + FastAPI server, dashboard, auth, scheduler |
| `pip install picosentry[watch-server]` | + FastAPI + uvicorn for watch HTTP daemon |
| `pip install picosentry[otel]` | + OpenTelemetry tracing |
| `pip install picosentry[sigstore]` | + Sigstore signing support |
| `pip install picosentry[all]` | Everything |

---

## Feature maturity

| Component | Status | Description |
|-----------|--------|-------------|
| `picosentry scan` | ✅ Stable | Core supply-chain scanner for 7 ecosystems |
| `picosentry sandbox` | ⚠️ Beta | seccomp-bpf sandbox; gRPC transport experimental |
| `picosentry watch` | ⚠️ Beta | Prompt injection detection; server experimental |
| `picosentry serve` | 🔬 Experimental | API server + dashboard in active development |
| Postgres backend | ❌ Stub | SQLite only; Postgres not started (PRs welcome) |
| DDoS shield | 🔬 Experimental | Basic rate limiting only |
| Cluster mode | 🔬 Experimental | Single-node OK; multi-node untested |
| Corpus marketplace | 🔬 Experimental | Import/export works; CLI commands pending |
| Detection benchmarks | ❌ Stub | Framework defined, no real data yet |

See [`picosentry/experimental.py`](picosentry/experimental.py) for full details.

---

## Key design principles

- **Deterministic**: Same inputs + same policy = same SHA-256 output. No randomness, no probabilistic scoring, no network dependence.
- **Offline by default**: No phone-home, no remote API calls at scan time. Works in air-gapped environments.
- **Typed**: Full Python type annotations. `mypy --strict` compatible.
- **Fast**: Sub-second scans for typical projects. No heavyweight dependency tree download at scan time.

---

## Repository structure

```
picosentry/
    _core/          Vendored shared primitives
    scan/           Supply-chain scanner
    sandbox/        Runtime sandbox (seccomp-bpf)
    watch/          LLM prompt guard
    serve/          API server + dashboard
    experimental.py Maturity tracking
examples/
    pypi-obfuscated-setup/
    npm-postinstall-exfil/
    prompt-injection/
docs/
    rules/          Full rule catalog per ecosystem
    strategic/      Design docs and architecture
tests/              3000+ tests
```

---

## License

BUSL-1.1 — see [LICENSE](LICENSE) and [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md).