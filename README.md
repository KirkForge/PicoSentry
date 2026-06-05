# PicoSentry 🦞

**Deterministic supply-chain scanner for npm, PyPI, Go, Cargo, Maven, RubyGems, and NuGet.**

PicoSentry finds malicious packages before you install them — fully offline,
deterministic rule-based detection, no probabilistic ML scoring. Same inputs +
same policy = same SHA-256 output. Every time.

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

```text
🦞 PicoSentry
Target: examples/pypi-obfuscated-setup
Engine: v2.0.0 | Corpus: vef6b3b3115bb
Scan ID: 9952b1a9c6a07e7f

Packages scanned: 0
Files scanned:     2
Duration:          7ms

Rule Timings:
  L2-PYPI-OBFS-001       0ms  (1 findings)
  L2-PYPI-OBFS-002       0ms  (2 findings)
  L2-PYPI-OBFS-007       0ms  (1 findings)
  L2-PYPI-POST-001       0ms  (1 findings)
  …

Pinches by Severity:
  HARD PINCH  : 3
  HARD PINCH  : 2

Pinches:

  [HARD PINCH] L2-PYPI-OBFS-001 unknown
    File: setup.py:10
    Dynamic code execution via exec
    Evidence: exec(
    Confidence: HIGH

  [HARD PINCH] L2-PYPI-OBFS-002 unknown
    File: setup.py:7
    Base64-decoded string detected
    Evidence: base64.b64decode(encoded)
    Confidence: HIGH

  [HARD PINCH] L2-PYPI-OBFS-002 unknown
    File: setup.py:15
    Base64-decoded string detected
    Evidence: base64.b64decode("ZXZpbC1zZXJ2ZXIuZXhhbXBsZS5jb20=")
    Confidence: HIGH

  [HARD PINCH] L2-PYPI-OBFS-007 unknown
    File: setup.py:7
    Base64 decode followed by exec/eval
    Evidence: b64decode(encoded).decode("utf-8")
    Confidence: HIGH

  [HARD PINCH] L2-PYPI-POST-001 pypi-obfuscated-setup
    File: setup.py
    setup.py contains code execution during installation
    Evidence: line 10: exec(decoded); line 13: if "CI" not in os.environ:; …
    Confidence: EXACT
```

> Note: rule IDs and counts above are taken from the current CLI run on
> `examples/pypi-obfuscated-setup`. Re-run `picosentry scan examples/pypi-obfuscated-setup`
> to reproduce; the `Scan ID` and `Corpus` digest will match exactly.

---

## What it detects

| Rule | What it catches | Example |
|------|----------------|---------|
| L2-TYPO-001 | Typosquatted package names | `reqursts` instead of `requests` |
| L2-DEPC-001 | Dependency confusion (private → public) | `internal-pkg` not on registry |
| L2-PYPI-OBFS-001 | Dynamic execution in setup.py | `exec()` / `eval()` in install scripts |
| L2-PYPI-OBFS-002 | Base64-decoded payloads in source | `base64.b64decode(...)` + dynamic use |
| L2-PYPI-OBFS-007 | Base64 decode + exec/eval combo | Decode-then-execute obfuscation chain |
| L2-PYPI-POST-001 | Postinstall code execution | `setup.py` runs code at install time |
| L2-NETEX-001 | Network calls during install | `urllib.request`, `curl`, `wget` at install |
| L2-IOC-001 | Known IOC behavior patterns | Hardcoded C2 host, exfil URL patterns |
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
picosentry scan ./package.json                  # single file
picosentry scan --format json ./project        # JSON output
picosentry scan --format sarif ./project        # SARIF output
picosentry scan --format cyclonedx ./project    # CycloneDX SBOM
picosentry scan --verify-determinism ./project  # assert SHA-256 stability
picosentry scan --diff scan-a.json scan-b.json  # compare two scans
picosentry scan --fail-on high ./project        # exit non-zero on HIGH+
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