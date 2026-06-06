# PicoSentry 🦞

![PicoSentry Banner](docs/banner.png)

**Local supply-chain scanner with offline, deterministic detection across npm, PyPI, Go, Cargo, Maven, RubyGems, and NuGet. Kernel-sandbox enforcement is included as a beta capability for runtime containment.**

> PicoSentry scans a candidate package for malicious-behavior patterns — obfuscation,
> typosquatting, dependency confusion, post-install exfiltration, known IOCs, and CVEs —
> using a fully offline rule catalog. A kernel-sandbox (`seccomp-bpf` + `landlock`) is
> available to enforce syscalls at install time; full per-syscall tracing from the kernel
> is tracked as future work.

[![PyPI](https://img.shields.io/pypi/v/picosentry)](https://pypi.org/project/picosentry/)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue)](https://pypi.org/project/picosentry/)
[![License: BUSL-1.1](https://img.shields.io/badge/license-BUSL--1.1-blue)](LICENSE)

---

## Status

Source of truth: [`picosentry/experimental.py`](picosentry/experimental.py).

| Component | Status | Notes |
|-----------|--------|-------|
| `picosentry scan` | **Stable** | Core scanner; 7 ecosystems; deterministic, offline |
| `picosentry sandbox` | **Beta** | seccomp-bpf enforces; gRPC transport experimental |
| `picosentry watch` | **Beta** | Prompt-injection detection works; HTTP server experimental |
| `picosentry serve` | **Experimental** | API server + dashboard in active development |
| Cross-layer correlation | **Experimental** | Links findings across layers |
| Plugin system | **Beta** | Loads and dispatches; signature verify works |
| Postgres backend | **Stub** | SQLite only; migration not started |
| Cluster mode | **Experimental** | Single-node verified; multi-node gossip untested |
| Detection benchmarks | **Stub** | Framework defined, no real data yet |
| Corpus marketplace | **Stub** | Export/import CLI commands not wired |

The scanner is the stable product. The kernel sandbox is beta enforcement-only today;
it kills disallowed syscalls but does not yet emit a per-syscall trace (see "What it
does NOT do" below).

---

## What it does NOT do (today)

- **Does not record per-syscall traces from the kernel sandbox.** The seccomp-bpf
  backend enforces (kills on disallowed syscalls) and emits meta-events (verdict,
  timeout, violation, degradation) — not a syscall stream. L4 behavioral observers
  read subprocess stdout, not the kernel.
- **Does not scan LLM model weights.** It guards prompts and outputs in deployed
  apps, not the model itself.
- **Does not run cluster mode in production.** Single-node only; multi-node gossip
  is untested.
- **Does not have a real Postgres backend.** SQLite only.
- **Does not have detection-benchmark data.** The validation harness exists
  (`picosentry scan --validate`); the rule-level precision/recall numbers have not
  been run against a real dataset.
- **Does not advertise a CVE database on its own.** CVE matching uses the OSV
  corpus (`[scan]` extra); offline-only operation pulls from the local corpus
  snapshot.

If a feature is in `experimental.py` as Stub or Experimental, treat it as not
shipped.

---

## 30-second demo (no clone)

```bash
pip install picosentry
picosentry scan ./your-project          # any project on disk
picosentry scan ./package.json          # or a single manifest
```

If you prefer a reproducible example, the repo ships a malicious PyPI fixture:

```bash
git clone https://github.com/KirkForge/PicoSentry.git
cd PicoSentry
picosentry scan examples/pypi-obfuscated-setup/
```

### Real CLI output

```text
$ picosentry scan examples/pypi-obfuscated-setup/
PICOSENTRY_CACHE_HMAC_KEY not set — cache entries will be invalidated on process restart. Set it for persistent cache integrity.
🦞 PicoSentry
Target: /home/kirk/Madlab/Clean-Live/PicoSeries/picosentry/examples/pypi-obfuscated-setup
Engine: v2.0.5 | Corpus: vef6b3b3115bb
Scan ID: 08057439b4ba08d8

Packages scanned: 0
Files scanned:     2
Duration:          20ms
```

The scan above fires 5+ findings across the obfuscation, post-install, and
exfiltration rules. Re-run with the same inputs and the `Scan ID` and `Corpus`
digest will match exactly — that's the determinism guarantee.

> A complete sample output (with rule IDs and severities) for the same example is
> checked into the repo. The example is the reproducible fixture we use in CI.

---

## What it detects (a subset)

| Rule | What it catches | Example |
|------|----------------|---------|
| L2-TYPO-001 | Typosquatted package names | `reqursts` instead of `requests` |
| L2-DEPC-001 | Dependency confusion (private → public) | `internal-pkg` not on registry |
| L2-PYPI-OBFS-001 | Dynamic execution in setup.py | `exec()` / `eval()` in install scripts |
| L2-PYPI-OBFS-002 | Base64-decoded payloads in source | `base64.b64decode(...)` + dynamic use |
| L2-PYPI-OBFS-007 | Base64 decode + exec/eval combo | Decode-then-execute obfuscation chain |
| L2-PYPI-POST-001 | Post-install code execution | `setup.py` runs code at install time |
| L2-NETEX-001 | Network calls during install | `urllib.request`, `curl`, `wget` at install |
| L2-IOC-001 | Known IOC behavior patterns | Hardcoded C2 host, exfil URL patterns |
| L2-CVE-001 | Known CVEs in dependency tree | OSV-matched vulnerabilities |
| L2-DEP-001 | Deprecated / insecure dependency | End-of-life library versions |
| L2-SBOM-001 | SBOM generation | CycloneDX-compatible output |
| L2-LICENSE-001 | License compliance | Copyleft, unknown, deprecated licenses |

Full rule catalog: [`picosentry/scan/docs/rules/`](picosentry/scan/docs/rules/) (50 rules
across the supported ecosystems).

---

## Feature matrix

| Feature | PicoSentry | pip-audit | osv-scanner | Trivy | Socket |
|---------|:---------:|:---------:|:-----------:|:-----:|:------:|
| Offline operation | yes | partial | partial | partial | no |
| Deterministic output (bit-identical runs) | yes | no | no | no | no |
| Malicious-behavior detection (not just CVEs) | yes | no | no | partial | partial |
| Multi-ecosystem (npm, PyPI, Go, Cargo, Maven, RubyGems, NuGet) | yes | partial | yes | yes | partial |
| Runtime sandbox enforcement (kernel-level) | beta | no | no | no | no |
| Runtime syscall observation from kernel | no | no | no | no | no |
| FOSS source available | yes (BUSL-1.1) | yes (Apache-2.0) | yes (Apache-2.0) | yes (Apache-2.0) | no |

Where PicoSentry is weaker: pip-audit and osv-scanner have wider and more frequently
refreshed CVE coverage via OSV. Trivy has broader container and IaC scanning. Socket
has hosted workflow integrations PicoSentry doesn't ship. The differentiator is the
combination of offline + deterministic + malicious-behavior rules in a single offline
binary — not raw CVE breadth.

---

## Install

```bash
# Core scanner — works offline, no HTTP deps (only `pyyaml` installed)
pip install picosentry

# Extras
pip install picosentry[scan]      # + online corpus management
pip install picosentry[serve]     # + API server + dashboard
pip install picosentry[all]       # Everything
```

The default `pip install picosentry` is deliberately lightweight — it pulls in
only `pyyaml`, which is enough to run `picosentry scan` against any project.
To use the API server, dashboard, or HTTP corpus refresh, install the matching
extras (see [install options](#install-options) below).

### Install options

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

## Usage

```bash
picosentry scan ./my-project
picosentry scan ./package.json                  # single file
picosentry scan --format json ./project         # JSON output
picosentry scan --format sarif ./project        # SARIF output
picosentry scan --format cyclonedx ./project    # CycloneDX SBOM
picosentry scan --verify-determinism ./project  # assert SHA-256 stability
picosentry scan --diff scan-a.json scan-b.json  # compare two scans
picosentry scan --fail-on high ./project        # exit non-zero on HIGH+
picosentry sandbox echo "hello"                 # beta — kernel-level enforcement
picosentry watch scan-prompt --text "..."       # beta — LLM prompt guard
picosentry serve --port 8765                    # experimental — API + dashboard
picosentry health
```

---

## Design principles

- **Deterministic**: same inputs + same policy = same SHA-256 output. No randomness,
  no probabilistic scoring, no network dependence. Asserted by `--verify-determinism`.
- **Offline by default**: no phone-home, no remote API calls at scan time. Works in
  air-gapped environments. Online corpus refresh is opt-in via the `[scan]` extra.
- **Typed**: full Python type annotations, `py.typed` shipped.
- **Lightweight core**: the default install pulls only `pyyaml`. Heavy deps are
  gated behind extras.

---

## Repository structure

```
picosentry/
    _core/          shared primitives
    scan/           supply-chain scanner (CLI: `picosentry scan`)
    sandbox/        runtime kernel-sandbox (CLI: `picosentry sandbox`, beta)
    watch/          LLM prompt/output guard (CLI: `picosentry watch`, beta)
    serve/          API server + dashboard (CLI: `picosentry serve`, experimental)
    experimental.py feature-maturity tracking
examples/
    pypi-obfuscated-setup/    reproducible malicious PyPI fixture
    npm-postinstall-exfil/    reproducible npm post-install fixture
    prompt-injection/         reproducible prompt-injection fixture
docs/
    rules/          per-rule documentation (see picosentry/scan/docs/rules/)
    strategic/      design docs and architecture
tests/             test suite
```

---

## Where to get help

- **Bug reports / feature requests**: [GitHub Issues](https://github.com/KirkForge/PicoSentry/issues)
- **Security issues** (do **not** file a public issue): see [SECURITY.md](SECURITY.md) —
  email `security@kirkforge.dev` or open a [private vulnerability report](https://github.com/KirkForge/PicoSentry/security/advisories/new).
- **Questions / discussion**: [GitHub Discussions](https://github.com/KirkForge/PicoSentry/discussions)
- **Contributing**: see [CONTRIBUTING.md](CONTRIBUTING.md)

---

## License

BUSL-1.1 — see [LICENSE](LICENSE) and [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md).
