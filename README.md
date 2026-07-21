# PicoSentry

![PicoSentry Banner](docs/banner.png)

[![PyPI version](https://img.shields.io/pypi/v/picosentry?label=PyPI&color=blue)](https://pypi.org/project/picosentry/)
[![Python](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.13-blue?label=Python)](https://pypi.org/project/picosentry/)
[![License: BUSL-1.1](https://img.shields.io/badge/license-BUSL--1.1-blue)](LICENSE)
[![Docker Hub](https://img.shields.io/badge/Docker-kirkforge%2Fpicodome-blue?logo=docker&logoColor=white)](https://hub.docker.com/r/kirkforge/picodome)
[![Docker Image Version](https://img.shields.io/docker/v/kirkforge/picodome?label=Docker%20Tag)](https://hub.docker.com/r/kirkforge/picodome)
[![Docker Image Size](https://img.shields.io/docker/image-size/kirkforge/picodome/latest?label=Image%20Size)](https://hub.docker.com/r/kirkforge/picodome)
[![Build Status](https://img.shields.io/github/actions/workflow/status/KirkForge/PicoSentry/ci.yml?branch=main&label=CI)](https://github.com/KirkForge/PicoSentry/actions)
[![Downloads](https://img.shields.io/pypi/dm/picosentry?label=Downloads&color=blue)](https://pypi.org/project/picosentry/)
[![GitHub Stars](https://img.shields.io/github/stars/KirkForge/PicoSentry?style=social)](https://github.com/KirkForge/PicoSentry)
[![GitHub Issues](https://img.shields.io/github/issues/KirkForge/PicoSentry)](https://github.com/KirkForge/PicoSentry/issues)
[![Code style: ruff](https://img.shields.io/badge/code%20style-ruff-black)](https://github.com/astral-sh/ruff)
[![SLSA](https://img.shields.io/badge/SLSA-provenance-green)](https://slsa.dev)

---

**Catch malicious packages before they bite.** PicoSentry is an offline supply-chain scanner that detects obfuscation, typosquatting, dependency confusion, post-install exfiltration, known IOCs, and CVEs across 7 ecosystems — no internet required.

> Kernel sandbox enforcement and LLM prompt/output guards are included as stable capabilities.

---

## Quick start

```bash
pip install picosentry
picosentry scan ./your-project
```

That's it. Works offline, deterministic, no phone-home.

### See it in action

```bash
git clone https://github.com/KirkForge/PicoSentry.git
cd PicoSentry
picosentry scan examples/pypi-obfuscated-setup/
```

```text
🦞 PicoSentry
Target: /home/you/PicoSentry/examples/pypi-obfuscated-setup
Engine: v2.0.5 | Corpus: vef6b3b3115bb
Scan ID: 08057439b4ba08d8

Packages scanned: 0
Files scanned:     2
Duration:          20ms
```

The scan fires 5+ findings across obfuscation, post-install, and exfiltration rules. Re-run and the `Scan ID` and `Corpus` digest match exactly — that's the determinism guarantee.

---

## What it detects

| Rule | What it catches | Example |
|------|----------------|---------|
| L2-TYPO-001 | Typosquatted package names | `reqursts` instead of `requests` |
| L2-DEPC-001 | Dependency confusion (private → public) | `internal-pkg` not on registry |
| L2-PYPI-OBFS-001 | Dynamic execution in setup.py | `exec()` / `eval()` in install scripts |
| L2-PYPI-OBFS-002 | Base64-decoded payloads in source | `base64.b64decode(...)` + dynamic use |
| L2-PYPI-POST-001 | Post-install code execution | `setup.py` runs code at install time |
| L2-NETEX-001 | Network calls during install | `urllib.request`, `curl`, `wget` at install |
| L2-IOC-001 | Known IOC behavior patterns | Hardcoded C2 host, exfil URL patterns |
| L2-CVE-001 | Known CVEs in dependency tree | OSV-matched vulnerabilities |

**54 rules across npm, PyPI, Go, Cargo, Maven, RubyGems, and NuGet.**
Full catalog: [`picosentry/scan/docs/rules/`](picosentry/scan/docs/rules/)

---

## Supported ecosystems

| Ecosystem | Typosquat | Dep Confusion | Obfuscation | CVE Match | License |
|-----------|:---------:|:-------------:|:-----------:|:---------:|:-------:|
| npm | ✅ | ✅ | ✅ | ✅ | ✅ |
| PyPI | ✅ | ✅ | ✅ | ✅ | ✅ |
| Go | ✅ | ✅ | — | ✅ | ✅ |
| Cargo | ✅ | ✅ | — | ✅ | ✅ |
| Maven | ✅ | ✅ | — | ✅ | ✅ |
| RubyGems | ✅ | ✅ | — | ✅ | ✅ |
| NuGet | ✅ | ✅ | — | ✅ | ✅ |

---

## Why PicoSentry?

| Capability | PicoSentry | pip-audit | osv-scanner | Trivy | Socket |
|------------|:---------:|:---------:|:-----------:|:-----:|:------:|
| Offline operation | ✅ | partial | partial | partial | ❌ |
| Deterministic output | ✅ | ❌ | ❌ | ❌ | ❌ |
| Malicious-behavior rules | ✅ | ❌ | ❌ | partial | partial |
| 7 ecosystems | ✅ | partial | ✅ | ✅ | partial |
| Kernel sandbox | ✅ | ❌ | ❌ | ❌ | ❌ |

**PicoSentry's edge:** offline + deterministic + malicious-behavior rules in one package. Other tools have wider CVE coverage or broader container scanning — PicoSentry focuses on catching *malicious intent*, not just known vulnerabilities.

---

## Status

| Component | Status | Notes |
|-----------|--------|-------|
| `picosentry scan` | **Stable** | Core scanner; 7 ecosystems; deterministic, offline; 54 rules, 1048 fixtures |
| `picosentry sandbox` | **Stable** | seccomp-bpf enforces; gRPC + HTTP daemon; L4 behavioral analysis; seccomp-trace is opt-in and argument-limited |
| `picosentry watch` | **Stable** | Deterministic regex + lexical classifier pre-filter for prompt injection (L5) and output validation (L6); not a semantic/LLM guarantee; CLI + HTTP server |
| `picosentry serve` | **Beta** | API server, dashboard, RBAC, multi-tenant Postgres backend — security review + regression tests in place |
| `picosentry daemon` | **Beta** | Sandbox-as-a-service; HTTP + gRPC; auth, rate limiting, TLS/mTLS, audit |
| `picosentry admission` | **Beta** | K8s admission webhook; pod security validation + optional image scanning; fail-closed by default when image scanning is enabled; live-tested against a kind cluster |
| `picosentry corpus` | **Stable** | Export/import/validate/list/sign IoC packs; 3 built-in packs; deterministic signatures |
| Cross-layer correlation | **Stable** | Links findings across scan + sandbox + watch layers; persistence, dedup, and per-minute backpressure tested in CI |
| Plugin system | **Stable** | Loads, validates, dispatches; Ed25519 signature verify against a configured trusted-key allowlist; unsigned plugins load only when signing is not required |
| Postgres backend | **Stable** | psycopg2 pool + runtime placeholder translation + DDL auto-translation + dialect helpers; live PG 15/16 CI |
| Cluster mode | **Beta** | Gossip over HTTP(S) with shared cluster token + optional mTLS; monotonic versioning; 3-node integration test |
| Detection benchmarks | **Stable** | 1048 fixtures (899 pos / 142 neg / 7 tricky), 54 rules, 94.44% mean precision, 73.79% mean recall — see [model card](docs/model-card.md) |
| Docker image | **Stable** | `kirkforge/picodome:v2.0.18` on Docker Hub; multi-arch (linux/amd64 + linux/arm64); non-root user |
| PyPI package | **Stable** | `pip install picosentry` — v2.0.18 published |

"Beta" means it works, has regression and security tests, and is suitable for controlled production use. See the per-component security reviews in [`docs/`](docs/).

---

## Install

```bash
pip install picosentry                # core (lightweight, offline-ready)
pip install picosentry[scan]          # + online corpus management
pip install picosentry[serve]         # + API server + dashboard
pip install picosentry[all]           # everything
```

**Docker:** `docker pull kirkforge/picodome:v2.0.18` — multi-arch (amd64 + arm64), non-root.

---

## More

- **[Technical manual](docs/manual.md)** — full install options, gRPC transport, plugin system, corpus management, repository structure, and sandbox details
- **[Architecture](docs/ARCHITECTURE.md)** — component diagram and trust boundaries
- **[Detection benchmarks](docs/model-card.md)** — 1048 fixtures, 54 rules, precision/recall per rule
- **[Security reviews](docs/SECURITY_REVIEW.md)** — per-component security analysis
- **[Plugin development](docs/PLUGIN_DEVELOPMENT.md)** — write, sign, and deploy plugins

---

## Design principles

- **Deterministic** — same inputs + same policy = same SHA-256 output. No randomness, no network dependence.
- **Offline by default** — no phone-home, no remote API calls at scan time. Works in air-gapped environments.
- **Lightweight core** — default install pulls only `pyyaml`. Heavy deps are gated behind extras.
- **Typed** — full Python type annotations, `py.typed` shipped.

---

## Getting help

- **Issues / features:** [GitHub Issues](https://github.com/KirkForge/PicoSentry/issues)
- **Security issues** (do **not** file a public issue): see [SECURITY.md](SECURITY.md) or open a [private vulnerability report](https://github.com/KirkForge/PicoSentry/security/advisories/new)
- **Discussion:** [GitHub Discussions](https://github.com/KirkForge/PicoSentry/discussions)
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md)

---

## License

BUSL-1.1 — see [LICENSE](LICENSE) and [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md).
