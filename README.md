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

**Catch malicious packages before they bite.** Offline supply-chain scanner — obfuscation, typosquatting, dependency confusion, exfiltration, IOCs, CVEs across 7 ecosystems. No internet required.

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
Engine: v2.1.1 | Corpus: vabd36dc30c3f
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
| L2-DEPC-001 | Dependency confusion | `internal-pkg` not on registry |
| L2-PYPI-OBFS-001 | Dynamic execution in setup.py | `exec()`/`eval()` in install scripts |
| L2-PYPI-OBFS-002 | Base64-decoded payloads | `base64.b64decode(...)` + dynamic use |
| L2-PYPI-POST-001 | Post-install code execution | `setup.py` runs code at install time |
| L2-NETEX-001 | Network calls during install | `urllib.request`, `curl`, `wget` at install |
| L2-IOC-001 | Known IOC behavior patterns | Hardcoded C2 host, exfil URL patterns |
| L2-CVE-001 | Known CVEs in dependency tree | OSV-matched vulnerabilities |
| L2-INTEL-001 | Suspiciously-new low-download packages | Package <30 days old with <100 downloads (`package_intel.py`, `rules/package_age.py`) |

Advisory findings also carry a **`reachable`** flag — `True` when the vulnerable package is actually imported/used in the scanned source, so you can triage present-but-unused CVEs (`rules/advisory_check.py`).

**53 L2 rules (68 with L4 behavioral detectors) across npm, PyPI, Go, Cargo, Maven, RubyGems, and NuGet.**
Full catalog: [`picosentry/scan/docs/rules/`](picosentry/scan/docs/rules/)

---

## Supported ecosystems

| Ecosystem | Typosquat | Dep Confusion | Obfuscation | CVE Match | License |
|-----------|:---------:|:-------------:|:-----------:|:---------:|:-------:|
| npm | ✅ | ✅ | ✅ | ✅ | ✅ |
| PyPI | ✅ | ✅ | ✅ | ✅ | — |
| Go | ✅ | ✅ | — | ✅ | — |
| Cargo | ✅ | ✅ | — | ✅ | — |
| Maven | ✅ | ✅ | — | ✅ | — |
| RubyGems | ✅ | ✅ | — | ✅ | — |
| NuGet | ✅ | ✅ | — | ✅ | — |

License detection (`L2-LICENSE-001`) reads npm `package.json` license fields only.

---

## Why PicoSentry?

| Capability | PicoSentry | pip-audit | osv-scanner | Trivy | Socket |
|------------|:---------:|:---------:|:-----------:|:-----:|:------:|
| Offline operation | ✅ | partial | partial | partial | ❌ |
| Deterministic output | ✅ | ❌ | ❌ | ❌ | ❌ |
| Malicious-behavior rules | ✅ | ❌ | ❌ | partial | partial |
| 7 ecosystems | ✅ | partial | ✅ | ✅ | partial |
| Kernel sandbox | ✅ | ❌ | ❌ | ❌ | ❌ |

Offline + deterministic + malicious-behavior rules in one package.

---

## Status

| Component | Status | Notes |
|-----------|--------|-------|
| `picosentry scan` | **Stable** | Core scanner; 7 ecosystems; deterministic, offline; 53 rules, 5673 fixtures |
| `picosentry sandbox` | **Stable** | seccomp-bpf enforces; gRPC + HTTP daemon; L4 behavioral analysis; seccomp-trace is opt-in and argument-limited |
| `picosentry watch` | **Stable** | Deterministic regex + lexical classifier pre-filter for prompt injection (L5) and output validation (L6); not a semantic/LLM guarantee; CLI + HTTP server |
| `picosentry serve` | **Beta** | API server, dashboard, RBAC, multi-tenant Postgres backend — security review + regression tests in place. Auth hardening: MFA/TOTP enrollment, JWT `jti` revocation, account lockout, role-scoped API keys (`services/auth.py`) |
| `picosentry daemon` | **Beta** | Sandbox-as-a-service; HTTP + gRPC; auth, rate limiting, TLS/mTLS, audit |
| `picosentry admission` | **Beta** | K8s admission webhook; pod security validation + optional image scanning; fail-closed by default when image scanning is enabled; live-tested against a kind cluster |
| `picosentry corpus` | **Stable** | Export/import/validate/list/sign IoC packs; 3 built-in packs; deterministic signatures |
| Cross-layer correlation | **Stable** | Links findings across scan + sandbox + watch layers; persistence, dedup, and per-minute backpressure tested in CI |
| Plugin system | **Stable** | Loads, validates, dispatches; Ed25519 signature verify against a configured trusted-key allowlist; unsigned plugins load only when signing is not required |
| Postgres backend | **Stable** | psycopg2 pool + runtime placeholder translation + DDL auto-translation + dialect helpers; live PG 15/16 CI |
| Cluster mode | **Beta** | Gossip over HTTP(S) with shared cluster token + optional mTLS; monotonic versioning; 3-node integration test |
| Detection benchmarks | **Stable** | 5673 fixtures (3431 pos / 2235 neg), 53 rules, 100.00% prec, 90.87% recall — see docs/model-card.md |
| Docker image | **Stable** | `kirkforge/picodome:v2.1.1` on Docker Hub; multi-arch (linux/amd64 + linux/arm64); non-root user |
| PyPI package | **Stable** | `pip install picosentry` — v2.1.1 published |

"Beta" = works, has regression + security tests, suitable for controlled production use. Per-component reviews in [`docs/`](docs/).

---

## Install

```bash
pip install picosentry                # core (offline-ready)
pip install picosentry[scan]          # + online corpus management
pip install picosentry[serve]          # + API server + dashboard
pip install picosentry[all]            # everything
```

**Docker:** `docker pull kirkforge/picodome:v2.1.1` — multi-arch, non-root.

---

## More

- **[Technical manual](docs/manual.md)** — full install options, gRPC transport, plugin system, corpus management, repository structure, and sandbox details

### CLI commands

`picosentry scan` (core scanner), `sandbox` (isolation), `watch` (LLM guards), `serve` (API server), `daemon` (sandbox-as-a-service), `admission` (K8s webhook), `corpus` (IoC packs), `diff` (compare scans), `doctor` (self-verification), `firewall` (network policy), `rules` (list/disable rules), `init` (project config), `health` (status check), `version`, `update`.

- **[Architecture](docs/ARCHITECTURE.md)** — component diagram and trust boundaries
- **[Detection benchmarks](docs/model-card.md)** — 5673 fixtures, 53 L2 + 15 L4 behavioral rules, precision/recall per rule
- **[Threat model](docs/THREAT_MODEL.md)** / **[attack surface](docs/SECURITY-ATTACK-SURFACE.md)** — trust boundaries and per-component analysis
- **[Plugin development](docs/PLUGIN_DEVELOPMENT.md)** — write, sign, and deploy plugins

**Supply chain:** wheel builds are **reproducible** — `SOURCE_DATE_EPOCH` is pinned from the commit timestamp in `release.yml`, the Dockerfile, and CI, so the same source yields a byte-identical wheel (asserted by the CI `reproducible-build` job).

---

## Design principles

- **Deterministic** — same inputs + same policy = same SHA-256 output
- **Offline by default** — no phone-home, no remote API calls
- **Lightweight core** — default install pulls only `pyyaml` + `cryptography`
- **Typed** — full annotations, `py.typed` shipped

---

## Getting help

- **Issues:** [GitHub Issues](https://github.com/KirkForge/PicoSentry/issues)
- **Security** (not a public issue): [SECURITY.md](SECURITY.md) or [private report](https://github.com/KirkForge/PicoSentry/security/advisories/new)
- **Discussion:** [GitHub Discussions](https://github.com/KirkForge/PicoSentry/discussions)
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md)

---

## License

BUSL-1.1 — see [LICENSE](LICENSE) and [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md).