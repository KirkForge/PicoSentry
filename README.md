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

Works offline, deterministic, no phone-home.

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

**50 rules** across npm, PyPI, Go, Cargo, Maven, RubyGems, and NuGet. Full catalog: [`picosentry/scan/docs/rules/`](picosentry/scan/docs/rules/)

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

Offline + deterministic + malicious-behavior rules in one package.

---

## Status

| Component | Status | Notes |
|-----------|--------|-------|
| `picosentry scan` | **Stable** | 7 ecosystems; deterministic, offline; 50 rules, 6495 fixtures |
| `picosentry sandbox` | **Stable** | seccomp-bpf; gRPC + HTTP; L4 behavioral analysis |
| `picosentry watch` | **Stable** | Regex + lexical classifier for prompt injection (L5) and output validation (L6) |
| `picosentry serve` | **Beta** | API server, dashboard, RBAC, multi-tenant Postgres |
| `picosentry daemon` | **Beta** | Sandbox-as-a-service; HTTP + gRPC; auth, rate limiting, TLS/mTLS |
| `picosentry admission` | **Beta** | K8s admission webhook; fail-closed by default |
| `picosentry corpus` | **Stable** | Export/import/validate/sign IoC packs; 3 built-in |
| Cross-layer correlation | **Stable** | Links findings across scan + sandbox + watch layers |
| Plugin system | **Stable** | Ed25519 signature verify; unsigned plugins when signing not required |
| Postgres backend | **Stable** | psycopg2 pool + dialect helpers; PG 15/16 CI |
| Cluster mode | **Beta** | Gossip over HTTP(S); monotonic versioning; 3-node integration test |
| Detection benchmarks | **Stable** | 6495 fixtures (5558 pos / 930 neg / 7 tricky), 50 rules, 94.44% prec, 68.89% recall |
| Docker image | **Stable** | `kirkforge/picodome:v2.0.18`; multi-arch, non-root |
| PyPI package | **Stable** | v2.0.18 |

"Beta" = works, has regression + security tests, suitable for controlled production use. Per-component reviews in [`docs/`](docs/).

---

## Install

```bash
pip install picosentry                # core (offline-ready)
pip install picosentry[scan]          # + online corpus management
pip install picosentry[serve]          # + API server + dashboard
pip install picosentry[all]            # everything
```

**Docker:** `docker pull kirkforge/picodome:v2.0.18` — multi-arch, non-root.

---

## More

- **[Technical manual](docs/manual.md)** — install, gRPC, plugins, corpus, sandbox
- **[Architecture](docs/ARCHITECTURE.md)** — component diagram and trust boundaries
- **[Detection benchmarks](docs/model-card.md)** — 6495 fixtures, 50 rules, precision/recall
- **[Security reviews](docs/SECURITY_REVIEW.md)** — per-component analysis
- **[Plugin development](docs/PLUGIN_DEVELOPMENT.md)** — write, sign, deploy plugins

---

## Design principles

- **Deterministic** — same inputs + same policy = same SHA-256 output
- **Offline by default** — no phone-home, no remote API calls
- **Lightweight core** — default install pulls only `pyyaml`
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