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

**Catch malicious packages before they bite.** PicoSentry is an offline,
deterministic supply-chain security suite: a static scanner for typosquatting,
dependency confusion, obfuscation, exfiltration, IOCs and CVEs across 7
ecosystems; a kernel sandbox; an LLM prompt/output guard; and a multi-tenant
API server tying them together. No internet required, no phone-home,
bit-identical output for identical inputs.

All technical documentation lives in the **[manual](docs/manual.md)** —
install options, CLI reference, every detection rule, deployment, security
model, operations, and benchmarks.

---

## 60-second quickstart

```bash
pip install picosentry
picosentry scan ./your-project
```

Works offline, deterministic, no API keys. Try it on a built-in malicious
fixture:

```bash
git clone https://github.com/KirkForge/PicoSentry.git
cd PicoSentry
picosentry scan examples/pypi-obfuscated-setup/
```

The scan fires 5+ findings across obfuscation, post-install, and exfiltration
rules. Re-run it: the `Scan ID` and `Corpus` digest match exactly — that's the
determinism guarantee (`--verify-determinism` asserts it in CI).

---

## The four components

**`picosentry scan`** — the static supply-chain scanner. Analyzes package
manifests, lockfiles, and source across npm, PyPI, Go, Cargo, Maven, RubyGems,
and NuGet: 53 L2 detection rules covering typosquats, dependency confusion,
install-time execution, obfuscation, credential access, network exfiltration,
known CVEs (OSV), and license compliance. Advisory findings carry a `reachable`
flag so present-but-unused CVEs triage faster. → [Manual ch. 5](docs/manual.md#5-scanner-rules-ecosystems-and-corpus)

**`picosentry sandbox`** — the runtime sandbox (PicoDome). Executes untrusted
commands under seccomp-bpf (Linux) or seatbelt (macOS), records syscall-level
behavioral events for L4 analysis, and ships as an HTTP + gRPC
sandbox-as-a-service daemon with auth, rate limiting, TLS/mTLS, and
token-scoped multi-tenancy. → [Manual ch. 8](docs/manual.md#8-sandbox-picodome)

**`picosentry watch`** — the LLM defense layer (PicoWatch). Deterministic,
offline prompt-injection detection (L5) and output-policy validation (L6):
regex rules plus a lexical classifier behind a normalizer that defeats
base64/ROT13/homoglyph/zero-width obfuscation. A fast pre-filter, honestly not
a semantic guarantee. → [Manual ch. 7](docs/manual.md#7-watch-llm-defense)

**`picosentry serve`** — the control plane. FastAPI API server with dashboard,
RBAC (viewer/operator/admin), MFA/TOTP, JWT revocation, role-scoped API keys,
multi-tenant SQLite/Postgres persistence, plugins, scheduling, alerting, and
cross-layer kill-chain correlation (Beta). → [Manual ch. 9](docs/manual.md#9-serve-control-plane)

Also: `picosentry firewall` (registry metadata proxy), `daemon`, `admission`
(K8s webhook), `corpus`, `advisories`, `update`, `diff`, `doctor`, `rules`,
`init`, `health`, `version` — full CLI reference in the
[manual ch. 4](docs/manual.md#4-cli-reference).

---

## Status

| Component | Status | Notes |
|-----------|--------|-------|
| `picosentry scan` | **Stable** | Core scanner; 7 ecosystems; deterministic, offline; 53 rules, 5674 fixtures |
| `picosentry sandbox` | **Stable** | seccomp-bpf enforces; gRPC + HTTP daemon; L4 behavioral analysis; seccomp-trace is opt-in and argument-limited |
| `picosentry watch` | **Stable** | Deterministic regex + lexical classifier pre-filter for prompt injection (L5) and output validation (L6); not a semantic/LLM guarantee; CLI + HTTP server |
| `picosentry serve` | **Beta** | API server, dashboard, RBAC, multi-tenant Postgres backend — security review + regression tests in place. Auth hardening: MFA/TOTP enrollment, JWT `jti` revocation, account lockout, role-scoped API keys (`services/auth.py`) |
| `picosentry daemon` | **Beta** | Sandbox-as-a-service; HTTP + gRPC; auth, rate limiting, TLS/mTLS, audit |
| `picosentry admission` | **Beta** | K8s admission webhook; pod security validation + optional image scanning; fail-closed by default when image scanning is enabled; live-tested against a kind cluster |
| `picosentry corpus` | **Stable** | Export/import/validate/list/sign IoC packs; 3 built-in packs; deterministic signatures |
| Cross-layer correlation | **Stable** | Links findings across scan + sandbox + watch layers; persistence, dedup, and per-minute backpressure tested in CI |
| Plugin system | **Stable** | Loads, validates, dispatches; Ed25519 signature verify against a configured trusted-key allowlist; unsigned plugins load only when signing is not required |
| Postgres backend | **Stable** | psycopg2 pool + runtime placeholder translation + DDL auto-translation + dialect helpers; live PG 15/16/17/18 CI |
| Cluster mode | **Beta** | Gossip over HTTP(S) with shared cluster token + optional mTLS; monotonic versioning; 3-node integration test |
| Detection benchmarks | **Stable** | 5674 fixtures (3431 pos / 2236 neg), 53 rules, 100.00% prec, 90.87% recall — see docs/model-card.md |
| Docker image | **Stable** | multi-arch (linux/amd64 + linux/arm64), non-root; latest published: kirkforge/picodome:v2.0.18 — kirkforge/picodome:v2.2.0 push pending (WO5.0.0-014) |
| PyPI package | **Stable** | `pip install picosentry` — v2.2.0 published |

"Beta" = works, has regression + security tests, suitable for controlled
production use. This table is generated from
[`picosentry/experimental.py`](picosentry/experimental.py) and CI-enforced
against drift. Per-component reviews: [manual, security chapters](docs/manual.md#16-threat-model).

---

## Install

```bash
pip install picosentry                # core (offline-ready)
pip install picosentry[scan]          # + online corpus management
pip install picosentry[serve]         # + API server + dashboard
pip install picosentry[all]           # everything
```

**Docker:** `docker pull kirkforge/picodome:v2.0.18` (latest published;
multi-arch, non-root) — `kirkforge/picodome:v2.2.0` push pending (WO5.0.0-014).
All install options incl. `[grpc]`, `[watch-server]`, `[otel]`, `[sigstore]`:
[manual ch. 2](docs/manual.md#2-installation).

---

## The manual

Everything technical is in **[docs/manual.md](docs/manual.md)**:

[Quick start](docs/manual.md#1-quick-start) ·
[Install](docs/manual.md#2-installation) ·
[Docker](docs/manual.md#3-docker-builds-and-deployment) ·
[CLI reference](docs/manual.md#4-cli-reference) ·
[Scanner](docs/manual.md#5-scanner-rules-ecosystems-and-corpus) ·
[Firewall](docs/manual.md#6-registry-firewall) ·
[Watch](docs/manual.md#7-watch-llm-defense) ·
[Sandbox](docs/manual.md#8-sandbox-picodome) ·
[Serve](docs/manual.md#9-serve-control-plane) ·
[Plugins](docs/manual.md#10-plugin-system) ·
[Architecture](docs/manual.md#11-architecture) ·
[Configuration](docs/manual.md#12-configuration-reference) ·
[Runbook](docs/manual.md#13-operations-runbook) ·
[Offline](docs/manual.md#14-offline-and-air-gapped-operation) ·
[Deployment security](docs/manual.md#15-deployment-security-checklist) ·
[Threat model](docs/manual.md#16-threat-model) ·
[Attack surface](docs/manual.md#17-attack-surface-and-pentest-scope) ·
[Benchmarks & model card](docs/manual.md#18-detection-benchmarks-and-model-card) ·
[Internal API map](docs/manual.md#19-internal-api-map) ·
[Extension guide](docs/manual.md#20-extension-guide) ·
[Limitations & status](docs/manual.md#21-known-limitations-and-component-status) ·
[ADR index](docs/manual.md#23-appendix-adr-index)

Reference files that stay standalone: generated per-rule benchmark table
[docs/BENCHMARKS.md](docs/BENCHMARKS.md) (CI-enforced) and the
[ADRs](docs/adr/).

**Supply chain:** wheel builds are **reproducible** — `SOURCE_DATE_EPOCH` is
pinned from the commit timestamp in `release.yml`, the Dockerfile, and CI, so
the same source yields a byte-identical wheel (asserted by the CI
`reproducible-build` job). Details: [manual ch. 15](docs/manual.md#reproducible-builds).

---

## Getting help

- **Issues:** [GitHub Issues](https://github.com/KirkForge/PicoSentry/issues)
- **Security** (not a public issue): [SECURITY.md](SECURITY.md) or [private report](https://github.com/KirkForge/PicoSentry/security/advisories/new)
- **Discussion:** [GitHub Discussions](https://github.com/KirkForge/PicoSentry/discussions)
- **Contributing:** [CONTRIBUTING.md](CONTRIBUTING.md)

---

## License

BUSL-1.1 — see [LICENSE](LICENSE) and [COMMERCIAL-LICENSE.md](COMMERCIAL-LICENSE.md).
