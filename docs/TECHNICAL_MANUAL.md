# PicoSentry Technical Manual

> Version 2.1.2 —BUSL-1.1— Source of truth: codebase and `picosentry/experimental.py`.

This manual covers installation, CLI reference, detection rules, sandboxing, LLM
defense, the serve API, plugins, corpus management, cross-layer correlation,
configuration, security model, and known limitations. For a quick overview, see
the [README](../README.md). For architecture, see [ARCHITECTURE.md](ARCHITECTURE.md).
For threat analysis, see [THREAT_MODEL.md](THREAT_MODEL.md).

---

## Table of contents

- [1. Overview](#1-overview)
- [2. Installation](#2-installation)
- [3. CLI reference](#3-cli-reference)
- [4. Detection rules](#4-detection-rules)
- [5. Ecosystem coverage](#5-ecosystem-coverage)
- [6. Output formats](#6-output-formats)
- [7. Sandbox](#7-sandbox)
- [8. Watch (LLM defense)](#8-watch-llm-defense)
- [9. Serve API](#9-serve-api)
- [10. Plugin system](#10-plugin-system)
- [11. Corpus management](#11-corpus-management)
- [12. Cross-layer correlation](#12-cross-layer-correlation)
- [13. Configuration](#13-configuration)
- [14. Security model](#14-security-model)
- [15. Known limitations](#15-known-limitations)
- [16. Repository structure](#16-repository-structure)
- [17. Component status](#17-component-status)

---

## 1. Overview

PicoSentry is an **offline, deterministic supply-chain security suite** that
combines four capabilities in a single binary:

| Layer | What it does |
|-------|-------------|
| **scan** | Static analysis of package manifests, lockfiles, and source for typosquatting, dependency confusion, obfuscation, post-install hooks, CVEs, license violations, and more. |
| **sandbox** | Runtime enforcement and behavioral analysis via seccomp-bpf (Linux), seatbelt (macOS), or subprocess fallback. Observes syscalls at L4. |
| **watch** | Deterministic regex + lexical classifier for LLM prompt-injection detection (L5) and output-policy validation (L6). |
| **serve** | FastAPI API server with RBAC, multi-tenant Postgres, plugin system, and orchestration across all layers. |

**Design principles:**

- **Offline by default.** `picosentry scan` works with zero network access. Online
  features (advisory DB, corpus update, serve dashboard) are opt-in extras.
- **Deterministic output.** Two scans of the same input produce bit-identical JSON.
  Use `--verify-determinism` to assert SHA-256 stability in CI.
- **Fail-closed defaults.** Admission webhooks deny on misconfiguration; watch
  can be set to fail-closed; `serve` blocks insecure secrets in production.
- **Honest about limitations.** Detection benchmarks, known gaps, and retracted
  claims (see ADR-002) are documented rather than hidden.

---

## 2. Installation

### pip

| Command | What you get |
|---------|-------------|
| `pip install picosentry` | Core: scanner, sandbox, watch (`pyyaml` + `cryptography` only) |
| `pip install picosentry[scan]` | + `requests` for online corpus/advisory updates |
| `pip install picosentry[serve]` | + FastAPI, PyJWT, bcrypt, pyotp, webauthn, pydantic — full API server |
| `pip install picosentry[watch-server]` | + FastAPI + uvicorn for the watch HTTP daemon |
| `pip install picosentry[otel]` | + OpenTelemetry tracing |
| `pip install picosentry[sigstore]` | + Sigstore signing for corpus packs |
| `pip install picosentry[grpc]` | + `grpcio>=1.81.1`, `protobuf>=6.30.0,<7.0.0` — sandbox gRPC transport |
| `pip install picosentry[all]` | All of the above |

**Python:** ≥ 3.10. **License:** BUSL-1.1.

### Docker

```
docker pull kirkforge/picodome:v2.0.18
```

Multi-arch image (linux/amd64 + linux/arm64), non-root user. `v2.0.18` is
the latest published tag; the `v2.1.2` image push is pending (WO5.0.0-014).
See `deploy/` for Kubernetes and Helm charts.

---

## 3. CLI reference

```
picosentry <subcommand> [options]
```

### `picosentry scan`

Supply-chain scanner — static analysis of manifests, lockfiles, and source.

```bash
picosentry scan ./my-project                     # scan a directory
picosentry scan ./package.json                   # scan a single file
picosentry scan --format json ./project          # JSON output
picosentry scan --format sarif ./project         # SARIF 2.1.0 for CI/CD
picosentry scan --format cyclonedx ./project      # CycloneDX SBOM
picosentry scan --format ml-context ./project     # LLM-friendly context
picosentry scan --format github ./project         # SARIF file + markdown summary
picosentry scan --fail-on high ./project          # exit 1 on HIGH+ findings
picosentry scan --severity-threshold medium ./project  # show MEDIUM+
picosentry scan --verify-determinism ./project    # assert SHA-256 stability
picosentry diff scan-a.json scan-b.json           # compare two scans (own subcommand)
picosentry scan --validate                       # run validation harness
picosentry scan --baseline baseline.json ./project  # suppress known findings
picosentry scan --baseline-update baseline.json ./project  # update baseline
picosentry scan --offline ./project              # refuse all network access
picosentry scan --enterprise ./project            # enterprise policy enforcement
picosentry scan --policy .picosentry-policy.yml ./project  # custom policy
picosentry scan --timeout 120 ./project           # scan timeout in seconds
```

| Flag | Description |
|------|-------------|
| `--format`, `-f` | Output: `table` (default), `json`, `sarif`, `cyclonedx`, `ml-context`, `github` |
| `--output`, `-o` | Write output to file instead of stdout |
| `--rules`, `-r` | Run only specific rules (e.g. `L2-POST-001 L2-OBFS-001`) |
| `--corpus`, `-c` | Path to corpus directory (default: built-in) |
| `--advisory-db` | Path to OSV-format advisory database |
| `--no-color` | Disable colored output (table format only) |
| `--token-budget` | Token budget for `ml-context` format (default: 4096) |
| `--exit-code` | Exit 1 if any findings, 0 if clean |
| `--fail-on` | Exit 1 only if findings at or above this severity (`low`/`medium`/`high`/`critical`) |
| `--quiet`, `-q` | Summary line only, no detail |
| `--summary` | One-line summary for CI. Implies `--quiet`. |
| `--baseline`, `-b` | Baseline JSON/ignore file — suppress known findings |
| `--baseline-update` | Write updated baseline after filtering |
| `--verbose`, `-v` | Per-rule timing and progress |
| `--timeout` | Scan timeout in seconds (0 = no timeout; exit 3 on timeout) |
| `--fail-on-rule-error` | Exit 4 if any detector rule raises an exception |
| `--enterprise` | Enable enterprise mode |
| `--policy`, `-p` | Path to `.picosentry-policy.yml` |
| `--verify-determinism` | Run twice, assert SHA-256 identical (implies `--format json`) |
| `--validate` | Run validation harness against built-in fixtures |
| `--deterministic-output` | Omit timestamps for byte-stable JSON |
| `--offline` | No network (also `PICOSENTRY_OFFLINE=1`) |
| `--sarif-file` | Path for SARIF output when `--format github` |
| `--token-budget` | Max tokens for `ml-context` output |

**Exit codes:**

| Code | Meaning |
|------|---------|
| 0 | Clean — no findings at or above threshold |
| 1 | Findings at or above `--fail-on` severity |
| 2 | Scan error (invalid target, missing deps, etc.) |
| 3 | Scan timed out (`--timeout`) |
| 4 | Rule error (`--fail-on-rule-error`) or determinism failure |

### `picosentry sandbox`

Runtime sandbox — execute a command under seccomp-bpf/seatbelt/subprocess
enforcement and observe behavioral signals.

```bash
picosentry sandbox echo "hello"                  # sandbox a command
picosentry sandbox --backend seccomp-bpf ./run   # explicit backend
picosentry sandbox --backend seccomp-trace ./run  # syscall observability (Linux, requires CONFIG_SECCOMP_LOG=y)
picosentry sandbox --backend seatbelt ./run       # macOS seatbelt
picosentry sandbox --backend subprocess ./run     # unconfined subprocess (for testing)
picosentry sandbox --policy policy.yml ./run      # custom policy
python -m picosentry.sandbox analyze --input report.json  # L4 analysis on an L3 report
python -m picosentry.sandbox rules               # list L4 behavioral rules
```

(`analyze` and `rules` belong to the legacy `picodome` inner CLI, reachable via
`python -m picosentry.sandbox`; they are not subcommands of the unified
`picosentry sandbox`.)

| Flag | Description |
|------|-------------|
| `--format` | Output: `table`, `json`, `sarif`, `ml-context`, `cyclonedx`, `github` |
| `--backend` | `auto` (default), `seccomp-bpf`, `seccomp-trace`, `seatbelt`, `subprocess` |
| `--allow-degraded` | Allow fallback to less restrictive backend |
| `--allow-runtime` | Pre-approve runtime: `node` or `python` |
| `--fail-on` | Exit 1 if findings at or above severity |
| `--timeout` | Sandbox execution timeout in seconds |
| `--policy` | Path to sandbox policy file |
| `--verify-determinism` | Assert SHA-256 stable output |

### `picosentry watch`

LLM prompt-injection detection and output-policy validation.

```bash
picosentry watch scan-prompt --text "ignore previous instructions"   # scan a prompt
picosentry watch scan-prompt --file prompt.txt                         # scan from file
picosentry watch validate-output --schema schema.json --output out.json  # validate output
picosentry watch rules                                                 # list defense rules
picosentry watch health                                                # health check
picosentry watch serve --host 127.0.0.1 --port 8766                   # HTTP daemon
```

### `picosentry serve`

API server, dashboard, and orchestration.

```bash
picosentry serve --port 8765                                     # default
picosentry serve --host 0.0.0.0 --port 8765 --workers 4          # production
picosentry serve --plugin-dir /opt/plugins                       # add plugin dir
picosentry serve --require-signed-plugins                        # enforce Ed25519 signing
picosentry serve --trusted-public-keys "hex1,hex2"               # trusted signing keys
```

### `picosentry daemon`

Sandbox-as-a-service daemon (HTTP + optional gRPC).

```bash
picosentry daemon --host 127.0.0.1 --port 8443                   # HTTP only
picosentry daemon --transport grpc --grpc-port 50051              # gRPC transport
picosentry daemon --store-backend sqlite                          # job storage
picosentry daemon --metrics-port 9090                             # separate metrics port
picosentry daemon --background                                    # daemonize
```

### `picosentry admission`

Kubernetes admission webhook server.

```bash
picosentry admission --cert-file tls.crt --key-file tls.key      # TLS required
picosentry admission --scan-enabled --daemon-url http://daemon:8443  # with image scanning
picosentry admission --scan-min-severity high                     # block on HIGH+ findings
```

### `picosentry corpus`

Manage custom IoC corpus packs — export, import, validate, sign, list.

```bash
picosentry corpus list                                             # list packs
picosentry corpus export my-iocs.json --name my-iocs              # export custom IoCs
picosentry corpus export my-iocs.json --sign sigstore             # sign with Sigstore
picosentry corpus import pack.json                                 # import a pack
picosentry corpus import pack.json --verify-crypto                 # verify signature
picosentry corpus validate pack.json                               # validate without importing
picosentry corpus sign pack.json --method minisign --secret-key key.key  # sign a pack
```

### `picosentry update`

Download or refresh the typosquat/dep-confusion package corpus.

```bash
picosentry update --ecosystem npm --top 5000
picosentry update --ecosystem all --top 10000
picosentry update --ecosystem cargo --source-url https://example.com/top-crates.json
picosentry update --offline   # refuses network (error if no cached corpus)
```

Supported ecosystems: `npm`, `pypi`, `go`, `cargo`, `maven`, `rubygems`, `nuget`.

### Other subcommands

| Command | Description |
|---------|-------------|
| `picosentry diff <a.json> <b.json>` | Compare two scan results |
| `picosentry rules [--json]` | List all scanner rules |
| `picosentry health` | Health check — verify all components import |
| `picosentry init [dir]` | Generate `.picosentry-policy.yml` template |
| `picosentry version` | Show component versions |

---

## 4. Detection rules

PicoSentry ships **53 L2 rule IDs** in `RULE_INFO` (40 primary detectors plus
13 sub-rule IDs produced by expanding 3 detectors through `RULE_ID_ALIASES`,
across 7 ecosystems).

| Rule ID | Name | Description | Severity | Category |
|---------|------|-------------|----------|----------|
| L2-POST-001 | post_install | Install scripts with network/credential access | CRITICAL | execution |
| L2-OBFS-001 | obfuscation_eval | eval() calls in install scripts | CRITICAL | obfuscation |
| L2-OBFS-002 | obfuscation_hex | Hex-encoded strings in install scripts | HIGH | obfuscation |
| L2-OBFS-003 | obfuscation_base64 | Base64 + exec patterns in install scripts | CRITICAL | obfuscation |
| L2-OBFS-004 | obfuscation_unicode | Unicode escape sequences in install scripts | HIGH | obfuscation |
| L2-DEPC-001 | dep_confusion | Internal dependencies without private registry configuration | HIGH | dependency |
| L2-TYPO-001 | typosquat | Package names within edit distance ≤2 of top-327 npm packages | HIGH | typosquat |
| L2-MANI-001 | manifest_version_range | Dangerous version ranges (*, latest, x ranges) | MEDIUM | manifest |
| L2-MANI-002 | manifest_optional_scripts | Optional dependencies with install scripts | HIGH | manifest |
| L2-FORK-001 | fork_drift | Missing repository URL or fork indicators | MEDIUM | provenance |
| L2-CRED-001 | credential_read | Install scripts reading .npmrc, .aws/, .ssh/, env vars | HIGH | credential |
| L2-LOCK-001 | lockfile_drift | Missing lockfile, missing deps, pnpm dangerouslyAllowAllBuilds | MEDIUM | lockfile |
| L2-BUND-001 | bundled_shadow | bundledDependencies shadows (event-stream attack vector) | HIGH | dependency |
| L2-PROV-001 | provenance | Missing repo, no integrity hash, scripts without provenance | LOW | provenance |
| L2-MAINT-001 | maintainer_change | Publisher/author mismatch, anonymous scripts, bus factor, domain transfer | MEDIUM | maintainer |
| L2-PNPM-001 | pnpm_config | dangerouslyAllowAllBuilds, missing .npmrc, overrides, patchedDependencies | MEDIUM | lockfile |
| L2-LICENSE-001 | license | Missing, unlicensed, copyleft (GPL/AGPL/LGPL), or unrecognized license fields | MEDIUM | compliance |
| L2-ENGIN-001 | engine_constraints | Missing, overly permissive, or suspicious Node.js engine constraints | MEDIUM | compatibility |
| L2-SIDELOAD-001 | protocol_sideloading | Dependencies using git://, file:, link:, github: protocols that bypass registry integrity | HIGH | dependency |
| L2-IOC-001 | custom_ioc_detection | Checks installed packages against user-registered custom IoC indicators | HIGH | supply-chain |
| L2-ADV-001 | advisory_vulnerability | Checks installed packages against OSV/GHSA/npm advisory database for known CVEs | HIGH | vulnerability |
| L2-WORM-001 | worm_propagation | Self-propagating worm patterns (npm publish, curl\|sh, self-modifying packages) | CRITICAL | supply-chain |
| L2-NETEX-001 | network_exfiltration | C2 domains, cloud metadata access, phishing domains, credential exfiltration | CRITICAL | supply-chain |
| L2-GO-TYPO-001 | go_typosquat | Go module short names within edit distance ≤2 of top Go packages | HIGH | typosquat |
| L2-GO-DEPC-001 | go_dep_confusion | Internal Go modules without private proxy configuration | CRITICAL | dependency |
| L2-GO-ADV-001 | go_advisory_vulnerability | Checks Go modules against OSV advisory database for known CVEs | HIGH | vulnerability |
| L2-CARGO-TYPO-001 | cargo_typosquat | Crate names within edit distance ≤2 of top Rust crates | HIGH | typosquat |
| L2-CARGO-DEPC-001 | cargo_dep_confusion | Internal crates without private registry configuration | CRITICAL | dependency |
| L2-CARGO-ADV-001 | cargo_advisory_vulnerability | Checks Rust crates against OSV advisory database for known CVEs | HIGH | vulnerability |
| L2-PYPI-TYPO-001 | pypi_typosquat | Package names within edit distance ≤2 of top PyPI packages | HIGH | typosquat |
| L2-PYPI-DEPC-001 | pypi_dep_confusion | Internal PyPI dependencies without private index configuration | CRITICAL | dependency |
| L2-PYPI-POST-001 | pypi_post_install | setup.py/pyproject.toml with install-time code execution | CRITICAL | execution |
| L2-PYPI-OBFS-001 | pypi_obfuscation_eval | exec/eval calls in Python packages | CRITICAL | obfuscation |
| L2-PYPI-OBFS-002 | pypi_obfuscation_base64 | Base64-decoded strings in Python packages | HIGH | obfuscation |
| L2-PYPI-OBFS-003 | pypi_obfuscation_hex | Hex-encoded strings in Python packages | HIGH | obfuscation |
| L2-PYPI-OBFS-004 | pypi_obfuscation_unicode | Unicode character arithmetic obfuscation in Python packages | HIGH | obfuscation |
| L2-PYPI-OBFS-005 | pypi_obfuscation_zlib | Compressed (zlib) payload imported for execution | CRITICAL | obfuscation |
| L2-PYPI-OBFS-006 | pypi_obfuscation_marshal | Marshal deserialization (arbitrary code execution) | CRITICAL | obfuscation |
| L2-PYPI-OBFS-007 | pypi_obfuscation_b64_exec | Base64 decode followed by exec/eval | CRITICAL | obfuscation |
| L2-PYPI-ADV-001 | pypi_advisory_vulnerability | Checks installed Python packages against OSV advisory database for known CVEs | HIGH | vulnerability |
| L2-MAVEN-TYPO-001 | maven_typosquat | Artifact IDs within edit distance ≤2 of top Maven packages | HIGH | typosquat |
| L2-MAVEN-DEPC-001 | maven_dep_confusion | Internal Maven artifacts without private repository configuration | CRITICAL | dependency |
| L2-MAVEN-ADV-001 | maven_advisory_vulnerability | Checks Maven artifacts against OSV advisory database for known CVEs | HIGH | vulnerability |
| L2-RUBYGEMS-TYPO-001 | rubygems_typosquat | Gem names within edit distance ≤2 of top RubyGems packages | HIGH | typosquat |
| L2-RUBYGEMS-DEPC-001 | rubygems_dep_confusion | Internal gems without private gem server configuration | CRITICAL | dependency |
| L2-RUBYGEMS-ADV-001 | rubygems_advisory_vulnerability | Checks Ruby gems against OSV advisory database for known CVEs | HIGH | vulnerability |
| L2-NUGET-TYPO-001 | nuget_typosquat | Package IDs within edit distance ≤2 of top NuGet packages | HIGH | typosquat |
| L2-NUGET-DEPC-001 | nuget_dep_confusion | Internal NuGet packages without private package source configuration | CRITICAL | dependency |
| L2-NUGET-ADV-001 | nuget_advisory_vulnerability | Checks .NET packages against OSV advisory database for known CVEs | HIGH | vulnerability |
| L2-BUILD-001 | dangerous_build_hooks | Build scripts (Cargo, Go, RubyGems, Maven, NuGet) that spawn processes, download code, or read credentials during install | CRITICAL | execution |
| L2-INTEL-001 | suspicious_new_package | Very low download count and very young package age (suspicious new package) | MEDIUM | supply-chain |
| L2-NSCOL-001 | namespace_collision | New low-download package claiming a well-known namespace/scope prefix | MEDIUM | supply-chain |
| L2-VCONF-001 | version_confusion | Popular, established package pinned at a placeholder version (0.0.0/1.0.0) — possible version-squatting | MEDIUM | supply-chain |

Per-rule documentation: [`picosentry/scan/docs/rules/`](../picosentry/scan/docs/rules/)

---

## 5. Ecosystem coverage

PicoSentry covers **7 package ecosystems**:

| Ecosystem | Typosquat | Dep confusion | Advisory (CVE) | Post-install / build hooks | Obfuscation | Other rules |
|-----------|:---------:|:-------------:|:--------------:|:------------------------:|:-----------:|:----------:|
| **npm** | L2-TYPO-001 | L2-DEPC-001 | L2-ADV-001 | L2-POST-001 | L2-OBFS-001–004 | manifest, lockfile, credential, bundled, provenance, maintainer, pnpm, license, engine, sideloading, IoC, worm, network exfil |
| **PyPI** | L2-PYPI-TYPO-001 | L2-PYPI-DEPC-001 | L2-PYPI-ADV-001 | L2-PYPI-POST-001 | L2-PYPI-OBFS-001–007 | — |
| **Go** | L2-GO-TYPO-001 | L2-GO-DEPC-001 | L2-GO-ADV-001 | L2-BUILD-001 | — | — |
| **Cargo** | L2-CARGO-TYPO-001 | L2-CARGO-DEPC-001 | L2-CARGO-ADV-001 | L2-BUILD-001 | — | — |
| **Maven** | L2-MAVEN-TYPO-001 | L2-MAVEN-DEPC-001 | L2-MAVEN-ADV-001 | L2-BUILD-001 | — | — |
| **RubyGems** | L2-RUBYGEMS-TYPO-001 | L2-RUBYGEMS-DEPC-001 | L2-RUBYGEMS-ADV-001 | L2-BUILD-001 | — | — |
| **NuGet** | L2-NUGET-TYPO-001 | L2-NUGET-DEPC-001 | L2-NUGET-ADV-001 | L2-BUILD-001 | — | — |

---

## 6. Output formats

| Format | Flag | Use case |
|--------|------|----------|
| **table** | `--format table` (default) | Human-readable terminal output |
| **json** | `--format json` | Machine-readable; includes rule IDs, severities, locations |
| **sarif** | `--format sarif` | SARIF 2.1.0 for GitHub Actions, Azure DevOps, etc. |
| **cyclonedx** | `--format cyclonedx` | CycloneDX-compatible SBOM generation |
| **ml-context** | `--format ml-context` | LLM-friendly context injection (token-budget controlled) |
| **github** | `--format github` | Writes SARIF file + prints markdown summary for GitHub PRs |

All JSON/SARIF outputs are deterministic when `--deterministic-output` is used
(timestamps and timing metadata are omitted).

---

## 7. Sandbox

### Backends

| Backend | Platform | What it does |
|---------|----------|-------------|
| **seccomp-bpf** | Linux | Kernel-level syscall allowlist enforcement. Blocks unexpected syscalls at the kernel boundary. |
| **seccomp-trace** | Linux | Observability mode — logs syscalls without killing the process. Requires `CONFIG_SECCOMP_LOG=y`. **Path/address arguments on events are not yet captured.** |
| **landlock** | Linux ≥5.13 | Path-based filesystem ACL (`get_backend("landlock")`, falls back to seccomp when unavailable). Not selectable via `--backend`; enforces a fixed read-only/read-write path set that does **not** yet honor per-policy paths, and captures no stdout/stderr. |
| **seatbelt** | macOS | Apple Seatbelt profile for basic filesystem and process restrictions. |
| **subprocess** | Any | Unconfined subprocess fallback (for testing only; no enforcement). |
| **auto** | Any | Selects the best available backend per platform. |

### What the sandbox does

- Enforces a syscall allowlist via seccomp-bpf (Linux) or seatbelt (macOS).
- Records observed behavioral events for L4 analysis.
- Supports gRPC and HTTP transport for the daemon.
- Supports fail-closed policy: `PICODOME_ADMISSION_FAIL_CLOSED=true`.

### What the sandbox does NOT do

- It does **not** provide a full VM or container boundary.
- It does **not** trace every syscall by default; `seccomp-trace` is opt-in and
  argument-limited.
- It does **not** provide path-based filesystem access control through the CLI
  surface. A `LandlockBackend` exists (`get_backend("landlock")`,
  `picosentry/sandbox/l3/backends/landlock_backend.py`, Linux ≥ 5.13, seccomp
  fallback) but is not exposed via `--backend` and enforces a fixed path set
  that does not yet honor per-policy paths — see ADR-002's addendum.
  Filesystem access is otherwise bounded by the child's working directory and
  the syscall allowlist.
- It does **not** guarantee detection of all malware.

### gRPC transport

```bash
pip install 'picosentry[grpc]'
picosentry daemon --transport grpc --grpc-port 50051
```

The generated protobuf stubs (`picodome_pb2.py`, `picodome_pb2_grpc.py`) are
committed under `picosentry/sandbox/grpc_transport/proto/` and ship in the
wheel. RPCs: `Scan`, `Health`, `GetPolicy`, `QueryAudit`. See
`picosentry/sandbox/grpc_transport/proto/picodome.proto` for the full schema.

### Kubernetes

`deploy/kubernetes/deployment.yaml` boots the daemon with gRPC enabled.
Helm values:

```yaml
grpc:
  enabled: true
  port: 50051
```

---

## 8. Watch (LLM defense)

`picosentry watch` provides **two defense layers**:

| Layer | Name | What it checks |
|-------|------|----------------|
| **L5** | Prompt injection detection | Deterministic regex + lexical classifier for common injection patterns (ignore instructions, role play, jailbreaks, encoding tricks). |
| **L6** | Output policy validation | Validates LLM output against a schema or policy (e.g. no PII, no code execution). |

**What it is:** A fast pre-filter using deterministic rules and a lexical
classifier. It catches common, known patterns reliably and deterministically.

**What it is NOT:** A semantic/LLM guarantee. Paraphrase, novel phrasing,
encoding tricks, or adversarial prompts can slip through. For high-stakes LLM
deployments, pair it with a dedicated model-based guard as a second layer.

**Fail-closed mode:** Set `PICOSENTRY_WATCH_FAIL_CLOSED=true` to make watch
return a non-zero exit on rule-load failures or evaluation crashes instead of
passing through.

---

## 9. Serve API

**Status: Beta** — security review and regression tests in place; not yet
battle-tested in broad multi-tenant production.

- **Framework:** FastAPI + uvicorn
- **Auth:** JWT (PyJWT) with bcrypt/PBKDF2 password hashing; role-scoped API keys
  (`viewer`/`operator`/`admin`) enforced through the same RBAC checks as JWTs.
- **RBAC:** `viewer < operator < admin` role hierarchy with `require_role` and
  `require_permission` dependencies.
- **Multi-tenancy:** Flat `org_id` scoping on reads/writes; `org_projects`
  junction table enforces project ownership.
- **Persistence:** SQLite (default) or Postgres (`PICOSHOGUN_DATABASE_BACKEND=postgres`).
  Postgres backend includes psycopg2 pooling, DDL auto-translation, and live PG
  15/16 CI.
- **Security hardening:** CORS blocking in production, HTTPS enforcement,
  API docs restricted in production, secure secret assertions, rate limiting
  (100 IP/min default), DDoS shield, 10 MB body limit, 30 s timeout.
- **Dashboard:** Built-in web dashboard for scan results, alerts, and project management.

See [THREAT_MODEL.md](THREAT_MODEL.md) and [SECURITY-ATTACK-SURFACE.md](SECURITY-ATTACK-SURFACE.md)
for trust boundaries, attack surface, and honest limitations.

---

## 10. Plugin system

**Status: Stable**

### Discovery

Plugins are discovered from three locations, in priority order:

1. `--plugin-dir PATH` (repeatable) on the `serve` subcommand.
2. `PICOSHOGUN_PLUGIN_DIR` env var (comma-separated paths).
3. `~/.picosentry/plugins/` if it exists.

The bundled `picosentry/serve/plugins/` (`test_plugin`, `test_discord_notifier`) is
always scanned last.

### Signing and trust (ADR-004)

Each plugin manifest may be Ed25519-signed. **Signing is admission, not safety.**
The sandbox is the safety boundary:

| State | Loads? | Capabilities |
|-------|--------|--------------|
| Signed by trusted key | Yes (all envs) | deny-by-default sandbox |
| Signed by untrusted key | No | — |
| Unsigned, non-production | Yes | deny-by-default sandbox |
| Unsigned, production | No (boot refuses unless `REQUIRE_SIGNED_PLUGINS=1`) | — |

- `PICOSHOGUN_REQUIRE_SIGNED_PLUGINS=1` enforces signature verification.
- `PICOSHOGUN_TRUSTED_PUBLIC_KEYS` / `PICOSHOGUN_TRUSTED_PUBLIC_KEYS_FILE` —
  Ed25519 public key allowlist.
- All plugins run in a subprocess with a stripped environment and deny-by-default
  capability allowlist (`network`, `filesystem`, `subprocess`, `environment`,
  `secrets`, `detection_write`). Undeclared access is refused.

See [PLUGIN_DEVELOPMENT.md](PLUGIN_DEVELOPMENT.md) for the full guide.

---

## 11. Corpus management

`picosentry corpus` manages IoC packs — export, import, validate, sign, and list.

- **3 built-in packs** ship with the wheel.
- Packs are JSON files containing IoC indicators with metadata.
- Signing methods: `digest` (SHA-256), `minisign`, `sigstore`.
- Import verifies pack integrity and optionally verifies cryptographic signatures.

```bash
picosentry corpus list                              # list built-in + user packs
picosentry corpus export iocs.json --name my-iocs   # export custom IoCs
picosentry corpus export iocs.json --sign sigstore   # sign with Sigstore
picosentry corpus import pack.json --verify-crypto   # import with signature verify
picosentry corpus validate pack.json                 # validate without importing
picosentry corpus sign pack.json --method minisign --secret-key key.key
```

Corpus freshness: the scanner warns when any ecosystem corpus is older than 30
days. Use `picosentry update` to refresh.

---

## 12. Cross-layer correlation

**Status: Stable**

`CorrelationEngine` ingests events from scan, sandbox L4, and watch layers. Each
event maps to a MITRE ATT&CK kill-chain phase. When an artifact has events
across multiple layers or multiple phases, the engine:

1. Builds a `KillChainTimeline`.
2. Computes a chain score.
3. Can trigger downstream auto-analysis via the event bus.

Persistence, dedup, and per-minute backpressure are tested in CI.

---

## 13. Configuration

### Environment variables

#### Scanner (`PICOSHOGUN_*` shared, `PICOSENTRY_*` scanner-specific)

| Variable | Purpose | Default |
|----------|---------|---------|
| `PICOSENTRY_OFFLINE` | Refuse all network access | `0` |
| `PICOSENTRY_QUIET` | Suppress cache HMAC warnings | `0` |
| `PICOSENTRY_MATURITY_ACK` | Suppress Beta/Experimental warnings | `0` |
| `PICOSENTRY_AUTH_MODE` | Scanner auth mode (`off`, `static`, `oidc`) | `off` |
| `PICOSENTRY_AUTH_TOKEN` | Static auth token | — |
| `PICOSENTRY_RATE_LIMIT_RPS` | Rate limit requests/sec | `0` (disabled) |
| `PICOSENTRY_WATCH_FAIL_CLOSED` | Watch fail-closed mode | `false` |

#### Serve (`PICOSHOGUN_*`)

| Variable | Purpose | Default |
|----------|---------|---------|
| `PICOSHOGUN_SECRET_KEY` | JWT signing key (must be strong in production) | — |
| `PICOSHOGUN_API_HOST` | Serve bind address | `127.0.0.1` |
| `PICOSHOGUN_API_PORT` | Serve bind port | `8765` |
| `PICOSHOGUN_API_WORKERS` | Uvicorn worker count | `1` |
| `PICOSHOGUN_API_RELOAD` | Enable hot reload | `false` |
| `PICOSHOGUN_DATABASE_BACKEND` | `sqlite` or `postgres` | `sqlite` |
| `PICOSHOGUN_DATABASE_URL` | Postgres connection string | — |
| `PICOSHOGUN_REDIS_URL` | Redis for rate limiting | `redis://localhost:6379/0` |
| `PICOSHOGUN_PLUGIN_DIR` | Comma-separated plugin directories | — |
| `PICOSHOGUN_REQUIRE_SIGNED_PLUGINS` | Enforce plugin signing | `0` |
| `PICOSHOGUN_TRUSTED_PUBLIC_KEYS` | Comma-separated Ed25519 public keys (hex) | — |
| `PICOSHOGUN_TRUSTED_PUBLIC_KEYS_FILE` | File with one key per line | — |
| `PICOSHOGUN_CORS_ORIGINS` | Explicit CORS origins (production) | — |
| `PICOSHOGUN_SCANS_WORKSPACE_ROOT` | Required for POST /scans | — |
| `PICOSHOGUN_ENV` | Environment label (`development`, `production`) | `development` |
| `PICOSHOGUN_SKIP_SECURE_ASSERT` | Skip boot security checks | **Dangerous** |

#### Daemon (`PICODOME_*`)

| Variable | Purpose | Default |
|----------|---------|---------|
| `PICODOME_API_TOKENS` | Comma-separated auth tokens | — |
| `PICODOME_DEV_MODE` | Disable auth (development only) | — |
| `PICODOME_ENTERPRISE_MODE` | Enterprise auth enforcement | — |
| `PICODOME_TLS_DEV` | Self-signed TLS (incompatible with enterprise) | — |
| `PICODOME_SKIP_SECURE_ASSERT` | Skip boot security checks | **Dangerous** |
| `PICODOME_CLUSTER_TOKEN` | Required for cluster gossip | — |
| `PICODOME_SQLITE_PATH` | SQLite database path | — |
| `PICODOME_MAX_SCAN_TIMEOUT` | Max scan timeout in seconds | `300` |
| `PICODOME_MAX_LIST_LIMIT` | Max list query limit | `1000` |
| `PICODOME_REDIS_URL` | Redis for distributed rate limiting | `redis://localhost:6379/0` |

#### Admission

| Variable | Purpose | Default |
|----------|---------|---------|
| `PICODOME_ADMISSION_FAIL_CLOSED` | Deny pods on webhook misconfiguration | `true` |

---

## 14. Security model

### Trust boundaries

| Boundary | What it separates | Enforcement |
|----------|-------------------|-------------|
| CLI → engine | User input → deterministic scanner | Path validation, no network in default scan |
| Engine → rules | Detection logic | Signed corpus packs, rule validation |
| Sandbox host → worker | Server process → untrusted command | Subprocess + seccomp-bpf / seatbelt |
| Plugin host → worker | Server process → third-party plugin | Subprocess, stripped env, deny-by-default capabilities |
| Serve API → DB | HTTP clients → persistence | RBAC permissions, org scoping |
| Serve API → plugins | API callers → plugin hooks | Permission checks, `detection_write` capability gate |
| Cluster peers | Daemon nodes | Shared cluster token, mTLS optional |

### Fail-closed defaults

| Situation | Default | Override |
|-----------|---------|----------|
| Admission validator missing | **deny** | configure a validator |
| Admission daemon unreachable | **deny** if fail-closed is on | `PICODOME_ADMISSION_FAIL_CLOSED=false` |
| Watch rule load failure | **pass** (fail-open) | `PICOSENTRY_WATCH_FAIL_CLOSED=true` |
| Watch rule evaluation crash | **pass** unless fail-closed | `PICOSENTRY_WATCH_FAIL_CLOSED=true` |
| Plugin worker timeout | worker terminated, call raises | tune `timeout` per plugin |
| Corpus older than threshold | CLI exits 5 (`--check-corpus-age`, currently only on the inner `check` command — see `picosentry/scan/cli_commands/check.py`; not yet wired into the unified `picosentry` CLI) | wire up / use `picosentry scan` staleness warning |
| Rate-limiter table full | new distinct IPs denied | increase `max_clients` |
| Serve auth failure | HTTP 401/403 | — |
| Cluster token missing | cluster manager does not start | set `PICODOME_CLUSTER_TOKEN` |
| Production insecure secret | boot refuses (exit 7) | `ALLOW_INSECURE_SECRET=true` (dev only) |
| Production unsigned plugins | boot refuses unless `REQUIRE_SIGNED_PLUGINS=1` | set the flag |

### ADR references

- **ADR-002** — Kernel sandbox via seccomp-bpf. The CLI sandbox surface is
  seccomp-bpf; a `LandlockBackend` was later added behind
  `get_backend("landlock")` (not CLI-exposed, fixed path set — see the ADR's
  addendum). See [`docs/adr/ADR-002-kernel-sandbox.md`](adr/ADR-002-kernel-sandbox.md).
- **ADR-004** — Plugin trust boundary: signing is authenticity, sandboxing is
  safety. See [`docs/adr/ADR-004-plugin-trust-boundary.md`](adr/ADR-004-plugin-trust-boundary.md).

### Per-component security documentation

- [`THREAT_MODEL.md`](THREAT_MODEL.md) — trust boundaries, failure modes, all components
- [`SECURITY-ATTACK-SURFACE.md`](SECURITY-ATTACK-SURFACE.md) — entry points, previously-fixed findings, hardening table

---

## 15. Known limitations

### What it does NOT do (today)

- **Sandbox does not provide full VM/container isolation.** It enforces syscalls
  via seccomp-bpf and observes behavioral events. It does **not** trace every
  syscall by default; `seccomp-trace` is opt-in and argument-limited. There is
  no policy-driven path-based filesystem ACL in the CLI sandbox (the existing
  landlock backend is not CLI-exposed and uses a fixed path set — see ADR-002
  addendum).

- **Watch is a fast pre-filter, not a semantic guarantee.** Paraphrase, novel
  phrasing, encoding tricks, or adversarial prompts can still slip through.
  Pair with a model-based guard for high-stakes deployments.

- **Watch does not scan LLM model weights.** It guards prompts and outputs in
  deployed apps, not the model itself.

- **Cluster mode is Beta.** Gossip over HTTP(S) requires a shared cluster token
  and supports optional mTLS. A 3-node integration test exercises leader
  election, token enforcement, and scan redistribution. It has not been
  battle-tested in a real multi-host deployment.

- **Admission controller is Beta.** Live-tested against kind; the real-cluster
  matrix in `.github/workflows/admission-kind.yml` exercises pod admission
  decisions across K8s v1.28–v1.30.

- **Serve is Beta.** Security review complete, regression tests in place. Known
  limitations: in-memory rate limiter by default (Redis backend available), no
  global session revocation list, effectively no password policy (the register
  endpoint enforces `min_length=1`). See
  [THREAT_MODEL.md](THREAT_MODEL.md) and [SECURITY-ATTACK-SURFACE.md](SECURITY-ATTACK-SURFACE.md).

- **Detection benchmarks are published.** See [`docs/model-card.md`](model-card.md).
  The corpus is **6495 fixtures** (3558 positive / 2930 negative / 7 tricky)
  across **7 ecosystems**; the 2026-07-29 benchmark run measured **94.44% mean
  precision / 68.89% mean recall** over 54 rule IDs (50 static at the time + 4
  campaign matchers); `RULE_INFO` has since grown to 53 static rules
  (+`L2-INTEL-001`, `L2-NSCOL-001`, `L2-VCONF-001`), which are not yet in the
  per-rule table. Zero false positives on negative fixtures. Advisory rules
  (L2-*-ADV-001) show low recall in offline mode because OSV data is not
  available without network or `--advisory-db`. See the model card for honest
  per-rule breakdowns and what the numbers do and don't prove.

- **CVE matching requires OSV corpus.** Offline-only operation uses the local
  snapshot; online mode (`[scan]` extra) can query the OSV API directly.

- **Reachability/VEX/Remediation and AI-agent-security design work is deferred.**
  These were design tracks in the former `docs/strategic/` directory, which no
  longer exists; no shipped feature tracks them.

---

## 16. Repository structure

```
picosentry/
    _core/          shared primitives (config, security_check, hashing)
    scan/           supply-chain scanner (CLI: picosentry scan)
        cli/        CLI subcommand dispatch
        corpus/     IoC corpus packs and indexing
        rules/      53 L2 detection rules
        docs/       per-rule documentation
    sandbox/        runtime kernel sandbox (CLI: picosentry sandbox)
        l3/         L3 sandbox engine + backends (seccomp-bpf, seccomp-trace, landlock, seatbelt, subprocess)
        l4/         L4 behavioral analysis
        daemon/     PicoDome daemon (HTTP + gRPC)
        grpc_transport/  gRPC transport and proto stubs
    watch/          LLM prompt/output guard (CLI: picosentry watch)
        rules/      prompt injection and output policy rules
    serve/          API server + dashboard (CLI: picosentry serve)
        api/        FastAPI routers and middleware
        front/      Web dashboard (HTML/CSS/JS)
        services/   business logic, plugin manager, plugin host
        plugins/    bundled plugins (test_plugin, test_discord_notifier)
        database/   SQLite/Postgres backend, pools, migrations
        config/     settings, version
    experimental.py feature-maturity tracking (source of truth)
examples/
    pypi-obfuscated-setup/    reproducible malicious PyPI fixture
    npm-postinstall-exfil/     reproducible npm post-install fixture
    prompt-injection/          reproducible prompt-injection fixture
docs/
    adr/           Architecture Decision Records
    ops/           operational runbook
    workorders/    improvement workorder specs
    (per-rule documentation lives in picosentry/scan/docs/rules/)
tests/            test suite
deploy/
    kubernetes/    K8s deployment manifests
    helm/          Helm charts (picodome daemon, picodome-admission)
```

---

## 17. Component status

Source of truth: [`picosentry/experimental.py`](../picosentry/experimental.py).

| Component | Status | Notes |
|-----------|--------|-------|
| `picosentry scan` | **Stable** | Core scanner; 7 ecosystems; deterministic, offline; 53 rules, 6495 fixtures |
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
| Detection benchmarks | **Stable** | 6495 fixtures (3558 pos / 2930 neg / 7 tricky), 53 rules, 94.44% mean precision, 68.89% mean recall — see [model card](model-card.md) |
| Docker image | **Stable** | multi-arch (linux/amd64 + linux/arm64), non-root; latest published: `kirkforge/picodome:v2.0.18` — `kirkforge/picodome:v2.1.2` push pending (WO5.0.0-014) |
| PyPI package | **Stable** | `pip install picosentry` — v2.1.2 published |

---

*Supersedes `docs/manual.md` (both are maintained; this is the extended
reference). Landlock references updated: a landlock backend now exists behind
`get_backend("landlock")` but is not CLI-exposed (ADR-002 addendum). The
former `docs/strategic/` design docs were removed; those tracks are deferred.*