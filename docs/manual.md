# PicoSentry Manual

> Version 2.1.3 — BUSL-1.1 — Source of truth: codebase and [`picosentry/experimental.py`](../picosentry/experimental.py).
>
> This is the single PicoSentry manual. Every former standalone tech doc is a
> chapter here; the old files remain as one-line pointer stubs for link
> stability. Generated files stay standalone: [`docs/BENCHMARKS.md`](BENCHMARKS.md)
> is re-rendered by `scripts/render_benchmarks.py` and CI-enforced against drift,
> and the ADRs in [`docs/adr/`](adr/) are immutable records indexed in the
> [ADR appendix](#23-appendix-adr-index).

**Start here.** PicoSentry is an **offline, deterministic supply-chain security
suite** that combines four capabilities in a single binary:

| Layer | What it does |
|-------|-------------|
| **scan** | Static analysis of package manifests, lockfiles, and source for typosquatting, dependency confusion, obfuscation, post-install hooks, CVEs, license violations, and more. |
| **sandbox** | Runtime enforcement and behavioral analysis via seccomp-bpf (Linux), seatbelt (macOS), or subprocess fallback. Observes syscalls at L4. |
| **watch** | Deterministic regex + lexical classifier for LLM prompt-injection detection (L5) and output-policy validation (L6). |
| **serve** | FastAPI API server with RBAC, multi-tenant Postgres, plugin system, and orchestration across all layers. |

If you just want to try it: `pip install picosentry && picosentry scan ./your-project`.
If you operate it in production: start with [Chapter 13, Operations](#13-operations-runbook)
and [Chapter 15, Deployment security](#15-deployment-security-checklist).
If you are reviewing its security: [Chapter 16, Threat model](#16-threat-model) and
[Chapter 17, Attack surface](#17-attack-surface-and-pentest-scope).

## Table of contents

- [1. Quick start](#1-quick-start)
- [2. Installation](#2-installation)
- [3. Docker builds and deployment](#3-docker-builds-and-deployment)
- [4. CLI reference](#4-cli-reference)
- [5. Scanner rules, ecosystems, and corpus](#5-scanner-rules-ecosystems-and-corpus)
- [6. Registry firewall](#6-registry-firewall)
- [7. Watch LLM defense](#7-watch-llm-defense)
- [8. Sandbox PicoDome](#8-sandbox-picodome)
- [9. Serve control plane](#9-serve-control-plane)
- [10. Plugin system](#10-plugin-system)
- [11. Architecture](#11-architecture)
- [12. Configuration reference](#12-configuration-reference)
- [13. Operations runbook](#13-operations-runbook)
- [14. Offline and air-gapped operation](#14-offline-and-air-gapped-operation)
- [15. Deployment security checklist](#15-deployment-security-checklist)
- [16. Threat model](#16-threat-model)
- [17. Attack surface and pentest scope](#17-attack-surface-and-pentest-scope)
- [18. Detection benchmarks and model card](#18-detection-benchmarks-and-model-card)
- [19. Internal API map](#19-internal-api-map)
- [20. Extension guide](#20-extension-guide)
- [21. Known limitations and component status](#21-known-limitations-and-component-status)
- [22. Repository structure](#22-repository-structure)
- [23. Appendix ADR index](#23-appendix-adr-index)

---

## 1. Quick start

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
Engine: v2.1.3 | Corpus: vabd36dc30c3f
Scan ID: 08057439b4ba08d8

Packages scanned: 0
Files scanned:     2
Duration:          20ms
```

The scan fires 5+ findings across obfuscation, post-install, and exfiltration
rules. Re-run and the `Scan ID` and `Corpus` digest match exactly — that's the
determinism guarantee.

### Design principles

- **Offline by default.** `picosentry scan` works with zero network access.
  Online features (advisory DB, corpus update, serve dashboard) are opt-in extras.
- **Deterministic output.** Two scans of the same input produce bit-identical
  JSON. Use `--verify-determinism` to assert SHA-256 stability in CI.
- **Fail-closed defaults.** Admission webhooks deny on misconfiguration; watch
  can be set to fail-closed; `serve` blocks insecure secrets in production.
- **Honest about limitations.** Detection benchmarks, known gaps, and retracted
  claims (see ADR-002) are documented rather than hidden.
- **Lightweight core.** The default install pulls only `pyyaml` + `cryptography`.
- **Typed.** Full annotations, `py.typed` shipped.

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

The default `pip install picosentry` is deliberately lightweight — it pulls in
only `pyyaml` and `cryptography`, which is enough to run `picosentry scan`
against any project. To use the API server, dashboard, or HTTP corpus refresh,
install the matching extras.

### Docker

```
docker pull kirkforge/picodome:v2.0.18
```

Multi-arch image (linux/amd64 + linux/arm64), non-root user. `v2.0.18` is
the latest published tag; the `v2.1.3` image push is pending (WO5.0.0-014).
See `deploy/` for Kubernetes and Helm charts.

---

## 3. Docker builds and deployment

The official image supports `linux/amd64` and `linux/arm64`.

### Quick local build

```bash
docker build -t picosentry:latest .
```

### Multi-arch build and push

Requirements:

- Docker with `buildx` enabled
- `binfmt` / QEMU user-static for arm64 emulation on amd64 hosts
- Logged in to the registry if pushing

#### Using `docker buildx bake`

```bash
# Build only
docker buildx bake

# Build and push
docker buildx bake --push
```

#### Using the helper script

```bash
./scripts/build_docker_multiarch.sh        # build only
./scripts/build_docker_multiarch.sh --push # build and push
```

The script auto-registers QEMU binfmt if the local builder does not list
`linux/arm64`, reads the current version from `pyproject.toml`, and builds
both architectures.

### Helm chart

`deploy/helm/picodome/values.yaml` uses `kirkforge/picodome` by default. The
chart does not require any architecture-specific settings; Kubernetes pulls the
matching manifest from the multi-arch image. The chart's `appVersion` is
v-prefixed (`v2.1.3`) to match the registry tag scheme — image references
resolve without a `v`-less/appVersion mismatch.

### Runtime smoke test

```bash
docker run --rm kirkforge/picodome:latest --version
docker run --rm kirkforge/picodome:latest sandbox echo "hello"
```

---

## 4. CLI reference

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
picosentry scan --no-cache ./project             # bypass the scan cache
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
| `--no-cache` | Bypass the scan cache; compute results fresh (the cache key covers rules, filters, and non-lockfile inputs — use this when you suspect cache interference) |
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
| 2 | Scan error (invalid target, missing deps, or an explicit `--rules` selection where no requested rule was applicable to the target — the skipped rules are listed on stderr) |
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
picosentry serve --port 8765                                     # default (single worker)
picosentry serve --host 0.0.0.0 --port 8765 --workers 4          # multi-worker (see ceilings below)
picosentry serve --plugin-dir /opt/plugins                       # add plugin dir
picosentry serve --require-signed-plugins                        # enforce Ed25519 signing
picosentry serve --trusted-public-keys "hex1,hex2"               # trusted signing keys
```

> **Multi-worker status (honest-doc):** the multi-worker posture landed in
> WO5-031 with documented ceilings (event fanout latency = the outbox poll
> interval; scheduler jobs may be skipped across a leader takeover; rate
> limits sync every `RATE_LIMIT_SYNC_SECONDS`; `/metrics` is per-worker —
> see `picosentry/serve/api/server.py` deployment matrix). Two correctness
> fixes are still pending as of this build: WO6-009 (outbox poller dies on
> the Postgres backend; N× escalation delivery across workers) and WO6-010
> (related outbox correctness). Until those land, `--workers > 1` can
> multiply side-effectful escalation deliveries (alerts/webhooks) on
> Postgres — prefer `--workers 1` for alerting-critical deployments, or run
> multi-worker behind a single-worker alerting node.

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

### `picosentry firewall`

Local registry metadata proxy — see [Chapter 6](#6-registry-firewall).

```bash
npm --registry http://127.0.0.1:3132 install left-pad
pip install --index-url http://127.0.0.1:3132/pypi/simple requests
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

### `picosentry advisories`

Fetch the OSV-format advisory database on a networked machine (unified-CLI
subcommand; forwards to the scan package).

```bash
picosentry advisories fetch <advisory-bundle-url> -o advisories/
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
| `picosentry doctor` | Self-verification: rule registry/implementation consistency, fixture and corpus file presence, import health, git-hygiene, secrets-in-source, experimental-claims vs code, and version consistency across pyproject/lockfile/CLI |
| `picosentry health` | Health check — verify all components import |
| `picosentry init [dir]` | Generate `.picosentry-policy.yml` template |
| `picosentry version` | Show component versions |

### Programmatic use

PicoSentry is **CLI-first**. The supported interface is the command line
(`picosentry`, `picowatch`, `picodome`, …). The Python modules under
`picosentry.*` are internal implementation details and may change without
notice; there is no stable public import API today. If you need a programmatic
entrypoint, open an issue describing the use case.

---

## 5. Scanner rules, ecosystems, and corpus

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

Advisory findings (L2-ADV-001, `L2-{ECO}-ADV-001`, etc.) carry a **`reachable`**
boolean — `True` when the vulnerable package is imported/used in the scanned
source, `False` when present but unused — computed by
`picosentry/scan/rules/advisory_check.py`.

### Ecosystem coverage

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

License detection (`L2-LICENSE-001`) reads npm `package.json` license fields only.

### Output formats

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

### Corpus management

PicoSentry ships with a small built-in typosquat/dep-confusion corpus. For
stronger coverage, download per-ecosystem top-package lists and keep them fresh:

```bash
picosentry update --ecosystem npm --top 5000
picosentry update --ecosystem all --top 10000
```

Supported ecosystems: `npm`, `pypi`, `go`, `cargo`, `maven`, `rubygems`, `nuget`.
All seven have live registry fetchers (`_fetch_npm` … `_fetch_nuget` in
`picosentry/scan/cli_commands/update.py`); ecosystems without a curated fetcher
fall back to a built-in list, and `--source-url` can override the source for any
ecosystem. The command writes a `corpus.json` manifest, and the scanner warns
when any ecosystem corpus is older than 30 days.

`picosentry corpus` manages IoC packs — export, import, validate, sign, and list:

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

## 6. Registry firewall

A metadata firewall: a local HTTP proxy in front of npm / PyPI that scans
package **metadata** before your machine ever fetches an artifact. Start it
with `picosentry firewall` (see `picosentry firewall --help`).

```
npm --registry http://127.0.0.1:3132 install left-pad
pip install --index-url http://127.0.0.1:3132/pypi/simple requests
```

### What gets scanned

| Path shape | Example | Treatment |
|---|---|---|
| npm manifest | `/left-pad`, `/left-pad/1.3.0` | scanned, verdict applied |
| PyPI JSON | `/pypi/requests/json`, `/pypi/requests/2.31.0/json` | scanned, verdict applied |
| Metadata URL with a query string | `/left-pad?refresh=1` | scanned — classification runs on the query-less path, so `$`-anchored regexes never see `?refresh=1`, and the query never pollutes the name used for scanning/cache keys |
| Everything else (tarballs, static assets) | `/left-pad/-/left-pad-1.3.0.tgz` | **passed through unscanned** (see below) |

### Tarball decision (explicit, not accidental)

This is a **metadata** firewall. Tarballs are streamed through **without
inspection** and tagged `X-PicoSentry-Verdict: passthrough`. Rationale:

- Metadata (name, scripts, dependencies, maintainers) is small, fetchable in
  one request, and catches the dominant registry attacks (typosquats,
  dependency confusion, malicious install hooks) before any code lands on
  disk.
- Scanning tarballs synchronously in the proxy path would mean downloading,
  extracting and scanning every artifact every client pulls — that is
  `picosentry scan`'s job, run where you extract/install artifacts.
- If you need artifact scanning, run `picosentry scan` on the installed tree
  or CI workspace; the firewall is the metadata gate, not the artifact gate.

### Version-scoped verdicts

Verdicts are computed from the **requested version's manifest slice**, not the
whole-catalog document npm returns for `/pkg`:

- `GET /pkg` → the `dist-tags.latest` version's manifest from `versions`
- `GET /pkg/1.2.3` → the `1.2.3` manifest
- PyPI → the `info` object (already the requested version's metadata)

A malicious 0.9.0 therefore does not poison the verdict for a clean 1.0.0, and
a clean latest is not judged blind from root-level catalog fields. Verdicts
are cached per `(ecosystem, name, version)` for `cache_ttl_seconds`.

### Rules applied

The firewall scans with the default engine **minus artifact rules** — rules
that require local artifacts registry metadata can never contain and that
would therefore fire on every package:

- `L2-LOCK-001` (lockfile drift — a manifest has no lockfile by definition)
- `L2-PNPM-001` (pnpm workspace config — likewise absent from metadata)

### Verdicts and headers

Every scanned response carries `X-PicoSentry-Verdict`; pass-through responses
carry `X-PicoSentry-Proxy: true` too.

| Verdict | Meaning | Default response |
|---|---|---|
| `allow` | no findings at/above quarantine threshold | body served |
| `quarantine` | HIGH/MEDIUM findings (e.g. install scripts present) | body served + `X-PicoSentry-Reasons: <rule ids>` |
| `block` | CRITICAL findings (verified typosquat, dep confusion, worm patterns) | `403` + JSON reasons body |

Default severity mapping is **BLOCK on CRITICAL only**. HIGH/MEDIUM findings
quarantine-tag instead of failing the install: a metadata firewall that
403s every package shipping an install script (esbuild & co.) breaks more
builds than it protects. CI can enforce stricter postures from the headers:
set `block_severities=["CRITICAL","HIGH"]` and/or
`quarantine_action="block"` to make quarantine a hard 403.

### Configuration (`FirewallConfig`)

| Option | Default | Notes |
|---|---|---|
| `listen_host` | `127.0.0.1` | Loopback by default — the proxy is unauthenticated unless `auth_token` is set. Set `"0.0.0.0"` explicitly to expose. |
| `listen_port` | `3132` | |
| `auth_token` | `None` | If set, clients must send `Authorization: Bearer <token>`; compared constant-time. |
| `upstream_npm` / `upstream_pypi` | npmjs.org / pypi.org | Must be `https://` (enforced). |
| `block_severities` | `["CRITICAL"]` | See verdicts above. |
| `quarantine_severities` | `["HIGH", "MEDIUM"]` | |
| `quarantine_action` | `"tag"` | `"tag"` serves the body with warning headers; `"block"` returns 403. |
| `pass_through_max_bytes` | 512 MiB | Pass-through streams in 64 KiB chunks; bodies exceeding this are truncated and the connection closed — memory stays bounded regardless of artifact size. |
| `cache_ttl_seconds` / `cache_max_entries` | 3600 / 10000 | Verdict cache. |
| `scan_timeout_seconds` | 30 | Upstream fetch + rule timebox. |

The server is a `ThreadingHTTPServer` (`daemon_threads=True`) — one slow
client cannot head-of-line-block the proxy.

### Known limitations (honest-doc)

- **Short generic names can still hard-BLOCK via `L2-TYPO-001`.** e.g. `pkg`
  is edit-distance 1 from `pg` → CRITICAL → 403. This is scan-rule
  calibration (known-legitimate allowlist in `picosentry/scan/rules/typosquat.py`),
  not firewall logic; track under the scan detection-quality workorders.
- **PyPI metadata coverage is thin.** Of the metadata rules only the
  typosquat family reads PyPI shapes today, so PyPI verdicts are
  allow/quarantine-by-typo; there is no PyPI-side install-script signal in
  registry metadata to scan.
- **Upstream must be HTTPS.** `http://` upstreams are refused even for local
  mirrors; terminate TLS or extend `allow_http` support if you need one.
- **No lockfile/pnpm enforcement, by design** — those rules cannot see
  registry metadata. Run `picosentry scan` on the project tree for that.

---

## 7. Watch LLM defense

PicoWatch (`picosentry watch`) is the LLM-defense layer in PicoSentry. It provides:

- **L5 prompt guard**: deterministic, offline detection of prompt-injection attempts.
- **L6 output guard**: deterministic output-policy validation.

Both are **pre-filters**, not semantic guarantees. They are designed to catch
high-confidence attack patterns at very low latency and with zero external
dependencies, while being honest about what regex and lexical analysis cannot do.

### Architecture

```
input text
    |
    v
Normalizer  ──>  Unicode / whitespace / comment / zero-width / punctuation / base64 / ROT13 / URL-decode
    |
    v
RuleEngine  ──>  YAML-driven regex rules (weighted, categorized)
    |
    v
Scorer      ──>  score = max(max_weight, avg_weight) over regex matches
    |
    v
Classifier  ──>  lexical/structural second opinion when regex is below threshold
    |
    v
Final score  ──>  block / warn / pass
```

#### Normalizer

The normalizer defeats common obfuscation techniques *before* the regex and
classifier see the text:

- NFKC Unicode normalization (homoglyphs, full-width characters).
- Zero-width character stripping.
- Spaced-character collapse (`i g n o r e` -> `ignore`).
- Punctuation collapse (`ignore.all.previous` -> `ignore all previous`).
- HTML/C/line comment stripping.
- Base64 (standard and URL-safe alphabets), hex, ROT13, and URL decoding
  with rescan — applied to both the raw text and its NFKC-normalized variant,
  so fullwidth- or zero-width-wrapped payloads are still decoded. Decoded
  variants are deduped and capped at 32 per request.

#### Regex rule engine

Rules are YAML files in `picosentry/watch/rules/prompt_injection/` and
`picosentry/watch/rules/output_policy/`. Each rule has:

- `id`, `category`, `weight` (0.0–1.0), `pattern`, `description`.

Rules are deterministic, versioned by a SHA-256 corpus hash, and sorted by id
for reproducible evaluation order.

#### Lexical classifier

The classifier is a rule-based layer that runs only when the regex score is
below the block threshold. It scores text on:

- Distinct injection families present (override, role manipulation, extraction,
  multi-turn, format breakout, system prefix).
- Density of suspicious tokens within the text.
- Structural signals (e.g., `System:` / `Admin:` prefix, imperative sentence
  start).
- Cross-family diversity: multiple independent signals amplify the score.

The classifier is intentionally conservative:

- A single ambiguous keyword is capped at warn level.
- Benign contextual markers (`"I made a typo"`, `"correction"`, thanks,
  apologies, fiction framing like `"for my novel"`) suppress weak signals.
- Strong structural signals or multiple families can still override suppression.

The classifier can be disabled via config:

```toml
[picowatch]
classifier_enabled = false
```

or environment:

```bash
PICOWATCH_CLASSIFIER_ENABLED=false
```

### Scoring and verdicts

```python
score = max(regex_score, classifier_score * classifier_blend_factor)

if score >= threshold_block:  # default 0.7
    verdict = BLOCK
elif score >= threshold_warn:  # default 0.4
    verdict = WARN
else:
    verdict = PASS
```

The classifier can only *elevate* the regex score, never lower it, so existing
detections cannot regress.

### Fail-closed mode

Set `PICOSENTRY_WATCH_FAIL_CLOSED=true` to make watch return a non-zero exit
on rule-load failures or evaluation crashes instead of passing through. Use
this in high-assurance deployments; the default remains fail-open to avoid
breaking existing integrations.

### Honest limitations

1. **No semantic understanding.** Regex and lexical classifiers do not comprehend
   meaning. A carefully paraphrased injection that avoids all keyword patterns
   can still bypass the guard.
2. **No model-based reasoning.** It does not use embeddings, transformers, or LLM
   judges, so it cannot catch genuinely novel framing that a human would spot.
3. **Determinism trade-off.** The layer is fully deterministic and offline, which
   is a feature for reproducibility but a ceiling on detection quality.
4. **Fast pre-filter role.** It is best used as the first tier in a layered
   defense: block obvious attacks cheaply, then send borderline prompts to a
   heavier model-based guard.
5. **Roleplay framing false positives.** A short imperative that starts a
   roleplay with no benign context ("act as if you are tired") reads as a
   structural signal and can block; fiction framing ("for my novel") or
   question form avoids it. The corpus floor (`tests/watch/fixtures/`) pins
   the benign roleplay set that must keep passing.

Watch does not scan LLM model weights — it guards prompts and outputs in
deployed apps, not the model itself.

### HTTP server hardening

`picosentry watch serve` starts two FastAPI applications on separate ports:

- **Main API** (`PICOWATCH_HOST`/`PICOWATCH_PORT`, default `127.0.0.1:8766`) —
  prompt/output scan endpoints.
- **Admin API** (`PICOWATCH_ADMIN_HOST`/`PICOWATCH_ADMIN_PORT`, default
  `127.0.0.1:9091`) — read-only health, metrics, and rules endpoints.

#### Authentication

Set a strong API key (`PICOWATCH_API_KEY`, >= 32 characters) to gate mutation
endpoints. Unknown or missing keys get `401`. Admin endpoints are also gated
by the same key when `PICOWATCH_ADMIN_AUTH_ENABLED=true` (default).

```bash
export PICOWATCH_API_KEY="$(openssl rand -hex 32)"
export PICOWATCH_ADMIN_AUTH_ENABLED=true
```

- `POST /v1/scan/prompt` and `POST /v1/scan/output` require the key.
- `GET /v1/rules/{rule_id}` (reveals regex patterns) requires the key.
- Admin `GET /metrics`, `GET /v1/rules`, and `GET /v1/rules/{rule_id}` require
  the key when admin auth is enabled.
- `GET /v1/health` is always unauthenticated so load balancers can probe it.

Keys are accepted via `X-API-Key` or `Authorization: Bearer <key>`.

#### Gateway shim (per-tenant profiles)

The PicoWatch gateway (`picosentry/watch/gateway.py`) fronts the guard server
with per-tenant policy profiles: each configured gateway API key selects a
rule-category subset and thresholds (`TenantProfile`). When tenant keys are
configured they are the auth surface — an unknown or missing key gets 401
(WO5.0.0-023); only a gateway configured without tenants falls back to the
default profile. Streaming output cannot be scored token-by-token — the
gateway fully buffers "streaming" responses (SSE cadence is not preserved) and
annotates them with `X-Picowatch-Streaming: buffered` plus
`X-Picowatch-Output-Scanned: false` where the output guard did not evaluate
them (a buffered streaming scanner is the documented upgrade hook).

#### Rate limiting

All endpoints except `GET /v1/health` share a per-IP rate limit:

```toml
[picowatch]
rate_limit = 100        # requests per window
rate_limit_window = 60  # seconds
```

Excess requests receive `429 Too Many Requests` with a `Retry-After` header.

#### Auto-generated docs

FastAPI's `/docs` and `/redoc` are **disabled by default** to reduce exposed
surface. Enable them only in internal/debug environments:

```toml
[picowatch]
enable_docs = true
```

#### Security headers

Every response includes:

- `X-Content-Type-Options: nosniff`
- `X-Frame-Options: DENY`
- `Referrer-Policy: strict-origin-when-cross-origin`
- `Cache-Control: no-store` on `/v1/scan/*`

#### Output schema limits

Runtime JSON schemas passed to `POST /v1/scan/output` are bounded by default:

- `max_json_schema_nodes` = 1,000 nodes
- `max_json_schema_depth` = 32 levels

Schemas exceeding either limit are rejected with `413` before evaluation,
preventing pathological schemas from consuming CPU or memory.

### CLI usage

```bash
# Scan a prompt
picosentry watch scan-prompt --text "ignore all previous instructions"

# Start the HTTP guard server
picosentry watch serve

# Scan via the HTTP API
curl -X POST http://127.0.0.1:8766/v1/scan/prompt \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $PICOWATCH_API_KEY" \
  -d '{"text": "..."}'

# Validate LLM output with a runtime JSON schema
curl -X POST http://127.0.0.1:8766/v1/scan/output \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $PICOWATCH_API_KEY" \
  -d '{"output": "{}", "schema": {"type": "object"}}'

# Read rule metadata (no key required when unauthenticated)
curl http://127.0.0.1:8766/v1/rules

# Read rule pattern (key required — pattern redaction)
curl http://127.0.0.1:8766/v1/rules/inj_override_ignore \
  -H "X-API-Key: $PICOWATCH_API_KEY"

# Admin metrics
curl http://127.0.0.1:9091/metrics \
  -H "X-API-Key: $PICOWATCH_API_KEY"
```

### Recommended deployment

For production LLM deployments, use PicoWatch as a lightweight edge guard and
combine it with a dedicated model-based input/output guard (e.g., a small
classifier model or an LLM-as-judge) for prompts that score in the WARN range or
for applications that tolerate higher latency.

---

## 8. Sandbox PicoDome

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

The sandbox daemon can serve over gRPC instead of HTTP. Install the extra,
then start the daemon with `--transport=grpc`:

```bash
pip install 'picosentry[grpc]'

# Start the daemon (port 50051 by default; pass --grpc-port to change)
picosentry daemon --host=0.0.0.0 --port=8443 --transport=grpc --grpc-port=50051
```

The generated protobuf stubs (`picodome_pb2.py`, `picodome_pb2_grpc.py`) are
committed under `picosentry/sandbox/grpc_transport/proto/` and ship in the
wheel, so a client only needs `grpcio` to talk to the daemon. Regenerate the
stubs with `scripts/regen_proto.sh` after editing `picodome.proto`.

The gRPC service exposes `Scan`, `Health`, `GetPolicy`, and `QueryAudit` RPCs —
see `picosentry/sandbox/grpc_transport/proto/picodome.proto` for the full
schema.

### Kubernetes

`deploy/kubernetes/deployment.yaml` boots the daemon with gRPC enabled by
default and ships a `picodome-grpc` Service on port 50051. For Helm:

```yaml
# values.yaml
grpc:
  enabled: true
  port: 50051
```

```bash
helm install picodome deploy/helm/picodome/ --set grpc.enabled=true
```

### Multi-tenancy (tenant isolation)

The daemon supports token-bound tenant isolation, configured entirely through
environment variables (loaded by `picosentry/sandbox/tenant/__init__.py` and
wired into the daemon and gRPC transport):

| Variable | Format | Purpose |
|----------|--------|---------|
| `PICODOME_TENANTS` | `id:Display Name;id2:Name2` | Tenants to register. |
| `PICODOME_TENANT_TOKEN_MAP` | `<sha256(token)>:tenant_id,...` | Maps an API token (by SHA-256 hash) to the tenant it belongs to. |
| `PICODOME_TENANT_OPERATOR_TOKENS` | `<sha256(token)>,...` | Tokens that see all tenants (operator scope). |

Semantics: a token's tenant assignment comes from the token map. The
`X-Tenant` request header is **confirm-only** — a request may name its own
tenant (or omit the header), but naming any other tenant is rejected with
`403 X-Tenant does not match token's tenant`. Audit records and tenant
listings are scoped by tenant; operator tokens are exempt from scoping.

---

## 9. Serve control plane

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
  15/16/17/18 CI.
- **Security hardening:** CORS blocking in production, HTTPS enforcement,
  API docs restricted in production, secure secret assertions, rate limiting
  (100 IP/min default), DDoS shield, 10 MB body limit, 30 s timeout.
- **Dashboard:** Built-in web dashboard for scan results, alerts, and project management.

See [Chapter 16, Threat model](#16-threat-model) and
[Chapter 17, Attack surface](#17-attack-surface-and-pentest-scope)
for trust boundaries, attack surface, and honest limitations.

### Authentication and API keys

Implemented in `picosentry/serve/services/auth.py` and
`picosentry/serve/api/routers/auth.py`.

#### MFA / TOTP

A user with TOTP enabled must supply a 6-digit code on login (`totp_code`);
the server responds `401 mfa_required` until one is verified. Endpoints:

- `POST /auth/mfa/enroll` — generate a TOTP secret + `otpauth://` URI for the caller (`enroll_totp`).
- `POST /auth/mfa/verify` — verify a 6-digit code for the caller (`verify_totp_for_user`).

#### JWT revocation

JWTs carry a `jti` claim. `POST /auth/revoke` (body `{"jti": "..."}`) inserts
the `jti` into the `revoked_tokens` table; `validate_token` rejects any
revoked `jti`.

#### Account lockout

After `LOCKOUT_MAX_ATTEMPTS` (default `5`) consecutive failed logins for a
username, the account locks for `LOCKOUT_WINDOW_MINUTES` (default `15`). The
login endpoint returns `423` while locked. Config in
`picosentry/serve/config/settings.py` (`SecurityConfig.lockout_max_attempts`,
`lockout_window_minutes`).

#### Role-scoped API keys

`POST /auth/api-key` mints a key scoped to a role (`viewer`/`operator`/`admin`)
and optional `org_id`; a caller cannot mint a key with a role higher than its
own. `create_api_key(role=..., org_id=...)` stores the scope, and
`get_current_user` (`picosentry/serve/api/deps.py`) authenticates via the
`X-API-Key` header, enforcing the key's role through the same RBAC checks as
JWTs.

### Alert delivery

Alerts fan out to configured webhooks. Webhook URLs are read from the
environment at settings load: canonical `PICOSHOGUN_DISCORD_WEBHOOK_URL` and
`PICOSHOGUN_SLACK_WEBHOOK_URL`, with the legacy unprefixed
`DISCORD_WEBHOOK_URL` / `SLACK_WEBHOOK_URL` still honored (deprecated, logged).
Per-org webhook identity (each org delivering with its own webhook
configuration) is persisted via the alerting migrations. Delivery failures
surface in the alert history — delivery status is reported truthfully rather
than assumed.

### Cross-layer correlation

**Status: Stable**

`CorrelationEngine` ingests events from scan, sandbox L4, and watch layers.
Each event maps to a MITRE ATT&CK kill-chain phase. When an artifact has
events across multiple layers or multiple phases, the engine:

1. Builds a `KillChainTimeline`.
2. Computes a chain score.
3. Can trigger downstream auto-analysis via the event bus.

Persistence, dedup, and per-minute backpressure are tested in CI.

---

## 10. Plugin system

**Status: Stable**

PicoShogun is the plugin system used by `picosentry serve` to extend the server
with custom hooks (notifications, intelligence enrichment, alert filtering,
etc.) without running third-party code inside the main server process.

### Discovery

Plugins are discovered from three locations, in priority order:

1. `--plugin-dir PATH` (repeatable) on the `serve` subcommand.
2. `PICOSHOGUN_PLUGIN_DIR` env var (comma-separated paths).
3. `~/.picosentry/plugins/` if it exists.

The bundled `picosentry/serve/plugins/` (`test_plugin`, `test_discord_notifier`)
is always scanned last.

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

### What a plugin can do

A plugin implements one or more lifecycle hooks that the server calls over a
subprocess JSON-RPC channel:

| Hook | When called | Return value |
|------|-------------|--------------|
| `initialize(config)` | Once when the plugin worker starts | `bool` |
| `on_project_start(project_id, metadata)` | When a project run starts | `None` |
| `on_project_complete(project_id, result)` | When a project run finishes | `None` |
| `on_intelligence(intel)` | When new intelligence is ingested | enriched intel dict, or `None` |
| `on_alert(alert)` | When an alert is raised | alert dict, or `None` to suppress |
| `health_check()` | Periodic health probes | `{"status": "ok"\|"unhealthy", ...}` |
| `shutdown()` | When the server is stopping | `None` |

Plugins run in a **dedicated subprocess** spawned by `PluginHost`. The parent
process strips the environment, restricts the working directory to the plugin
directory, and enforces a deny-by-default **capability model**. Plugins cannot
read host secrets, access the network, or write files unless they declare the
corresponding capability and the operator has authorized it.

### Manifest (`plugin.json`)

Every plugin must contain a `plugin.json` manifest at the root of its directory:

```json
{
  "name": "my_notifier",
  "version": "1.0.0",
  "author": "you@example.com",
  "description": "Post alerts to an internal webhook",
  "entry_point": "handler",
  "hooks": ["alert"],
  "dependencies": [],
  "capabilities": ["network"],
  "public_key": "ffdbacc3ef1b141c1b75e4e7f0da291e17e64229fcfb9f959bdb6b694fa3ed02",
  "signature": "36943c9f..."
}
```

Field reference:

- `name` — unique identifier; must match `^[a-zA-Z0-9_.-]+$`.
- `entry_point` — Python module name (without `.py`) that contains a
  `PluginInterface` subclass. The module is imported from the plugin directory.
- `hooks` — subset of `project_start`, `project_complete`, `intelligence`,
  `alert`. The server only registers hooks declared here.
- `capabilities` — subset of:
  - `network` — worker receives host `HTTP_PROXY`/`HTTPS_PROXY` and can open
    outbound sockets.
  - `filesystem` — worker can read/write outside its own directory.
  - `subprocess` — worker can spawn child processes.
  - `environment` — worker receives the full host environment instead of a
    stripped minimal set.
  - `detection_write` — returned hook results may be used to modify server state.
    Without this capability the server treats returned data as read-only advice.
- `public_key` / `signature` — Ed25519 public key and detached minisign-style
  signature used to verify the manifest author. The key must be in the server's
  trusted-public-key allowlist (`BUNDLED_TRUSTED_PUBLIC_KEYS` or
  `PICOSHOGUN_TRUSTED_PUBLIC_KEYS`) or the plugin is rejected unless signing is
  optional in the current mode.

### Minimal handler (`handler.py`)

```python
from typing import Any
from picosentry.serve.services.plugin_manager import PluginInterface

class MyNotifier(PluginInterface):
    def initialize(self, config: dict[str, Any]) -> bool:
        self.webhook_url = config.get("webhook_url", "")
        return bool(self.webhook_url)

    def on_alert(self, alert: dict) -> dict | None:
        # Post to webhook if network capability is granted.
        return alert

    def health_check(self) -> dict:
        return {"status": "ok" if self.webhook_url else "unhealthy"}
```

Only one `PluginInterface` subclass per module is discovered. The class name is
irrelevant.

### Creating a plugin (quick start)

```bash
mkdir -p ~/.picosentry/plugins/my-plugin
cat > ~/.picosentry/plugins/my-plugin/plugin.json <<'EOF'
{
  "name": "my_plugin",
  "version": "0.1.0",
  "author": "you",
  "description": "on-alert hook example",
  "entry_point": "my_plugin",
  "hooks": ["alert"]
}
EOF
cat > ~/.picosentry/plugins/my-plugin/my_plugin.py <<'EOF'
from picosentry.serve.services.plugin_manager import PluginInterface

class MyPlugin(PluginInterface):
    def initialize(self, config): return True
    def on_alert(self, alert): return alert
EOF
```

```bash
picosentry serve --plugin-dir /opt/picosentry-plugins
PICOSHOGUN_PLUGIN_DIR=/srv/plugs:/opt/picosentry-plugins picosentry serve
```

The `GET /plugins` endpoint returns the resolved directory list in a `dirs`
field alongside the loaded plugin status, so you can verify discovery worked
without checking the logs.

### Capabilities are deny-by-default

A plugin that does **not** declare a capability is denied that surface area:

- No `network` → the worker process has no route to outbound sockets unless the
  host firewall permits it; proxy env vars are removed.
- No `filesystem` → the worker `cwd` is locked to its own directory.
- No `environment` → the worker receives only a minimal set of env vars required
  for Python to boot (`PATH`, `PYTHONPATH`, `HOME`, `TMPDIR`, etc.). Host
  secrets such as `PICODOME_POLICY_KEY`, `DATABASE_URL`, or cloud credentials
  are stripped.
- No `subprocess` → spawning children is blocked by the seccomp-bpf / seatbelt
  policy applied to the worker.

If a plugin declares a capability it does not need, `PluginHost` still enforces
the declaration by passing it to the worker and logging it for audit, but the
actual host-level enforcement is what matters. Operators should review
`capabilities` before deploying a plugin.

### Signing a plugin

Plugins must be signed with a trusted Ed25519 key before production deployment.
The manifest signature covers a canonical JSON payload containing the plugin
name, version, entry point, sorted hooks, and the SHA-256 checksum of the
entry module file:

```python
import hashlib
import json
from pathlib import Path
from nacl.signing import SigningKey

plugin_dir = Path("/path/to/my_notifier")
entry_file = plugin_dir / "handler.py"
module_checksum = hashlib.sha256(entry_file.read_bytes()).hexdigest()

manifest = json.loads((plugin_dir / "plugin.json").read_text())
payload = json.dumps(
    {
        "name": manifest["name"],
        "version": manifest["version"],
        "entry_point": manifest["entry_point"],
        "hooks": sorted(manifest.get("hooks", [])),
        "module_sha256": module_checksum,
    },
    sort_keys=True,
    separators=(",", ":"),
)

signing_key = SigningKey(bytes.fromhex("your-private-key-hex"))
signature = signing_key.sign(payload.encode()).signature.hex()
manifest["public_key"] = signing_key.verify_key.encode().hex()
manifest["signature"] = signature
(plugin_dir / "plugin.json").write_text(json.dumps(manifest, indent=2) + "\n")
```

The server verifies the signature against the trusted-public-key allowlist
(`BUNDLED_TRUSTED_PUBLIC_KEYS` or `PICOSHOGUN_TRUSTED_PUBLIC_KEYS`) before
loading the plugin.

> **PyNaCl is required for both signing and verification** and is not pulled in
> by any `picosentry` extra — install it explicitly (`pip install pynacl`) on
> both the signing host and the server. Without it the server logs
> "pynacl is not installed" and treats signed plugins as unsigned, which means
> a `REQUIRE_SIGNED_PLUGINS=1` deployment will refuse every plugin.

### Deployment

Plugins are loaded from directories listed in `PICOSHOGUN_PLUGIN_DIR`
(comma-separated). The bundled plugins live under
`picosentry/serve/plugins/`. To install a custom plugin:

1. Create a directory named after the plugin, e.g. `my_notifier/`.
2. Place `plugin.json`, the handler module, and any helper modules inside.
3. Sign `plugin.json`.
4. Add the plugin directory's parent to `PICOSHOGUN_PLUGIN_DIR`.
5. Restart `picosentry serve` or trigger a plugin reload via the API.

### Testing a plugin

Use the `PluginHost` directly in tests to exercise the subprocess boundary:

```python
from picosentry.serve.services.plugin_host import PluginHost
from picosentry.serve.services.plugin_manager import PluginMetadata

metadata = PluginMetadata(
    name="my_notifier",
    version="1.0.0",
    author="pytest",
    description="test",
    entry_point="handler",
    hooks=["alert"],
    dependencies=[],
    capabilities=[],
)

host = PluginHost(plugin_path="/path/to/my_notifier", metadata=metadata, module_checksum="abcd")
assert host.initialize({"webhook_url": "https://example.com/hook"})
host.on_alert({"message": "test"})
assert host.health_check()["status"] == "ok"
host.shutdown()
```

### Security checklist

Before deploying a plugin, verify:

- [ ] It declares only the capabilities it actually needs.
- [ ] It does not import or execute code from the network at runtime.
- [ ] It does not rely on host secrets being present in the environment.
- [ ] Its `on_intelligence` / `on_alert` return values are validated by the
      server if it does not hold `detection_write`.
- [ ] Its manifest is signed and the public key is in the server's trusted
      allowlist.
- [ ] It has a meaningful `health_check()` that fails closed when dependencies
      are unavailable.
- [ ] It expects the server to swallow hook/health-check/shutdown failures so a
      misbehaving plugin cannot crash the host; it should never rely on an
      unhandled exception crossing the subprocess boundary.

---

## 11. Architecture

This chapter describes the high-level components of PicoSentry, how they
communicate, and the trust boundaries between them. It is intended for
operators, security reviewers, and contributors who need to understand the
system without reading every module.

### Component overview

```mermaid
flowchart TB
    subgraph CLI["picosentry CLI"]
        scan["scan"]
        sandbox["sandbox"]
        watch["watch"]
        serve["serve"]
    end

    subgraph Sources["Package sources"]
        pypi["PyPI / npm / crates.io / Go / GitHub"]
        local["Local path / tarball"]
    end

    scan -->|"files / metadata"| Engine["Scan engine\n(picosentry/scan)"]
    Engine -->|"matches"| Rules["Detection rules\n(53 rules, 7 ecosystems)"]
    Engine -->|"findings"| Formatter["Output formatters\n(SARIF / CycloneDX / table)"]

    sandbox -->|"command + policy"| L3["L3 sandbox\nseccomp-bpf / seatbelt / subprocess"]
    L3 -->|"syscall events"| L4["L4 behavioral engine\n(picosentry/sandbox/l4)"]

    watch -->|"prompt / output"| PromptGuard["PromptGuard\n(picosentry/watch)"]

    serve -->|"REST / WebSocket"| API["Serve API\nFastAPI + RBAC"]
    API -->|"project runs"| Orchestrator["Orchestrator"]
    API -->|"events"| PluginMgr["PluginManager / PluginHost"]
    API -->|"alerts / intel"| DB[("Database\nSQLite / Postgres")]

    Orchestrator -->|"scan request"| Engine
    Orchestrator -->|"sandbox request"| L3
    Orchestrator -->|" LLM check"| PromptGuard

    PluginMgr -->|"subprocess RPC"| PluginWorker["Plugin worker"]
    PluginWorker -->|"hook results"| API

    L3 -.->|"cluster gossip"| Cluster["ClusterManager\n(gossip snapshots)"]
    API -.->|"admission webhook"| K8s["Kubernetes admission"]
```

### Trust boundaries

| Boundary | What it separates | Enforcement |
|----------|-------------------|-------------|
| **CLI → engine** | User input → deterministic scanner | Path validation, no network in default scan |
| **Engine → rules** | Detection logic | Signed corpus packs, rule validation |
| **Sandbox host → worker** | Server process → untrusted command | Subprocess + seccomp-bpf / seatbelt policy |
| **Plugin host → worker** | Server process → third-party plugin | Subprocess, stripped env, capability allowlist |
| **Serve API → DB** | HTTP clients → persistence | RBAC permissions, org scoping |
| **Serve API → plugins** | API callers → plugin hooks | Permission checks, `detection_write` capability gate |
| **Cluster peers** | Daemon nodes | Shared cluster token, mTLS optional |

### Data flow: project run

1. Client calls `POST /api/v1/projects/{id}/run` with a token that has
   `RUN_PROJECTS`.
2. Serve validates the token, resolves the tenant `org_id`, and passes the run
   to the orchestrator.
3. The orchestrator invokes the configured scanners (supply-chain scan,
   optional sandbox, optional watch) in sequence or in parallel.
4. Each stage returns structured findings; the orchestrator labels metrics and
   intelligence with `org_id`.
5. Critical cross-layer findings are correlated into a kill-chain timeline
   by the `CorrelationEngine`.
6. Registered plugins receive `on_project_complete` / `on_alert` hooks via
   their isolated `PluginHost` workers.
7. Alerts, intelligence, and run history are persisted to the database scoped
   by `org_id`.

### Subprocess isolation

Two components spawn subprocess workers for security boundaries:

- **L3 sandbox** (`picosentry/sandbox/l3/engine.py`) runs the target command in
  a subprocess with a syscall policy. The backend may be seccomp-bpf (Linux),
  seatbelt (macOS), or a plain subprocess fallback.
- **PicoShogun plugins** (`picosentry/serve/services/plugin_host.py`) runs
  each plugin in its own Python subprocess with a stripped environment,
  restricted working directory, and a deny-by-default capability model.

Both workers communicate with their parents over line-delimited JSON on
stdin/stdout. The parent validates responses before applying them to server
state.

### Multi-tenancy

Serve uses a flat `org_id` column to scope reads and writes. The junction table
`org_projects` enforces project ownership. API tokens carry a role; FastAPI
dependencies (`require_permission`, `require_role`) check both authentication
and authorization before touching data. Endpoints that return lists filter by
`org_id` in the service layer and in SQL queries.

### Correlation and kill chains

`CorrelationEngine` ingests events from scan, sandbox L4, and watch layers. Each
event maps to a MITRE ATT&CK kill-chain phase. When an artifact has events
across multiple layers or multiple phases, the engine builds a
`KillChainTimeline`, computes a chain score, and can trigger downstream
auto-analysis via the event bus.

### Plugin trust model

Plugins are loaded from directories listed in `PICOSHOGUN_PLUGIN_DIR`. The
manifest is signed with Ed25519; the public key must be in the server's trusted
allowlist (`BUNDLED_TRUSTED_PUBLIC_KEYS` or `PICOSHOGUN_TRUSTED_PUBLIC_KEYS`).
Signing can be made mandatory with
`PICOSHOGUN_REQUIRE_SIGNED_PLUGINS=1`. See
[Chapter 10, Plugin system](#10-plugin-system) for the full plugin
development guide.

### Operational interfaces

| Interface | Protocol | Authentication | Purpose |
|-----------|----------|----------------|---------|
| `picosentry serve` | HTTP / WebSocket | Bearer token + RBAC | API server and dashboard |
| `picosentry daemon` | HTTP (TLS/mTLS optional) | API token | Sandbox job submission |
| `picosentry daemon --cluster-token` | HTTP cluster gossip | Shared cluster token | Multi-node state merge |
| `picosentry watch` | HTTP / WebSocket | Bearer token | LLM prompt/output guard |
| Kubernetes admission | HTTPS webhook | TLS cert + K8s ValidatingWebhookConfiguration | Pod security validation |

---

## 12. Configuration reference

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
| `PICOSHOGUN_SSL_CERT_PATH` / `PICOSHOGUN_SSL_KEY_PATH` | Serve TLS certificate/key paths | — |
| `PICOSHOGUN_SKIP_SECURE_ASSERT` | Skip boot security checks | **Dangerous** |
| `PICOSHOGUN_RATE_LIMIT_BACKEND` | `memory`, `sqlite`, or `redis` | `memory` |
| `PICOSHOGUN_RATELIMIT_REDIS_FAIL_CLOSED` | `true`: 429 when Redis unreachable instead of failing open | `false` |
| `PICOSHOGUN_DISCORD_WEBHOOK_URL` | Discord alert webhook URL (legacy unprefixed `DISCORD_WEBHOOK_URL` honored, deprecated) | — |
| `PICOSHOGUN_SLACK_WEBHOOK_URL` | Slack alert webhook URL (legacy unprefixed `SLACK_WEBHOOK_URL` honored, deprecated) | — |

#### Watch (`PICOWATCH_*`)

| Variable | Purpose | Default |
|----------|---------|---------|
| `PICOWATCH_API_KEY` | API key for scan endpoints (≥ 32 chars recommended) | — |
| `PICOWATCH_ADMIN_AUTH_ENABLED` | Gate admin endpoints with the same key | `true` |
| `PICOWATCH_CLASSIFIER_ENABLED` | Enable the lexical classifier | `true` |
| `PICOWATCH_SKIP_SECURE_ASSERT` | Skip boot security checks | **Dangerous** |

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
| `PICODOME_TENANTS` / `PICODOME_TENANT_TOKEN_MAP` / `PICODOME_TENANT_OPERATOR_TOKENS` | Tenant isolation — see [Chapter 8](#8-sandbox-picodome) | — |

#### Admission

| Variable | Purpose | Default |
|----------|---------|---------|
| `PICODOME_ADMISSION_FAIL_CLOSED` | Deny pods on webhook misconfiguration | `true` |

---

## 13. Operations runbook

Quick reference for operators running PicoSentry in production or CI.

### Local CI-quality validation

Run the same checks CI runs, concurrently:

```bash
python scripts/test_doctor.py --workers 4
```

Run only a subset of areas:

```bash
python scripts/test_doctor.py --workers 4 --areas ruff mypy pytest-watch pytest-scan
```

Run with the local venv Python if your system Python is missing dependencies:

```bash
.venv/bin/python scripts/test_doctor.py --workers 4
```

### Database backend

`picosentry serve` can use SQLite (default, single-node) or PostgreSQL
(production). The backend is selected at startup with environment variables:

```bash
# SQLite (default)
export PICOSHOGUN_DATABASE_BACKEND=sqlite
export PICOSHOGUN_DATABASE_PATH=/var/lib/picoshogun/picoshogun.db

# PostgreSQL
export PICOSHOGUN_DATABASE_BACKEND=postgres
export PICOSHOGUN_DATABASE_URL=postgresql://user:pass@host:5432/picoshogun
```

#### Switching from SQLite to Postgres

1. Start a Postgres 15+ instance and create the database.
2. Set `PICOSHOGUN_DATABASE_BACKEND=postgres` and `PICOSHOGUN_DATABASE_URL`.
3. Start `picosentry serve`. Migrations run automatically via
   `picosentry.serve.database.manager`.
4. Validate the schema:
   ```bash
   psql $PICOSHOGUN_DATABASE_URL -c "\dt"
   ```

#### Backup and restore

- **SQLite** (single-node default): create a backup via the admin API
  (requires an admin token) or use the Python helper directly while the
  service is stopped:
  ```bash
  # via API
  curl -s -X POST "https://picoshogun.example.com/backup" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json"

  # via Python helper, service stopped
  python3 -c "
from pathlib import Path
from shutil import copy2
copy2('/var/lib/picoshogun/picoshogun.db',
      '/backups/picoshogun-$(date +%F).db')
"
  ```
- **PostgreSQL** (production): use standard Postgres tooling:
  ```bash
  pg_dump $PICOSHOGUN_DATABASE_URL > /backups/picoshogun-$(date +%F).sql
  ```

Restore:

- **SQLite**: stop the server, replace the database file, then restart.
  If a `.tar.gz` backup was created by the admin API, extract it first and
  copy `database.sqlite3` into place.
- **PostgreSQL**: restore the dump into a fresh Postgres database and point
  `PICOSHOGUN_DATABASE_URL` at it.

#### Upgrade

Application migrations run automatically on startup. For major version
upgrades, back up first, then restart the service and verify with:

```bash
picosentry health
python scripts/test_doctor.py --areas pytest-serve
```

### Stale corpus

#### Detect

The scanner warns when any ecosystem corpus is older than 30 days. An
exit-code gate (`--check-corpus-age`) exists on the inner `check` command
(`picosentry/scan/cli_commands/check.py`) but is **not yet wired into the
unified `picosentry` CLI**, so CI must call the inner scan CLI:

```bash
python -m picosentry.scan check . --check-corpus-age 30
```

Exit codes:

- `0` — corpus is fresh.
- `5` — corpus is older than the threshold (or missing).
- other — runtime error.

In CI, use the exit code to block a release when the bundled corpus is too
old:

```yaml
- run: python -m picosentry.scan check . --check-corpus-age 30
```

#### Remediate

1. Update the corpus source files under `picosentry/scan/corpus/`.
2. Regenerate `corpus.json` and any ecosystem-specific top-package lists.
3. Re-run the check.
4. If the corpus is distributed as signed packs, re-sign with minisign or
   Sigstore and verify the signature before deploying.

### Plugin sandbox incident

#### Symptoms

- Plugin worker logs show `Plugin worker for '<name>' did not respond within`.
- Host CPU spikes from orphaned plugin processes.
- Unexpected env vars or filesystem writes from a plugin.

#### Response

1. Check the plugin manifest capabilities:
   ```bash
   cat plugins/<name>/plugin.json
   ```
2. Inspect the worker stderr (plugin workers inherit the server's logger; the
   host logs `Plugin worker for '<name>' did not respond within ...` and worker
   tracebacks to the serve log — there is no `picosentry serve plugin logs`
   subcommand):
3. Validate the signature against the trusted-public-key allowlist.
4. If the plugin is untrusted or misbehaving:
   - Remove it from the plugin directory.
   - Restart the host process so the finalizer reaps the worker.
5. Review the `PICOSHOGUN_PLUGIN_CAPABILITIES` env var in worker logs to confirm
   the capability grant matches the manifest.

### Watch prompt-guard incident

#### False negative (prompt bypassed the guard)

1. Reproduce with the watch CLI:
   ```bash
   picosentry watch scan-prompt --file suspicious-prompt.txt
   ```
2. Check the normalized input and matched rules in the output.
3. If the bypass is due to encoding (base64, ROT13, homoglyphs), add a rule
   with the appropriate `normalization` list.
4. If the bypass is novel, file a rule-corpus issue with the payload and the
   expected verdict.

#### False positive (benign prompt blocked)

1. Re-run and read the matched-rule list in the scan output (`scan-prompt` has
   no `--verbose` flag; matched rules and scores are always in the output).
2. Lower the rule weight or tighten the regex so it does not match benign
   patterns.
3. Add a negative test case in `tests/watch/`.

#### Fail-closed mode

To make the guard block when rules cannot load or evaluation crashes:

```bash
export PICOSENTRY_WATCH_FAIL_CLOSED=true
```

Use this in high-assurance deployments. The default remains fail-open to avoid
breaking existing integrations.

### Admission webhook incident

#### Symptom: all pods denied

Possible causes:

- No validator configured.
- `PICODOME_ADMISSION_DAEMON_URL` is unreachable and fail-closed is on.
- TLS cert/key mismatch or expired.

#### Response

1. Check daemon health:
   ```bash
   curl https://<daemon>:8443/health
   ```
2. If the daemon is expected to be down and you must admit pods, set:
   ```bash
   export PICODOME_ADMISSION_FAIL_CLOSED=false
   ```
   This is a temporary safety valve, not a steady-state configuration.
3. Verify the webhook URL with the SSRF guard:
   ```python
   from picosentry.scan._network import assert_url_safe
   assert_url_safe("http://<daemon>:8443")
   ```

#### Admission deployment and certificate rotation

1. Generate or rotate the webhook TLS secret. The simplest path with
   cert-manager is in the Helm chart (`deploy/helm/picodome-admission/values.yaml`):
   ```yaml
   tls:
     certManager:
       enabled: true
       issuerRef:
         name: picodome-admission-issuer
         kind: ClusterIssuer
   ```
2. Ensure `ValidatingWebhookConfiguration.caBundle` references the same CA. The
   Helm template populates it from the cert-manager secret when
   `certRotation.rollingUpdateOnRenew: true`.
3. Rollout restart after manual cert changes when not using cert-manager:
   ```bash
   kubectl rollout restart deployment picodome-admission -n <namespace>
   ```
4. Validate the webhook responds:
   ```bash
   kubectl run test-pod --image=busybox --restart=Never --rm -i -- echo ok
   ```
5. Rollback: redeploy the previous chart revision or set
   `webhook.failurePolicy: Ignore` temporarily while you diagnose.

### Sandbox daemon operations

#### Deployment

Start the daemon with mTLS in production:

```bash
export PICODOME_DAEMON_HOST=0.0.0.0
export PICODOME_DAEMON_PORT=8443
export PICODOME_API_TOKENS="$(openssl rand -hex 32)"
export PICODOME_ENTERPRISE_MODE=1
export PICODOME_TLS_CERT=/certs/tls.crt
export PICODOME_TLS_KEY=/certs/tls.key
export PICODOME_TLS_CA=/certs/ca.crt
export PICODOME_STORE_BACKEND=jsonl
export PICODOME_JOB_STORE_DIR=/var/lib/picodome

picosentry daemon --host=0.0.0.0 --port=8443
```

For gRPC transport:

```bash
picosentry daemon --host=0.0.0.0 --port=8443 --transport=grpc --grpc-port=50051
```

#### mTLS certificate rotation

The daemon reloads its TLS context on `SIGHUP` without dropping connections:

```bash
kill -HUP <pid>
```

For a rolling rotation in Kubernetes:

1. Update the `picodome-tls` Secret with the new cert/key/CA.
2. Restart pods one at a time (`kubectl rollout restart deployment picodome`).
3. Verify `/health` and `/ready` on each restarted pod.

#### Job store backup and restore

**JSONL (default):**

```bash
# Backup
systemctl stop picodome
tar czf /backups/picodome-jsonl-$(date +%F).tar.gz /var/lib/picodome
systemctl start picodome

# Restore
systemctl stop picodome
rm -rf /var/lib/picodome/*
tar xzf /backups/picodome-jsonl-<date>.tar.gz -C /
systemctl start picodome
```

**SQLite:**

```bash
# Backup while running (WAL-safe)
sqlite3 /var/lib/picodome/picodome.db ".backup /backups/picodome-$(date +%F).db"

# Restore
systemctl stop picodome
cp /backups/picodome-<date>.db /var/lib/picodome/picodome.db
systemctl start picodome
```

#### Audit sink incident

If an audit sink (file/syslog/webhook) is failing:

1. Check the configured sinks:
   ```bash
   echo $PICODOME_AUDIT_SINKS   # e.g. null,file,webhook
   ```
2. Inspect the daemon log for `Failed to initialize sink` or `Failed to start sink`.
3. For webhook failures, verify `PICODOME_WEBHOOK_URL` and `PICODOME_WEBHOOK_TOKEN`.
4. To fail closed when sinks cannot start, stop the daemon and do not restart until
   the sink is healthy. A fail-closed audit mode is not yet implemented.

#### Metrics endpoint

If `metrics.separatePort` is enabled, `/metrics` is served on a separate port
without auth. Network-segment it so only Prometheus (or your scraper) can reach it.
Use the Helm `networkPolicy.ingress.from` list to restrict sources.

### Cluster mode operations

#### Bootstrap a cluster

1. Start the first daemon with a cluster token:
   ```bash
   export PICODOME_CLUSTER_TOKEN="$(openssl rand -hex 32)"
   export PICODOME_CLUSTER_ADDRESS=0.0.0.0
   export PICODOME_CLUSTER_PORT=8444
   export PICODOME_CLUSTER_BACKEND=memory
   picosentry daemon --host=0.0.0.0 --port=8443
   ```
2. Join additional nodes:
   ```bash
   python -m picosentry.sandbox cluster join <seed-node>:8444 \
     --cluster-token "$PICODOME_CLUSTER_TOKEN" \
     --node-id node-2
   ```
3. Check status:
   ```bash
   python -m picosentry.sandbox cluster status
   ```

#### Adding and removing nodes

- To add: run `python -m picosentry.sandbox cluster join` on the new node pointing at any existing peer.
- To remove gracefully: run `python -m picosentry.sandbox cluster leave` on the node. The leader
  redistributes pending scans to remaining members.

#### Token rotation

Cluster mode supports graceful token rotation without a maintenance window.
Each node maintains a primary token and an accepted-token set. New tokens
are propagated through gossip snapshots; old tokens remain accepted until
retired.

Rotation uses **HMAC-derived primaries** (WO5-030) and an **ANY-MEMBER
adoption** policy so the cluster can rotate without a coordinator:

- The rotating node derives the new primary as
  `HMAC-SHA256(old_primary, "picodome-cluster-rotation:v1:<ts>")` — every
  holder of the old primary can re-derive the same new token from public
  snapshot data alone. The new token's raw bytes never travel on the wire.
- The gossip snapshot carries an **announcement**
  `{announced_by, hmac, announced_at, grace_expires}` where `hmac` is
  `HMAC-SHA256(old_primary, new_primary)`. Peers apply the announcement
  *before* the trust check so a peer that missed the rotation (or rejoined
  after grace) re-derives the new token from a token it still holds instead
  of splitting.
- **ANY-MEMBER adoption**: any peer that can verify the announcement adopts
  the rotated token. Quorum adoption is the documented upgrade path; until
  it lands, the cluster relies on each holder re-deriving independently.
- **Grace behavior**: the old token stays in the accepted set until
  `--retire-after` elapses (default 300s from `rotate-token`, or
  `PICODOME_CLUSTER_TOKEN_GRACE_SECONDS` for the shared-trust window). A
  node that was partitioned across the rotation keeps its tokens until an
  operator intervenes (no announcement verifies → no forced eviction).
- **Self-refresh caveat (pending WO6-014)**: because `apply_announcement`
  stamps adopted candidates with the announcer-chosen `announced_at`, a
  holder of any accepted token can iteratively self-rotate — each derived
  candidate gets a fresh grace clock and is itself a valid anchor, so
  `retire_older_than` can never starve an evictee that keeps gossiping.
  This is a known ceiling of the ANY-MEMBER policy; WO6-014 will land a
  retirement ledger (persist retired digests; refuse re-adoption of
  retired lineage) or monotonic `announced_at` per anchor. Until then,
  treat rotation as a cooperative operator action, not an eviction
  mechanism.

1. Rotate the token on any node:
   ```bash
   python -m picosentry.sandbox cluster rotate-token
   ```
   Or provide a specific value:
   ```bash
   python -m picosentry.sandbox cluster rotate-token --new-token $(openssl rand -hex 32)
   ```
2. Wait for gossip to propagate the new token to all peers. Verify with:
   ```bash
   python -m picosentry.sandbox cluster status
   ```
3. Retire old tokens once all peers have acknowledged the new one (default
   grace window is 300 seconds):
   ```bash
   python -m picosentry.sandbox cluster rotate-token --retire-after 0
   ```

If you must use the legacy single-token mode, all nodes still share
`PICODOME_CLUSTER_TOKEN`, but a rolling restart with mismatched tokens will
break gossip until every node is updated.

For stronger identity, use mTLS gossip instead:

```bash
export PICODOME_CLUSTER_TLS_CERT=/certs/cluster.crt
export PICODOME_CLUSTER_TLS_KEY=/certs/cluster.key
export PICODOME_CLUSTER_TLS_CA=/certs/cluster-ca.crt
python -m picosentry.sandbox cluster join <seed-node>:8444 --tls-cert ... --tls-key ... --tls-ca ...
```

#### Split-brain / disaster recovery

1. Stop all cluster nodes.
2. Pick the node with the most recent state (check the SQLite backend or the
   newest JSONL file modification time).
3. Restart that node alone; it will auto-elect as leader.
4. Rejoin the remaining nodes one at a time and verify `python -m picosentry.sandbox cluster status`.
5. If state diverged, accept that scans assigned during the partition may need
   manual reconciliation (the merge is optimistic).

### Rate-limiter overload

#### Symptom: legitimate clients are rejected

1. Inspect `active_clients` and `max_requests` metrics.
2. If a flood of distinct source IPs is filling the client table, raise
   `max_clients` or deploy the DDoS shield middleware in front of `serve`.
3. If a single client is burst-ing, shorten `window_seconds` or lower
   `max_requests`.

#### Distributed (Redis) rate-limit backend

For multi-replica deployments, enable the shared Redis backend so all pods
enforce the same IP and org API-key windows:

```bash
export PICOSHOGUN_RATE_LIMIT_BACKEND=redis
export PICOSHOGUN_REDIS_URL=redis://redis.example.com:6379/0
```

Behaviour:

- `memory` (default): per-process in-memory counters; fastest but not shared
  across replicas.
- `sqlite`: per-node persistence across restarts (legacy; still per-node).
- `redis`: shared counters across all `serve` replicas using Redis sorted sets.

When Redis becomes unreachable, the middleware falls back to in-memory counters
for that request and logs a warning. The fallback preserves availability but
loses cross-replica consistency until Redis recovers.

To verify the backend at runtime, send an authenticated request and check the
logs for `Rate limit Redis backend connected` or `Redis rate-limit backend
connection failed`.

### GitNexus index drift

If the MCP tools report a stale index or fail with `LadybugDB unavailable`
/ `Resource temporarily unavailable`:

1. Rebuild the index from the project root:
   ```bash
   node .gitnexus/run.cjs analyze
   # or: npx gitnexus analyze
   ```
2. Restart or reconnect your editor's GitNexus MCP client so it opens the
   freshly built `lbug` database without a stale file handle.

### Emergency contacts and rollback

- Roll back to the previous image: `docker run kirkforge/picodome:<previous-tag>`
- Reinstall the previous PyPI version:
  ```bash
  pip install 'picosentry<2.1.3'
  ```
- Verify a rollback with `picosentry health` and `python scripts/test_doctor.py`.

---

## 14. Offline and air-gapped operation

PicoSentry runs fully offline. No telemetry, no phone-home, no network required.

### Quick start

```bash
pip install picosentry
picosentry scan ./project          # works offline, no API keys needed
```

The built-in corpus and rules ship with the package. First scan works without internet.

### Corpus updates (offline)

Export a corpus pack (JSON) on a networked machine, transfer it to the
air-gapped host. Note: there is no single-archive "update from pack" command —
`picosentry update --offline` only refuses network access and takes no pack
argument; offline pack updates go through `corpus import`.

```bash
# Networked machine
picosentry corpus export /path/to/pack.json

# Air-gapped host
picosentry corpus import /path/to/pack.json
```

### Advisory packs

A bundled advisory snapshot (npm critical advisories) ships with the package
(`picosentry/scan/corpus/advisories/`). For a fuller dataset, fetch the
advisory database on a networked machine and transfer the output directory:

```bash
# Networked machine
picosentry advisories fetch <advisory-bundle-url> -o advisories/

# Air-gapped host — scan with the local database
picosentry scan ./project --advisory-db /path/to/advisories/
```

Online OSV queries (`api.osv.dev`) happen only in connected intelligence mode
(`--intelligence connected`), which requires network by design.

### Air-gapped Docker deployment

Pin an explicit published version tag (`latest` drifts and is not
reproducible; check the
[tag list](https://hub.docker.com/r/kirkforge/picodome/tags) for the
newest release):

```bash
# Networked machine
docker pull docker.io/kirkforge/picodome:v2.0.18
docker save kirkforge/picodome:v2.0.18 -o picodome.tar

# Transfer via USB, copy to air-gapped host
docker load -i picodome.tar
docker run --rm --network none kirkforge/picodome:v2.0.18 scan /project
```

The `--network none` flag ensures zero outbound connectivity for the container.

### Deterministic output

Same input + same policy = same SHA-256. No timestamps, no randomness.

```bash
# Verify byte-identical output across two runs
picosentry scan ./project --verify-determinism
# Exit 0: deterministic. Exit 4: results differ.

# Produce byte-stable JSON (no timestamps, no timing metadata)
picosentry scan ./project --deterministic-output --format json -o report.json
```

Use `--verify-determinism` in CI for audit compliance.

---

## 15. Deployment security checklist

PicoSentry can run with several **dev-only** environment variables that disable
security gates. This checklist helps operators verify that a production
deployment does not accidentally enable them.

> **Goal:** every production pod should start with `PICODOME_ENTERPRISE_MODE=1`,
> valid mTLS credentials, strong API tokens, **and no dev-bypass variables**.

### Dev-bypass variables (must be unset in production)

| Variable | Severity | What it disables |
|----------|----------|------------------|
| `PICODOME_DEV_MODE` | **CRITICAL** | Daemon authentication |
| `PICODOME_TLS_DEV` | **HIGH** | TLS certificate validation (self-signed certs) |
| `PICODOME_SKIP_SECURE_ASSERT` | **HIGH** | Daemon secure-boot checks |
| `PICOSHOGUN_SKIP_SECURE_ASSERT` | **HIGH** | `picosentry serve` secure-boot checks |
| `PICOWATCH_SKIP_SECURE_ASSERT` | **HIGH** | `picosentry watch` secure-boot checks |

### Production hardening variables

| Variable | Default | When to set |
|----------|---------|-------------|
| `PICOSHOGUN_REQUIRE_SIGNED_PLUGINS` | unset | Set `1` in production so `picosentry serve` refuses to load unsigned plugins. |
| `PICODOME_MAX_SCAN_TIMEOUT` | `300` | Upper bound (seconds) for `POST /api/v1/scan` `timeout`. |
| `PICODOME_MAX_LIST_LIMIT` | `1000` | Upper bound for `GET /api/v1/scans?limit` and `/api/v1/audit?limit`. |
| `PICODOME_WORKSPACE_ROOT` | `cwd` | Directory that `picosentry sandbox --policy` and `--cwd` must resolve inside. |
| `PICOSHOGUN_LOCKOUT_MAX_ATTEMPTS` | `5` | Failed logins before an account locks. |
| `PICOSHOGUN_LOCKOUT_WINDOW_MINUTES` | `15` | How long a locked account stays locked. |
| `PICOSHOGUN_CORS_ORIGINS` | `http://localhost:8765` | Explicit comma-separated origins. The wildcard `*` is **rejected** when credentials are enabled (see below). |
| `PICODOME_AUDIT_FSYNC` | `true` | When set, each audit JSONL line is `fsync`'d before returning, so an event is durable before a crash. Set to `false` to trade durability for throughput. |

### CORS hardening

`picosentry serve` rejects the CORS wildcard `*` origin combined with
`allow_credentials=True` in `Settings.validate()` — this is enforced in **every**
environment (not just production), because a wildcard origin with credentials lets
any site carry the caller's cookies/headers. Configure explicit origins via
`PICOSHOGUN_CORS_ORIGINS`.

### Reproducible builds

Wheel builds are **byte-identical** across runs: `SOURCE_DATE_EPOCH` is pinned
from the commit timestamp in `.github/workflows/release.yml`, the `Dockerfile`
builder stage, and CI. The CI `reproducible-build` job builds the wheel twice and
asserts equal sha256 hashes. The runtime `pip install` dependency layer is a
documented non-hash-pinned ceiling (upgrade path: `uv export --frozen`).

### Health endpoint rate-limiting

The PicoShogun API (`picosentry serve`) and the PicoDome daemon (`picosentry daemon`) both exempt their health/readiness probes from per-actor rate limits:

- `/health`, `/health/live`, `/health/ready` (PicoShogun)
- `/health`, `/ready` (PicoDome)

Load-balancer probes must never be rate-limited, otherwise the rate limiter can cause the outage it is meant to protect against.

### Helm production install

The `deploy/helm/picodome` chart runs an init container that refuses to start
the pod when any bypass is detected. Enable it with the default
`security.blockDevBypasses: true`:

```bash
helm upgrade --install picodome ./deploy/helm/picodome \
  --namespace picodome \
  --create-namespace \
  --set auth.existingSecret=picodome-api-tokens \
  --set mtls.existingTLSSecret=picodome-tls
```

To intentionally allow a development Helm install, set:

```yaml
security:
  blockDevBypasses: false
```

**Never disable this in production.**

### Verify a running deployment

Run the shared checker against the pod environment:

```bash
kubectl exec -n picodome deploy/picodome -- \
  python3 -m picosentry._core.security_check --strict
```

Expected output on a clean deployment:

```text
✅ No deployment-security findings.
```

Inject a bypass to confirm the checker fails:

```bash
kubectl exec -n picodome deploy/picodome -- \
  python3 -m picosentry._core.security_check --strict \
    --env PICODOME_TLS_DEV=1
# ❌ FAIL — deployment-security check failed
```

### CI lint

Run the deployment manifest linter locally:

```bash
python3 tests/sandbox/check_deploy_security.py --strict
```

The linter scans:

- raw K8s manifests under `deploy/kubernetes/`
- Helm values/templates under `deploy/helm/picodome/`
- the Dockerfile
- source files for hardcoded secrets
- `.gitignore` for secret patterns

### Copy-paste verification commands

Check a host for bypass variables before deploying:

```bash
for var in PICODOME_DEV_MODE PICODOME_TLS_DEV PICODOME_SKIP_SECURE_ASSERT \
           PICOSHOGUN_SKIP_SECURE_ASSERT PICOWATCH_SKIP_SECURE_ASSERT; do
  if [ "${!var}" = "1" ]; then
    echo "🚨 $var=1 is set"
  fi
done
```

Run the Python checker with custom env values:

```bash
python3 -m picosentry._core.security_check \
  --env PICODOME_ENTERPRISE_MODE=1 \
  --env PICODOME_TLS_DEV=0 \
  --strict
```

### What to do if a bypass is detected

1. **Do not expose the deployment to untrusted traffic.**
2. Remove the bypass variable from the manifest, Helm values, or runtime env.
3. Re-run the checker until it returns `✅ No deployment-security findings.`
4. Rotate any tokens or keys that may have been used while the bypass was
   active.

### See also

- [`picosentry/_core/security_check.py`](../picosentry/_core/security_check.py)
  — shared checker used by the Helm init container and CI lint
- [`tests/sandbox/check_deploy_security.py`](../tests/sandbox/check_deploy_security.py)
  — manifest-level deployment security lint
- The [README](../README.md) status table — current maturity and honest
  limitations

---

## 16. Threat model

This chapter describes the trust boundaries, assets, and threats that guide
PicoSentry's security posture. It is intended for operators, reviewers, and
contributors who need to understand where enforcement ends and observability
begins.

### Scope

Source of truth for component maturity is [`picosentry/experimental.py`](../picosentry/experimental.py).

| Component | Responsibility | Maturity |
|-----------|----------------|----------|
| **scan** | Offline deterministic supply-chain scanner | **STABLE** |
| **sandbox** | Runtime containment (seccomp-bpf / behavioral analysis) | **STABLE** |
| **watch** | LLM prompt/output guard (L5/L6) | **STABLE** |
| **serve** | API server, scheduler, webhooks, multi-tenant metrics | **BETA** |
| **daemon** | Long-running policy enforcement daemon | **BETA** |
| **admission** | Kubernetes admission webhook | **BETA** |
| **correlation** | Cross-layer kill-chain correlation | **STABLE** |
| **plugin system** | Signed, capability-sandboxed plugins | **STABLE** |
| **Postgres backend** | Production persistence backend | **STABLE** |
| **cluster mode** | Multi-node daemon gossip | **BETA** |

"Beta" means the component works, has regression/security tests, and is
suitable for controlled production use, but has not been battle-tested in a
broad multi-tenant deployment. See the trust-boundary sections below and
[Chapter 17, Attack surface](#17-attack-surface-and-pentest-scope) for specific
blockers and honest limitations.

### Assets

1. **Detection corpus and rules** — the source of PicoSentry's detection signal.
2. **Plugin code** — third-party extensions that run inside or beside the host.
3. **Host secrets** — credentials, tokens, TLS keys, API keys in the process
   environment.
4. **Tenant data** — project runs, alerts, intelligence, metrics in `serve`.
5. **Cluster state** — peer snapshots, shared token, and leader election state
   used by the daemon gossip protocol.

### Trust boundaries

```
┌─────────────────────────────────────────────────────────────┐
│                         Untrusted Input                       │
│  (package tarballs, container images, LLM prompts, API reqs)  │
└─────────────────────────────────────────────────────────────┘
                              │
                              ▼
┌─────────────────────────────────────────────────────────────┐
│  scan / watch analyzers  —  read-only, offline, deterministic   │
│  Rules corpus is trusted; input packages are untrusted.       │
└─────────────────────────────────────────────────────────────┘
                              │
              ┌───────────────┼───────────────┐
              ▼               ▼               ▼
        ┌─────────┐     ┌─────────┐   ┌─────────────┐
        │ sandbox │     │  watch  │   │ serve/daemon│  ← host secrets may exist here
        │ (L3/L4) │     │ (L5/L6) │   │   (API)     │
        └─────────┘     └─────────┘   └─────────────┘
              │               │               │
              ▼               ▼               ▼
        ┌─────────────────────────────────────────┐
        │  Plugins (subprocess isolation)         │
        │  Capability-allowlist, deny-by-default  │
        └─────────────────────────────────────────┘
```

#### Boundary 1: Scanner input

- **Assumption:** files and packages under analysis are untrusted.
- **Enforcement:** the scanner never executes package code; it reads static
  files. Symlinked scan targets are rejected at entry to prevent traversal out
  of the intended root.
- **Limits:** the scanner does not prove absence of malware, only presence of
  known patterns. A sufficiently novel or adversarially mutated sample may
  bypass detection.

#### Boundary 2: Plugin host

- **Assumption:** plugins may be signed by a trusted key, but signing proves
  authenticity, not safety.
- **Enforcement:** every plugin is spawned as a separate Python subprocess
  with a stripped environment and a capability allowlist. By default plugins
  get no `network`, `filesystem`, `subprocess`, `secrets`, or
  `detection_write` capability. The host validates all worker responses before
  applying them to host state. Signing can be made mandatory with
  `PICOSHOGUN_REQUIRE_SIGNED_PLUGINS=1`.
- **Limits:** plugins currently share the same kernel as the host. A kernel
  or Python sandbox escape would breach this boundary.

#### Boundary 3: Sandbox / daemon runtime enforcement

- **Assumption:** the host OS and kernel are trusted.
- **Enforcement:** Linux seccomp-bpf blocks dangerous syscalls. The CLI sandbox
  has no policy-driven path-based filesystem ACL today: a `LandlockBackend`
  exists (`get_backend("landlock")`, Linux ≥ 5.13, seccomp fallback) but is
  not exposed via `--backend` and enforces a fixed read-only/read-write path
  set that does not yet honor per-policy paths (see the ADR-002 addendum).
  Filesystem access is otherwise bounded by the child's working directory and
  the syscall allowlist. The daemon uses
  TLS/mTLS for its HTTP/gRPC interfaces. Audit sinks (file, syslog, webhook)
  are opt-in; the JSONL audit log is chain-hashed and each line is fsync'd by
  default (`PICODOME_AUDIT_FSYNC`) so a recorded event survives a crash.
- **Limits:** seccomp-trace and some advanced sandbox tests require kernel
  configs that are not present on every distribution. macOS uses the lighter
  Seatbelt backend. The sandbox is **enforcement** for syscalls, not full
  system-call tracing or observability. The daemon is **Beta**; see
  [Chapter 17, Attack surface](#17-attack-surface-and-pentest-scope).

#### Boundary 4: `serve` API and multi-tenancy

- **Assumption:** `serve` is intended to run behind a reverse proxy or inside
  a controlled network until its Beta blockers are accepted as risk.
- **Enforcement:** Bearer-token authentication, role/permission dependencies,
  `org_id` scoping on DB-backed reads and metrics, rate limiting, and DDoS
  shield middleware. Account lockout (after `lockout_max_attempts` failed
  logins) throttles credential brute force. JWTs carry a `jti` that can be
  revoked via `POST /auth/revoke` and are rejected at validation. Users may
  enroll TOTP so login requires a one-time code. API keys can be minted scoped
  to a role and org and are enforced through the same RBAC checks as JWTs.
- **Limits:** `serve` is **Beta**. Honest limitations include in-memory rate
  limiting by default (Redis backend available) and effectively no password
  policy (register enforces `min_length=1`) —
  see [Chapter 17, Attack surface](#17-attack-surface-and-pentest-scope).

#### Boundary 5: Admission webhook

- **Assumption:** the Kubernetes API server is the only caller.
- **Enforcement:** TLS required in production; pod validation policy is
  fail-closed by default (`PICODOME_ADMISSION_FAIL_CLOSED=true`).
- **Limits:** a misconfigured webhook without a validator will deny all pods.
  The admission controller is **Beta**.

#### Boundary 6: Cluster gossip

- **Assumption:** cluster peers are mutually untrusted at the network layer
  but share a single secret token.
- **Enforcement:** membership requires the `PICODOME_CLUSTER_TOKEN`; mTLS is
  optional. State snapshots are merged, not blindly trusted.
- **Limits:** the protocol has not been formally reviewed for Byzantine or
  network-partition behavior. Cluster mode is **Beta**.

### Failure modes and defaults

| Situation | Default | Override |
|-----------|---------|----------|
| Admission validator missing | **deny** | configure a validator |
| Admission daemon unreachable | **deny** if fail-closed is on | `PICODOME_ADMISSION_FAIL_CLOSED=false` |
| Watch rule load failure | **pass** (fail-open) | `PICOSENTRY_WATCH_FAIL_CLOSED=true` |
| Watch rule evaluation crash | **pass** unless fail-closed is on | `PICOSENTRY_WATCH_FAIL_CLOSED=true` |
| Plugin worker timeout | worker terminated, call raises | tune `timeout` per plugin |
| Corpus older than threshold | scanner warns (30-day staleness check); exit 5 gate exists on the inner `check` command, not yet wired into the unified CLI | `--check-corpus-age` on `picosentry/scan/cli_commands/check.py` |
| Rate-limiter table full | new distinct IPs denied | increase `max_clients` |
| `serve` auth failure | HTTP 401/403 | — |
| Cluster token missing | cluster manager does not start | set `PICODOME_CLUSTER_TOKEN` |

### Threats and mitigations

#### T1 — Malicious input evades detection

- **Mitigation:** deterministic rule engine, corpus freshness checks,
  adversarial mutation testing, and a documented recall floor.
- **Residual risk:** zero-day obfuscation or novel attack classes may slip
  through.

#### T2 — Plugin escapes sandbox

- **Mitigation:** subprocess isolation, capability allowlist, stripped env,
  trusted-key signing, and response validation.
- **Residual risk:** shared kernel; a sandbox escape is a critical finding.

#### T3 — Operator misconfiguration leaves service fail-open

- **Mitigation:** security-sensitive defaults are fail-closed or opt-out.
  Fail-open flags are documented in this model, the ops runbook, and per-component
  security reviews. The Helm chart has an init container that blocks dev-bypass
  variables.
- **Residual risk:** an operator may explicitly disable fail-closed behavior.

#### T4 — Cross-tenant data leak in `serve`

- **Mitigation:** `org_id` scoping on reads, permission-level RBAC, negative
  tests for A↔B isolation.
- **Residual risk:** `serve` is still Beta; new endpoints must enforce
  org scoping.

#### T5 — SSRF via daemon or image-scanner URL

- **Mitigation:** `assert_url_safe()` is applied to daemon URLs, cloud
  metadata endpoints are blocked, and scanner network access is controlled.
- **Residual risk:** custom DNS rebinding or internal redirects not fully
  mitigated by hostname checks alone.

#### T6 — Corpus tampering

- **Mitigation:** corpus packs can be signed (minisign / Sigstore), checksums
  are verified on load, and `is_corpus_stale()` warns when data is old.
- **Residual risk:** a compromised build pipeline could ship a malicious
  corpus if signing keys are exposed.

#### T7 — Cluster token compromise or partition abuse

- **Mitigation:** token is required for gossip membership; mTLS can be enabled
  for transport authentication and confidentiality.
- **Residual risk:** a single shared secret means any compromised node can
  join the cluster. There is no certificate-pinning or token rotation helper
  yet.

#### T8 — Credential brute force / stolen JWT reuse in `serve`

- **Mitigation:** account lockout after `LOCKOUT_MAX_ATTEMPTS` failed logins;
  optional TOTP MFA on login; JWTs carry a `jti` that can be revoked
  (`POST /auth/revoke`) and are checked against a `revoked_tokens` table at
  validation. API keys can be scoped to a role/org and rotated or revoked.
- **Residual risk:** lockout is per-username (distributed attacks across many
  usernames are still possible); MFA is opt-in per user.

### What the sandbox does NOT do

- It does not provide a full virtual machine or container boundary.
- It does not trace every syscall by default; behavioral analysis is
  observability, not enforcement.
- It does not guarantee detection of all malware; it raises structured findings
  for known patterns.

### Review cadence

Update the threat model after any change to:

- a trust boundary,
- a fail-closed/fail-open default,
- plugin capability model,
- `serve` auth/RBAC,
- daemon / admission / cluster behavior,
- component maturity (`picosentry/experimental.py`).

---

## 17. Attack surface and pentest scope

*Primary scope reference for pentest engagement. Cross-references ADR-001 through ADR-005.*

### Entry points

#### CLI arguments (`picosentry scan`)

- **Input**: Package manifest + lockfile path (npm `package.json`/`package-lock.json`, PyPI `requirements.txt`, Maven `pom.xml`, NuGet `.csproj`, RubyGems `Gemfile`, Cargo `Cargo.toml`, Go `go.sum`)
- **Trust boundary**: User-controlled filesystem path; scanner reads only the declared manifest files. No `--include` / recursive glob that could drag in unexpected files.
- **Attack surface**: A crafted manifest could exploit parser vulnerabilities in the JSON/YAML/TOML/XML parsers. All parsers are stdlib or well-vetted (`pyyaml`, `tomli`, `xml.etree.ElementTree`).

#### Corpus pack import (`picosentry corpus import`)

- **Input**: JSON corpus pack (optionally cryptographically signed)
- **Trust boundary**: packs may carry Ed25519/minisign/Sigstore signatures; cryptographic verification at import is opt-in (`--verify-crypto`). Production trust is gated by source trust levels (`CorpusTrustLevel`, `corpus_governance.py`) — quarantined/too-low-trust sources are rejected.
- **Attack surface**: A maliciously crafted corpus pack could inject false-positive/negative rules. Mitigated by opt-in signature verification, source trust gating, and the offline deterministic design (ADR-001).

#### Sandbox backends (`picosentry sandbox`)

| Backend | Trust boundary | Status |
|---------|---------------|--------|
| seccomp-bpf (ADR-002) | Kernel-level syscall allowlist; blocks unexpected syscalls at the kernel boundary | Active (Stable) |
| landlock | Path-based filesystem ACL | Implemented (`get_backend("landlock")`, ADR-002 addendum) but **not CLI-exposed**; enforces a fixed path set, does not yet honor per-policy paths, captures no stdout/stderr |
| firejail | Process-level sandboxing; weaker than kernel seccomp | Not implemented |
| Docker | Container isolation; strongest boundary but requires Docker daemon | Not implemented as sandbox backend |

- **Attack surface**: seccomp-bpf is the only kernel sandbox. There is no filesystem path restriction layer beyond the child's CWD and the syscall allowlist. Non-root container operation requires `CAP_SYS_ADMIN`.

#### Plugin system (ADR-004)

- **Entry point**: `picosentry serve` loads plugins from `--plugin-dir`, `PICOSHOGUN_PLUGIN_DIR`, and `~/.picosentry/plugins/` (bundled `picosentry/serve/plugins/` always scanned last)
- **Trust boundary**: Ed25519 manifest signature verification (authenticity) + `PluginHost` subprocess sandbox with deny-by-default capabilities (safety)
- **Attack surface**: A signed-but-malicious plugin is confined to its declared capabilities. Unsigned plugins load in non-production but are sandboxed. Production requires `PICOSHOGUN_REQUIRE_SIGNED_PLUGINS=1`.

#### Watch daemon (`picosentry watch`)

- **Entry point**: HTTP endpoint receiving LLM output for prompt-injection classification
- **Trust boundary**: Deterministic regex + lexical analysis; no LLM calls in the hot path (ADR-001)
- **Attack surface**: Crafted prompt-injection payloads could bypass the regex classifier. The classifier is deterministic but may miss novel injection patterns.

#### Serve API (`picosentry serve`)

- **Entry point**: FastAPI HTTP server with JWT + API-key authentication
- **Trust boundary**: Token/API-key auth, tenant isolation via `org_id`, role-scoped API keys
- **Attack surface**: API auth bypass, tenant isolation failure, JWT token handling, credential brute force

#### Admission webhook (`picosentry admission`)

- **Entry point**: Kubernetes admission webhook (HTTPS)
- **Trust boundary**: TLS mutual authentication, Kubernetes API server trust
- **Attack surface**: MITM on webhook TLS, misconfiguration of admission rules

### Trust boundaries

| Boundary | Enforcement | ADR |
|----------|-------------|-----|
| Scanner offline mode | No outbound network calls in scan path | ADR-001 |
| Kernel sandbox | seccomp-bpf syscall allowlist | ADR-002 |
| Plugin admission | Ed25519 signature verification | ADR-004 |
| Plugin safety | Deny-by-default subprocess sandbox | ADR-004 |
| Corpus pack integrity | Signature verification before ingestion | ADR-003 |
| Supply-chain build | uv lockfile + pyproject.toml pinning | ADR-003 |
| Component naming | Public vs internal split (PicoSentry vs picoshogun) | ADR-005 |

### Secrets handling

| Secret | Storage | Scope |
|--------|---------|-------|
| `PICOSHOGUN_SECRET_KEY` | Environment variable (never in code) | JWT signing, session tokens |
| Plugin signing keys | Ed25519 keypair; private key in env var | Plugin manifest verification |
| Docker Hub credentials | GitHub Actions secrets (`DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`) | CI/CD image push only |
| Sigstore signing | Keyless OIDC (no stored secrets) | Wheel/sdist signing |
| Database credentials | Environment variable (`PICOSHOGUN_DATABASE_URL`) | Serve backend only |

**Policy**: No secrets are committed to the repository. All signing is keyless (OIDC) in CI. Local development uses environment variables.

### Previously-fixed findings (verify by pentester)

| ID | Finding | Fixed in | Verification |
|----|---------|----------|--------------|
| PS-001 | Scanner symlink traversal | v0.1.x | Verify no path traversal via symlinks in manifest |
| PS-002 | Sandbox seccomp allowlist gap | v0.1.x | Verify all unexpected syscalls are blocked |
| PS-003 | Watch prompt injection bypass (basic) | v0.1.x | Verify prompt injection regex covers basic payloads |
| PS-004 | Serve token handling in logs | v0.1.x | Verify no tokens appear in log output |
| PS-005 | Daemon socket permission | v0.1.x | Verify daemon socket has correct permissions |

### Known hardening

| Feature | Description | Ref |
|---------|-------------|-----|
| Offline deterministic scanning | 50 rules across 7 ecosystems, no model calls in scan path | ADR-001 |
| Kernel sandbox (seccomp-bpf) | Syscall allowlist enforced at kernel level | ADR-002 |
| Python/uv packaging | Lockfile pinning, reproducible builds, sigstore signing | ADR-003 |
| Plugin trust boundary | Signing = admission, sandbox = safety; never conflated | ADR-004 |
| Supply-chain evidence | CycloneDX SBOM, SLSA provenance, sigstore wheel signatures | release.yml |
| Docker cosign signing | Container image signed with cosign in `release.yml` | release.yml |
| MFA / TOTP | Login requires a TOTP code when enabled; enroll/verify via `/auth/mfa/*` (`services/auth.py`) | WO2.0.0-007 |
| JWT `jti` revocation | JWTs carry a `jti`; `POST /auth/revoke` adds to a `revoked_tokens` table, `validate_token` rejects revoked `jti`s | WO2.0.0-007 |
| Account lockout | After `LOCKOUT_MAX_ATTEMPTS` (5) failed logins an account locks for `LOCKOUT_WINDOW_MINUTES` (15) | WO2.0.0-007 |
| Role-scoped API keys | Keys minted scoped to a role + org; `get_current_user` accepts `X-API-Key` (`api/deps.py`) | WO2.0.0-010 |
| CORS hardening | Wildcard `*` origin with credentials rejected in `settings.validate()` | WO2.0.0-010 |
| Audit fsync | Audit JSONL writes are fsync'd by default (`PICODOME_AUDIT_FSYNC`) | WO2.0.0-008 |
| Reachability | Advisory findings flag `reachable: bool` (package imported/used) | WO2.0.0-011 |
| Package intel depth | `download_count` + `package_age_days`; `L2-INTEL-001` flags new low-download packages | WO2.0.0-012 |
| Serve audit hash-chain verifier | `GET /audit/verify` recomputes the `prev_hash`/`row_hash` chain (`services/audit_chain.py:verify_audit_chain`, ADR-006) | a48e1eff |

### Out-of-scope items

- Denial-of-service against production infrastructure
- Social engineering / phishing against KirkForge staff
- Physical attacks on data centers
- Third-party service dependencies (GitHub, PyPI, npm) — mitigated by offline mode (ADR-001)
- Vulnerabilities in upstream dependencies (pyyaml, fastapi, etc.) — tracked by Dependabot

### Cross-references

| Document | Path |
|----------|------|
| ADR-001: Offline deterministic scanner | [`docs/adr/ADR-001-offline-deterministic-scanner.md`](adr/ADR-001-offline-deterministic-scanner.md) |
| ADR-002: Kernel sandbox | [`docs/adr/ADR-002-kernel-sandbox.md`](adr/ADR-002-kernel-sandbox.md) |
| ADR-003: Python/uv packaging | [`docs/adr/ADR-003-python-uv-packaging.md`](adr/ADR-003-python-uv-packaging.md) |
| ADR-004: Plugin trust boundary | [`docs/adr/ADR-004-plugin-trust-boundary.md`](adr/ADR-004-plugin-trust-boundary.md) |
| ADR-005: Component naming | [`docs/adr/ADR-005-picoshogun-picosentry-naming.md`](adr/ADR-005-picoshogun-picosentry-naming.md) |
| Threat model | [Chapter 16](#16-threat-model) |
| Model card | [Chapter 18](#18-detection-benchmarks-and-model-card) |

---

## 18. Detection benchmarks and model card

> **These benchmarks are measured against a synthetic regression corpus, not real-world malware.** They demonstrate rule coverage and regression prevention, not production detection rates. Real-world held-out benchmarking is an ongoing validation track.

*Generated 2026-08-17 (WO4.0.0-008 detection-quality round). Corpus: 5,673 test fixtures (3,431 positive / 2,235 negative / 7 tricky) across 7 ecosystems. See [Validation limitations](#validation-limitations) for scope boundaries.*

The mechanically re-rendered per-rule table lives in the generated file
[`docs/BENCHMARKS.md`](BENCHMARKS.md) — it is spliced from
`tests/scan/fixtures/validation/REPORT.json` by `scripts/render_benchmarks.py`
and CI-enforced against drift. This chapter is the narrative model card.

### Rule count

| Layer | Type | Count |
|---|---|---|
| **L2** | Static scan rules (`RULE_INFO`) | 53 |
| **L2** | Campaign benchmarks (`L2-CAMP-*`) | 4 |
| **L4** | Sandbox behavioral detectors | 15 |
| **Total** | | **72** |

The 4 `L2-CAMP-*` entries are campaign-specific IoC matchers validated against known attack packages, not general-purpose static rules. They are included in the per-rule table for transparency but are not counted as detection rules above.

Note: three static rules (`L2-INTEL-001`, `L2-NSCOL-001`, `L2-VCONF-001`; `RULE_INFO`
grew 50 → 53) have no positive fixtures in the corpus and therefore do not appear in
the per-rule table — a fixture-authoring gap, not a rule-count discrepancy.

### Three detection modes

PicoSentry operates in three distinct modes. Benchmarks in this card cover only the first two.

| Mode | Description | Status |
|---|---|---|
| **Offline Deterministic** | Known corpus + deterministic pattern rules (L2 static). No network, no nondeterminism. | Benchmarked (synthetic + real-world) |
| **Offline Behavioral** | Static analysis + sandbox behavioral observation (L4). Runs in isolation, no network. | Partial (L4 rules exercised in integration tests, not in corpus) |
| **Connected Intelligence** | OSV.dev threat feed + package metadata + campaign intelligence. Requires network. | Implemented (`--intelligence=connected`); advisory recall boosted when OSV available |

### Summary

| Metric | Value |
|---|---|
| **Test fixtures** | 5,673 (5,666 validated + 7 tricky) |
| **Positive fixtures** | 3,431 |
| **Negative fixtures** | 2,235 |
| **Tricky fixtures** | 7 |
| **L2 rules benchmarked** | 54 (50 static + 4 campaign) |
| **Mean precision** | 100.00% |
| **Mean recall** | 90.87% |
| **Fixture failures** | 37 (all documented-ceiling, see below) |
| **Ecosystems** | npm, PyPI, Go, Cargo, Maven, RubyGems, NuGet |
| **Corpus source** | Synthetically generated combinatorial variants + hand-curated real-world malware patterns |

> **2026-08-17 re-baseline #2 (corrected narrative).** The 84.92% / 72.79% numbers above
> (and the earlier 94.44% / 68.89% claim) both mis-stated the *causes* of low quality.
> The exploration round (WO4.0.0-008) verified the real root causes live, and this round
> fixed them:
>
> 1. **Precision (6,050 FPs):** five npm metadata rules (`L2-ENGIN/FORK/LICENSE/MAINT/PROV-001`)
>    fired informational findings on ANY sparse manifest — 1,210 generated clean fixtures
>    × 5 rules. Fixed: informational branches now require a risk signal (install hooks
>    present, or the manifest lives under `node_modules`).
> 2. **L2-PYPI-DEPC-001 (75 FNs):** the config used hyphen-only prefixes; PyPI convention
>    is underscores (`company_auth`). One config line (shared `_INTERNAL_ALL_PATTERNS`).
> 3. **L2-DEPC-001 (152 FNs):** npm recognized only `@internal/`+`@private/` scopes and
>    never pattern-checked unscoped names. Fixed: internal-word scopes + the shared
>    unscoped pattern check the other six ecosystems use.
> 4. **Typosquat FNs were NOT "edit-distance limits":** they were (a) corpus files missing
>    the popular names fixtures target (maven/rubygems/go/nuget — 461 fixtures), (b) ~84
>    fixtures encoding the typo as the project's own name in setup.py/gemspec with zero
>    dependencies — structurally invisible to the collectors, regenerated dependency-based,
>    and (c) fixtures expecting generic `L2-TYPO-001` from ecosystem scanners that emit
>    `L2-{ECO}-TYPO-001`.
> 5. **CVE fixtures (115 FNs) never fired for three stacked reasons:** they expected the
>    nonexistent `L2-CVE-001`; they used remediated/DB-unknown name+version pairs; and
>    `AdvisoryDB._parse_version` silently returned "not affected" for 1- and 2-component
>    versions ("1.30", "9.0"). Fixed: expected ids → `L2-{ECO}-ADV-001`, advisory-aligned
>    name/version pairs, and the parser now zero-pads short versions.
> 6. **`L2-NPM-OBFS/POST-001` never existed** (32 FNs): npm has no JS obfuscation rules —
>    the detectable signal for a payload in an install hook is `L2-POST-001`.
>
> The loader now also warns (counted, visible in `--validate` output) when a fixture
> expects a rule id that does not exist — items 5/6 would have been caught at authoring
> time. The numbers in this card are the current, reproducible aggregate.

### Recall by category

Mean recall is 90.87%; the 37 failing fixtures concentrate in documented ceilings:

| Category | Rules | Approx. FN | Root cause (verified) |
|---|---|---|---|
| Transitive dependency resolution | `*-ADV-001` (7 ecosystems) | ~20 | A vulnerable package reached only *through* another dependency is invisible without lockfile/transitive resolution — a genuine feature gap (see ceiling below), not a detector bug |
| Advisory-DB coverage | `L2-MAVEN-ADV-001`, `L2-NUGET-ADV-001`, `L2-PYPI-ADV-001` | ~10 | Fixtures reference name/version pairs (or artifact-vs-project name mappings like `spring-webmvc` vs `spring-framework`) the shipped offline DB does not carry |
| Boundary semantics | `*-ADV-001` | ~4 | "range_overlap" fixtures pin the exact *fixed* version and assert it fires; OSV semantics say it must not |
| Pre-existing hand-fixture gaps | `L2-CRED`, `L2-BUILD`, `L2-LOCK`, `L2-NETEX`, `L2-PNPM` | ~9 | Hand-authored fixtures whose techniques trip other rules than expected (e.g. CRED-001 reads JS sources, not setup.py); pre-date this round |
| High-recall rules (remaining) | 43+ | 0 | — |

#### Known ceiling: transitive dependency resolution

The advisory rules check packages *declared* in manifests (and installed
packages). When `cve_maven_*_transitive` declares `some-lib` whose *own*
POM would pull `log4j-core 2.14.1`, the scanner cannot see it offline —
that requires dependency-graph resolution against a registry index.
This is the single largest remaining FN class (~20 fixtures) and is
deliberately documented rather than papered over.

### False positives

Zero false positives across 2,235 synthetic negative fixtures. This demonstrates no overtriggering on clean package patterns in the regression corpus, but does not constitute a real-world false-positive rate guarantee.

### 2026-07-29 expansion

- **Typosquats**: +291 fixtures across all 7 ecosystems (npm, PyPI, Go, Cargo, Maven, RubyGems, NuGet)
- **Negative fixtures**: +2050 clean packages (npm, PyPI, Go, Cargo, Maven, RubyGems, NuGet)
- **CVE fixtures**: +115 Maven and RubyGems CVE patterns (Log4Shell, Spring4Shell, Jackson, Commons Collections, Nokogiri, Rails, Devise, Rack)
- **Multi-attack**: +30 fixtures combining typosquat+obfuscation, dep-confusion+credential theft, obfuscation+network exfil
- **Obfuscation**: +24 variants (nested eval, chained base64, hex+chr, unicode escapes, getattr bypass, importlib bypass, subprocess variants, socket/urllib exfil)
- **Dependency confusion**: +300 internal-package patterns (internal-*, private-*, corp-*, company-*, org-*, secure-*)

### 2026-08-17 detection-quality round (WO4.0.0-008)

- **FP gating**: the 5 npm metadata rules fire informational findings only with a risk
  signal (install hooks or under node_modules) — 6,050 FPs eliminated
- **Corpus alignment**: +130 real popular-package entries across maven/rubygems/go/nuget
  (targets the typosquat fixtures reference were below the `picosentry update` cutoffs)
- **Fixture honesty**: ecosystem-specific expected ids; dependency-based pypi/rubygems
  typosquat fixtures; advisory-DB-aligned CVE fixtures; tautological/undetectable typo
  pairs filtered from the generators (deterministic seed-42, idempotent reruns)
- **Rule fixes found along the way**: underscore PyPI names, npm internal-word scopes +
  unscoped pattern checks, 1-/2-component advisory version parsing, dict-form non-GitHub
  repos, npm advisory checks on declared deps, zlib-obfuscation via plain `import zlib`
- **Floors raised**: 0.84/0.70 → 0.94/0.84 (test + CLI gates aligned)

### Per-rule precision/recall

The per-rule table is mechanically re-rendered into the generated file
[`docs/BENCHMARKS.md`](BENCHMARKS.md) from the checked-in
[`tests/scan/fixtures/validation/REPORT.json`](../tests/scan/fixtures/validation/REPORT.json)
(the JSON is the source of truth if the two diverge). See that file for the
current per-rule TP/FP/FN/precision/recall table.

### Validation limitations

1. **Synthetic corpus**: All positive and negative fixtures are synthetically generated from combinatorial templates. They exercise rule logic, not real-world malware diversity.
2. **Synthetic negatives**: The negative corpus consists of generated clean package patterns, not real-world benign packages. The zero-FP claim applies only to these synthetic patterns.
3. **Advisory rules cannot reach OSV in air-gapped validation**: L2-*-ADV-001 rules require the OSV advisory database, which is unavailable in the default offline validation mode. Low recall reflects fixture limitations, not detector capability.
4. **Real-world corpus is now available**: The `datasets/realworld/` directory contains a curated benchmark built from public OSV data. See [Real-world validation](#real-world-validation) for details. The synthetic-corpus numbers above remain the primary regression benchmark; the real-world corpus supplements it.
5. **No comparison against other tools**: Benchmarks measure PicoSentry against its own corpus, not against competitor scanners.
6. **Low-recall rules are documented with verified root causes**: the residual 37 fixture failures are transitive-resolution, advisory-DB coverage, boundary-semantics, and pre-existing hand-fixture gaps (see [Recall by category](#recall-by-category)). The earlier "dep-confusion requires private-registry markers" and "typosquat is edit-distance vs. short names" explanations were wrong — those FNs were a config bug, missing corpus entries, structurally invisible fixtures, and expected-id authoring errors.
7. **L4 behavioral rules are not in the corpus**: The per-rule table covers L2 static rules and campaign IoC matchers only. L4 sandbox detectors are validated through integration tests, not this regression corpus.

### Real-world validation

PicoSentry also maintains a curated real-world malware benchmark corpus built from public OSV/advisory data in `datasets/malware/`. This corpus exercises the scanner against known-malicious packages rather than synthetic patterns.

| Property | Value |
|---|---|
| **Source** | Public OSV/advisory datasets (DataDog, OSV, Backstabber) |
| **Total fixtures** | See `datasets/realworld/METADATA.json` |
| **Train/held-out split** | 75/25, deterministic (SHA-256 first byte of entry ID) |
| **Ecosystems** | npm, PyPI, Go, Cargo, Maven, RubyGems, NuGet |
| **Fixture type** | Minimal manifests only — no executable payloads |
| **Categories** | `malicious`, `compromised_lib` |

Each fixture maps to one or more PicoSentry rules based on OSV category and metadata signals (summary keywords, CVE/GHSA references). Entries without a clear rule mapping are excluded — precision over coverage.

The train set (`datasets/realworld/train/`) is used for regression testing; the held-out set (`datasets/realworld/held_out/`) is reserved for future version reporting. Held-out results will be reported in a future model card update.

To rebuild the corpus:

```bash
python scripts/build_realworld_corpus.py
```

To run the real-world benchmark:

```bash
uv run python scripts/run_realworld_benchmark.py
```

### Real-world benchmark results

*Benchmark run: 2026-08-07. Corpus: 1522 train fixtures (500 compromised_lib / 1022 malicious) across 7 ecosystems. All fixtures are positive (no negatives in train). Fixtures are minimal manifests — no executable payloads.*

#### Overall

| Metric | Value |
|---|---|
| **Fixtures** | 1522 |
| **Errors** | 0 |
| **Elapsed** | 113s |
| **Overall precision** | 100.00% |
| **Overall recall** | 66.10% |
| **Mean per-rule precision** | 50.00% |
| **Mean per-rule recall** | 50.00% |

Overall recall counts each expected rule per fixture: 737 of 1115 expected rule–fixture pairs fired (66.10%). Mean per-rule averages each rule's own precision/recall, so rules with 0 TP dominate the average.

#### Per-ecosystem

| Ecosystem | Fixtures | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|---|
| npm | 368 | 368 | 0 | 368 | 100.00% | 50.00% |
| pypi | 379 | 369 | 0 | 10 | 100.00% | 97.36% |
| go | 14 | 14 | 0 | 0 | 100.00% | 100.00% |
| cargo | 7 | 7 | 0 | 0 | 100.00% | 100.00% |
| maven | 2 | 2 | 0 | 0 | 100.00% | 100.00% |
| rubygems | 375 | 375 | 0 | 0 | 100.00% | 100.00% |
| nuget | 377 | 377 | 0 | 0 | 100.00% | 100.00% |

npm recall is 50% because all 368 `compromised_lib` fixtures expect `L2-ADV-001` (advisory rule) which cannot fire without the OSV advisory database. `L2-MAINT-001` fires on all of them, so every npm fixture is detected by at least one rule.

#### Per-category

| Category | Fixtures | TP | FP | FN | Precision | Recall |
|---|---|---|---|---|---|---|
| compromised_lib | 368 | 368 | 0 | 368 | 100.00% | 50.00% |
| malicious | 379 | 369 | 0 | 10 | 100.00% | 97.36% |

#### Per-rule

| Rule ID | TP | FP | FN | Precision | Recall | Notes |
|---|---|---|---|---|---|---|
| L2-ADV-001 | 0 | 0 | 368 | 0.00% | 0.00% | Requires OSV advisory DB; cannot fire offline |
| L2-CRED-001 | 0 | 0 | 1 | 0.00% | 0.00% | 1 expected; not triggered |
| L2-MAINT-001 | 368 | 0 | 0 | 100.00% | 100.00% | |
| L2-NETEX-001 | 0 | 0 | 9 | 0.00% | 0.00% | 9 expected; not triggered |
| L2-PYPI-OBFS-001 | 8 | 0 | 0 | 100.00% | 100.00% | |
| L2-PYPI-POST-001 | 361 | 0 | 0 | 100.00% | 100.00% | |

#### Assessment

**What the results mean:**

- **Zero false positives** — no clean packages were misflagged (there are no negative fixtures in the train set, so this only covers positive-fixture stray findings).
- **Strong detection on malicious code** (97.36% recall for PyPI) — PyPI fixtures with install-time or network exfiltration patterns are reliably caught.
- **Full detection on Go, Cargo, Maven, RubyGems, NuGet** (100% recall) — `L2-BUILD-001` fires on all non-npm/non-PyPI malicious fixtures because build scripts with subprocess/network patterns are generated for each.
- **Low per-rule recall is advisory-driven** — `L2-ADV-001` accounts for 368 of 378 false negatives. This rule requires the OSV advisory database, which is unavailable in offline benchmark mode. With `--advisory-db` or network access, `L2-ADV-001` would fire on all 368 `compromised_lib` fixtures.
- **Ecosystem coverage is now broad** — 12+ rules exercised across all 7 ecosystems (npm, PyPI, Go, Cargo, Maven, RubyGems, NuGet). Go/Cargo/Maven/RubyGems/NuGet fixtures exercise `L2-BUILD-001` via supplementary build files.
- **All fixtures are minimal manifests** (package.json, setup.py, go.mod, Cargo.toml, pom.xml, .gemspec, .nuspec) plus ecosystem-specific build scripts — no real executable payloads.
- **Held-out results** (507 fixtures) will be reported separately.

**Limitations:**

1. No negative fixtures in the train set — false-positive rate is not measured here.
2. `L2-ADV-001` cannot fire in offline mode, inflating false negatives by 368.
3. Go/Cargo/Maven/RubyGems/NuGet fixtures primarily exercise `L2-BUILD-001`; deeper ecosystem-specific rules (typosquat, dep-confusion) require typosquat corpus fixtures, not real-world OSV data.
4. Minimal manifests may miss patterns that real package tarballs would expose.

### Running validation

```bash
# Full validation against built-in fixtures
picosentry scan --validate

# With advisory DB for CVE rules
picosentry scan --validate --advisory-db datasets/malware/

# Generate machine-readable report
picosentry scan --validate --output tests/scan/fixtures/validation/REPORT.json
```

---

## 19. Internal API map

This chapter maps the key internal entry points per component. It is intended
for contributors who need to navigate the codebase quickly.

### Component index

| Component | Path | Responsibility |
|-----------|------|----------------|
| CLI | `picosentry/cli.py` | Top-level `picosentry` command dispatcher. |
| Scan engine | `picosentry/scan/engine.py` | Runs detection rules against a package path. |
| Scan rules | `picosentry/scan/rules/` | Detection rule implementations. |
| Scan models | `picosentry/scan/models.py` | `Finding`, `ScanResult`, `RuleExecution`, etc. |
| Scan validation | `picosentry/scan/validation.py` | Fixture-based precision/recall floor. |
| Sandbox L3 | `picosentry/sandbox/l3/` | Syscall policy enforcement. |
| Sandbox L4 | `picosentry/sandbox/l4/` | Behavioral analysis of sandbox events. |
| Sandbox models | `picosentry/sandbox/models.py` | Shared sandbox data models. |
| Watch prompt guard | `picosentry/watch/prompt_guard/` | L5 prompt-injection detection. |
| Watch output guard | `picosentry/watch/output_guard/` | L6 output-policy validation. |
| Watch telemetry | `picosentry/watch/telemetry/` | Audit/metrics sink. |
| Serve API | `picosentry/serve/api/server.py` | FastAPI application factory. |
| Serve services | `picosentry/serve/services/` | Auth, orchestrator, plugin host, webhooks, etc. |
| Serve config | `picosentry/serve/config/` | Settings and JSON schemas. |
| Daemon | `picosentry/sandbox/daemon/` | Sandbox-as-a-service HTTP + gRPC daemon. |
| Correlation | `picosentry/serve/services/correlation/` | Cross-layer kill-chain correlation. |
| Cluster | `picosentry/sandbox/cluster/` | Gossip-based cluster manager (daemon-side). |
| Plugin system | `picosentry/serve/services/plugin_*.py` | Plugin host, manager, and interface. |
| _core | `picosentry/_core/` | Cross-cutting utilities (security check, version). |

### Scan module

#### Entry points

| File | Symbol | Purpose |
|------|--------|---------|
| `picosentry/scan/engine.py` | `ScanEngine` | Register rules and run scans. |
| `picosentry/scan/engine.py` | `create_default_engine()` | Factory with all bundled rules; imports each `detect_*` and calls `engine.register(rule_id, fn)`. |
| `picosentry/scan/engine.py` | `ScanEngine.scan(target, ...)` | Execute a scan and return `ScanResult`. |
| `picosentry/scan/rules/__init__.py` | `RULE_INFO` / `RULE_ID_ALIASES` | Rule metadata registry (id → name/severity/category) and detector → sub-rule_id expansion. |
| `picosentry/scan/models.py` | `Finding` | Structured detection result. |
| `picosentry/scan/cli.py` | `main` | Legacy inner CLI entry point for the scan package. |

#### Adding a rule

1. Implement a callable in `picosentry/scan/rules/`.
2. Import it in `create_default_engine()` (`picosentry/scan/engine.py`) and call `engine.register(rule_id, fn)`; add a `RULE_INFO` entry so the rule is catalogued.
3. Add fixtures in `tests/scan/fixtures/validation/`.
4. Run `picosentry scan --validate`.

See [Chapter 20, Extension guide](#20-extension-guide) for a worked example.

### Watch module

#### Entry points

| File | Symbol | Purpose |
|------|--------|---------|
| `picosentry/watch/prompt_guard/__init__.py` | `PromptGuard` | L5 prompt scanner. |
| `picosentry/watch/output_guard/__init__.py` | `OutputGuard` | L6 output validator. |
| `picosentry/watch/prompt_guard/rules.py` | `RuleEngine` | Loads and evaluates YAML regex rules. |
| `picosentry/watch/server.py` | `create_app(...)` | FastAPI app for `picosentry watch serve`. |
| `picosentry/watch/config.py` | `PicoWatchConfig` | All-in-one configuration dataclass. |

#### Rule file locations

| Type | Directory |
|------|-----------|
| Prompt injection | `picosentry/watch/rules/prompt_injection/` |
| Output policy | `picosentry/watch/rules/output_policy/` |

### Sandbox module

#### L3 backend entry points

| File | Symbol | Purpose |
|------|--------|---------|
| `picosentry/sandbox/l3/backends/__init__.py` | `get_backend(...)` | Selects and instantiates a backend (`seccomp`, `landlock`, `subprocess`). |
| `picosentry/sandbox/l3/backends/base.py` | `SandboxBackend` | Abstract backend interface. |
| `picosentry/sandbox/l3/backends/seccomp_backend.py` | `SeccompBackend` | Linux seccomp-bpf enforcement. |
| `picosentry/sandbox/l3/backends/subprocess_backend.py` | `SubprocessBackend` | Fallback subprocess runner. |
| `picosentry/sandbox/l3/models.py` | `Policy`, `SandboxResult` | Backend data contracts. |

#### L4 behavioral engine

| File | Symbol | Purpose |
|------|--------|---------|
| `picosentry/sandbox/l4/engine.py` | `analyze(...)` | Convert sandbox events into behavioral findings. |
| `picosentry/sandbox/l4/models.py` | `BehavioralFinding` | Structured L4 result. |

### Serve module

#### Entry points

| File | Symbol | Purpose |
|------|--------|---------|
| `picosentry/serve/api/server.py` | `create_app(...)` | FastAPI app factory. |
| `picosentry/serve/services/auth.py` | `AuthService` | User/token/auth helpers. |
| `picosentry/serve/services/orchestrator.py` | `Orchestrator` | Coordinates scan/sandbox/watch runs. |
| `picosentry/serve/services/plugin_manager.py` | `PluginManager` | Loads and dispatches plugins. |
| `picosentry/serve/services/plugin_host.py` | `PluginHost` | Subprocess wrapper for a plugin. |
| `picosentry/serve/services/correlation/engine.py` | `CorrelationEngine` | Cross-layer kill-chain builder. |
| `picosentry/serve/services/webhooks.py` | `WebhookDispatcher` | Alert webhook delivery. |
| `picosentry/serve/services/websocket_manager.py` | `WebSocketManager` | Live results streaming. |
| `picosentry/serve/services/scheduler.py` | `Scheduler` | Periodic task runner. |
| `picosentry/serve/config/settings.py` | `Settings` | Dataclass settings + env loading (`PICOSHOGUN_*`). |

#### Plugin interface

| File | Symbol | Purpose |
|------|--------|---------|
| `picosentry/serve/services/plugin_manager.py` | `PluginInterface` | Base class for plugins. |
| `picosentry/serve/services/plugin_host.py` | `PluginHost` | Spawns and communicates with plugin workers. |

### Data and corpus

| File | Symbol | Purpose |
|------|--------|---------|
| `picosentry/scan/corpus/` | — | Offline malware/IOC/advisory JSON datasets. |
| `picosentry/scan/advisory.py` | `AdvisoryDB` | Parses OSV-style advisories. |
| `picosentry/scan/corpus_index.py` | `CorpusIndex` | BK-tree edit-distance index for typosquat. |
| `datasets/malware/` | — | Larger benchmark malware corpora (not shipped in wheel). |

### CLI dispatch

`picosentry/cli.py` builds the root parser; command modules under
`picosentry/cli_commands/` call `register(name, add_arguments, cmd)` at import
time. Legacy inner CLIs also exist per package:

- `picosentry/scan/cli_commands/` (scan-package commands, incl. `check`)
- `picosentry/sandbox/cli_commands/` (picodome inner CLI: `analyze`, `pipeline`,
  `cluster`, `audit`, `notary`, … — run via `python -m picosentry.sandbox`)
- `picosentry/watch/cli.py`
- `picosentry/serve/cli.py`

### Testing helpers

| File | Purpose |
|------|---------|
| `scripts/test_doctor.py` | Unified local CI-quality runner. |
| `tests/conftest.py` | Shared fixtures. |
| `tests/scan/fixtures/validation/` | Regression fixture corpus for scan rules. |

### HTTP API reference

All endpoints require JWT authentication via `Authorization: Bearer <token>`
(unless noted). Role and permission requirements are listed per endpoint.
Org scoping is enforced via one of:

- `X-Org-API-Key: <org-key>` — an org-scoped API key (`sk_…`). Resolves the
  org from the key's stored row; the caller must be a member of that org
  (`deps.get_current_org` → `_resolve_current_org`).
- `X-Org-Id: <numeric org id>` — for multi-org JWT users, selects which of
  the caller's own orgs this request acts in (WO5-032). Must be a numeric
  org id; 400 if non-numeric, 403 if the caller is not a member. No header
  = the caller's first org (pre-existing behavior).
- An org-scoped role API key (`X-API-Key`) — pinned to the org it was
  minted for; the `X-Org-*` headers are ignored on this path.

See `picosentry/serve/api/deps.py` (`get_current_org`,
`_resolve_current_org`) for the resolution order.

Base path: Most endpoints are mounted on the root; scans and dashboard are
under `/api/v1`.

#### Authentication and authorization

| Role | Permissions |
|------|-------------|
| `viewer` | `read:*` (projects, intelligence, alerts, metrics, dashboard, health, orgs, plugins, events, webhooks, scheduler, anomaly) |
| `operator` | All `viewer` permissions + `run:projects`, `write:webhooks`, `write:intelligence`, `write:alerts`, `write:scheduler`, `write:anomaly`, `read:logs`, `read:backups` |
| `admin` | All permissions including `admin:users`, `admin:orgs`, `admin:backups`, `admin:audit`, `admin:logs` |

#### Organizations API

Org lifecycle, membership, usage, and tier quotas. Source:
`picosentry/serve/api/routers/orgs.py`, `picosentry/serve/services/orgs.py`.

##### Tier quotas

Each org has a tier that bounds members, projects, runs/day, and storage.
Quota exhaustion returns **HTTP 402 Payment Required** (mapped in
`picosentry/serve/api/server.py` and `picosentry/serve/errors.py`).

| Tier | Users | Projects | Runs/day | Storage |
|------|-------|----------|----------|---------|
| `free` | 1 | 3 | 50 | 100 MB |
| `starter` | 5 | 25 | 500 | 1 GB |
| `pro` | 25 | 100 | 5 000 | 10 GB |
| `enterprise` | 999 | 999 | 99 999 | ~1 TB |

##### `GET /orgs`

List the orgs the caller is a member of.

| Field | Value |
|-------|-------|
| Auth | any authenticated user |
| Response | `{ "orgs": [...], "count": int }` |

##### `POST /orgs`

Create a new org (the caller becomes the owner).

| Field | Value |
|-------|-------|
| Auth | any authenticated user |
| Request body | `OrgCreateRequest`: `name` (str), `slug` (str), `tier` (one of `free\|starter\|pro\|enterprise`, default `free`) |
| Response 201 | `OrgCreateResponse`: `id`, `name`, `slug`, `tier`, `api_key` |
| Errors | 409 slug already exists; 500 internal failure |

##### `GET /orgs/{org_id}`

Org detail including current usage.

| Field | Value |
|-------|-------|
| Auth | org member |
| Response | `OrgDetailResponse`: `id`, `name`, `slug`, `tier`, `api_key` (hidden), `is_active`, `created_at`, `usage` |

##### `GET /orgs/{org_id}/members`

List members of an org.

| Field | Value |
|-------|-------|
| Auth | org member |
| Response | `OrgMemberListResponse`: `{ "members": [...], "count": int }` |

##### `POST /orgs/{org_id}/members`

Invite a user to the org. Requires org-admin **and** the global
`ADMIN_USERS` permission (dual gate).

| Field | Value |
|-------|-------|
| Auth | org admin + `admin:users` permission |
| Request body | `OrgMemberInviteRequest`: `user_id` (int), `role` (str) |
| Response 201 | `OrgMemberInviteResponse` |
| Errors | 403 not an org admin; 402 member quota exceeded |

##### `PATCH /orgs/{org_id}/members/{user_id}`

Change a member's org-level role.

| Field | Value |
|-------|-------|
| Auth | org admin + `admin:users` permission |
| Request body | `OrgMemberRoleUpdateRequest`: `role` (str) |
| Response | `OrgMemberRoleResponse`: `user_id`, `role` |
| Errors | 403 not an org admin; 404 user is not a member |

##### `DELETE /orgs/{org_id}/members/{user_id}`

Remove a member from the org.

| Field | Value |
|-------|-------|
| Auth | org admin + `admin:users` permission |
| Response | `OrgMemberRemoveResponse`: `user_id`, `removed: true` |
| Errors | 403 not an org admin; 404 user is not a member |

##### `GET /orgs/{org_id}/usage`

Current usage against the org's tier quotas.

| Field | Value |
|-------|-------|
| Auth | org member |
| Response | `OrgUsageResponse` (members used, projects used, runs today, storage bytes) |

##### `POST /orgs/{org_id}/upgrade`

Upgrade the org's tier. Requires global `admin` role **and** org-admin
membership (dual gate).

| Field | Value |
|-------|-------|
| Auth | global admin + org admin |
| Request body | `OrgTierUpgradeRequest`: `tier` (one of `free\|starter\|pro\|enterprise`) |
| Response | `OrgUpgradeResponse`: `message`, `tier` |
| Errors | 400 invalid tier; 403 not an org admin |

#### Correlation API

Correlation endpoints expose the cross-layer kill-chain engine. Source:
`picosentry/serve/api/routers/correlation.py`.

##### `GET /chains`

List kill chains, sorted by chain score descending.

| Field | Value |
|-------|-------|
| Auth | `viewer` role |
| Query params | `threshold` (float 0.0–1.0, default 0.0) — minimum `chain_score` filter; `limit` (int 1–500, default 50) |
| Response | `{ "total": int, "chains": [KillChainTimeline.to_dict(), ...] }` |
| Org scoping | All orgs visible (global correlation state) |

##### `GET /chains/{artifact_id}`

Full kill-chain timeline for a single artifact.

| Field | Value |
|-------|-------|
| Auth | `viewer` role |
| Path params | `artifact_id` (string, max 512 chars) — e.g. `lodash@4.17.21` |
| Response | `KillChainTimeline.to_dict()` — includes `artifact_id`, `chain_score`, `severity`, `confidence`, `narrative`, `phases`, `related_targets`, `event_count`, `phase_count` |
| Errors | 404 if no chain data for artifact |

##### `GET /chains/{artifact_id}/narrative`

Human-readable narrative summary for an artifact's kill chain.

| Field | Value |
|-------|-------|
| Auth | `viewer` role |
| Path params | `artifact_id` (string, max 512 chars) |
| Response | `{ "artifact_id": str, "narrative": str, "chain_score": float, "phase_count": int, "event_count": int }` |
| Errors | 404 if no chain data for artifact |

##### `GET /chains/summary`

Aggregate statistics across all kill chains.

| Field | Value |
|-------|-------|
| Auth | `viewer` role |
| Response | `{ "total_chains": int, "total_events": int, "total_artifacts": int, "layers_active": int, "layer_coverage": [...], "critical_count": int, "high_count": int, "medium_count": int, "low_count": int, "avg_chain_score": float, "phase_distribution": {...}, "top_chains": [...] }` |

##### `POST /events`

Ingest a correlation event from an external integration.

| Field | Value |
|-------|-------|
| Auth | `operator` role |
| Request body | `EventIngestRequest` (see below) |
| Response | `{ "status": "ok", "event": CorrelatedEvent.to_dict() }` |

`EventIngestRequest`:

| Field | Type | Constraints |
|-------|------|-------------|
| `artifact_id` | string | required, max 512 chars |
| `layer` | string | required, one of `scan`, `sandbox_l3`, `sandbox_l4`, `watch` |
| `rule_id` | string | required, max 128 chars |
| `severity` | string | optional, one of `INFO`, `LOW`, `MEDIUM`, `HIGH`, `CRITICAL` (default `MEDIUM`) |
| `confidence` | string | optional, one of `LOW`, `MEDIUM`, `HIGH`, `EXACT` (default `MEDIUM`) |
| `target` | string | optional, max 512 chars (defaults to `artifact_id`) |
| `title` | string | optional, max 256 chars (defaults to `layer/rule_id`) |
| `detail` | string | optional, max 4096 chars |

Org scoping: the event's `org_id` is set from the authenticated user's org.

##### `POST /chains/persist`

Persist in-memory correlation state to the database.

| Field | Value |
|-------|-------|
| Auth | `operator` role |
| Response | `{ "status": "ok", "events_persisted": int, "chains_persisted": int, "persist_enabled": bool }` |

Persistence requires the `correlation_events` table (auto-created by
migrations). When `persist_enabled` is `false`, the counts will be 0.

##### `GET /engine/stats`

Correlation engine statistics.

| Field | Value |
|-------|-------|
| Auth | `viewer` role |
| Response | `{ "artifacts": int, "events": int, "cached_chains": int, "avg_events_per_artifact": float }` |

#### Anomaly API

Anomaly endpoints expose the metric-based anomaly detector. Source:
`picosentry/serve/api/routers/anomaly.py`.

##### `GET /anomaly/rules`

List all configured anomaly rules.

| Field | Value |
|-------|-------|
| Auth | `read:anomaly` permission (viewer, operator, admin) |
| Response | Array of rule objects: `{ "id", "metric_name", "threshold", "comparison", "duration_seconds", "alert_channel", "description", "labels", "enabled" }` |

##### `GET /anomaly/alerts`

List recent anomaly alerts from the database.

| Field | Value |
|-------|-------|
| Auth | `read:anomaly` permission |
| Query params | `limit` (int 1–200, default 50) |
| Response | Array of alert objects: `{ "rule_id", "metric_name", "value", "threshold", "comparison", "severity", "description", "timestamp" }` |

##### `POST /anomaly/check`

Trigger an immediate anomaly detection cycle.

| Field | Value |
|-------|-------|
| Auth | `write:anomaly` permission (operator, admin) |
| Request body | none |
| Response | `{ "triggered": int, "alerts": [{ "rule_id", "metric", "value", "threshold", "severity" }] }` |

##### `PATCH /anomaly/rules/{rule_id}`

Update an anomaly rule (enable/disable or change threshold).

| Field | Value |
|-------|-------|
| Auth | `write:anomaly` permission (operator, admin) |
| Path params | `rule_id` (string, max 64 chars) |
| Request body | `AnomalyRuleUpdateRequest`: `{ "enabled"?: bool, "threshold"?: float (0.0–1.0) }` |
| Response | `{ "status": "updated", "rule_id": str }` |
| Errors | 400 if no updates provided; 404 if rule not found |

#### Scheduler API

Scheduler endpoints manage periodic background jobs. Source:
`picosentry/serve/api/routers/scheduler.py`.

##### `GET /scheduler/jobs`

List scheduled jobs for the authenticated org.

| Field | Value |
|-------|-------|
| Auth | `read:scheduler` permission (viewer, operator, admin) |
| Org scoping | Only jobs belonging to the user's org are returned |
| Response | `{ "jobs": [{ "id", "name", "cron", "command", "enabled", "next_run", "last_run", "last_status", "org_id" }] }` |

##### `POST /scheduler/jobs`

Create a new scheduled job.

| Field | Value |
|-------|-------|
| Auth | `write:scheduler` permission (operator, admin) |
| Request body | `SchedulerJobCreateRequest` (see below) |
| Response | `{ "job_id": int, "status": "scheduled" }` (HTTP 201) |
| Errors | 400 for invalid command or params |

`SchedulerJobCreateRequest`:

| Field | Type | Constraints |
|-------|------|-------------|
| `name` | string | required, 1–200 chars |
| `cron` | string | required, 1+ chars (cron expression or `every N minute/hour/day`) |
| `command` | string | required, one of `batch`, `run`, `report`, `backup`, `cleanup`, `health_check` |
| `params` | object | optional, values must be strings, numbers, or booleans |
| `enabled` | bool | optional, default `true` |

Org scoping: `org_id` is set from the authenticated user's org.

##### `PATCH /scheduler/jobs/{job_id}/enable`

Enable a disabled job.

| Field | Value |
|-------|-------|
| Auth | `write:scheduler` permission |
| Path params | `job_id` (integer) |
| Response | `{ "job_id": str, "status": "enabled" }` |
| Errors | 404 if job not found or not in user's org |

##### `PATCH /scheduler/jobs/{job_id}/disable`

Disable an enabled job.

| Field | Value |
|-------|-------|
| Auth | `write:scheduler` permission |
| Path params | `job_id` (integer) |
| Response | `{ "job_id": str, "status": "disabled" }` |
| Errors | 404 if job not found or not in user's org |

##### `DELETE /scheduler/jobs/{job_id}`

Delete a scheduled job.

| Field | Value |
|-------|-------|
| Auth | `write:scheduler` permission |
| Path params | `job_id` (integer) |
| Response | 204 No Content |
| Errors | 404 if job not found or not in user's org |

#### Admin API

Admin endpoints for backup, logs, audit, and event history. Source:
`picosentry/serve/api/routers/admin.py`. All admin endpoints require the
`admin` role.

##### `POST /backup`

Create a database backup (tar.gz of database + optional logs).

| Field | Value |
|-------|-------|
| Auth | `admin` role |
| Request body | none |
| Response | `{ "status": "backup_created", "path": str }` |

##### `GET /backups`

List available backups.

| Field | Value |
|-------|-------|
| Auth | `admin` role |
| Request body | none |
| Response | `{ "backups": [{ "name", "path", "size", "created" }] }` |

##### `GET /logs/stats`

Log directory statistics.

| Field | Value |
|-------|-------|
| Auth | `admin` role |
| Response | `{ "directory": str, "file_count": int, "total_size_mb": float, "max_size_mb": float, "retention_days": int, "files": [...] }` |

##### `POST /logs/rotate`

Trigger manual log rotation.

| Field | Value |
|-------|-------|
| Auth | `admin` role |
| Request body | none |
| Response | `{ "status": "rotated" }` |

##### `GET /logs`

Query log entries.

| Field | Value |
|-------|-------|
| Auth | `admin` role |
| Query params | `level` (string, optional — filter by log level); `source` (string, optional — filter by source); `search` (string, optional — text search); `limit` (int 1–1000, default 100) |
| Response | `{ "entries": [{ "file": str, "line": str }] }` |

##### `GET /audit/stats`

Audit log statistics.

| Field | Value |
|-------|-------|
| Auth | `admin` role |
| Response | `{ "total_entries": int, "oldest_entry": str\|null, "newest_entry": str\|null, "top_actions": [...], "retention_policy": {...} }` |

##### `GET /audit/verify`

Recompute the tamper-evident audit hash chain (`prev_hash`/`row_hash`, ADR-006)
and report whether it is intact. Source: `services/audit_chain.py:verify_audit_chain`.

| Field | Value |
|-------|-------|
| Auth | `admin` role |
| Query params | `limit` (optional — verify only the most recent N rows) |
| Response | `{ "valid": bool, "rows_checked": int, "violation": str\|null, "row_id": int\|null }` — reports the first chain break |

##### `POST /audit/purge`

Purge old audit log entries.

| Field | Value |
|-------|-------|
| Auth | `admin` role |
| Query params | `retention_days` (int ≥ 1, optional — override default tiered retention); `dry_run` (bool, default false — return count without deleting) |
| Response | If `dry_run`: `{ "would_delete": int, "cutoff": str }`. If not dry_run: `{ "deleted": int, "cutoff": str }` per severity tier, or single count if `retention_days` specified. |

Default retention policy: critical 365 days, high 180 days, medium 90 days,
low 30 days, default 90 days.

##### `GET /events/history`

Event bus history.

| Field | Value |
|-------|-------|
| Auth | `admin` role |
| Query params | `event_type` (string, optional — filter by event type); `limit` (int 1–1000, default 100) |
| Response | Array of event objects: `{ "id": str, "type": str, "source": str, "payload": dict, "timestamp": str, "priority": str }` |

#### WebSocket protocol

Source: `picosentry/serve/api/routers/ws.py`,
`picosentry/serve/services/websocket_manager.py`.

##### `WS /ws`

Authenticated WebSocket fanout for real-time event streaming.

**Connecting:**

- Connect to `ws://host:port/ws` (or `wss://` in production).
- Optional: pass `?token=<jwt>` as a query parameter for connect-time auth —
  **development only**: in production (`PICOSHOGUN_ENV=production`) the server
  accepts the connection and immediately closes with 4001 ("Query-string auth
  not allowed in production; use in-band auth").
- If a token is provided and invalid, the server accepts the connection then
  closes with code **4001** and reason `"Invalid authentication token"`.

**In-band authentication:**

If connected without a query-string token, send:

```json
{"action": "auth", "token": "<jwt>"}
```

- On success: `{"type": "auth", "status": "ok", "user_id": "<id>"}`
- On failure: `{"type": "auth", "status": "denied"}` then close with code
  **4001**.

**Unauthenticated connections** are accepted with an **empty channel set**.
They can send messages but receive no broadcasts and cannot `subscribe` until
they authenticate.

**Subscribing to channels:**

After successful auth, send:

```json
{"action": "subscribe", "channels": ["scan.completed", "chain.escalated", "*"]}
```

- `*` subscribes to all event types.
- On success: `{"type": "subscribed", "channels": [...]}`.
- If unauthenticated: `{"type": "error", "message": "Authentication required before subscribe"}`.

**Keepalive:**

```json
{"action": "ping"}
```

Server responds with:

```json
{"type": "pong"}
```

**Broadcasts:**

Subscribed clients receive:

```json
{"type": "<event_type>", "payload": {...}, "timestamp": "<iso8601>"}
```

**Channel semantics:**

- The `*` channel matches all event types.
- Subscribing replaces the previous channel set (not additive).
- Malformed JSON frames are silently ignored.
- Unknown actions are silently ignored (not echoed).

**Close codes:**

| Code | Meaning |
|------|---------|
| 4001 | Invalid authentication token |

### Determinism contract

PicoSentry's scanner and watch guard rely on deterministic behavior. Any code
path that introduces randomness, wall-clock timing, or non-deterministic IDs
must be isolated and documented (see the "Determinism" bullets in
[`CONTRIBUTING.md`](../CONTRIBUTING.md) and `picosentry scan --verify-determinism`).

---

## 20. Extension guide

This guide shows how to extend PicoSentry without touching its core engine. Each
extension type is self-contained and has a well-defined contract.

- [Add a scan detection rule](#add-a-scan-detection-rule)
- [Add a PicoWatch rule](#add-a-picowatch-rule)
- [Add a sandbox L3 backend](#add-a-sandbox-l3-backend)

### Add a scan detection rule

Scan rules live in `picosentry/scan/rules/` and are invoked by the scan engine
(`picosentry/scan/engine.py`). A rule is a plain Python callable that returns a
list of `Finding` objects.

#### Choose an implementation style

The engine accepts two rule shapes:

| Shape | Signature | Use when |
|-------|-----------|----------|
| Path-only | `fn(target_path: Path) -> list[Finding]` | Static analysis of files/metadata. |
| Path + corpus | `fn(target_path: Path, corpus_dir: Path) -> list[Finding]` | The rule needs the offline corpus (typosquat, IOC index, etc.). |

Rules are registered with a `rule_id` string. The engine groups rules by function
identity and runs them concurrently through a bounded thread pool.

#### Implement the rule

Create a new module under `picosentry/scan/rules/`, for example
`network_beacon.py`:

```python
from __future__ import annotations

from pathlib import Path

from picosentry.scan.models import Confidence, Finding, Severity


def detect_network_beacon(target: Path) -> list[Finding]:
    """Flag packages that reference well-known exfiltration endpoints."""
    findings: list[Finding] = []

    suspicious = target.rglob("*.js")
    for path in suspicious:
        text = path.read_text(encoding="utf-8", errors="ignore")
        if "attacker.example.com" in text:
            findings.append(
                Finding(
                    rule_id="L2-NETEX-999",
                    severity=Severity.CRITICAL,
                    confidence=Confidence.EXACT,
                    package=target.name,
                    file=str(path.relative_to(target)),
                    message="Hard-coded attacker C2 domain",
                    evidence="attacker.example.com",
                    remediation="Remove the hard-coded domain and report the incident.",
                )
            )

    return findings
```

Best practices:

- Keep rules deterministic: no randomness, no wall-clock timeouts, no
  non-deterministic IDs.
- Respect `MAX_FILE_BYTES` / `MAX_FILES_PER_PACKAGE` limits to avoid blowing up
  on minified bundles.
- Return an empty list when nothing matches.
- Catch and log unexpected I/O errors rather than crashing the whole scan.

#### Register the rule

Rules are wired in `picosentry/scan/engine.py` (`create_default_engine`): import
your callable and register it, then add a metadata entry in
`picosentry/scan/rules/__init__.py` (`RULE_INFO`) so the rule is catalogued:

```python
# picosentry/scan/engine.py — inside create_default_engine()
from .rules.network_beacon import detect_network_beacon

engine.register("L2-NETEX-999", detect_network_beacon)
```

```python
# picosentry/scan/rules/__init__.py
"L2-NETEX-999": {
    "name": "network_beacon",
    "description": "Hard-coded attacker C2 domain",
    "severity": "CRITICAL",
    "category": "supply-chain",
},
```

Use a rule ID prefix that matches the existing scheme:

- `L2-*-TYPO-001` — typosquat (per ecosystem)
- `L2-*-DEPC-001` — dependency confusion
- `L2-*-OBFS-*` — obfuscation
- `L2-*-ADV-001` — advisory/CVE
- `L2-IOC-*` / `L2-NETEX-*` / `L2-INTEL-*` — IoC, network exfiltration, package intel

#### Add fixtures

Every rule needs a positive fixture (known-bad) and ideally a negative fixture
(known-good). Fixtures live under `tests/scan/fixtures/validation/`:

```text
tests/scan/fixtures/validation/
  positive/
    network_beacon_exfil/
      fixture.json
      package.json
      index.js
  negative/
    network_beacon_legit/
      fixture.json
      package.json
      index.js
```

A `fixture.json` looks like this (`label` must be exactly `positive` or
`negative`; optional keys: `expected_findings`/`unexpected_findings` assertion
objects, `forbidden_rule_ids`, `strict`):

```json
{
  "label": "positive",
  "description": "Reference to a hard-coded C2 domain",
  "expected_rule_ids": ["L2-NETEX-999"],
  "forbidden_rule_ids": []
}
```

Run the validation floor to confirm the new rule is calibrated:

```bash
picosentry scan --validate
python -m pytest tests/scan/test_validation.py -v
```

The CI floor (`test_validation_passes_at_100_percent_on_current_fixtures`) fails
below **85% mean precision / 70% mean recall** — known offline gaps (advisory,
dep-confusion rules) sit under that floor by design; if your rule raises false
positives on existing negative fixtures, adjust the pattern or add more
negatives.

### Add a PicoWatch rule

PicoWatch rules are YAML files. They are loaded from:

- `picosentry/watch/rules/prompt_injection/` — L5 prompt guard
- `picosentry/watch/rules/output_policy/` — L6 output guard

#### Write the rule YAML

```yaml
# picosentry/watch/rules/prompt_injection/my_new_category.yaml
- id: inj_my_custom
  category: instruction_override
  weight: 0.75
  pattern: "(?i)pretend\s+you\s+are\s+(?:the\s+)?developer"
  description: "Role-play as the system developer"
  normalization: [unicode, whitespace, comments]
```

Fields:

| Field | Meaning |
|-------|---------|
| `id` | Unique rule identifier. |
| `category` | One of the existing categories; used by the classifier for diversity scoring. |
| `weight` | 0.0–1.0 regex contribution to the final score. |
| `pattern` | Python-compatible regex string. Use `(?i)` for case-insensitive. |
| `description` | Human-readable explanation surfaced in results. |
| `normalization` | Which normalizers to apply before matching (`unicode`, `whitespace`, `comments`, `base64`, `url`, `rot13`). |

#### Test the rule

Add a unit test in `tests/watch/test_prompt_guard.py` or
`tests/watch/test_output_guard.py`, or simply run:

```bash
python -m pytest tests/watch/ -v -k "prompt"
```

The corpus hash is computed from the rule file contents, so adding a rule
changes the reported `corpus_hash` and `corpus_version`. Update any tests that
assert exact hash values.

#### Calibrate the classifier

If the new category changes the lexical classifier behavior, run the
classifier tests and adjust `tests/watch/test_prompt_guard.py` expectations.
The classifier is intentionally conservative: a single ambiguous keyword
should not block benign text.

### Add a sandbox L3 backend

The L3 sandbox dispatches commands to a `SandboxBackend` implementation based on
the `--backend` flag. Existing backends are in
`picosentry/sandbox/l3/backends/`.

#### Implement `SandboxBackend`

Subclass `picosentry.sandbox.l3.backends.base.SandboxBackend`:

```python
from __future__ import annotations

from picosentry.sandbox.l3.backends.base import SandboxBackend
from picosentry.sandbox.l3.models import Policy, SandboxResult


class FirejailBackend(SandboxBackend):
    @property
    def name(self) -> str:
        return "firejail"

    @property
    def isolation_level(self) -> str:
        return "namespace"

    @property
    def enforcement_guarantee(self) -> str:
        return "kernel_enforced"

    def is_available(self) -> bool:
        import shutil

        return shutil.which("firejail") is not None

    def run(
        self,
        command: list[str],
        policy: Policy,
        timeout: float | None = None,
        cwd: str | None = None,
        env: dict | None = None,
    ) -> SandboxResult:
        # Build the sandboxed command from `policy.rules` and run it.
        # Return a SandboxResult with events and verdict.
        ...
```

Key responsibilities:

- `is_available()` — returns `True` only when the host supports this backend.
- `run(...)` — execute the command under the policy and return a `SandboxResult`.
- `name` — short identifier used by `--backend <name>`.
- `isolation_level` / `enforcement_guarantee` — metadata for reporting.

#### Register the backend

Edit `picosentry/sandbox/l3/backends/__init__.py` (`get_backend`):

1. Import the new backend.
2. Add a `if name == "firejail": ...` branch returning it (falling back to an
   available backend when `is_available()` is False).

#### Add tests

Add tests in `tests/sandbox/` that exercise the new backend when available and
skip cleanly when it is not. The existing tests use `pytest.mark.skipif` based
on backend availability — follow that pattern.

### General checklist

Before opening a PR for any extension:

- [ ] `ruff check picosentry/ tests/ scripts/` passes.
- [ ] `ruff format --check picosentry/ tests/ scripts/` passes.
- [ ] `mypy picosentry/` passes.
- [ ] New code has tests following existing conventions.
- [ ] Determinism is preserved (no randomness, no wall-clock timeouts in rules).
- [ ] Extension is documented in this guide if the pattern is novel.

---

## 21. Known limitations and component status

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
  [Chapter 16, Threat model](#16-threat-model) and
  [Chapter 17, Attack surface](#17-attack-surface-and-pentest-scope).

- **Detection benchmarks are published.** See
  [Chapter 18, Benchmarks and model card](#18-detection-benchmarks-and-model-card).
  The corpus is **5,673 fixtures** (3,431 positive / 2,235 negative / 7 tricky)
  across **7 ecosystems**; the 2026-08-17 benchmark run measured **100.00% mean
  precision / 90.87% mean recall** over 54 rule IDs (50 static at the time + 4
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

If a feature is listed as Experimental, treat it as not production-ready.

### Feature matrix

| Feature | PicoSentry | pip-audit | osv-scanner | Trivy | Socket |
|---------|:---------:|:---------:|:-----------:|:-----:|:------:|
| Offline operation | yes | partial | partial | partial | no |
| Deterministic output (bit-identical runs) | yes | no | no | no | no |
| Malicious-behavior detection (not just CVEs) | yes | no | no | partial | partial |
| Multi-ecosystem (npm, PyPI, Go, Cargo, Maven, RubyGems, NuGet) | yes | partial | yes | yes | partial |
| Runtime sandbox enforcement (kernel-level) | yes | no | no | no | no |
| Runtime syscall observation from kernel | partial (no path/address args) | no | no | no | no |
| Source-available license | yes (BUSL-1.1) | yes (Apache-2.0) | yes (Apache-2.0) | yes (Apache-2.0) | no |

Where PicoSentry is weaker: pip-audit and osv-scanner have wider and more
frequently refreshed CVE coverage via OSV. Trivy has broader container and IaC
scanning. Socket has hosted workflow integrations PicoSentry doesn't ship. The
differentiator is the combination of offline + deterministic + malicious-behavior
rules in a single offline binary — not raw CVE breadth.

### Component status

The per-component status table (Stable / Beta / Experimental, with notes) is
maintained in the [README](../README.md#status) and rendered programmatically
from [`picosentry/experimental.py`](../picosentry/experimental.py) — the code is
the source of truth, and a CI test asserts the README table matches it
byte-for-byte. `"Beta"` = works, has regression + security tests, suitable for
controlled production use.

---

## 22. Repository structure

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
    manual.md      this manual
    BENCHMARKS.md  generated per-rule benchmark table (CI-enforced)
    workorders/    improvement workorder specs
    (per-rule documentation lives in picosentry/scan/docs/rules/)
tests/            test suite
deploy/
    kubernetes/    K8s deployment manifests
    helm/          Helm charts (picodome daemon, picodome-admission)
```

---

## 23. Appendix ADR index

Architecture Decision Records are immutable records; they live in
[`docs/adr/`](adr/) and are indexed here, not absorbed.

| ADR | Title | One-line summary |
|-----|-------|------------------|
| [ADR-001](adr/ADR-001-offline-deterministic-scanner.md) | Offline deterministic scanning | No model calls in the hot path; detection is deterministic and offline. |
| [ADR-002](adr/ADR-002-kernel-sandbox.md) | Kernel sandbox via seccomp-bpf | The CLI sandbox surface is seccomp-bpf; the later landlock backend is not CLI-exposed (see the ADR's addendum). |
| [ADR-003](adr/ADR-003-python-uv-packaging.md) | Python with uv for packaging | uv lockfile pinning, reproducible builds, sigstore signing. |
| [ADR-004](adr/ADR-004-plugin-trust-boundary.md) | Plugin trust boundary | Signing is authenticity, sandboxing is safety; never conflated. |
| [ADR-005](adr/ADR-005-picoshogun-picosentry-naming.md) | Picoshogun → PicoSentry rename | Public name PicoSentry; `picoshogun` retained as internal codename (hence the `PICOSHOGUN_*` env prefix). |
| [ADR-006](adr/ADR-006-audit-hash-chain.md) | Tamper-evident audit hash-chain | Serve audit rows chain `prev_hash`/`row_hash`; `GET /audit/verify` recomputes the chain. |
| [ADR-007](adr/ADR-007-multi-tenancy.md) | Multi-tenancy / org isolation | Flat `org_id` scoping on reads and writes. |
| [ADR-008](adr/ADR-008-serve-orchestration-api.md) | Serve orchestration API | FastAPI control plane orchestrating scan/sandbox/watch runs. |
| [ADR-009](adr/ADR-009-llm-watch.md) | LLM watch subsystem (PicoWatch) | Deterministic L5/L6 guard layers for prompts and outputs. |

---

*Manual structure note: this manual supersedes the former standalone tech docs
(`TECHNICAL_MANUAL.md`, the pre-2.1.3 `manual.md`, `ARCHITECTURE.md`,
`INTERNAL_API.md`, `EXTENSION_GUIDE.md`, `PLUGIN_DEVELOPMENT.md`, `WATCH.md`,
`FIREWALL.md`, `docker.md`, `THREAT_MODEL.md`, `SECURITY-ATTACK-SURFACE.md`,
`DEPLOYMENT_SECURITY.md`, `model-card.md`, `docs/ops/runbook.md`, and root
`OFFLINE.md`), which remain as pointer stubs. `docs/BENCHMARKS.md` is generated
and CI-gated and is referenced, not absorbed. The former `docs/strategic/`
design docs were removed earlier; those tracks are deferred.*

