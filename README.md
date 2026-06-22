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
| `picosentry scan` | **Stable** | Core scanner; 7 ecosystems; deterministic, offline; 54 rules, 188 fixtures |
| `picosentry sandbox` | **Beta** | seccomp-bpf enforces; gRPC + HTTP daemon; L4 behavioral analysis |
| `picosentry watch` | **Beta** | Deterministic regex + lexical classifier pre-filter for prompt injection (L5) and output validation (L6); not a semantic/LLM guarantee; CLI + HTTP server |
| `picosentry serve` | **Beta** | API server, dashboard, RBAC, multi-tenant — security review + regression tests in place |
| `picosentry daemon` | **Beta** | Sandbox-as-a-service; HTTP + gRPC; auth, rate limiting, TLS/mTLS, audit |
| `picosentry admission` | **Beta** | K8s admission webhook; pod security validation + optional image scanning; live-tested against a kind cluster |
| `picosentry corpus` | **Beta** | Export/import/validate/list/sign IoC packs; 3 built-in packs |
| Cross-layer correlation | **Beta** | Links findings across scan + sandbox + watch layers; persistence, dedup, and per-minute backpressure tested |
| Plugin system | **Beta** | Loads, validates, dispatches; Ed25519 signature verify; PicoShogun protocol |
| Postgres backend | **Beta** | psycopg2 pool + runtime placeholder translation + DDL auto-translation + dialect helpers |
| Cluster mode | **Beta** | Gossip over HTTP(S) with shared cluster token + optional mTLS; monotonic versioning; 3-node integration test |
| Detection benchmarks | **Stable** | 188 fixtures (150 pos / 38 neg), 54 rules, 100% CI floor (small corpus — see honest limitations) |
| Docker image | **Stable** | `kirkforge/picodome:v2.0.15` on Docker Hub; multi-arch (linux/amd64 + linux/arm64); non-root user |
| PyPI package | **Stable** | `pip install picosentry` — v2.0.15 published |

The scanner is the stable product. Everything else is beta or experimental —
read the notes column honestly. "Beta" means it works but hasn't been
battle-tested in production. "Experimental" means it runs but hasn't had a
security review — don't expose it to untrusted networks.

---

## What it does NOT do (today)

- **Records per-syscall traces from the kernel sandbox** (opt-in via
  `--backend=seccomp-trace` on `picosentry sandbox`; requires Linux + libseccomp +
  `CONFIG_SECCOMP_LOG=y`). Path/address arguments on events are not yet captured.
- **`picosentry watch` is a fast pre-filter, not a semantic guarantee.** It uses
  deterministic regex rules plus a lexical classifier to catch common prompt
  injections and output-policy violations. Paraphrase, novel phrasing, encoding
  tricks, or adversarial prompts can still slip through. For high-stakes LLM
  deployments, pair it with a dedicated model-based guard as a second layer.
- **Does not scan LLM model weights.** It guards prompts and outputs in deployed
  apps, not the model itself.
- **Cluster mode is beta.** Gossip over HTTP(S) requires a shared cluster token
  and supports optional mTLS; a 3-node integration test exercises leader election,
  token enforcement, and scan redistribution. It has not been battle-tested in a
  real multi-host deployment.
- **Postgres backend is Beta.** It includes a live integration test for
  connection pooling, runtime placeholder translation, and DDL
  auto-translation, but it has not been battle-tested at scale.
- **Admission controller is not tested against a real K8s cluster.** The code
  exists and the CLI works, but it hasn't seen a real API server.
- **Has published detection-benchmark data** in
  [`docs/BENCHMARKS.md`](docs/BENCHMARKS.md). The v2.0.15 corpus is 188
  fixtures (150 positive, 38 negative) / 50 L2 rule_ids + 4 L2-CAMP rule_ids
  / 100% precision / 100% recall. The corpus is small (mean ~3
  positives + ~3 negatives per rule across 54 rules) and the fixtures are
  mostly hand-crafted, so the 100% number is a smoke test, not a
  statistically meaningful measurement. See "Honest limitations" in
  that document for what the numbers do and don't prove.
- **Does not advertise a CVE database on its own.** CVE matching uses the OSV
  corpus (`[scan]` extra); offline-only operation pulls from the local corpus
  snapshot.

If a feature is listed as Experimental above, treat it as not production-ready.

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

Full rule catalog: [`picosentry/scan/docs/rules/`](picosentry/scan/docs/rules/) (49
L2 rule_ids in `RULE_INFO`; `RULE_ID_ALIASES` expands 3 detectors to
13 sub-rule_ids for a total of 50 measurable rule_ids across the
supported ecosystems).

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
| Source-available license | yes (BUSL-1.1) | yes (Apache-2.0) | yes (Apache-2.0) | yes (Apache-2.0) | no |

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
| `pip install picosentry[grpc]` | + `grpcio>=1.50` for the sandbox gRPC transport (committed protobuf stubs are included in the wheel, no `grpc_tools` required) |
| `pip install picosentry[all]` | Everything (including `[grpc]`) |

---

### Sandbox gRPC transport (opt-in)

The sandbox daemon can serve over gRPC instead of HTTP. Install the
extra, then start the daemon with `--transport=grpc`:

```bash
pip install 'picosentry[grpc]'

# Start the daemon (port 50051 by default; pass --grpc-port to change)
picosentry daemon --host=0.0.0.0 --port=8443 --transport=grpc --grpc-port=50051
```

The generated protobuf stubs (`picodome_pb2.py`, `picodome_pb2_grpc.py`)
are committed under `picosentry/sandbox/grpc_transport/proto/` and
ship in the wheel, so a client only needs `grpcio` to talk to the
daemon. Regenerate the stubs with `scripts/regen_proto.sh` after
editing `picodome.proto`.

For Kubernetes: `deploy/kubernetes/deployment.yaml` boots the daemon
with gRPC enabled by default and ships a `picodome-grpc` Service on
port 50051. For Helm, the equivalent is opt-in:

```yaml
# values.yaml
grpc:
  enabled: true
  port: 50051
```

```bash
helm install picodome deploy/helm/picodome/ --set grpc.enabled=true
```

The gRPC service exposes `Scan`, `Health`, `GetPolicy`, and
`QueryAudit` RPCs — see `picosentry/sandbox/grpc_transport/proto/picodome.proto`
for the full schema.

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
picosentry serve --port 8765                    # beta — API + dashboard
picosentry health
```

### Corpus management

PicoSentry ships with a small built-in typosquat/dep-confusion corpus.  For
stronger coverage, download per-ecosystem top-package lists and keep them
fresh:

```bash
picosentry update --ecosystem npm --top 5000
picosentry update --ecosystem all --top 10000
```

Supported ecosystems: `npm`, `pypi`, `go`, `cargo`, `maven`, `rubygems`,
`nuget`.  npm and PyPI have live registry fetchers; other ecosystems merge a
built-in fallback with any names supplied via `--source-url`.  The command
writes a `corpus.json` manifest, and the scanner warns when any ecosystem
corpus is older than 30 days.

---

## Plugins (serve mode)

The `picosentry serve` runtime discovers plugins from three places, in
priority order:

1. **`--plugin-dir PATH`** (repeatable) on the `serve` subcommand.
2. **`PICOSHOGUN_PLUGIN_DIR`** env var (comma-separated list of paths).
3. **`~/.picosentry/plugins/`** if it exists.

The bundled `picosentry/serve/plugins/` (which ships `test_plugin` and
`discord_notifier`) is always scanned last. Each plugin lives in its
own subdirectory containing `plugin.json` (manifest) and a Python
entry-point module. Manifests are validated against
`picosentry/serve/services/plugin_manager.py:REQUIRED_MANIFEST_FIELDS`
and may be Ed25519-signed — the `PICOSHOGUN_REQUIRE_SIGNED_PLUGINS=1`
env var turns signature verification from a warning into a hard refusal
to load.

```bash
# Install a plugin in your user-level directory:
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

# Or pass it on the command line:
picosentry serve --plugin-dir /opt/picosentry-plugins

# Or set the env var (takes a comma-separated list):
PICOSHOGUN_PLUGIN_DIR=/srv/plugs:/opt/picosentry-plugins picosentry serve
```

The `GET /plugins` endpoint returns the resolved directory list in a
`dirs` field alongside the loaded plugin status, so you can verify
discovery worked without checking the logs.

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
    serve/          API server + dashboard (CLI: `picosentry serve`, beta)
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
