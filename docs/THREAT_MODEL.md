# PicoSentry Threat Model

This document describes the trust boundaries, assets, and threats that guide
PicoSentry's security posture. It is intended for operators, reviewers, and
contributors who need to understand where enforcement ends and observability
begins.

## Scope

PicoSentry has four main runtime components:

| Component | Responsibility | Maturity |
|-----------|----------------|----------|
| **scan** | Offline deterministic supply-chain scanner | STABLE |
| **sandbox** | Runtime containment (seccomp-bpf / Landlock / behavioral analysis) | BETA |
| **watch** | LLM prompt/output guard (L5/L6) | BETA |
| **serve** | API server, scheduler, webhooks, multi-tenant metrics | EXPERIMENTAL |
| **daemon** | Long-running policy enforcement daemon | BETA |
| **admission** | Kubernetes admission webhook | BETA |

This model covers all of them. Anything marked **EXPERIMENTAL** has not yet
received a full adversarial security review; do not expose it to untrusted
networks without additional hardening.

## Assets

1. **Detection corpus and rules** — the source of PicoSentry's detection signal.
2. **Plugin code** — third-party extensions that run inside or beside the host.
3. **Host secrets** — credentials, tokens, TLS keys, API keys in the process
   environment.
4. **Tenant data** — project runs, alerts, intelligence, metrics in `serve`.
5. **Cluster state** — peer snapshots and tokens used by the daemon gossip
   protocol.

## Trust Boundaries

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

### Boundary 1: Scanner input

- **Assumption:** files and packages under analysis are untrusted.
- **Enforcement:** the scanner never executes package code; it reads static
  files. Symlinked scan targets are rejected at entry to prevent traversal out
  of the intended root.
- **Limits:** the scanner does not prove absence of malware, only presence of
  known patterns. A sufficiently novel or adversarially mutated sample may
  bypass detection.

### Boundary 2: Plugin host

- **Assumption:** plugins may be signed by a trusted key, but signing proves
  authenticity, not safety.
- **Enforcement:** every plugin is spawned as a separate Python subprocess
  with a stripped environment and a capability allowlist. By default plugins
  get no `network`, `filesystem`, `subprocess`, `secrets`, or
  `detection_write` capability. The host validates all worker responses before
  applying them to host state.
- **Limits:** plugins currently share the same kernel as the host. A kernel
  or Python sandbox escape would breach this boundary.

### Boundary 3: Sandbox / daemon runtime enforcement

- **Assumption:** the host OS and kernel are trusted.
- **Enforcement:** Linux seccomp-bpf blocks dangerous syscalls; Landlock
  restricts filesystem access where available. The daemon uses TLS/mTLS for
  its HTTP/gRPC interfaces.
- **Limits:** seccomp-trace and some advanced sandbox tests require kernel
  configs that are not present on every distribution. macOS uses the lighter
  Seatbelt backend. The sandbox is **enforcement** for syscalls, not full
  system-call tracing or observability.

### Boundary 4: `serve` API and multi-tenancy

- **Assumption:** `serve` runs behind a reverse proxy or inside a trusted
  network until its security review is complete.
- **Enforcement:** Bearer-token authentication, role/permission dependencies,
  `org_id` scoping on DB-backed reads and metrics, rate limiting, and DDoS
  shield middleware.
- **Limits:** `serve` is **EXPERIMENTAL**. Cross-tenant isolation has been
  hardened but should be reviewed before exposing to arbitrary users.

### Boundary 5: Admission webhook

- **Assumption:** the Kubernetes API server is the only caller.
- **Enforcement:** TLS required in production; pod validation policy is
  fail-closed by default (`PICODOME_ADMISSION_FAIL_CLOSED=true`).
- **Limits:** a misconfigured webhook without a validator will deny all pods.

## Failure Modes and Defaults

| Situation | Default | Override |
|-----------|---------|----------|
| Admission validator missing | **deny** | configure a validator |
| Admission daemon unreachable | **deny** if fail-closed is on | `PICODOME_ADMISSION_FAIL_CLOSED=false` |
| Watch rule load failure | **pass** (fail-open) | `PICOSENTRY_WATCH_FAIL_CLOSED=true` |
| Watch rule evaluation crash | **pass** unless fail-closed is on | `PICOSENTRY_WATCH_FAIL_CLOSED=true` |
| Plugin worker timeout | worker terminated, call raises | tune `timeout` per plugin |
| Corpus older than threshold | CLI exits 5 | `--check-corpus-age` |
| Rate-limiter table full | new distinct IPs denied | increase `max_clients` |
| `serve` auth failure | HTTP 401/403 | — |

## Threats and Mitigations

### T1 — Malicious input evades detection

- **Mitigation:** deterministic rule engine, corpus freshness checks,
  adversarial mutation testing, and a documented recall floor.
- **Residual risk:** zero-day obfuscation or novel attack classes may slip
  through.

### T2 — Plugin escapes sandbox

- **Mitigation:** subprocess isolation, capability allowlist, stripped env,
  trusted-key signing, and response validation.
- **Residual risk:** shared kernel; a sandbox escape is a critical finding.

### T3 — Operator misconfiguration leaves service fail-open

- **Mitigation:** security-sensitive defaults are fail-closed or opt-out.
  Fail-open flags are documented in this model and in the ops runbook.
- **Residual risk:** an operator may explicitly disable fail-closed behavior.

### T4 — Cross-tenant data leak in `serve`

- **Mitigation:** `org_id` scoping on reads, permission-level RBAC, negative
  tests for A↔B isolation.
- **Residual risk:** `serve` is still experimental; new endpoints must enforce
  org scoping.

### T5 — SSRF via daemon or image-scanner URL

- **Mitigation:** `assert_url_safe()` is applied to daemon URLs, cloud
  metadata endpoints are blocked, and scanner network access is controlled.
- **Residual risk:** custom DNS rebinding or internal redirects not fully
  mitigated by hostname checks alone.

### T6 — Corpus tampering

- **Mitigation:** corpus packs can be signed (minisign / Sigstore), checksums
  are verified on load, and `is_corpus_stale()` warns when data is old.
- **Residual risk:** a compromised build pipeline could ship a malicious
  corpus if signing keys are exposed.

## What the Sandbox Does **Not** Do

- It does not provide a full virtual machine or container boundary.
- It does not trace every syscall by default; behavioral analysis is
  observability, not enforcement.
- It does not guarantee detection of all malware; it raises structured findings
  for known patterns.

## Review Cadence

Update this document after any change to:

- a trust boundary,
- a fail-closed/fail-open default,
- plugin capability model,
- `serve` auth/RBAC,
- admission webhook behavior.
