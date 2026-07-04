# PicoSentry Internal API Map

This document maps the key internal entry points per component. It is intended
for contributors who need to navigate the codebase quickly.

## Component index

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
| Serve API | `picosentry/serve/server.py` | FastAPI application factory. |
| Serve services | `picosentry/serve/services/` | Auth, orchestrator, plugin host, webhooks, etc. |
| Serve config | `picosentry/serve/config/` | Settings and JSON schemas. |
| Daemon | `picosentry/sandbox/daemon/` | Sandbox-as-a-service HTTP + gRPC daemon. |
| Correlation | `picosentry/serve/services/correlation/` | Cross-layer kill-chain correlation. |
| Cluster | `picosentry/serve/services/cluster.py` | Gossip-based cluster manager. |
| Plugin system | `picosentry/serve/services/plugin_*.py` | Plugin host, manager, and interface. |
| _core | `picosentry/_core/` | Cross-cutting utilities (security check, version). |

## Scan module

### Entry points

| File | Symbol | Purpose |
|------|--------|---------|
| `picosentry/scan/engine.py` | `ScanEngine` | Register rules and run scans. |
| `picosentry/scan/engine.py` | `create_default_engine()` | Factory with all bundled rules. |
| `picosentry/scan/engine.py` | `ScanEngine.scan(target, ...)` | Execute a scan and return `ScanResult`. |
| `picosentry/scan/rules/__init__.py` | `RULE_REGISTRY` | Mapping from `rule_id` to rule callable. |
| `picosentry/scan/models.py` | `Finding` | Structured detection result. |
| `picosentry/scan/cli.py` | `scan_command` | CLI entry point for `picosentry scan`. |

### Adding a rule

1. Implement a callable in `picosentry/scan/rules/`.
2. Register it in `picosentry/scan/rules/__init__.py`.
3. Add fixtures in `tests/scan/fixtures/validation/`.
4. Run `picosentry scan --validate`.

See [`EXTENSION_GUIDE.md`](EXTENSION_GUIDE.md) for a worked example.

## Watch module

### Entry points

| File | Symbol | Purpose |
|------|--------|---------|
| `picosentry/watch/prompt_guard/__init__.py` | `PromptGuard` | L5 prompt scanner. |
| `picosentry/watch/output_guard/__init__.py` | `OutputGuard` | L6 output validator. |
| `picosentry/watch/prompt_guard/rules.py` | `RuleEngine` | Loads and evaluates YAML regex rules. |
| `picosentry/watch/server.py` | `create_app(...)` | FastAPI app for `picosentry watch serve`. |
| `picosentry/watch/config.py` | `PicoWatchConfig` | All-in-one configuration dataclass. |

### Rule file locations

| Type | Directory |
|------|-----------|
| Prompt injection | `picosentry/watch/rules/prompt_injection/` |
| Output policy | `picosentry/watch/rules/output_policy/` |

## Sandbox module

### L3 backend entry points

| File | Symbol | Purpose |
|------|--------|---------|
| `picosentry/sandbox/l3/engine.py` | `get_backend(...)` | Selects and instantiates a backend. |
| `picosentry/sandbox/l3/backends/base.py` | `SandboxBackend` | Abstract backend interface. |
| `picosentry/sandbox/l3/backends/seccomp_backend.py` | `SeccompBackend` | Linux seccomp-bpf enforcement. |
| `picosentry/sandbox/l3/backends/subprocess_backend.py` | `SubprocessBackend` | Fallback subprocess runner. |
| `picosentry/sandbox/l3/models.py` | `Policy`, `SandboxResult` | Backend data contracts. |

### L4 behavioral engine

| File | Symbol | Purpose |
|------|--------|---------|
| `picosentry/sandbox/l4/engine.py` | `analyze(...)` | Convert sandbox events into behavioral findings. |
| `picosentry/sandbox/l4/models.py` | `BehavioralFinding` | Structured L4 result. |

## Serve module

### Entry points

| File | Symbol | Purpose |
|------|--------|---------|
| `picosentry/serve/server.py` | `create_app(...)` | FastAPI app factory. |
| `picosentry/serve/services/auth.py` | `AuthService` | User/token/auth helpers. |
| `picosentry/serve/services/orchestrator.py` | `Orchestrator` | Coordinates scan/sandbox/watch runs. |
| `picosentry/serve/services/plugin_manager.py` | `PluginManager` | Loads and dispatches plugins. |
| `picosentry/serve/services/plugin_host.py` | `PluginHost` | Subprocess wrapper for a plugin. |
| `picosentry/serve/services/correlation/engine.py` | `CorrelationEngine` | Cross-layer kill-chain builder. |
| `picosentry/serve/services/webhooks.py` | `WebhookDispatcher` | Alert webhook delivery. |
| `picosentry/serve/services/websocket_manager.py` | `WebSocketManager` | Live results streaming. |
| `picosentry/serve/services/scheduler.py` | `Scheduler` | Periodic task runner. |
| `picosentry/serve/config/settings.py` | `Settings` | Pydantic settings + env loading. |

### Plugin interface

| File | Symbol | Purpose |
|------|--------|---------|
| `picosentry/serve/services/plugin_manager.py` | `PluginInterface` | Base class for plugins. |
| `picosentry/serve/services/plugin_host.py` | `PluginHost` | Spawns and communicates with plugin workers. |

## Data and corpus

| File | Symbol | Purpose |
|------|--------|---------|
| `picosentry/scan/corpus/` | — | Offline malware/IOC/advisory JSON datasets. |
| `picosentry/scan/advisory.py` | `AdvisoryDB` | Parses OSV-style advisories. |
| `picosentry/scan/corpus_index.py` | `CorpusIndex` | BK-tree edit-distance index for typosquat. |
| `datasets/malware/` | — | Larger benchmark malware corpora (not shipped in wheel). |

## CLI dispatch

`picosentry/cli.py` uses subcommands defined in:

- `picosentry/scan/cli_commands/`
- `picosentry/sandbox/cli_commands/`
- `picosentry/watch/cli.py`
- `picosentry/serve/cli.py`

Each subcommand module exposes a `register_*` function that adds its commands
to the main parser.

## Testing helpers

| File | Purpose |
|------|---------|
| `scripts/test_doctor.py` | Unified local CI-quality runner. |
| `tests/conftest.py` | Shared fixtures. |
| `tests/scan/fixtures/validation/` | Regression fixture corpus for scan rules. |

## Determinism contract

PicoSentry's scanner and watch guard rely on deterministic behavior. Any code
path that introduces randomness, wall-clock timing, or non-deterministic IDs
must be isolated and documented. See `docs/determinism.md`.
