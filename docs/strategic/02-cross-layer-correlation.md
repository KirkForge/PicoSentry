# 02 — Cross-Layer Kill-Chain Correlation

**Leverage:** Category ownership | **Effort:** Medium | **Dependency:** None (pure serve-layer addition)

---

## Why

The scanner, sandbox, and LLM guard each emit structured events about
the same artifact (a package, a prompt, a process), but those events
land in different stores with different schemas. A user who runs all
three layers gets three separate reports, not one picture.

Cross-layer correlation joins events by artifact identity into a
single timeline and scores the chain. That converts a list of
warnings into a chronology: which package triggered which rule in
which layer, in what order, and how serious the chain is as a whole.
The output answers the alert-fatigue question directly: "I have 42
findings — which ones actually matter together?"

## Architecture

### Current state: findings are siloed

```
scan ──→ ScanResult.findings[] ──→ CLI output / JSON file
sandbox ──→ SandboxResult.events[] ──→ CLI output / JSON file  
watch ──→ PromptScanResult ──→ HTTP response / telemetry DB
serve ──→ orchestrator CLI subprocess ──→ stdout text ──→ regex intel extraction
```

Key gaps:
- No shared correlation ID across layers
- Serve stores raw stdout, not structured findings
- `IntelligenceEngine.find_correlations()` matches `intel_type` strings across projects within a 24h window — no multi-hop chain linking
- No event subscription: scan completes → no one triggers analysis

### Target state: per-artifact kill-chain timeline

```
                        ┌──────────────────────────────────────┐
                        │      CorrelationEngine               │
                        │                                      │
  scan_finding ────────→│  package_x@1.2.3: L2-POST-001 HIGH   │
                        │    + 2h later → L4 socket to X.X.X.X │
  sandbox_event ───────→│    + prompt-injection via that agent │
                        │    ───────────────────────────────── │
  watch_verdict ────────→│  Kill-chain score: CRITICAL (3/4)   │
                        │  Attack narrative: "malicious npm →  │
                        │  C2 beacon → exfiltration via agent" │
                        └──────────────────────────────────────┘
```

### New component: CorrelationEngine

A pure-data service in the serve layer that receives structured events from all layers, correlates them by package identity, and produces kill-chain verdicts.

**File:** `picosentry/serve/services/correlation.py`

**Conceptual interface:**

```python
class CorrelationEngine:
    # Called by the orchestrator when any layer completes
    def ingest(self, event: CorrelatedEvent) -> None: ...

    # Query: what's the full story for package_x@1.2.3?
    def kill_chain(self, package: str, target: str) -> KillChainTimeline: ...

    # Query: high-signal packages right now
    def critical_chains(self, threshold: float = 0.7) -> list[KillChainTimeline]: ...

    # Trigger downstream actions when chain crosses threshold
    def on_chain_escalated(self, chain: KillChainTimeline) -> None: ...
```

## Data Model

### CorrelatedEvent (new)

A small, deterministic event schema that any layer can emit:

```python
@dataclass(frozen=True)
class CorrelatedEvent:
    artifact_id: str            # package@version, globally unique (e.g. "lodash@4.17.21")
    layer: str                  # "scan" | "sandbox_l3" | "sandbox_l4" | "watch"
    rule_id: str                # e.g. "L2-POST-001", "L4-NETEX-001"
    severity: Severity          # shared enum from pico_core
    confidence: Confidence      # shared enum from pico_core
    target: str                 # scan target / project name / prompt session
    title: str                  # human-readable one-liner
    detail: str                 # evidence / context
    timestamp: str              # ISO 8601 UTC (deterministic for scan events)
    run_id: str | None = None   # serve orchestrator run ID for traceability
```

### KillChainTimeline (new)

The correlated output — a chronology of related events that form an attack narrative:

```python
@dataclass
class KillChainTimeline:
    artifact_id: str                    # the package under analysis
    phases: dict[str, list[CorrelatedEvent]]  # kill-chain phase → events
    # phases: "reconnaissance", "delivery", "execution", "persistence",
    #         "c2", "exfiltration", "impact"
    severity: Severity                  # overall chain severity
    confidence: Confidence              # overall chain confidence
    chain_score: float                  # 0.0–1.0 composite
    narrative: str                      # AI-generated attack story
    related_targets: list[str]          # other targets in the same chain
```

### Kill-chain phase mapping

Rules map to kill-chain phases:

| Phase | Example Events | Source Layers |
|-------|---------------|---------------|
| Reconnaissance | Prompt injection attempt, suspicious domain lookup | Watch, Sandbox L4 |
| Delivery | Dep-confusion / typosquat install, malicious postinstall | Scan |
| Execution | Obfuscated script execution, `install` hook call | Sandbox L3, Scan |
| Persistence | Maintainer-change alert, installs to system dirs | Scan, Sandbox L3 |
| C2 | Outbound socket to unrecognized IP, DNS exfil | Sandbox L3, L4 |
| Exfiltration | File read + network egress, PII in LLM output | Sandbox L4, Watch |
| Impact | Data leak, service disruption, prompt injection success | Watch, Sandbox L3 |

## Integration Points

### 1. Orchestrator injection (`serve/services/orchestrator.py`)

Instead of subprocess stdout → regex intel, the orchestrator calls `CorrelationEngine.ingest()` after each layer completes:

```python
# After scan completes:
for finding in scan_result.findings:
    event = CorrelatedEvent(
        artifact_id=finding.package,
        layer="scan",
        rule_id=finding.rule_id,
        severity=finding.severity,
        confidence=finding.confidence,
        target=project_config.target,
        title=finding.message,
        detail=finding.evidence,
        timestamp=scan_result.completed_at,
        run_id=run_id,
    )
    correlation_engine.ingest(event)

# After sandbox completes:
for event in sandbox_result.events:
    correlation_engine.ingest(CorrelatedEvent(
        artifact_id=... derived from event,
        layer="sandbox_l3",
        ...
    ))
```

### 2. API endpoints (`serve/api/routers/correlation.py`)

New router:

| Method | Path | Purpose |
|--------|------|---------|
| `GET` | `/api/v1/chains` | List active kill chains (sorted by score desc) |
| `GET` | `/api/v1/chains/{artifact_id}` | Full timeline for one artifact |
| `GET` | `/api/v1/chains/{artifact_id}/narrative` | AI-generated narrative text |
| `POST` | `/api/v1/events` | Ingest an event (for custom integrations) |

### 3. Dashboard integration (`serve/front/index.html`)

New "Kill Chains" panel showing:
- Active chains ranked by score
- Phase dot-diagram: ● → ● → ● → ● (filled = confirmed, hollow = possible)
- Side panel with full timeline + narrative

## Scoring Model

`chain_score` is computed as:

```
score = sum(phase_score * phase_weight) / sum(phase_weight)

phase_score = max(events_in_phase, key=lambda e: severity_weight(e.severity))
phase_weight = phase_progression_weight  # later phases weighted higher
```

Severity weights: CRITICAL=1.0, HIGH=0.7, MEDIUM=0.4, LOW=0.2
Phase progression weights: reconnaissance=0.3, delivery=0.5, execution=0.6, persistence=0.7, c2=0.8, exfiltration=0.9, impact=1.0

A chain with events in delivery + execution + c2 phases will naturally score higher than events in delivery alone — the narrative emerges from the structure.

## Event Bus Integration

The existing `EventBus` (`serve/services/event_bus.py`) emits `project.run.completed` events. Subscribe the `CorrelationEngine` to these events so correlation happens automatically on scheduled runs:

```python
event_bus.on("project.run.completed", lambda evt: 
    correlation_engine.on_run_completed(evt.project_id, evt.run_id))
```

## Phases

### Phase 1: Core data model + ingestion
- `CorrelatedEvent` dataclass + `KillChainTimeline` (picosentry/serve/services/correlation.py)
- `CorrelationEngine.ingest()` + in-memory storage
- Orchestrator hook in `orchestrator.py` to ingest events from scan/sandbox/watch results

### Phase 2: Kill-chain scoring + query API
- Phase classification map (rule_id → kill-chain phase)
- `chain_score` computation
- `kill_chain()` and `critical_chains()` queries
- API router endpoints

### Phase 3: Dashboard + narrative
- Kill Chains panel in the SPA
- Narrative generation from phase evidence
- Event bus subscription for real-time escalation

### Phase 4: Alerting + auto-remediation
- `on_chain_escalated()` → triggers alert/incident
- Cross-layer auto-analysis: "scan found CRITICAL → auto-submit to sandbox for runtime analysis"
- Webhook delivery of kill-chain JSON payloads

## Verification

- Unit test: inject 3 events for the same artifact_id across scan/sandbox/watch → verify chain_score > 0.5
- Unit test: single-layer events → chain_score ≤ 0.3
- API test: `GET /chains` returns sorted by score
- Integration test: `picosentry serve` with a pre-configured project, run a scan that produces findings, verify events appear in chain endpoint
- Dashboard: Kill Chains panel renders phase diagram correctly for 0–4 phase chains