"""
Experimental features tracking — components that are not yet production-ready.

PicoSentry has a clear core (supply-chain scanning) and several experimental
extensions. This file documents which features are experimental and what's
needed to stabilize them.

Legend:
  ✅ Stable   — production-ready, tested, deterministic
  ⚠️ Beta     — works but may have rough edges
  🔬 Experimental — proof of concept, may change or be removed
  ❌ Stub     — placeholder, not implemented

## Feature maturity matrix

| Component | Status | Notes |
|-----------|--------|-------|
| CLI: scan | ✅ Stable | Core scanner — npm, PyPI, Go, Cargo, Maven, RubyGems, NuGet |
| CLI: sandbox | ⚠️ Beta | seccomp-bpf works; gRPC transport experimental |
| CLI: watch | ⚠️ Beta | Prompt injection detection works; server experimental |
| CLI: serve | 🔬 Experimental | API server + dashboard in active development |
| Cross-layer correlation | 🔬 Experimental | Links findings across layers |
| PostgresPool | ❌ Stub | SQLite only; Postgres migration not started |
| DDoSShieldMiddleware | 🔬 Experimental | Basic rate limiting, not adaptive |
| Cluster manager | 🔬 Experimental | Single-node ✓; multi-node gossip not tested |
| Detection quality benchmarks | ✅ Stable | 45 fixtures, 50 rules, 100% precision/recall; corpus expansion to 30+/rule in 2.1.0 (see docs/BENCHMARKS.md) |
| Corpus marketplace | ❌ Stub | Export/import CLI commands not wired |
| Plugin system | ⚠️ Beta | Loads and dispatches plugins; signature verify works |
| Dashboard | 🔬 Experimental | Basic UI, not feature-complete |
"""

__all__ = []  # documentation-only module
