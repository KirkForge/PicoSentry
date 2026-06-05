"""pico-core — shared primitives for the Pico Security Series.

Vendored directly into picosentry to eliminate the external pico-core
dependency. Provides shared types used across scan, sandbox, watch, and serve.

Modules:
    guards   — DeterministicGuard, DeterminismViolation, verify_determinism, deterministic_hash, diff_results
    policy   — PolicyBase, policy versioning, content hashing
    config   — from_env helper, assert_secure startup gate
    audit    — AuditSink base, AuditEvent, hash-chained audit log, HMAC signing
    models   — Shared enums (Verdict, Severity), ScanStats base dataclass, FindingProtocol
"""

__version__ = "0.1.0"