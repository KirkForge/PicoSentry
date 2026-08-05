---
name: ponytail-debt-ledger
description: Current ponytail: debt markers and remaining over-engineering items
metadata:
  type: project
---

# Ponytail Debt Ledger

## Active markers

`picosentry/serve/services/plugin_host.py:225` — select+readline assumes no message pipelining (true here); upgrade to raw-fd framed reader if the protocol ever batches.

`picosentry/serve/database/_schema.py:55` — no silent string-replace fallback; per-backend migration SQL is mandatory. If a general-purpose SQL transpiler is adopted or SQLite becomes the only target, revisit.

`picosentry/sandbox/l3/backends/_seccomp_common.py` — Removed prctl, memfd_create, io_uring from SAFE_SYSCALLS. `ponytail: re-add if a sandboxed workload requires these and kernel >= 6.1 is guaranteed.`

`picosentry/sandbox/l3/engine.py` — env stripping added to direct API path. `ponytail: currently strips known-secret patterns; switch to allowlist if sandbox workloads need arbitrary env vars.`

## 2 markers, 0 with no trigger. (plus 1 new seccomp marker from this session)