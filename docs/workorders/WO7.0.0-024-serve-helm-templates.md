# WO7.0.0-024 — Deploy: serve helm chart missing PVC/ServiceAccount/Secret/RBAC/NetworkPolicy/PDB templates

**Series:** WO7.0.0 (exploration round 2026-08-20)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/7.0.0/serve-helm-templates`)
**Priority:** P1 · Effort M · Risk L
**Scope:** `deploy/helm/serve/templates/`, `tests/deploy/`

**Gate:** `bash scripts/test.sh fast` + `helm template deploy/helm/serve` succeeds and renders PVC/SA/Secret/RBAC/NetworkPolicy/PDB; `helm lint` green.

## Objective
The serve helm chart's `deployment.yaml` references PVC/SA but the templates don't exist — `helm install` fails. The chart is deploy-broken.

## Evidence (verified 2026-08-20, explorer SA-core; file:line chain)
- `deploy/helm/serve/templates/deployment.yaml`: references `PVC`/`ServiceAccount` by name that no template file defines.
- `templates/` is missing: `_pvc.yaml`, `_serviceaccount.yaml`, `_secret.yaml`, `_rbac.yaml`, `_networkpolicy.yaml`, `_pdb.yaml` (the picodome chart has the full set — mirror it).

## Deliverables
1. Add the missing templates, mirroring the picodome chart's patterns.
2. `helm lint` + `helm template` green; regression test per the gate.