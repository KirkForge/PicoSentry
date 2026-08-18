# WO6.0.0-015 — Deploy: helm picodome default install never starts the daemon (prints `--help` and exits)

**Series:** WO6.0.0 (exploration round 2026-08-18 evening)
**Status:** OPEN
**Owner:** (unassigned — worktree `wo/6.0.0/helm-default-install`)
**Priority:** P0 (bites the moment the WO5-014 docker-push runbook executes) · Effort S · Risk L
**Scope:** `deploy/helm/picodome/templates/deployment.yaml`, `tests/test_release.py`

**Gate:** `bash scripts/test.sh fast` + release test asserts the DEFAULT render (grpc disabled) carries daemon args (`daemon --host --port`) and the grpc variant adds `--transport=grpc`; both render a real container command.

## Objective
The chart's default path produces a pod that runs `picosentry --help` and exits — masked today only because the image push is still pending.

## Evidence (verified 2026-08-18, explorer SA-AT; airtight chain)
`deployment.yaml:75-82`: the `args:` block exists ONLY inside `{{- if .Values.grpc.enabled }}`; no `command:` override anywhere; `values.yaml` defaults `grpc.enabled: false` (its own comment: "the default installation serves only the HTTP daemon"); Dockerfile `ENTRYPOINT [tini,--,picosentry] CMD [--help]`. Repo history corroborates: commit `d4b44c18` fixed this exact failure in the raw k8s manifest ("pod would print help and exit") but only added the grpc-conditional args to helm. `test_helm_chart_renders_v_prefixed_image_tag` asserts tags only, never args.

## Deliverables
1. Emit daemon args unconditionally; append grpc args only when enabled.
2. Extend the release test per the gate (parse-based render assertion — no helm binary needed, existing pattern).
