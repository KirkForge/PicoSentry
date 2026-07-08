# PicoSentry `admission` Security Review

**Scope:** Kubernetes admission webhook (`picosentry/sandbox/admission/` and
`picosentry/sandbox/cli_commands/admission.py`).
**Date:** 2026-07-06
**Status:** Beta — fail-closed by default, live-tested against kind, but not
yet reviewed for Enterprise production deployment.

## Reviewed areas

| Area | Verdict | Notes |
|------|---------|-------|
| Fail-closed default | PASS | With no validator configured the handler returns `allowed=False`. |
| Daemon unreachable handling | PASS | Helm chart and docs guide operators to set `PICODOME_ADMISSION_FAIL_CLOSED=true` / `false` intentionally. |
| TLS support | PASS | `AdmissionWebhookServer` can load cert/key; logs a warning when started without TLS. |
| Path validation | PASS | Only `/validate` is accepted; all other paths return 404. |
| JSON parsing | PASS | Invalid JSON returns an `AdmissionReview` response with `allowed=False`. |
| Missing request field | PASS | Requests without `request` are denied with a structured response. |
| Validator contract | PASS | Operator-supplied validator returns `(allowed, reason)`; reason flows back to K8s. |
| Image scanner config | PASS | `tests/sandbox/test_admission_scanner.py` validates env-based scanner configuration. |
| Helm chart | PASS | `tests/sandbox/test_admission_helm.py` validates chart security context, env vars, and labels. |

## Honest limitations (Enterprise blockers unless accepted as risk)

- **No formal security review.** This review is based on code inspection and
  existing tests, not an external adversarial review.
- **Only synthetic live testing.** The real-cluster matrix in
  `.github/workflows/admission-kind.yml` exercises kind clusters (K8s
  v1.28–v1.30), not a production Kubernetes distribution.
- **No webhook replay / idempotency guarantees.** The handler is stateless; a
  validator that relies on external state may behave inconsistently on K8s
  retries.
- **TLS is optional at the code level.** The server warns but still starts if
  no cert/key is provided. K8s `ValidatingWebhookConfiguration` should enforce
  TLS at the cluster level, but a misconfigured deployment could expose the
  webhook without TLS.
- **No built-in validator policies.** The only validator shipped is the
  example/image-scanner integration; operators must supply their own policy
  validator or rely on the daemon validator URL.
- **Limited runbook coverage.** `docs/ops/runbook.md` only has an incident
  snippet for "all pods denied"; there is no full admission deployment,
  rotation, or rollback procedure.

## Regression tests

- `tests/sandbox/test_admission_webhook.py` — handler behavior, fail-closed,
  validator contract.
- `tests/sandbox/test_admission_validator.py` — validator logic.
- `tests/sandbox/test_admission_scanner.py` — image scanner configuration.
- `tests/sandbox/test_admission_helm.py` — Helm chart security checks.
- `.github/workflows/admission-kind.yml` — live kind-cluster matrix.

Run the focused suite:

```bash
uv run pytest tests/sandbox/test_admission_webhook.py \
  tests/sandbox/test_admission_validator.py \
  tests/sandbox/test_admission_scanner.py \
  tests/sandbox/test_admission_helm.py -q
```

## Graduation criteria to Stable

- Complete an adversarial review of the admission webhook surface.
- Validate against at least one production-grade Kubernetes distribution in CI
  (e.g. EKS, GKE, or on-prem kubeadm) in addition to kind.
- Make TLS mandatory at server startup in production mode, or document the
  K8s-level enforcement as a hard requirement.
- Provide one or more built-in validators (pod security baseline, namespace
  labels, resource limits) so operators can enable admission without writing
  custom code.
- Expand the ops runbook with admission deployment, certificate rotation, and
  rollback procedures.
