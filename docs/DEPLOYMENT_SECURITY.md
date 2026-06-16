# Deployment Security Checklist

PicoSentry can run with several **dev-only** environment variables that disable
security gates. This checklist helps operators verify that a production
deployment does not accidentally enable them.

> **Goal:** every production pod should start with `PICODOME_ENTERPRISE_MODE=1`,
> valid mTLS credentials, strong API tokens, **and no dev-bypass variables**.

## Dev-bypass variables (must be unset in production)

| Variable | Severity | What it disables |
|----------|----------|------------------|
| `PICODOME_DEV_MODE` | **CRITICAL** | Daemon authentication |
| `PICODOME_TLS_DEV` | **HIGH** | TLS certificate validation (self-signed certs) |
| `PICODOME_SKIP_SECURE_ASSERT` | **HIGH** | Daemon secure-boot checks |
| `PICOSHOGUN_SKIP_SECURE_ASSERT` | **HIGH** | `picosentry serve` secure-boot checks |
| `PICOWATCH_SKIP_SECURE_ASSERT` | **HIGH** | `picosentry watch` secure-boot checks |

## Helm production install

The `deploy/helm/picodome` chart runs an init container that refuses to start
the pod when any bypass is detected. Enable it with the default
`security.blockDevBypasses: true`:

```bash
helm upgrade --install picodome ./deploy/helm/picodome \
  --namespace picodome \
  --create-namespace \
  --set auth.existingSecret=picodome-api-tokens \
  --set mtls.existingTLSSecret=picodome-tls
```

To intentionally allow a development Helm install, set:

```yaml
security:
  blockDevBypasses: false
```

**Never disable this in production.**

## Verify a running deployment

Run the shared checker against the pod environment:

```bash
kubectl exec -n picodome deploy/picodome -- \
  python3 -m picosentry._core.security_check --strict
```

Expected output on a clean deployment:

```text
✅ No deployment-security findings.
```

Inject a bypass to confirm the checker fails:

```bash
kubectl exec -n picodome deploy/picodome -- \
  python3 -m picosentry._core.security_check --strict \
    --env PICODOME_TLS_DEV=1
# ❌ FAIL — deployment-security check failed
```

## CI lint

Run the deployment manifest linter locally:

```bash
python3 tests/sandbox/check_deploy_security.py --strict
```

The linter scans:

- raw K8s manifests under `deploy/kubernetes/`
- Helm values/templates under `deploy/helm/picodome/`
- the Dockerfile
- source files for hardcoded secrets
- `.gitignore` for secret patterns

## Copy-paste verification commands

Check a host for bypass variables before deploying:

```bash
for var in PICODOME_DEV_MODE PICODOME_TLS_DEV PICODOME_SKIP_SECURE_ASSERT \
           PICOSHOGUN_SKIP_SECURE_ASSERT PICOWATCH_SKIP_SECURE_ASSERT; do
  if [ "${!var}" = "1" ]; then
    echo "🚨 $var=1 is set"
  fi
done
```

Run the Python checker with custom env values:

```bash
python3 -m picosentry._core.security_check \
  --env PICODOME_ENTERPRISE_MODE=1 \
  --env PICODOME_TLS_DEV=0 \
  --strict
```

## What to do if a bypass is detected

1. **Do not expose the deployment to untrusted traffic.**
2. Remove the bypass variable from the manifest, Helm values, or runtime env.
3. Re-run the checker until it returns `✅ No deployment-security findings.`
4. Rotate any tokens or keys that may have been used while the bypass was
   active.

## See also

- [`picosentry/_core/security_check.py`](../../picosentry/_core/security_check.py)
  — shared checker used by the Helm init container and CI lint
- [`tests/sandbox/check_deploy_security.py`](../../tests/sandbox/check_deploy_security.py)
  — manifest-level deployment security lint
- [`README.md`](../../README.md) — current maturity status and honest
  limitations
