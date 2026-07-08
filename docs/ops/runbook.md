# PicoSentry Operations Runbook

Quick reference for operators running PicoSentry in production or CI.

## Local CI-quality validation

Run the same checks CI runs, concurrently:

```bash
python scripts/test_doctor.py --workers 4
```

Run only a subset of areas:

```bash
python scripts/test_doctor.py --workers 4 --areas ruff mypy pytest-watch pytest-scan
```

Run with the local venv Python if your system Python is missing dependencies:

```bash
.venv/bin/python scripts/test_doctor.py --workers 4
```

## Database backend

`picosentry serve` can use SQLite (default, single-node) or PostgreSQL
(production). The backend is selected at startup with environment variables:

```bash
# SQLite (default)
export PICOSHOGUN_DATABASE_BACKEND=sqlite
export PICOSHOGUN_DATABASE_PATH=/var/lib/picoshogun/picoshogun.db

# PostgreSQL
export PICOSHOGUN_DATABASE_BACKEND=postgres
export PICOSHOGUN_DATABASE_URL=postgresql://user:pass@host:5432/picoshogun
```

### Switching from SQLite to Postgres

1. Start a Postgres 15+ instance and create the database.
2. Set `PICOSHOGUN_DATABASE_BACKEND=postgres` and `PICOSHOGUN_DATABASE_URL`.
3. Start `picosentry serve`. Migrations run automatically via
   `picosentry.serve.database.manager`.
4. Validate the schema:
   ```bash
   psql $PICOSHOGUN_DATABASE_URL -c "\dt"
   ```

### Backup

- **SQLite** (single-node default): create a backup via the admin API
  (requires an admin token) or use the Python helper directly while the
  service is stopped:
  ```bash
  # via API
  curl -s -X POST "https://picoshogun.example.com/backup" \
    -H "Authorization: Bearer $ADMIN_TOKEN" \
    -H "Content-Type: application/json"

  # via Python helper, service stopped
  python3 -c "
from pathlib import Path
from shutil import copy2
copy2('/var/lib/picoshogun/picoshogun.db',
      '/backups/picoshogun-$(date +%F).db')
"
  ```
- **PostgreSQL** (production): use standard Postgres tooling:
  ```bash
  pg_dump $PICOSHOGUN_DATABASE_URL > /backups/picoshogun-$(date +%F).sql
  ```

### Restore

- **SQLite**: stop the server, replace the database file, then restart.
  If a `.tar.gz` backup was created by the admin API, extract it first and
  copy `database.sqlite3` into place.
- **PostgreSQL**: restore the dump into a fresh Postgres database and point
  `PICOSHOGUN_DATABASE_URL` at it.

### Upgrade

Application migrations run automatically on startup. For major version
upgrades, back up first, then restart the service and verify with:

```bash
picosentry health
python scripts/test_doctor.py --areas pytest-serve
```

## Stale corpus

### Detect

```bash
picosentry scan check --check-corpus-age 30
```

Exit codes:

- `0` — corpus is fresh.
- `5` — corpus is older than the threshold (or missing).
- other — runtime error.

In CI, use the exit code to block a release when the bundled corpus is too
old:

```yaml
- run: picosentry scan check --check-corpus-age 30
```

### Remediate

1. Update the corpus source files under `picosentry/scan/corpus/`.
2. Regenerate `corpus.json` and any ecosystem-specific top-package lists.
3. Re-run the check.
4. If the corpus is distributed as signed packs, re-sign with minisign or
   Sigstore and verify the signature before deploying.

## Plugin sandbox incident

### Symptoms

- Plugin worker logs show `Plugin worker for '<name>' did not respond within`.
- Host CPU spikes from orphaned plugin processes.
- Unexpected env vars or filesystem writes from a plugin.

### Response

1. Check the plugin manifest capabilities:
   ```bash
   cat plugins/<name>/plugin.json
   ```
2. Inspect the worker stderr:
   ```bash
   picosentry serve plugin logs --name <name>
   ```
3. Validate the signature against the trusted-public-key allowlist.
4. If the plugin is untrusted or misbehaving:
   - Remove it from the plugin directory.
   - Restart the host process so the finalizer reaps the worker.
5. Review the `PICOSHOGUN_PLUGIN_CAPABILITIES` env var in worker logs to confirm
   the capability grant matches the manifest.

## Watch prompt-guard incident

### False negative (prompt bypassed the guard)

1. Reproduce with the watch CLI:
   ```bash
   echo "suspicious prompt" | picosentry watch scan --rules rules/
   ```
2. Check the normalized input and matched rules in the output.
3. If the bypass is due to encoding (base64, ROT13, homoglyphs), add a rule
   with the appropriate `normalization` list.
4. If the bypass is novel, file a rule-corpus issue with the payload and the
   expected verdict.

### False positive (benign prompt blocked)

1. Run with `--verbose` to see which rule matched.
2. Lower the rule weight or tighten the regex so it does not match benign
   patterns.
3. Add a negative test case in `tests/watch/`.

### Fail-closed mode

To make the guard block when rules cannot load or evaluation crashes:

```bash
export PICOSENTRY_WATCH_FAIL_CLOSED=true
```

Use this in high-assurance deployments. The default remains fail-open to avoid
breaking existing integrations.

## Admission webhook incident

### Symptom: all pods denied

Possible causes:

- No validator configured.
- `PICODOME_ADMISSION_DAEMON_URL` is unreachable and fail-closed is on.
- TLS cert/key mismatch or expired.

### Response

1. Check daemon health:
   ```bash
   curl https://<daemon>:8443/health
   ```
2. If the daemon is expected to be down and you must admit pods, set:
   ```bash
   export PICODOME_ADMISSION_FAIL_CLOSED=false
   ```
   This is a temporary safety valve, not a steady-state configuration.
3. Verify the webhook URL with the SSRF guard:
   ```python
   from picosentry.scan._network import assert_url_safe
   assert_url_safe("http://<daemon>:8443")
   ```

### Admission deployment and certificate rotation

1. Generate or rotate the webhook TLS secret. The simplest path with
   cert-manager is in the Helm chart (`deploy/helm/picodome-admission/values.yaml`):
   ```yaml
   tls:
     certManager:
       enabled: true
       issuerRef:
         name: picodome-admission-issuer
         kind: ClusterIssuer
   ```
2. Ensure `ValidatingWebhookConfiguration.caBundle` references the same CA. The
   Helm template populates it from the cert-manager secret when
   `certRotation.rollingUpdateOnRenew: true`.
3. Rollout restart after manual cert changes when not using cert-manager:
   ```bash
   kubectl rollout restart deployment picodome-admission -n <namespace>
   ```
4. Validate the webhook responds:
   ```bash
   kubectl run test-pod --image=busybox --restart=Never --rm -i -- echo ok
   ```
5. Rollback: redeploy the previous chart revision or set
   `webhook.failurePolicy: Ignore` temporarily while you diagnose.

## Sandbox daemon operations

### Deployment

Start the daemon with mTLS in production:

```bash
export PICODOME_DAEMON_HOST=0.0.0.0
export PICODOME_DAEMON_PORT=8443
export PICODOME_API_TOKENS="$(openssl rand -hex 32)"
export PICODOME_ENTERPRISE_MODE=1
export PICODOME_TLS_CERT=/certs/tls.crt
export PICODOME_TLS_KEY=/certs/tls.key
export PICODOME_TLS_CA=/certs/ca.crt
export PICODOME_STORE_BACKEND=jsonl
export PICODOME_JOB_STORE_DIR=/var/lib/picodome

picosentry sandbox daemon --host=0.0.0.0 --port=8443
```

For gRPC transport:

```bash
picosentry sandbox daemon --host=0.0.0.0 --port=8443 --transport=grpc --grpc-port=50051
```

### mTLS certificate rotation

The daemon reloads its TLS context on `SIGHUP` without dropping connections:

```bash
kill -HUP <pid>
```

For a rolling rotation in Kubernetes:

1. Update the `picodome-tls` Secret with the new cert/key/CA.
2. Restart pods one at a time (`kubectl rollout restart deployment picodome`).
3. Verify `/health` and `/ready` on each restarted pod.

### Job store backup and restore

**JSONL (default):**

```bash
# Backup
systemctl stop picodome
tar czf /backups/picodome-jsonl-$(date +%F).tar.gz /var/lib/picodome
systemctl start picodome

# Restore
systemctl stop picodome
rm -rf /var/lib/picodome/*
tar xzf /backups/picodome-jsonl-<date>.tar.gz -C /
systemctl start picodome
```

**SQLite:**

```bash
# Backup while running (WAL-safe)
sqlite3 /var/lib/picodome/picodome.db ".backup /backups/picodome-$(date +%F).db"

# Restore
systemctl stop picodome
cp /backups/picodome-<date>.db /var/lib/picodome/picodome.db
systemctl start picodome
```

### Audit sink incident

If an audit sink (file/syslog/webhook) is failing:

1. Check the configured sinks:
   ```bash
   echo $PICODOME_AUDIT_SINKS   # e.g. null,file,webhook
   ```
2. Inspect the daemon log for `Failed to initialize sink` or `Failed to start sink`.
3. For webhook failures, verify `PICODOME_WEBHOOK_URL` and `PICODOME_WEBHOOK_TOKEN`.
4. To fail closed when sinks cannot start, stop the daemon and do not restart until
   the sink is healthy. A fail-closed audit mode is not yet implemented; see
   `docs/SECURITY_REVIEW_DAEMON.md`.

### Metrics endpoint

If `metrics.separatePort` is enabled, `/metrics` is served on a separate port
without auth. Network-segment it so only Prometheus (or your scraper) can reach it.
Use the Helm `networkPolicy.ingress.from` list to restrict sources.

## Cluster mode operations

### Bootstrap a cluster

1. Start the first daemon with a cluster token:
   ```bash
   export PICODOME_CLUSTER_TOKEN="$(openssl rand -hex 32)"
   export PICODOME_CLUSTER_ADDRESS=0.0.0.0
   export PICODOME_CLUSTER_PORT=8444
   export PICODOME_CLUSTER_BACKEND=memory
   picosentry sandbox daemon --host=0.0.0.0 --port=8443
   ```
2. Join additional nodes:
   ```bash
   picodome cluster join <seed-node>:8444 \
     --cluster-token "$PICODOME_CLUSTER_TOKEN" \
     --node-id node-2
   ```
3. Check status:
   ```bash
   picodome cluster status
   ```

### Adding and removing nodes

- To add: run `picodome cluster join` on the new node pointing at any existing peer.
- To remove gracefully: run `picodome cluster leave` on the node. The leader
  redistributes pending scans to remaining members.

### Token rotation

Cluster mode now supports graceful token rotation without a maintenance window.
Each node maintains a primary token and an accepted-token set. New tokens are
propagated through gossip snapshots; old tokens remain accepted until retired.

1. Rotate the token on any node:
   ```bash
   picodome cluster rotate-token
   ```
   Or provide a specific value:
   ```bash
   picodome cluster rotate-token --new-token $(openssl rand -hex 32)
   ```
2. Wait for gossip to propagate the new token to all peers. Verify with:
   ```bash
   picodome cluster status
   ```
3. Retire old tokens once all peers have acknowledged the new one (default
   grace window is 300 seconds):
   ```bash
   picodome cluster rotate-token --retire-after 0
   ```

If you must use the legacy single-token mode, all nodes still share
`PICODOME_CLUSTER_TOKEN`, but a rolling restart with mismatched tokens will
break gossip until every node is updated.

For stronger identity, use mTLS gossip instead:

```bash
export PICODOME_CLUSTER_TLS_CERT=/certs/cluster.crt
export PICODOME_CLUSTER_TLS_KEY=/certs/cluster.key
export PICODOME_CLUSTER_TLS_CA=/certs/cluster-ca.crt
picodome cluster join <seed-node>:8444 --tls-cert ... --tls-key ... --tls-ca ...
```

### Split-brain / disaster recovery

1. Stop all cluster nodes.
2. Pick the node with the most recent state (check the SQLite backend or the
   newest JSONL file modification time).
3. Restart that node alone; it will auto-elect as leader.
4. Rejoin the remaining nodes one at a time and verify `picodome cluster status`.
5. If state diverged, accept that scans assigned during the partition may need
   manual reconciliation (the merge is optimistic).

## Rate-limiter overload

### Symptom: legitimate clients are rejected

1. Inspect `active_clients` and `max_requests` metrics.
2. If a flood of distinct source IPs is filling the client table, raise
   `max_clients` or deploy the DDoS shield middleware in front of `serve`.
3. If a single client is burst-ing, shorten `window_seconds` or lower
   `max_requests`.

### Distributed (Redis) rate-limit backend

For multi-replica deployments, enable the shared Redis backend so all pods
enforce the same IP and org API-key windows:

```bash
export PICOSHOGUN_RATE_LIMIT_BACKEND=redis
export PICOSHOGUN_REDIS_URL=redis://redis.example.com:6379/0
```

Behaviour:

- `memory` (default): per-process in-memory counters; fastest but not shared
  across replicas.
- `sqlite`: per-node persistence across restarts (legacy; still per-node).
- `redis`: shared counters across all `serve` replicas using Redis sorted sets.

When Redis becomes unreachable, the middleware falls back to in-memory counters
for that request and logs a warning. The fallback preserves availability but
loses cross-replica consistency until Redis recovers.

To verify the backend at runtime, send an authenticated request and check the
logs for `Rate limit Redis backend connected` or `Redis rate-limit backend
connection failed`.

## GitNexus index drift

If the MCP tools report a stale index or fail with `LadybugDB unavailable`
/ `Resource temporarily unavailable`:

1. Kill orphaned GitNexus / LadybugDB locks:
   ```bash
   scripts/gitnexus-kill-orphans.sh
   ```
2. Rebuild the index inside the pinned Docker container (the host Node/libssl
   combination cannot reliably write the native `lbug` database on this
   machine):
   ```bash
   scripts/gitnexus-analyze.sh
   ```
3. Restart or reconnect your editor's GitNexus MCP client so it opens the
   freshly built `lbug` database without a stale file handle.

If you need a stable MCP server entry point (for example, when an editor lets
you configure a custom server command), use:

```bash
scripts/gitnexus-mcp-server.sh
```

## Emergency contacts and rollback

- Roll back to the previous image: `docker run kirkforge/picodome:<previous-tag>`
- Reinstall the previous PyPI version:
  ```bash
  pip install 'picosentry<2.0.18'
  ```
- Verify a rollback with `picosentry health` and `python scripts/test_doctor.py`.
