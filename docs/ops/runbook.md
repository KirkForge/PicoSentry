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

## Rate-limiter overload

### Symptom: legitimate clients are rejected

1. Inspect `active_clients` and `max_requests` metrics.
2. If a flood of distinct source IPs is filling the client table, raise
   `max_clients` or deploy the DDoS shield middleware in front of `serve`.
3. If a single client is burst-ing, shorten `window_seconds` or lower
   `max_requests`.

## GitNexus index drift

If the MCP tools report a stale index:

```bash
node .gitnexus/run.cjs analyze
# or, after index corruption:
node .gitnexus/run.cjs analyze --force
```

If the analyze step fails with missing FTS indexes, reinstall the global
package and retry:

```bash
npm i -g gitnexus
node .gitnexus/run.cjs analyze --force
```

## Emergency contacts and rollback

- Roll back to the previous image: `docker run kirkforge/picodome:<previous-tag>`
- Reinstall the previous PyPI version:
  ```bash
  pip install 'picosentry<2.0.17'
  ```
- Verify a rollback with `picosentry health` and `python scripts/test_doctor.py`.
