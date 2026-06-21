#!/usr/bin/env bash
# =============================================================================
# PicoSentry — PostgreSQL live integration test
# =============================================================================
# Spins up a temporary Postgres container, runs all serve migrations through
# the DatabaseManager Postgres backend, and exercises basic CRUD to verify the
# SQLite-to-Postgres translation and runtime placeholder handling work against
# a real database.
#
# Usage:
#   ./scripts/live_test_postgres.sh
#
# Requires:
#   - Docker with permission to run containers
#   - psycopg2-binary installed in the active Python environment
#   - pyproject.toml version matches the wheel the Dockerfile builds (optional)
# =============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

cd "${REPO_ROOT}"

PYTHON="${PYTHON:-.venv/bin/python}"
if [[ ! -x "$PYTHON" ]]; then
    echo "ERROR: Python interpreter not found at ${PYTHON}" >&2
    exit 1
fi

if ! "$PYTHON" -c "import psycopg2" 2>/dev/null; then
    echo "ERROR: psycopg2 is not installed. Install with:" >&2
    echo "  /usr/bin/pip3 install --prefix=${REPO_ROOT}/.venv psycopg2-binary" >&2
    exit 1
fi

if ! docker version >/dev/null 2>&1; then
    echo "ERROR: Docker is not available." >&2
    exit 1
fi

CONTAINER_NAME="picosentry-postgres-live-test"
VOLUME_NAME="picosentry-postgres-live-test-data"
POSTGRES_USER="picoshogun"
POSTGRES_PASSWORD="picoshogun-test"
POSTGRES_DB="picoshogun"
POSTGRES_PORT="15432"
DATABASE_URL="postgresql://${POSTGRES_USER}:${POSTGRES_PASSWORD}@127.0.0.1:${POSTGRES_PORT}/${POSTGRES_DB}"

cleanup() {
    echo "Cleaning up Postgres container..."
    docker rm -f "${CONTAINER_NAME}" >/dev/null 2>&1 || true
    docker volume rm "${VOLUME_NAME}" >/dev/null 2>&1 || true
}
trap cleanup EXIT

echo "Creating Postgres data volume..."
docker volume create "${VOLUME_NAME}" >/dev/null

echo "Starting Postgres container..."
docker run -d --rm \
    --name "${CONTAINER_NAME}" \
    -e POSTGRES_USER="${POSTGRES_USER}" \
    -e POSTGRES_PASSWORD="${POSTGRES_PASSWORD}" \
    -e POSTGRES_DB="${POSTGRES_DB}" \
    -p "127.0.0.1:${POSTGRES_PORT}:5432" \
    -v "${VOLUME_NAME}:/var/lib/postgresql/data" \
    postgres:16-alpine \
    -c log_min_messages=warning \
    >/dev/null

echo -n "Waiting for Postgres to accept connections"
for i in $(seq 1 60); do
    if "$PYTHON" -c "
import psycopg2
try:
    psycopg2.connect('${DATABASE_URL}').close()
    raise SystemExit(0)
except psycopg2.OperationalError:
    raise SystemExit(1)
" 2>/dev/null; then
        echo " OK"
        break
    fi
    echo -n "."
    sleep 1
done

# Verify the container is still running
docker ps --filter "name=${CONTAINER_NAME}" --format '{{.Names}}' | grep -q "${CONTAINER_NAME}" || {
    echo ""
    echo "ERROR: Postgres container is not running." >&2
    exit 1
}

export PICOSHOGUN_DATABASE_BACKEND=postgres
export PICOSHOGUN_DATABASE_URL="${DATABASE_URL}"

echo "Running migrations and CRUD sanity checks..."
"$PYTHON" - <<'PY'
from picosentry.serve.database.manager import db
from picosentry.serve.config.settings import settings

print(f"backend: {settings.database.backend}")
print(f"url:     {settings.database.url}")
print(f"connected: backend={db.backend}, dialect placeholders={db.dialect.placeholder}")

# Migrations ran during __init__; verify a few tenant-isolation tables exist.
for table in ("intelligence", "alerts", "metrics", "webhooks", "scheduled_jobs", "project_runs"):
    rows = db.execute(
        "SELECT COUNT(*) as n FROM information_schema.tables WHERE table_name = %s",
        (table,),
    )
    assert rows[0]["n"] == 1, f"table {table} missing"
    print(f"  table {table}: present")

# Basic insert + select round-trip for alerts.
db.execute_insert(
    "INSERT INTO alerts (severity, message, org_id) VALUES (?, ?, ?)",
    ("info", "Postgres live test alert", 1),
)
row = db.execute_one(
    "SELECT severity, message, org_id FROM alerts WHERE message = ? ORDER BY id DESC",
    ("Postgres live test alert",),
)
assert row is not None
assert row["severity"] == "info"
assert row["org_id"] == 1
print("  CRUD round-trip: OK")

# Verify placeholder translation for list parameters works.
rows = db.execute(
    "SELECT id FROM alerts WHERE severity IN (?, ?) AND message = ?",
    ("info", "warning", "Postgres live test alert"),
)
assert len(rows) >= 1
print(f"  placeholder IN clause: OK ({len(rows)} row(s))")

# Clean up test row.
db.execute("DELETE FROM alerts WHERE message = ?", ("Postgres live test alert",))
print("Postgres live integration test: PASSED")
PY
