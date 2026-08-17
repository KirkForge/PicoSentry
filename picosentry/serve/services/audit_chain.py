"""Audit log hash chain — the DB is the single source of truth.

The chain used to live in a module-global in the audit middleware, which
forked under multi-worker deployments (each worker seeded its own chain).
Linking now happens inside a BEGIN IMMEDIATE write transaction: the writer
reads the last committed row_hash and inserts in one atomic step, so any
number of processes append to one linear chain.
"""

import hashlib
import json
import logging
import sqlite3
import threading
from typing import Any, cast

from picosentry.serve.database.manager import DatabaseManager, db

try:
    import psycopg2
except ImportError:
    psycopg2 = cast("Any", None)

logger = logging.getLogger("picoshogun.AuditChain")

_CHAIN_ERRORS: tuple[type[BaseException], ...] = (
    OSError,
    RuntimeError,
    ValueError,
    TypeError,
    sqlite3.Error,
)
if psycopg2 is not None:
    _CHAIN_ERRORS = (*_CHAIN_ERRORS, psycopg2.Error)

# Postgres has no BEGIN IMMEDIATE; a transaction-scoped advisory lock keeps
# concurrent workers from reading the same prev_hash and forking the chain.
_PG_CHAIN_LOCK_KEY = 73021

_append_lock = threading.Lock()


def compute_row_hash(
    prev_hash: str, action: str, user_id: int | str | None, resource_id: str, details_json: str, ip_address: str | None
) -> str:
    canonical = "|".join([prev_hash, action, str(user_id), resource_id, details_json, ip_address or ""])
    return hashlib.sha256(canonical.encode()).hexdigest()


def append_audit_row(
    *,
    action: str,
    user_id: int | None,
    resource_type: str,
    resource_id: str,
    details: dict[str, Any] | str,
    ip_address: str | None = None,
    user_agent: str | None = None,
    severity: str = "default",
    org_id: int | None = None,
    database: DatabaseManager | None = None,
) -> bool:
    """Append one row, linked to the last committed row_hash in one transaction."""
    mgr = database or db
    details_json = details if isinstance(details, str) else json.dumps(details, sort_keys=True)
    stored_user_id = user_id if user_id is not None else -1
    try:
        with _append_lock, mgr.transaction(immediate=True) as conn:
            if mgr.backend == "postgres":
                mgr.execute_on(conn, "SELECT pg_advisory_xact_lock(?)", (_PG_CHAIN_LOCK_KEY,))
            rows = mgr.execute_on(conn, "SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1")
            prev_hash = rows[0]["row_hash"] if rows and rows[0].get("row_hash") else ""
            row_hash = compute_row_hash(prev_hash, action, stored_user_id, resource_id, details_json, ip_address)
            mgr.execute_on(
                conn,
                """
                    INSERT INTO audit_log (action, user_id, resource_type,
                        resource_id, details, ip_address, user_agent,
                        prev_hash, row_hash, org_id, severity)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    action,
                    stored_user_id,
                    resource_type,
                    resource_id,
                    details_json,
                    ip_address,
                    user_agent,
                    prev_hash,
                    row_hash,
                    org_id,
                    severity,
                ),
            )
        return True
    except _CHAIN_ERRORS:
        logger.exception("Audit chain append failed")
        return False


def _gap_explains(purged: set[int], prev_id, row_id: int) -> bool:
    """True when a recorded purge covers every id between the surviving rows."""
    if prev_id is None:
        # Nothing survives before this row: explained only if a purge removed
        # the entire id prefix 1..row_id-1.
        return row_id > 1 and bool(purged) and all(i in purged for i in range(1, row_id))
    if row_id == prev_id + 1:
        return False  # adjacent surviving predecessor: any mismatch is real
    return all(i in purged for i in range(prev_id + 1, row_id))


def verify_audit_chain(
    org_id: int | None = None, limit: int | None = None, database: DatabaseManager | None = None
) -> dict[str, Any]:
    """Walk audit_log rows in id order and recompute the chain.

    Mirrors the sandbox audit verifier semantics: report the first break.
    Checks per row: (a) row_hash matches a recomputation from the stored
    fields, (b) prev_hash matches the row_hash of the immediately preceding
    row in the table (a fork or off-chain insert breaks this) — except where
    a purge gap marker (``audit.purge`` row, WO4.0.0-004) covers every id
    between the two surviving rows: retention deletions are authorized gaps,
    not tampering.  Rows with empty prev_hash/row_hash predate the chain
    (migration 11) and reset the expected link, matching the legacy seeding
    behaviour.
    """
    mgr = database or db
    where = ""
    params: list[Any] = []
    if org_id is not None:
        where = "WHERE a.org_id = ?"
        params.append(org_id)
    limit_clause = ""
    if limit is not None:
        limit_clause = "ORDER BY a.id DESC LIMIT ?"
        params.append(limit)

    try:
        rows = mgr.execute(
            f"""
            SELECT a.*, p.id AS prev_id, p.row_hash AS prev_row_hash
            FROM audit_log a
            LEFT JOIN audit_log p ON p.id = (
                SELECT MAX(x.id) FROM audit_log x WHERE x.id < a.id
            )
            {where} {limit_clause}
        """,
            tuple(params),
        )
    except _CHAIN_ERRORS:
        logger.exception("Audit chain verify failed to read audit_log")
        return {"valid": False, "rows_checked": 0, "violation": "audit_log unreadable", "row_id": None}

    if limit is not None:
        rows = list(reversed(rows))

    from picosentry.serve.services.audit_cleanup import load_purged_ids

    # The chain is global; gap markers from every org's purge explain missing
    # predecessors even when verifying a single org's slice.
    purged = load_purged_ids(mgr)

    for row in rows:
        stored_prev = row["prev_hash"] or ""
        stored_hash = row["row_hash"] or ""
        if stored_prev == "" and stored_hash == "":
            continue
        predecessor = row["prev_row_hash"] or ""
        if stored_prev != predecessor:
            if _gap_explains(purged, row["prev_id"], row["id"]):
                continue
            return {
                "valid": False,
                "rows_checked": len(rows),
                "violation": f"row {row['id']}: prev_hash does not match predecessor (fork or deleted link)",
                "row_id": row["id"],
            }
        recomputed = compute_row_hash(
            stored_prev, row["action"], row["user_id"], row["resource_id"], row["details"], row["ip_address"]
        )
        if recomputed != stored_hash:
            return {
                "valid": False,
                "rows_checked": len(rows),
                "violation": f"row {row['id']}: row_hash does not match stored fields (tampered)",
                "row_id": row["id"],
            }

    return {"valid": True, "rows_checked": len(rows), "violation": None, "row_id": None}
