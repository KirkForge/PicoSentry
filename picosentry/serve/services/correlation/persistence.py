from __future__ import annotations

import logging
from hashlib import sha256

from picosentry.serve.services.correlation.helpers import (
    _confidence_from_str,
    _severity_from_str,
)
from picosentry.serve.services.correlation.models import CorrelatedEvent

logger = logging.getLogger("picosentry.correlation")


def _db():
    """Late-bound db singleton so tests can monkeypatch the manager."""
    from picosentry.serve.database.manager import db

    return db


def _dedup_key(event: CorrelatedEvent) -> str:
    return sha256(f"{event.artifact_id}|{event.layer}|{event.rule_id}|{event.timestamp}".encode()).hexdigest()[:16]


def _count_events(db_manager) -> int:
    row = db_manager.execute_one("SELECT COUNT(*) AS c FROM correlation_events")
    return row["c"] if row else 0


def _events_insert_sql() -> str:
    """Return backend-specific INSERT that ignores duplicate dedup_key."""
    db = _db()
    ph = db.dialect.placeholder()
    if db.backend == "postgres":
        return f"""
            INSERT INTO correlation_events
            (dedup_key, artifact_id, layer, rule_id, severity,
             confidence, target, title, detail, timestamp, run_id)
            VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
            ON CONFLICT (dedup_key) DO NOTHING
        """
    return f"""
        INSERT OR IGNORE INTO correlation_events
        (dedup_key, artifact_id, layer, rule_id, severity,
         confidence, target, title, detail, timestamp, run_id)
        VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
    """


def _persist_events_impl(engine) -> int:
    if not engine.PERSIST_ENABLED:
        return 0

    sql = _events_insert_sql()
    count = 0
    with engine._lock:
        for _artifact_id, events in list(engine._events.items()):
            for event in events:
                dedup_key = _dedup_key(event)

                try:
                    db = _db()
                    before = _count_events(db)
                    db.execute_insert(
                        sql,
                        (
                            dedup_key,
                            event.artifact_id,
                            event.layer,
                            event.rule_id,
                            event.severity.value,
                            event.confidence.value,
                            event.target,
                            event.title,
                            event.detail,
                            event.timestamp,
                            event.run_id,
                        ),
                    )
                    after = _count_events(db)
                    if after > before:
                        count += 1
                except Exception as e:
                    logger.debug("Persist skip for %s/%s: %s", event.artifact_id, event.rule_id, e)

    if count:
        logger.info("Persisted %d correlation event(s) to DB", count)
    return count


def _load_events_impl(engine) -> int:
    if not engine.PERSIST_ENABLED:
        return 0

    count = 0
    try:
        db = _db()
        rows = db.execute("""
            SELECT artifact_id, layer, rule_id, severity, confidence,
                   target, title, detail, timestamp, run_id
            FROM correlation_events
            ORDER BY timestamp ASC
        """)

        for row in rows:
            event = CorrelatedEvent(
                artifact_id=row["artifact_id"],
                layer=row["layer"],
                rule_id=row["rule_id"],
                severity=_severity_from_str(row["severity"]),
                confidence=_confidence_from_str(row["confidence"]),
                target=row["target"],
                title=row["title"],
                detail=row["detail"],
                timestamp=row["timestamp"],
                run_id=row["run_id"],
            )

            events = engine._events[event.artifact_id]
            events.append(event)
            count += 1

        engine._chains.clear()
        logger.info("Loaded %d correlation event(s) from DB", count)
    except Exception as e:
        logger.warning("Failed to load correlation events: %s", e)

    return count


def _persist_chains_cache_impl(engine) -> int:
    if not engine.PERSIST_ENABLED:
        return 0

    db = _db()
    ph = db.dialect.placeholder()
    count = 0
    with engine._lock:
        for artifact_id, chain in list(engine._chains.items()):
            event_count = sum(len(e) for e in chain.phases.values())
            phase_count = len(chain.phases)
            try:
                if db.backend == "postgres":
                    db.execute(
                        f"""
                        INSERT INTO correlation_chains
                        (artifact_id, chain_score, severity, confidence,
                         narrative, event_count, phase_count)
                        VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
                        ON CONFLICT (artifact_id) DO UPDATE SET
                            chain_score = EXCLUDED.chain_score,
                            severity = EXCLUDED.severity,
                            confidence = EXCLUDED.confidence,
                            narrative = EXCLUDED.narrative,
                            event_count = EXCLUDED.event_count,
                            phase_count = EXCLUDED.phase_count,
                            updated_at = CURRENT_TIMESTAMP
                    """,
                        (
                            artifact_id,
                            chain.chain_score,
                            chain.severity.value,
                            chain.confidence.value,
                            chain.narrative,
                            event_count,
                            phase_count,
                        ),
                    )
                else:
                    existing = db.execute_one(
                        "SELECT 1 FROM correlation_chains WHERE artifact_id = ?",
                        (artifact_id,),
                    )
                    if existing:
                        db.execute(
                            f"""
                            UPDATE correlation_chains
                            SET chain_score = {ph}, severity = {ph}, confidence = {ph},
                                narrative = {ph}, event_count = {ph}, phase_count = {ph},
                                updated_at = CURRENT_TIMESTAMP
                            WHERE artifact_id = {ph}
                        """,
                            (
                                chain.chain_score,
                                chain.severity.value,
                                chain.confidence.value,
                                chain.narrative,
                                event_count,
                                phase_count,
                                artifact_id,
                            ),
                        )
                    else:
                        db.execute_insert(
                            f"""
                            INSERT INTO correlation_chains
                            (artifact_id, chain_score, severity, confidence,
                             narrative, event_count, phase_count)
                            VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph}, {ph})
                        """,
                            (
                                artifact_id,
                                chain.chain_score,
                                chain.severity.value,
                                chain.confidence.value,
                                chain.narrative,
                                event_count,
                                phase_count,
                            ),
                        )
                count += 1
            except Exception as e:
                logger.debug("Chain persist skip for %s: %s", artifact_id, e)

    if count:
        logger.info("Persisted %d chain(s) to DB", count)
    return count


__all__ = [
    "_dedup_key",
    "_load_events_impl",
    "_persist_chains_cache_impl",
    "_persist_events_impl",
]
