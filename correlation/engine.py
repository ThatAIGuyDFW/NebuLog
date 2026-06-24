"""Correlation engine.

Loads active alert rules from PostgreSQL every tick and runs the appropriate
evaluator.  Uses APScheduler AsyncIOScheduler with two cadences:

  - real_time  (every 30 s) — threshold, blacklist, sequence
  - aggregate  (every 5 min) — absence, anomaly

Deduplication: for each AlertTrigger, if an open alert already exists with the
same (rule_id, group_key) it is updated (event_count, last_seen, description)
rather than creating a duplicate.
"""

from __future__ import annotations

import asyncio
import json
from datetime import datetime, timezone
from uuid import UUID

import asyncpg
import structlog
from apscheduler.schedulers.asyncio import AsyncIOScheduler

from correlation.rule_dsl import parse_rule_body
from correlation.evaluators.threshold import ThresholdEvaluator
from correlation.evaluators.sequence import SequenceEvaluator
from correlation.evaluators.absence import AbsenceEvaluator
from correlation.evaluators.blacklist import BlacklistEvaluator
from correlation.evaluators.anomaly import AnomalyEvaluator
from correlation.evaluators.base import AlertTrigger

log = structlog.get_logger()

_REAL_TIME_TYPES = {"threshold", "blacklist", "sequence"}
_AGGREGATE_TYPES = {"absence", "anomaly"}

_EVALUATORS = {
    "threshold": ThresholdEvaluator(),
    "sequence": SequenceEvaluator(),
    "absence": AbsenceEvaluator(),
    "blacklist": BlacklistEvaluator(),
    "anomaly": AnomalyEvaluator(),
}


class CorrelationEngine:
    """APScheduler-backed correlation engine."""

    def __init__(self, dsn: str) -> None:
        self._dsn = dsn
        self._pool: asyncpg.Pool | None = None
        self._scheduler = AsyncIOScheduler()

    async def start(self) -> None:
        self._pool = await asyncpg.create_pool(self._dsn, min_size=2, max_size=5)
        self._scheduler.add_job(
            self._run_real_time,
            "interval",
            seconds=30,
            id="real_time",
            max_instances=1,
        )
        self._scheduler.add_job(
            self._run_aggregate,
            "interval",
            seconds=300,
            id="aggregate",
            max_instances=1,
        )
        self._scheduler.start()
        log.info("correlation_engine_started")

    async def stop(self) -> None:
        self._scheduler.shutdown(wait=False)
        if self._pool:
            await self._pool.close()
        log.info("correlation_engine_stopped")

    # ------------------------------------------------------------------
    # Tick handlers
    # ------------------------------------------------------------------

    async def _run_real_time(self) -> None:
        await self._evaluate_rules(_REAL_TIME_TYPES)

    async def _run_aggregate(self) -> None:
        await self._evaluate_rules(_AGGREGATE_TYPES)

    async def _evaluate_rules(self, rule_types: set[str]) -> None:
        assert self._pool is not None
        async with self._pool.acquire() as conn:
            rules = await conn.fetch(
                """
                SELECT id, name, rule_type, severity, body
                FROM alert_rules
                WHERE enabled = TRUE
                  AND rule_type = ANY($1)
                """,
                list(rule_types),
            )
            for rule in rules:
                await self._evaluate_one(conn, rule)

    async def _evaluate_one(self, conn, rule) -> None:
        rule_id: UUID = rule["id"]
        rule_type: str = rule["rule_type"]
        evaluator = _EVALUATORS.get(rule_type)
        if evaluator is None:
            return

        try:
            raw_body = rule["body"]
            if isinstance(raw_body, str):
                raw_body = json.loads(raw_body)
            body = parse_rule_body(rule_type, raw_body)
        except Exception as exc:
            log.warning("rule_body_invalid", rule_id=str(rule_id), exc=str(exc))
            return

        try:
            triggers: list[AlertTrigger] = await evaluator.evaluate(
                rule_id=rule_id,
                rule_name=rule["name"],
                severity=rule["severity"],
                body=body,
                conn=conn,
            )
        except Exception as exc:
            log.error("evaluator_error", rule_id=str(rule_id), rule_type=rule_type, exc=str(exc))
            return

        for trigger in triggers:
            try:
                await self._upsert_alert(conn, trigger)
            except Exception as exc:
                log.error("alert_upsert_error", rule_id=str(rule_id), exc=str(exc))

    # ------------------------------------------------------------------
    # Alert deduplication
    # ------------------------------------------------------------------

    async def _upsert_alert(self, conn, t: AlertTrigger) -> None:
        """Create a new alert or update an existing open one (same rule+group)."""
        existing = await conn.fetchrow(
            """
            SELECT id FROM alerts
            WHERE rule_id = $1
              AND status = 'open'
              AND ($2::text IS NULL OR group_key = $2)
            ORDER BY created_at DESC
            LIMIT 1
            """,
            t.rule_id,
            t.group_key,
        )

        if existing:
            await conn.execute(
                """
                UPDATE alerts
                SET event_count = event_count + $1,
                    last_seen   = $2,
                    description = $3,
                    updated_at  = NOW()
                WHERE id = $4
                """,
                t.event_count,
                t.last_seen,
                t.description,
                existing["id"],
            )
            log.debug("alert_updated", alert_id=str(existing["id"]), rule_id=str(t.rule_id))
        else:
            await conn.execute(
                """
                INSERT INTO alerts
                  (rule_id, severity, title, description,
                   src_ip, source_host, first_seen, last_seen,
                   event_count, group_key, status, created_at, updated_at)
                VALUES
                  ($1, $2, $3, $4,
                   $5, $6, $7, $8,
                   $9, $10, 'open', NOW(), NOW())
                """,
                t.rule_id, t.severity, t.title, t.description,
                t.src_ip, t.source_host, t.first_seen, t.last_seen,
                t.event_count, t.group_key,
            )
            log.info("alert_created", rule_id=str(t.rule_id), title=t.title)
