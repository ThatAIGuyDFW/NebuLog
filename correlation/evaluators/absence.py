"""Absence evaluator.

Fires when there are ZERO events matching the filter within `window_seconds`.
Useful for heartbeat / expected-event monitoring (e.g., no backup job log
for 24 hours).
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import structlog

from correlation.rule_dsl import AbsenceBody
from .base import AlertTrigger, QueryBuilder, build_event_filter

log = structlog.get_logger()


class AbsenceEvaluator:
    """Evaluate absence-type correlation rules."""

    async def evaluate(
        self, rule_id: UUID, rule_name: str, severity: str,
        body: AbsenceBody, conn
    ) -> list[AlertTrigger]:
        qb = QueryBuilder()
        build_event_filter(qb, body.filters, window_seconds=body.window_seconds)

        sql = f"SELECT COUNT(*) AS cnt FROM events WHERE {qb.where}"
        row = await conn.fetchrow(sql, *qb.params)

        if not row or row["cnt"] > 0:
            return []

        now = datetime.now(tz=timezone.utc)
        return [AlertTrigger(
            rule_id=rule_id,
            severity=severity,
            title=rule_name,
            description=(
                f"No matching events in the last {body.window_seconds}s"
            ),
            src_ip=None,
            source_host=None,
            first_seen=now,
            last_seen=now,
            event_count=0,
            group_key=f"{rule_id}:absent",
        )]
