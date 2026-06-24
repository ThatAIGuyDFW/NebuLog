"""Blacklist evaluator.

Fires for every event (within the last `window_seconds`) whose `field` value
appears in the named blacklist table entry.

Each match produces a separate AlertTrigger so the engine can correlate the
exact event to the alert.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import structlog

from correlation.rule_dsl import BlacklistBody
from .base import AlertTrigger, safe_col

log = structlog.get_logger()

# How far back to look when evaluating a blacklist rule (30 minutes).
_DEFAULT_WINDOW_SECONDS = 1800


class BlacklistEvaluator:
    """Evaluate blacklist-type correlation rules."""

    async def evaluate(
        self, rule_id: UUID, rule_name: str, severity: str,
        body: BlacklistBody, conn
    ) -> list[AlertTrigger]:
        col = safe_col(body.field)

        sql = f"""
            SELECT DISTINCT e.{col},
                   MIN(e.received_at) AS first_seen,
                   MAX(e.received_at) AS last_seen,
                   COUNT(*) AS cnt
            FROM events e
            JOIN blacklists b
              ON b.value = e.{col}::text
             AND b.list_name = $1
            WHERE e.received_at >= NOW() - '{_DEFAULT_WINDOW_SECONDS} seconds'::interval
              AND e.{col} IS NOT NULL
            GROUP BY e.{col}
        """

        rows = await conn.fetch(sql, body.list_name)
        results = []
        for row in rows:
            val = str(row[col]) if row[col] else "unknown"
            first = row["first_seen"]
            last = row["last_seen"]
            if first and first.tzinfo is None:
                first = first.replace(tzinfo=timezone.utc)
            if last and last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            now = datetime.now(tz=timezone.utc)
            results.append(AlertTrigger(
                rule_id=rule_id,
                severity=severity,
                title=f"{rule_name}: {val}",
                description=(
                    f"{col} value '{val}' matched blacklist '{body.list_name}'"
                ),
                src_ip=val if col == "src_ip" else None,
                source_host=val if col == "source_host" else None,
                first_seen=first or now,
                last_seen=last or now,
                event_count=row["cnt"],
                group_key=f"{rule_id}:{col}:{val}",
            ))
        return results
