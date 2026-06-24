"""Threshold evaluator.

Fires when N events matching the filter arrive from the same `group_by`
value within `window_seconds`.

Supports:
  - Simple count threshold (count >= N)
  - distinct_users mode (N distinct user_name values)
  - aggregate mode (e.g., sum of extra.sentbyte > 500MB)
  - outside_hours restriction
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from uuid import UUID

import structlog

from correlation.rule_dsl import ThresholdBody
from .base import AlertTrigger, QueryBuilder, build_event_filter, safe_col

log = structlog.get_logger()


class ThresholdEvaluator:
    """Evaluate threshold-type correlation rules."""

    async def evaluate(
        self, rule_id: UUID, rule_name: str, severity: str,
        body: ThresholdBody, conn
    ) -> list[AlertTrigger]:
        """Run the threshold query and return any triggers."""
        qb = QueryBuilder()
        build_event_filter(qb, body.filters, window_seconds=body.window_seconds)

        triggers: list[AlertTrigger] = []

        if body.group_by:
            col = safe_col(body.group_by)
            triggers = await self._grouped(
                rule_id, rule_name, severity, body, conn, qb, col
            )
        else:
            triggers = await self._ungrouped(
                rule_id, rule_name, severity, body, conn, qb
            )

        # Apply outside_hours filter in Python (avoids timezone SQL complexity)
        if body.outside_hours and triggers:
            oh = body.outside_hours
            filtered = []
            for t in triggers:
                hour = t.last_seen.hour  # UTC
                if oh.start < oh.end:
                    in_window = oh.start <= hour < oh.end
                else:  # wraps midnight
                    in_window = hour >= oh.start or hour < oh.end
                if not in_window:
                    filtered.append(t)
            return filtered

        return triggers

    async def _grouped(
        self, rule_id, rule_name, severity, body: ThresholdBody,
        conn, qb: QueryBuilder, col: str
    ) -> list[AlertTrigger]:
        """Query grouped by col and check threshold per group."""
        if body.distinct_users:
            sql = f"""
                SELECT {col}, COUNT(DISTINCT user_name) AS cnt,
                       MIN(received_at) AS first_seen, MAX(received_at) AS last_seen
                FROM events
                WHERE {qb.where}
                GROUP BY {col}
                HAVING COUNT(DISTINCT user_name) >= {body.distinct_users}
            """
        elif body.aggregate:
            ag = body.aggregate
            # Aggregate on a JSONB extra field
            extra_field = ag.field.replace("'", "")   # basic sanitise
            op_map = {"gt": ">", "lt": "<", "gte": ">=", "lte": "<=", "eq": "="}
            op_sql = op_map[ag.op]
            sql = f"""
                SELECT {col},
                       COUNT(*) AS cnt,
                       MAX((extra->>'{extra_field}')::numeric) AS agg_val,
                       MIN(received_at) AS first_seen,
                       MAX(received_at) AS last_seen
                FROM events
                WHERE {qb.where}
                  AND (extra->>'{extra_field}') IS NOT NULL
                GROUP BY {col}
                HAVING MAX((extra->>'{extra_field}')::numeric) {op_sql} {ag.value}
            """
        else:
            sql = f"""
                SELECT {col}, COUNT(*) AS cnt,
                       MIN(received_at) AS first_seen, MAX(received_at) AS last_seen
                FROM events
                WHERE {qb.where}
                GROUP BY {col}
                HAVING COUNT(*) >= {body.count}
            """

        rows = await conn.fetch(sql, *qb.params)
        results = []
        for row in rows:
            group_val = str(row[col]) if row[col] else "unknown"
            cnt = row["cnt"]
            results.append(AlertTrigger(
                rule_id=rule_id,
                severity=severity,
                title=f"{rule_name}: {group_val}",
                description=f"Triggered {cnt} event(s) within {body.window_seconds}s",
                src_ip=group_val if col == "src_ip" else None,
                source_host=group_val if col == "source_host" else None,
                first_seen=row["first_seen"].replace(tzinfo=timezone.utc) if row["first_seen"].tzinfo is None else row["first_seen"],
                last_seen=row["last_seen"].replace(tzinfo=timezone.utc) if row["last_seen"].tzinfo is None else row["last_seen"],
                event_count=cnt,
                group_key=f"{rule_id}:{group_val}",
            ))
        return results

    async def _ungrouped(
        self, rule_id, rule_name, severity, body: ThresholdBody,
        conn, qb: QueryBuilder
    ) -> list[AlertTrigger]:
        """Query without grouping — global event count against threshold."""
        sql = f"""
            SELECT COUNT(*) AS cnt,
                   MIN(received_at) AS first_seen,
                   MAX(received_at) AS last_seen
            FROM events
            WHERE {qb.where}
        """
        row = await conn.fetchrow(sql, *qb.params)
        if not row or row["cnt"] < body.count:
            return []

        now = datetime.now(tz=timezone.utc)
        return [AlertTrigger(
            rule_id=rule_id,
            severity=severity,
            title=rule_name,
            description=f"Triggered {row['cnt']} event(s) within {body.window_seconds}s",
            src_ip=None,
            source_host=None,
            first_seen=row["first_seen"].replace(tzinfo=timezone.utc) if row["first_seen"] and row["first_seen"].tzinfo is None else (row["first_seen"] or now),
            last_seen=row["last_seen"].replace(tzinfo=timezone.utc) if row["last_seen"] and row["last_seen"].tzinfo is None else (row["last_seen"] or now),
            event_count=row["cnt"],
            group_key=f"{rule_id}:global",
        )]
