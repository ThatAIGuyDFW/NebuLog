"""Anomaly evaluator.

Fires when the event count in `window_seconds` deviates more than `std_devs`
standard deviations above the rolling `baseline_days`-day mean.

Baseline is computed from same-hour buckets over the baseline period so that
time-of-day patterns (e.g., night-time silence) don't inflate stddev.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import structlog

from correlation.rule_dsl import AnomalyBody
from .base import AlertTrigger, QueryBuilder, build_event_filter, safe_col

log = structlog.get_logger()


class AnomalyEvaluator:
    """Evaluate anomaly-type correlation rules."""

    async def evaluate(
        self, rule_id: UUID, rule_name: str, severity: str,
        body: AnomalyBody, conn
    ) -> list[AlertTrigger]:
        if body.group_by:
            return await self._grouped(rule_id, rule_name, severity, body, conn)
        return await self._ungrouped(rule_id, rule_name, severity, body, conn)

    async def _ungrouped(
        self, rule_id, rule_name, severity, body: AnomalyBody, conn
    ) -> list[AlertTrigger]:
        qb_filter = QueryBuilder()
        build_event_filter(qb_filter, body.filters, window_seconds=body.window_seconds)

        # Current window count
        count_sql = f"SELECT COUNT(*) AS cnt FROM events WHERE {qb_filter.where}"
        count_row = await conn.fetchrow(count_sql, *qb_filter.params)
        current_count = count_row["cnt"] if count_row else 0

        # Baseline: same-hour buckets over baseline_days
        qb_base = QueryBuilder()
        build_event_filter(
            qb_base, body.filters,
            window_seconds=body.baseline_days * 86400
        )
        baseline_sql = f"""
            SELECT AVG(bucket_count) AS mean, STDDEV_POP(bucket_count) AS stddev
            FROM (
                SELECT DATE_TRUNC('hour', received_at) AS bucket,
                       COUNT(*) AS bucket_count
                FROM events
                WHERE {qb_base.where}
                GROUP BY bucket
            ) hourly
        """
        base_row = await conn.fetchrow(baseline_sql, *qb_base.params)
        if not base_row or base_row["mean"] is None:
            log.debug("anomaly_no_baseline", rule_id=str(rule_id))
            return []

        mean = float(base_row["mean"])
        stddev = float(base_row["stddev"] or 0.0)

        if stddev == 0.0:
            return []

        z_score = (current_count - mean) / stddev
        if z_score <= body.std_devs:
            return []

        now = datetime.now(tz=timezone.utc)
        return [AlertTrigger(
            rule_id=rule_id,
            severity=severity,
            title=rule_name,
            description=(
                f"Event count {current_count} is {z_score:.1f}σ above "
                f"{body.baseline_days}-day baseline (mean={mean:.1f}, σ={stddev:.1f})"
            ),
            src_ip=None,
            source_host=None,
            first_seen=now,
            last_seen=now,
            event_count=current_count,
            group_key=f"{rule_id}:global",
            extra={"z_score": round(z_score, 2), "mean": round(mean, 2), "stddev": round(stddev, 2)},
        )]

    async def _grouped(
        self, rule_id, rule_name, severity, body: AnomalyBody, conn
    ) -> list[AlertTrigger]:
        col = safe_col(body.group_by)

        qb_filter = QueryBuilder()
        build_event_filter(qb_filter, body.filters, window_seconds=body.window_seconds)

        current_sql = f"""
            SELECT {col}, COUNT(*) AS cnt
            FROM events
            WHERE {qb_filter.where}
              AND {col} IS NOT NULL
            GROUP BY {col}
        """
        current_rows = await conn.fetch(current_sql, *qb_filter.params)
        if not current_rows:
            return []

        qb_base = QueryBuilder()
        build_event_filter(
            qb_base, body.filters,
            window_seconds=body.baseline_days * 86400
        )
        baseline_sql = f"""
            SELECT {col},
                   AVG(bucket_count) AS mean,
                   STDDEV_POP(bucket_count) AS stddev
            FROM (
                SELECT {col}, DATE_TRUNC('hour', received_at) AS bucket,
                       COUNT(*) AS bucket_count
                FROM events
                WHERE {qb_base.where}
                  AND {col} IS NOT NULL
                GROUP BY {col}, bucket
            ) hourly
            GROUP BY {col}
        """
        base_rows = await conn.fetch(baseline_sql, *qb_base.params)
        baselines: dict[str, tuple[float, float]] = {}
        for r in base_rows:
            if r["mean"] is not None and r["stddev"] and float(r["stddev"]) > 0:
                baselines[str(r[col])] = (float(r["mean"]), float(r["stddev"]))

        results = []
        now = datetime.now(tz=timezone.utc)
        for row in current_rows:
            group_val = str(row[col])
            if group_val not in baselines:
                continue
            mean, stddev = baselines[group_val]
            z_score = (row["cnt"] - mean) / stddev
            if z_score <= body.std_devs:
                continue
            results.append(AlertTrigger(
                rule_id=rule_id,
                severity=severity,
                title=f"{rule_name}: {group_val}",
                description=(
                    f"{group_val} count {row['cnt']} is {z_score:.1f}σ above "
                    f"{body.baseline_days}-day baseline (mean={mean:.1f}, σ={stddev:.1f})"
                ),
                src_ip=group_val if col == "src_ip" else None,
                source_host=group_val if col == "source_host" else None,
                first_seen=now,
                last_seen=now,
                event_count=row["cnt"],
                group_key=f"{rule_id}:{group_val}",
                extra={"z_score": round(z_score, 2), "mean": round(mean, 2), "stddev": round(stddev, 2)},
            ))
        return results
