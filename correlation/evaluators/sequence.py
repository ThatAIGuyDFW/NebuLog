"""Sequence evaluator.

Fires when step[0] is followed by step[1] (and optional subsequent steps)
from the same `group_by` value within `window_seconds`.

Uses a CTE chain: step_0 matches the first filter, step_1 matches the second
filter *after* step_0's timestamp for the same group key, etc.
"""

from __future__ import annotations

from datetime import datetime, timezone
from uuid import UUID

import structlog

from correlation.rule_dsl import SequenceBody, SequenceStep
from .base import AlertTrigger, QueryBuilder, safe_col

log = structlog.get_logger()


def _step_condition(step: SequenceStep) -> str:
    """Return a SQL AND-predicate for a single sequence step (no params)."""
    parts: list[str] = []
    if step.event_id:
        parts.append(f"event_id = '{step.event_id.replace(chr(39), '')}'")
    if step.action:
        parts.append(f"action = '{step.action.replace(chr(39), '')}'")
    if step.category:
        parts.append(f"category::text = '{step.category.replace(chr(39), '')}'")
    if step.log_level:
        parts.append(f"log_level::text = '{step.log_level.replace(chr(39), '')}'")
    return " AND ".join(parts) if parts else "TRUE"


class SequenceEvaluator:
    """Evaluate sequence-type correlation rules."""

    async def evaluate(
        self, rule_id: UUID, rule_name: str, severity: str,
        body: SequenceBody, conn
    ) -> list[AlertTrigger]:
        col = safe_col(body.group_by)
        window = body.window_seconds

        # Build a CTE chain: step_0 → step_1 → ... each requiring a later timestamp
        # from the same group key.
        #
        # WITH step_0 AS (
        #   SELECT {col}, received_at AS ts0
        #   FROM events
        #   WHERE received_at >= NOW() - '{window} seconds'::interval
        #     AND <step 0 filter>
        # ),
        # step_1 AS (
        #   SELECT s0.{col}, s0.ts0, e.received_at AS ts1
        #   FROM step_0 s0
        #   JOIN events e ON e.{col} = s0.{col}
        #  WHERE e.received_at > s0.ts0
        #    AND e.received_at >= NOW() - '{window} seconds'::interval
        #    AND <step 1 filter>
        # )
        # SELECT DISTINCT {col}, ts0 AS first_seen, ts_last AS last_seen
        # FROM step_N

        ctes: list[str] = []
        step0_filter = _step_condition(body.steps[0])
        ctes.append(
            f"step_0 AS (\n"
            f"  SELECT {col}, received_at AS ts0\n"
            f"  FROM events\n"
            f"  WHERE received_at >= NOW() - '{window} seconds'::interval\n"
            f"    AND {step0_filter}\n"
            f")"
        )

        for i, step in enumerate(body.steps[1:], start=1):
            prev = f"step_{i - 1}"
            cur = f"step_{i}"
            prev_ts = f"ts{i - 1}"
            cur_ts = f"ts{i}"
            step_filter = _step_condition(step)

            # Build SELECT list: carry all prior timestamps, add current
            ts_cols = ", ".join(f"s.ts{j}" for j in range(i))
            ctes.append(
                f"{cur} AS (\n"
                f"  SELECT s.{col}, {ts_cols}, e.received_at AS {cur_ts}\n"
                f"  FROM {prev} s\n"
                f"  JOIN events e ON e.{col} = s.{col}\n"
                f"  WHERE e.received_at > s.{prev_ts}\n"
                f"    AND e.received_at >= NOW() - '{window} seconds'::interval\n"
                f"    AND {step_filter}\n"
                f")"
            )

        last_step = f"step_{len(body.steps) - 1}"
        last_ts = f"ts{len(body.steps) - 1}"

        sql = (
            "WITH " + ",\n".join(ctes) + "\n"
            f"SELECT DISTINCT {col},\n"
            f"       ts0 AS first_seen,\n"
            f"       {last_ts} AS last_seen\n"
            f"FROM {last_step}"
        )

        rows = await conn.fetch(sql)
        results = []
        for row in rows:
            group_val = str(row[col]) if row[col] else "unknown"
            first = row["first_seen"]
            last = row["last_seen"]
            if first and first.tzinfo is None:
                first = first.replace(tzinfo=timezone.utc)
            if last and last.tzinfo is None:
                last = last.replace(tzinfo=timezone.utc)
            results.append(AlertTrigger(
                rule_id=rule_id,
                severity=severity,
                title=f"{rule_name}: {group_val}",
                description=(
                    f"{len(body.steps)}-step sequence completed within {window}s"
                ),
                src_ip=group_val if col == "src_ip" else None,
                source_host=group_val if col == "source_host" else None,
                first_seen=first or datetime.now(tz=timezone.utc),
                last_seen=last or datetime.now(tz=timezone.utc),
                event_count=len(body.steps),
                group_key=f"{rule_id}:{group_val}",
            ))
        return results
