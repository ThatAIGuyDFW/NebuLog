"""Base evaluator: AlertTrigger dataclass and SQL query builder."""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any
from uuid import UUID

from correlation.rule_dsl import ALLOWED_COLUMNS


@dataclass
class AlertTrigger:
    """Describes one alert that the engine should create or update."""

    rule_id: UUID
    severity: str
    title: str
    description: str
    src_ip: str | None
    source_host: str | None
    first_seen: datetime
    last_seen: datetime
    event_count: int
    # Deduplication key — same rule + same group_key → update existing open alert
    group_key: str | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class QueryBuilder:
    """Incrementally build a parameterized asyncpg query.

    Uses ``?`` as a placeholder; call ``add()`` to append conditions.
    The builder replaces ``?`` with ``$1``, ``$2``, … in order.
    """

    def __init__(self) -> None:
        self._conditions: list[str] = []
        self._params: list[Any] = []

    def add(self, condition: str, *values: Any) -> "QueryBuilder":
        """Append a WHERE condition with ``?`` placeholders."""
        for v in values:
            self._params.append(v)
            condition = condition.replace("?", f"${len(self._params)}", 1)
        self._conditions.append(condition)
        return self

    @property
    def where(self) -> str:
        return " AND ".join(self._conditions) if self._conditions else "TRUE"

    @property
    def params(self) -> list[Any]:
        return list(self._params)

    def next_param(self) -> str:
        """Return the placeholder for the next positional parameter."""
        return f"${len(self._params) + 1}"


def safe_col(name: str | None) -> str:
    """Validate and return a column name safe for interpolation into SQL."""
    if name not in ALLOWED_COLUMNS:
        raise ValueError(f"Column {name!r} not in ALLOWED_COLUMNS")
    return name


def build_event_filter(qb: QueryBuilder, filters, *, window_seconds: int) -> None:
    """Append standard EventFilter conditions to a QueryBuilder."""
    qb.add("received_at >= NOW() - ?::interval", f"{window_seconds} seconds")
    if filters.event_id:
        qb.add("event_id = ANY(?)", filters.event_id)
    if filters.category:
        qb.add("category::text = ?", filters.category)
    if filters.source_type:
        qb.add("source_type::text = ?", filters.source_type)
    if filters.action:
        qb.add("action = ?", filters.action)
    if filters.tags:
        qb.add("tags @> ?", filters.tags)
    if filters.user_name:
        qb.add("user_name = ?", filters.user_name)
    if filters.log_level:
        qb.add("log_level::text = ?", filters.log_level)
