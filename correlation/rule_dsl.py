"""Rule DSL — Pydantic v2 schemas for all 5 correlation rule types.

Each rule in the alert_rules table has a `body` JSONB column that validates
against one of these schemas based on the `rule_type` column.

Usage:
    body = parse_rule_body(rule_type, raw_body_dict)
"""

from __future__ import annotations

from typing import Annotated, Any, Literal

from pydantic import BaseModel, Field, model_validator


# ---------------------------------------------------------------------------
# Shared primitives
# ---------------------------------------------------------------------------

#: Column names allowed in GROUP BY / field lookups to prevent SQL injection
ALLOWED_COLUMNS: frozenset[str] = frozenset(
    {"src_ip", "dst_ip", "source_host", "user_name", "protocol", "event_id", "process_name"}
)


class EventFilter(BaseModel):
    """Predicate applied to events before counting / sequencing.

    All fields are optional.  Multiple fields are ANDed together.
    `event_id` and `tags` lists are OR-matched within the field.
    """

    event_id: list[str] | None = Field(
        default=None, description="Match any of these source-native event IDs"
    )
    category: str | None = Field(
        default=None, description="auth | network | endpoint | system | threat | compliance"
    )
    source_type: str | None = Field(
        default=None, description="fortigate | cisco_asa | windows | linux"
    )
    action: str | None = Field(default=None, description="Exact match on action field")
    tags: list[str] | None = Field(
        default=None, description="Event must carry ALL of these tags"
    )
    user_name: str | None = Field(default=None, description="Exact match on user_name")
    log_level: str | None = None

    model_config = {"extra": "allow"}   # allow source-specific filters in extra fields


class OutsideHours(BaseModel):
    """Time-of-day restriction.  Rule only fires if the event falls OUTSIDE
    the window [start, end) in UTC hours (0–23)."""

    start: int = Field(..., ge=0, le=23, description="First allowed hour (inclusive)")
    end: int = Field(..., ge=0, le=23, description="Last allowed hour (exclusive)")


class AggregateCondition(BaseModel):
    """Field-level aggregate check applied after the count filter."""

    field: str = Field(..., description="JSONB extra field or column name")
    op: Literal["gt", "lt", "gte", "lte", "eq"] = "gt"
    value: float


# ---------------------------------------------------------------------------
# Rule body schemas
# ---------------------------------------------------------------------------

class ThresholdBody(BaseModel):
    """Threshold rule: N events matching filters from same group_by value
    within window_seconds → alert."""

    filters: EventFilter = Field(default_factory=EventFilter)
    group_by: str | None = Field(
        default=None,
        description="Group events by this column (must be in ALLOWED_COLUMNS)",
    )
    count: int = Field(default=1, ge=1)
    window_seconds: int = Field(..., ge=1)
    outside_hours: OutsideHours | None = None
    aggregate: AggregateCondition | None = Field(
        default=None,
        description="Additional aggregate check (e.g., sentbyte > 500MB)",
    )
    distinct_users: int | None = Field(
        default=None,
        description="Require N distinct user_name values instead of N raw event rows",
    )

    @model_validator(mode="after")
    def _validate_group_by(self) -> "ThresholdBody":
        if self.group_by and self.group_by not in ALLOWED_COLUMNS:
            raise ValueError(
                f"group_by '{self.group_by}' not in allowed columns: {sorted(ALLOWED_COLUMNS)}"
            )
        return self


class SequenceStep(BaseModel):
    """One step in a sequence rule.  Fields ANDed together."""

    event_id: str | None = None
    action: str | None = None
    category: str | None = None
    log_level: str | None = None

    @model_validator(mode="after")
    def _at_least_one(self) -> "SequenceStep":
        if not any([self.event_id, self.action, self.category]):
            raise ValueError("Each sequence step must specify at least one of event_id, action, category")
        return self


class SequenceBody(BaseModel):
    """Sequence rule: step[0] followed by step[1] (and optionally more) from
    the same group_by value within window_seconds → alert."""

    steps: list[SequenceStep] = Field(..., min_length=2)
    group_by: str = Field(
        ..., description="Group events by this column (must be in ALLOWED_COLUMNS)"
    )
    window_seconds: int = Field(..., ge=1)

    @model_validator(mode="after")
    def _validate_group_by(self) -> "SequenceBody":
        if self.group_by not in ALLOWED_COLUMNS:
            raise ValueError(
                f"group_by '{self.group_by}' not in allowed columns: {sorted(ALLOWED_COLUMNS)}"
            )
        return self


class AbsenceBody(BaseModel):
    """Absence rule: no events matching filters in window_seconds → alert."""

    filters: EventFilter = Field(default_factory=EventFilter)
    window_seconds: int = Field(..., ge=1)


class BlacklistBody(BaseModel):
    """Blacklist rule: any event whose `field` value is in the named list → alert."""

    field: str = Field(
        ..., description="Column to check against the blacklist (must be in ALLOWED_COLUMNS)"
    )
    list_name: str = Field(..., min_length=1)

    @model_validator(mode="after")
    def _validate_field(self) -> "BlacklistBody":
        if self.field not in ALLOWED_COLUMNS:
            raise ValueError(
                f"field '{self.field}' not in allowed columns: {sorted(ALLOWED_COLUMNS)}"
            )
        return self


class AnomalyBody(BaseModel):
    """Anomaly rule: current window count deviates > std_devs standard deviations
    from the N-day rolling baseline → alert."""

    filters: EventFilter = Field(default_factory=EventFilter)
    metric: Literal["event_count"] = "event_count"
    group_by: str | None = None
    std_devs: float = Field(default=3.0, ge=0.5)
    baseline_days: int = Field(default=7, ge=1, le=90)
    window_seconds: int = Field(default=3600, ge=60)

    @model_validator(mode="after")
    def _validate_group_by(self) -> "AnomalyBody":
        if self.group_by and self.group_by not in ALLOWED_COLUMNS:
            raise ValueError(
                f"group_by '{self.group_by}' not in allowed columns: {sorted(ALLOWED_COLUMNS)}"
            )
        return self


# ---------------------------------------------------------------------------
# Discriminated parse helper
# ---------------------------------------------------------------------------

_BODY_SCHEMAS: dict[str, type[BaseModel]] = {
    "threshold": ThresholdBody,
    "sequence": SequenceBody,
    "absence": AbsenceBody,
    "blacklist": BlacklistBody,
    "anomaly": AnomalyBody,
}


def parse_rule_body(rule_type: str, raw: dict[str, Any]) -> BaseModel:
    """Parse and validate a rule body dict against the correct schema.

    Raises ValidationError on invalid data.
    """
    schema = _BODY_SCHEMAS.get(rule_type)
    if schema is None:
        raise ValueError(f"Unknown rule_type: {rule_type!r}")
    return schema.model_validate(raw)
