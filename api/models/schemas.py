"""Pydantic v2 request and response schemas for all API endpoints."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Generic, TypeVar
from uuid import UUID

from pydantic import BaseModel, Field

T = TypeVar("T")


# ---------------------------------------------------------------------------
# Generic pagination wrapper
# ---------------------------------------------------------------------------

class PaginatedResponse(BaseModel, Generic[T]):
    items: list[T]
    total: int
    page: int
    page_size: int
    pages: int


# ---------------------------------------------------------------------------
# Events
# ---------------------------------------------------------------------------

class EventSummary(BaseModel):
    id: UUID
    received_at: datetime
    event_time: datetime | None
    source_host: str
    source_type: str | None
    log_level: str | None
    category: str | None
    action: str | None
    src_ip: str | None
    src_port: int | None
    dst_ip: str | None
    dst_port: int | None
    protocol: str | None
    user_name: str | None
    event_id: str | None
    message: str
    tags: list[str]

    model_config = {"from_attributes": True}

    def model_post_init(self, __context: Any) -> None:
        if self.tags is None:
            object.__setattr__(self, "tags", [])


class EventDetail(EventSummary):
    process_name: str | None
    raw_message: str | None
    raw_hash: str | None
    geo_country: str | None
    geo_city: str | None
    alert_id: UUID | None
    ingest_node: str | None
    extra: dict[str, Any]

    def model_post_init(self, __context: Any) -> None:
        super().model_post_init(__context)
        if self.extra is None:
            object.__setattr__(self, "extra", {})


# ---------------------------------------------------------------------------
# Alerts
# ---------------------------------------------------------------------------

class AlertSummary(BaseModel):
    id: UUID
    rule_id: UUID
    severity: str
    status: str
    title: str
    src_ip: str | None
    source_host: str | None
    first_seen: datetime
    last_seen: datetime
    event_count: int
    assigned_to: str | None
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class AlertDetail(AlertSummary):
    description: str | None
    rule_name: str | None = None
    linked_events: list[EventSummary] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)


class AlertPatch(BaseModel):
    status: str | None = Field(
        default=None,
        description="acknowledged | closed | open",
    )
    assigned_to: str | None = None

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# Correlation Rules
# ---------------------------------------------------------------------------

class RuleSummary(BaseModel):
    id: UUID
    name: str
    description: str | None
    rule_type: str
    severity: str
    enabled: bool
    created_at: datetime
    updated_at: datetime

    model_config = {"from_attributes": True}


class RuleDetail(RuleSummary):
    body: dict[str, Any]


class RuleCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    description: str | None = None
    rule_type: str = Field(..., pattern="^(threshold|sequence|absence|blacklist|anomaly)$")
    severity: str = Field(..., pattern="^(critical|high|medium|low|info)$")
    enabled: bool = True
    body: dict[str, Any]

    model_config = {"extra": "forbid"}


class RuleUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    description: str | None = None
    rule_type: str | None = Field(default=None, pattern="^(threshold|sequence|absence|blacklist|anomaly)$")
    severity: str | None = Field(default=None, pattern="^(critical|high|medium|low|info)$")
    enabled: bool | None = None
    body: dict[str, Any] | None = None

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

class SourceSummary(BaseModel):
    id: UUID
    ip_address: str
    hostname: str | None
    source_type: str
    label: str | None
    enabled: bool
    last_seen: datetime | None
    event_rate_1m: int
    created_at: datetime

    model_config = {"from_attributes": True}


class SourceCreate(BaseModel):
    ip_address: str = Field(..., description="IP address of the log source")
    hostname: str | None = None
    source_type: str = Field(
        ..., pattern="^(fortigate|cisco_asa|cisco_ios|windows|linux)$"
    )
    label: str | None = None
    enabled: bool = True

    model_config = {"extra": "forbid"}


# ---------------------------------------------------------------------------
# Dashboard
# ---------------------------------------------------------------------------

class SeverityCount(BaseModel):
    severity: str
    count: int


class CategoryCount(BaseModel):
    category: str
    count: int


class TopSource(BaseModel):
    source_host: str
    event_count: int


class TopRule(BaseModel):
    rule_id: UUID
    rule_name: str
    alert_count: int


class DashboardSummary(BaseModel):
    period_hours: int
    total_events: int
    open_alerts: int
    events_by_severity: list[SeverityCount]
    events_by_category: list[CategoryCount]
    top_source_hosts: list[TopSource]
    top_alert_rules: list[TopRule]
    active_sources: int


class TimelineBucket(BaseModel):
    bucket: datetime
    count: int


class DashboardTimeline(BaseModel):
    bucket_size: str
    buckets: list[TimelineBucket]


# ---------------------------------------------------------------------------
# Compliance
# ---------------------------------------------------------------------------

class RetentionPosture(BaseModel):
    oldest_event: datetime | None
    required_retention_years: int
    hot_storage_months: int
    compliant: bool


class LogGap(BaseModel):
    source_host: str
    last_seen: datetime
    gap_hours: float


class ComplianceReport(BaseModel):
    framework: str
    period_from: datetime
    period_to: datetime
    generated_at: datetime
    total_events: int
    events_by_category: list[CategoryCount]
    failed_logins: int
    privilege_escalations: int
    audit_log_clears: int
    log_gaps: list[LogGap]
    retention_posture: RetentionPosture
    # PCI-specific (present when framework=pci_dss)
    cardholder_env_events: int | None = None
    daily_review_gaps: list[str] | None = None  # dates with no PCI-source events
