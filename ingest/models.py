"""Pydantic v2 schema for a normalized log event.

All parsers produce a NormalizedEvent. The storage worker persists it to PostgreSQL.
The archive worker uses raw_message from the same object for Blob Storage.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class SourceType(str, Enum):
    fortigate = "fortigate"
    cisco_asa = "cisco_asa"
    cisco_ios = "cisco_ios"
    windows = "windows"
    linux = "linux"


class LogLevel(str, Enum):
    emergency = "emergency"
    alert = "alert"
    critical = "critical"
    error = "error"
    warning = "warning"
    notice = "notice"
    info = "info"
    debug = "debug"


class Category(str, Enum):
    auth = "auth"
    network = "network"
    endpoint = "endpoint"
    system = "system"
    threat = "threat"
    compliance = "compliance"


# Syslog severity (RFC 5424) → LogLevel
SYSLOG_SEVERITY_MAP: dict[int, LogLevel] = {
    0: LogLevel.emergency,
    1: LogLevel.alert,
    2: LogLevel.critical,
    3: LogLevel.error,
    4: LogLevel.warning,
    5: LogLevel.notice,
    6: LogLevel.info,
    7: LogLevel.debug,
}


class NormalizedEvent(BaseModel):
    """Unified schema stored in the PostgreSQL events table."""

    id: uuid.UUID = Field(default_factory=uuid.uuid4)
    received_at: datetime = Field(
        description="Server-side ingest timestamp (UTC, set by ingest service)"
    )
    event_time: datetime | None = Field(
        default=None, description="Timestamp from source log (UTC normalised)"
    )

    source_host: str = Field(description="IP or FQDN of originating device")
    source_type: SourceType
    log_level: LogLevel | None = None
    category: Category | None = None

    action: str | None = None
    src_ip: str | None = None
    src_port: int | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    protocol: str | None = None

    user_name: str | None = None
    process_name: str | None = None
    event_id: str | None = None

    message: str = Field(description="Normalized human-readable message")
    raw_message: str | None = Field(default=None, description="Original unparsed log line")

    tags: list[str] = Field(default_factory=list)
    geo_country: str | None = None
    geo_city: str | None = None
    alert_id: uuid.UUID | None = None
    ingest_node: str | None = None
    raw_hash: str | None = Field(
        default=None, description="SHA-256 of raw_message for tamper detection"
    )
    extra: dict[str, Any] = Field(
        default_factory=dict,
        description="Source-specific fields not in core schema",
    )

    model_config = {"use_enum_values": True}
