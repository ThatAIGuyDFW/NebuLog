"""GET /dashboard/summary and GET /dashboard/timeline."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import TokenData, get_current_user
from api.db import get_db
from api.models.db_models import Alert, AlertRule, Event, Source
from api.models.schemas import (
    CategoryCount, DashboardSummary, DashboardTimeline, SeverityCount,
    TimelineBucket, TopRule, TopSource,
)

router = APIRouter(prefix="/dashboard", tags=["Dashboard"])

_BUCKET_TRUNCS = {"1m": "minute", "5m": "5 minutes", "1h": "hour"}


@router.get("/summary", response_model=DashboardSummary)
async def dashboard_summary(
    hours: int = Query(24, ge=1, le=168, description="Look-back window in hours (max 168 = 7 days)"),
    db: AsyncSession = Depends(get_db),
    _user: TokenData = Depends(get_current_user),
) -> DashboardSummary:
    since = datetime.now(tz=timezone.utc) - timedelta(hours=hours)

    # Total events
    total: int = (
        await db.execute(
            select(func.count()).select_from(Event).where(Event.received_at >= since)
        )
    ).scalar_one()

    # Events by severity (log_level maps to severity for display purposes)
    sev_rows = (
        await db.execute(
            select(Event.log_level, func.count().label("cnt"))
            .where(Event.received_at >= since)
            .where(Event.log_level.isnot(None))
            .group_by(Event.log_level)
            .order_by(func.count().desc())
        )
    ).all()

    # Events by category
    cat_rows = (
        await db.execute(
            select(Event.category, func.count().label("cnt"))
            .where(Event.received_at >= since)
            .where(Event.category.isnot(None))
            .group_by(Event.category)
            .order_by(func.count().desc())
        )
    ).all()

    # Top source hosts by event volume
    src_rows = (
        await db.execute(
            select(Event.source_host, func.count().label("cnt"))
            .where(Event.received_at >= since)
            .group_by(Event.source_host)
            .order_by(func.count().desc())
            .limit(10)
        )
    ).all()

    # Open alert count
    open_alerts: int = (
        await db.execute(select(func.count()).select_from(Alert).where(Alert.status == "open"))
    ).scalar_one()

    # Top alert rules firing (by open alert count)
    top_rule_rows = (
        await db.execute(
            select(Alert.rule_id, func.count().label("cnt"))
            .where(Alert.status == "open")
            .group_by(Alert.rule_id)
            .order_by(func.count().desc())
            .limit(5)
        )
    ).all()

    # Resolve rule names
    top_rules: list[TopRule] = []
    for rule_id, cnt in top_rule_rows:
        rule = (await db.execute(select(AlertRule).where(AlertRule.id == rule_id))).scalars().first()
        if rule:
            top_rules.append(TopRule(rule_id=rule_id, rule_name=rule.name, alert_count=cnt))

    # Active sources (seen in window)
    active_sources: int = (
        await db.execute(
            select(func.count(func.distinct(Event.source_host)))
            .where(Event.received_at >= since)
        )
    ).scalar_one()

    return DashboardSummary(
        period_hours=hours,
        total_events=total,
        open_alerts=open_alerts,
        events_by_severity=[SeverityCount(severity=r[0], count=r[1]) for r in sev_rows],
        events_by_category=[CategoryCount(category=r[0], count=r[1]) for r in cat_rows],
        top_source_hosts=[TopSource(source_host=r[0], event_count=r[1]) for r in src_rows],
        top_alert_rules=top_rules,
        active_sources=active_sources,
    )


@router.get("/timeline", response_model=DashboardTimeline)
async def dashboard_timeline(
    hours: int = Query(24, ge=1, le=168),
    bucket: str = Query("1h", description="Bucket size: 1m | 5m | 1h"),
    source_type: str | None = Query(None),
    db: AsyncSession = Depends(get_db),
    _user: TokenData = Depends(get_current_user),
) -> DashboardTimeline:
    if bucket not in _BUCKET_TRUNCS:
        from fastapi import HTTPException
        raise HTTPException(400, f"bucket must be one of {list(_BUCKET_TRUNCS)}")

    trunc = _BUCKET_TRUNCS[bucket]
    since = datetime.now(tz=timezone.utc) - timedelta(hours=hours)

    # date_trunc with interval string requires a workaround for non-standard intervals
    if trunc == "5 minutes":
        bucket_expr = text(
            "date_trunc('hour', received_at) + "
            "INTERVAL '5 min' * FLOOR(date_part('minute', received_at) / 5)"
        )
    else:
        bucket_expr = func.date_trunc(trunc, Event.received_at)

    stmt = (
        select(bucket_expr.label("bucket"), func.count().label("cnt"))
        .where(Event.received_at >= since)
    )
    if source_type:
        stmt = stmt.where(Event.source_type == source_type)

    stmt = stmt.group_by(text("1")).order_by(text("1"))
    rows = (await db.execute(stmt)).all()

    return DashboardTimeline(
        bucket_size=bucket,
        buckets=[TimelineBucket(bucket=r[0], count=r[1]) for r in rows],
    )
