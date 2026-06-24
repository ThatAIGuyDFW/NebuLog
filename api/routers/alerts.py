"""GET /alerts, GET /alerts/{id}, PATCH /alerts/{id}."""

from __future__ import annotations

import math
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import TokenData, get_current_user, require_roles
from api.db import get_db
from api.models.db_models import Alert, AlertRule, Event
from api.models.schemas import (
    AlertDetail, AlertPatch, AlertSummary, EventSummary, PaginatedResponse,
)

router = APIRouter(prefix="/alerts", tags=["Alerts"])

_VALID_STATUSES = {"open", "acknowledged", "closed"}
_VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}


@router.get("", response_model=PaginatedResponse[AlertSummary])
async def list_alerts(
    severity: str | None = Query(None, description="critical | high | medium | low | info"),
    status_filter: str | None = Query(None, alias="status", description="open | acknowledged | closed"),
    rule_id: UUID | None = Query(None),
    time_from: datetime | None = Query(None),
    time_to: datetime | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _user: TokenData = Depends(get_current_user),
) -> PaginatedResponse[AlertSummary]:
    stmt = select(Alert)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if status_filter:
        stmt = stmt.where(Alert.status == status_filter)
    if rule_id:
        stmt = stmt.where(Alert.rule_id == rule_id)
    if time_from:
        stmt = stmt.where(Alert.first_seen >= time_from)
    if time_to:
        stmt = stmt.where(Alert.first_seen <= time_to)

    total: int = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (
        await db.execute(
            stmt.order_by(Alert.last_seen.desc())
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).scalars().all()

    return PaginatedResponse(
        items=[AlertSummary.model_validate(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
        pages=max(1, math.ceil(total / page_size)),
    )


@router.get("/{alert_id}", response_model=AlertDetail)
async def get_alert(
    alert_id: UUID,
    include_events: bool = Query(True, description="Attach linked events to response"),
    db: AsyncSession = Depends(get_db),
    _user: TokenData = Depends(get_current_user),
) -> AlertDetail:
    alert = (await db.execute(select(Alert).where(Alert.id == alert_id))).scalars().first()
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    # Fetch the rule name
    rule = (await db.execute(select(AlertRule).where(AlertRule.id == alert.rule_id))).scalars().first()

    # Optionally fetch linked events (those pointing to this alert)
    linked: list[EventSummary] = []
    if include_events:
        event_rows = (
            await db.execute(
                select(Event)
                .where(Event.alert_id == alert_id)
                .order_by(Event.received_at.desc())
                .limit(100)
            )
        ).scalars().all()
        linked = [EventSummary.model_validate(e) for e in event_rows]

    detail = AlertDetail.model_validate(alert)
    detail.rule_name = rule.name if rule else None
    detail.linked_events = linked
    detail.extra = alert.extra or {}
    return detail


@router.patch("/{alert_id}", response_model=AlertSummary)
async def patch_alert(
    alert_id: UUID,
    body: AlertPatch,
    db: AsyncSession = Depends(get_db),
    user: TokenData = Depends(require_roles("admin", "analyst")),
) -> AlertSummary:
    """Acknowledge, assign, or close an alert.
    Requires at least the Analyst role.
    """
    alert = (await db.execute(select(Alert).where(Alert.id == alert_id))).scalars().first()
    if alert is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Alert not found")

    if body.status is not None:
        if body.status not in _VALID_STATUSES:
            raise HTTPException(400, f"status must be one of {_VALID_STATUSES}")
        alert.status = body.status

    if body.assigned_to is not None:
        alert.assigned_to = body.assigned_to

    from sqlalchemy import func as sqlfunc
    alert.updated_at = sqlfunc.now()
    await db.commit()
    await db.refresh(alert)
    return AlertSummary.model_validate(alert)
