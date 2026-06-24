"""GET /events — paginated log search with full filter set.
GET /events/{id} — single event detail.
GET /events/{id}/verify — SHA-256 tamper detection.
"""

from __future__ import annotations

import hashlib
import math
from datetime import datetime
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from fastapi.responses import JSONResponse
from sqlalchemy import cast, func, select, text
from sqlalchemy.dialects.postgresql import TEXT
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import TokenData, get_current_user
from api.db import get_db
from api.models.db_models import Event
from api.models.schemas import EventDetail, EventSummary, PaginatedResponse

router = APIRouter(prefix="/events", tags=["Events"])


def _apply_filters(stmt, *, time_from, time_to, source, source_type,
                   category, src_ip, dst_ip, user, log_level, q):
    if time_from:
        stmt = stmt.where(Event.received_at >= time_from)
    if time_to:
        stmt = stmt.where(Event.received_at <= time_to)
    if source:
        stmt = stmt.where(Event.source_host.ilike(f"%{source}%"))
    if source_type:
        stmt = stmt.where(cast(Event.source_type, TEXT) == source_type)
    if category:
        stmt = stmt.where(cast(Event.category, TEXT) == category)
    if src_ip:
        stmt = stmt.where(cast(Event.src_ip, TEXT) == src_ip)
    if dst_ip:
        stmt = stmt.where(cast(Event.dst_ip, TEXT) == dst_ip)
    if user:
        stmt = stmt.where(Event.user_name.ilike(f"%{user}%"))
    if log_level:
        stmt = stmt.where(cast(Event.log_level, TEXT) == log_level)
    if q:
        stmt = stmt.where(Event.message.ilike(f"%{q}%"))
    return stmt


@router.get("", response_model=PaginatedResponse[EventSummary])
async def list_events(
    time_from: datetime | None = Query(None, description="Start of time range (UTC ISO-8601)"),
    time_to: datetime | None = Query(None, description="End of time range (UTC ISO-8601)"),
    source: str | None = Query(None, description="Source host filter (partial match)"),
    source_type: str | None = Query(None, description="fortigate | cisco_asa | windows | linux"),
    category: str | None = Query(None, description="auth | network | endpoint | system | threat | compliance"),
    src_ip: str | None = Query(None, description="Exact source IP"),
    dst_ip: str | None = Query(None, description="Exact destination IP"),
    user: str | None = Query(None, description="Username (partial match)"),
    log_level: str | None = Query(None, description="emergency | alert | critical | error | warning | notice | info | debug"),
    q: str | None = Query(None, description="Free-text search on message field"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=500),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    db: AsyncSession = Depends(get_db),
    _user: TokenData = Depends(get_current_user),
) -> PaginatedResponse[EventSummary]:
    base = select(Event)
    base = _apply_filters(
        base, time_from=time_from, time_to=time_to, source=source,
        source_type=source_type, category=category, src_ip=src_ip,
        dst_ip=dst_ip, user=user, log_level=log_level, q=q,
    )

    count_stmt = select(func.count()).select_from(base.subquery())
    total: int = (await db.execute(count_stmt)).scalar_one()

    order_col = Event.received_at.desc() if sort_order == "desc" else Event.received_at.asc()
    data_stmt = (
        base.order_by(order_col)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    rows = (await db.execute(data_stmt)).scalars().all()

    return PaginatedResponse(
        items=[EventSummary.model_validate(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
        pages=max(1, math.ceil(total / page_size)),
    )


@router.get("/{event_id}", response_model=EventDetail)
async def get_event(
    event_id: UUID,
    db: AsyncSession = Depends(get_db),
    _user: TokenData = Depends(get_current_user),
) -> EventDetail:
    stmt = select(Event).where(Event.id == event_id)
    row = (await db.execute(stmt)).scalars().first()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")
    return EventDetail.model_validate(row)


@router.get("/{event_id}/verify")
async def verify_event_integrity(
    event_id: UUID,
    db: AsyncSession = Depends(get_db),
    _user: TokenData = Depends(get_current_user),
) -> JSONResponse:
    """Verify the SHA-256 hash of an event's raw_message against the stored raw_hash.

    Returns:
        { "intact": true }  — stored hash matches recomputed hash
        { "intact": false, "detail": "..." }  — tampering detected or hash unavailable
    """
    stmt = select(Event).where(Event.id == event_id)
    row = (await db.execute(stmt)).scalars().first()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Event not found")

    if not row.raw_hash:
        return JSONResponse(
            {"intact": False, "detail": "No raw_hash stored for this event"},
            status_code=status.HTTP_200_OK,
        )
    if not row.raw_message:
        return JSONResponse(
            {"intact": False, "detail": "No raw_message stored for this event"},
            status_code=status.HTTP_200_OK,
        )

    recomputed = hashlib.sha256(row.raw_message.encode()).hexdigest()
    intact = recomputed == row.raw_hash

    return JSONResponse(
        {
            "intact": intact,
            "event_id": str(event_id),
            "stored_hash": row.raw_hash,
            "recomputed_hash": recomputed,
        },
        status_code=status.HTTP_200_OK,
    )
