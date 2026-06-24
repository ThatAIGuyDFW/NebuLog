"""GET /sources, POST /sources."""

from __future__ import annotations

import httpx
import math
import os
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import TokenData, require_roles
from api.db import get_db
from api.models.db_models import Source
from api.models.schemas import PaginatedResponse, SourceCreate, SourceSummary

router = APIRouter(prefix="/sources", tags=["Sources"])

# Ingest service URL for hot-reload notification
_INGEST_URL = os.getenv("INGEST_API_URL", "http://localhost:8001")


async def _notify_ingest_reload() -> None:
    """Tell the ingest service to reload its source registry from the DB."""
    try:
        async with httpx.AsyncClient(timeout=5) as client:
            await client.get(f"{_INGEST_URL}/ingest/reload-sources")
    except Exception:
        pass  # Non-fatal; ingest will reload on next startup


@router.get("", response_model=PaginatedResponse[SourceSummary])
async def list_sources(
    enabled: bool | None = Query(None),
    source_type: str | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _user: TokenData = Depends(require_roles("admin", "analyst", "read_only")),
) -> PaginatedResponse[SourceSummary]:
    stmt = select(Source)
    if enabled is not None:
        stmt = stmt.where(Source.enabled == enabled)
    if source_type:
        stmt = stmt.where(Source.source_type == source_type)

    total: int = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (
        await db.execute(
            stmt.order_by(Source.label, Source.ip_address)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).scalars().all()

    return PaginatedResponse(
        items=[SourceSummary.model_validate(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
        pages=max(1, math.ceil(total / page_size)),
    )


@router.get("/{source_id}", response_model=SourceSummary)
async def get_source(
    source_id: UUID,
    db: AsyncSession = Depends(get_db),
    _user: TokenData = Depends(require_roles("admin", "analyst", "read_only")),
) -> SourceSummary:
    source = (await db.execute(select(Source).where(Source.id == source_id))).scalars().first()
    if source is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Source not found")
    return SourceSummary.model_validate(source)


@router.post("", response_model=SourceSummary, status_code=status.HTTP_201_CREATED)
async def register_source(
    body: SourceCreate,
    db: AsyncSession = Depends(get_db),
    _user: TokenData = Depends(require_roles("admin")),
) -> SourceSummary:
    """Register a new log source.  Triggers an ingest service registry reload."""
    # Check for duplicate IP
    existing = (
        await db.execute(select(Source).where(Source.ip_address == body.ip_address))
    ).scalars().first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Source with IP {body.ip_address} already registered (id={existing.id})",
        )

    source = Source(**body.model_dump())
    db.add(source)
    await db.commit()
    await db.refresh(source)
    await _notify_ingest_reload()
    return SourceSummary.model_validate(source)


@router.patch("/{source_id}/enable", response_model=SourceSummary)
async def enable_source(
    source_id: UUID,
    db: AsyncSession = Depends(get_db),
    _user: TokenData = Depends(require_roles("admin")),
) -> SourceSummary:
    source = (await db.execute(select(Source).where(Source.id == source_id))).scalars().first()
    if source is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Source not found")
    source.enabled = True
    await db.commit()
    await db.refresh(source)
    await _notify_ingest_reload()
    return SourceSummary.model_validate(source)


@router.patch("/{source_id}/disable", response_model=SourceSummary)
async def disable_source(
    source_id: UUID,
    db: AsyncSession = Depends(get_db),
    _user: TokenData = Depends(require_roles("admin")),
) -> SourceSummary:
    source = (await db.execute(select(Source).where(Source.id == source_id))).scalars().first()
    if source is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Source not found")
    source.enabled = False
    await db.commit()
    await db.refresh(source)
    await _notify_ingest_reload()
    return SourceSummary.model_validate(source)
