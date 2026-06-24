"""GET /rules, POST /rules, PUT /rules/{id}, DELETE /rules/{id}."""

from __future__ import annotations

import math
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import TokenData, require_roles
from api.db import get_db
from api.models.db_models import AlertRule
from api.models.schemas import PaginatedResponse, RuleCreate, RuleDetail, RuleSummary, RuleUpdate

router = APIRouter(prefix="/rules", tags=["Correlation Rules"])


@router.get("", response_model=PaginatedResponse[RuleSummary])
async def list_rules(
    rule_type: str | None = Query(None),
    enabled: bool | None = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
    _user: TokenData = Depends(require_roles("admin", "analyst", "read_only")),
) -> PaginatedResponse[RuleSummary]:
    stmt = select(AlertRule)
    if rule_type:
        stmt = stmt.where(AlertRule.rule_type == rule_type)
    if enabled is not None:
        stmt = stmt.where(AlertRule.enabled == enabled)

    total: int = (await db.execute(select(func.count()).select_from(stmt.subquery()))).scalar_one()
    rows = (
        await db.execute(
            stmt.order_by(AlertRule.name)
            .offset((page - 1) * page_size)
            .limit(page_size)
        )
    ).scalars().all()

    return PaginatedResponse(
        items=[RuleSummary.model_validate(r) for r in rows],
        total=total,
        page=page,
        page_size=page_size,
        pages=max(1, math.ceil(total / page_size)),
    )


@router.get("/{rule_id}", response_model=RuleDetail)
async def get_rule(
    rule_id: UUID,
    db: AsyncSession = Depends(get_db),
    _user: TokenData = Depends(require_roles("admin", "analyst", "read_only")),
) -> RuleDetail:
    rule = (await db.execute(select(AlertRule).where(AlertRule.id == rule_id))).scalars().first()
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    return RuleDetail.model_validate(rule)


@router.post("", response_model=RuleDetail, status_code=status.HTTP_201_CREATED)
async def create_rule(
    body: RuleCreate,
    db: AsyncSession = Depends(get_db),
    _user: TokenData = Depends(require_roles("admin")),
) -> RuleDetail:
    rule = AlertRule(**body.model_dump())
    db.add(rule)
    await db.commit()
    await db.refresh(rule)
    return RuleDetail.model_validate(rule)


@router.put("/{rule_id}", response_model=RuleDetail)
async def update_rule(
    rule_id: UUID,
    body: RuleUpdate,
    db: AsyncSession = Depends(get_db),
    _user: TokenData = Depends(require_roles("admin")),
) -> RuleDetail:
    rule = (await db.execute(select(AlertRule).where(AlertRule.id == rule_id))).scalars().first()
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")

    for field, value in body.model_dump(exclude_none=True).items():
        setattr(rule, field, value)

    from sqlalchemy import func as sqlfunc
    rule.updated_at = sqlfunc.now()
    await db.commit()
    await db.refresh(rule)
    return RuleDetail.model_validate(rule)


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_rule(
    rule_id: UUID,
    db: AsyncSession = Depends(get_db),
    _user: TokenData = Depends(require_roles("admin")),
) -> None:
    rule = (await db.execute(select(AlertRule).where(AlertRule.id == rule_id))).scalars().first()
    if rule is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Rule not found")
    await db.delete(rule)
    await db.commit()
