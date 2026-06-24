"""GET /compliance/report — HIPAA and PCI DSS compliance summary."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from api.auth import TokenData, require_roles
from api.db import get_db
from api.models.db_models import Event, Source
from api.models.schemas import (
    CategoryCount, ComplianceReport, LogGap, RetentionPosture,
)

router = APIRouter(prefix="/compliance", tags=["Compliance"])

_HIPAA_RETENTION_YEARS = 6
_PCI_HOT_MONTHS = 12


@router.get("/report", response_model=ComplianceReport)
async def compliance_report(
    framework: str = Query(..., description="hipaa | pci_dss"),
    time_from: datetime | None = Query(None),
    time_to: datetime | None = Query(None),
    db: AsyncSession = Depends(get_db),
    _user: TokenData = Depends(require_roles("admin", "analyst", "read_only")),
) -> ComplianceReport:
    if framework not in ("hipaa", "pci_dss"):
        raise HTTPException(400, "framework must be 'hipaa' or 'pci_dss'")

    now = datetime.now(tz=timezone.utc)
    period_to = time_to or now
    period_from = time_from or (now - timedelta(days=30))

    # -----------------------------------------------------------------------
    # Core event counts
    # -----------------------------------------------------------------------
    total: int = (
        await db.execute(
            select(func.count()).select_from(Event)
            .where(Event.received_at.between(period_from, period_to))
        )
    ).scalar_one()

    cat_rows = (
        await db.execute(
            select(Event.category, func.count().label("cnt"))
            .where(Event.received_at.between(period_from, period_to))
            .where(Event.category.isnot(None))
            .group_by(Event.category)
            .order_by(func.count().desc())
        )
    ).all()

    # Failed logins (event_id 4625 or action = logon_failed)
    failed_logins: int = (
        await db.execute(
            select(func.count()).select_from(Event)
            .where(Event.received_at.between(period_from, period_to))
            .where(
                (Event.event_id == "4625")
                | (Event.action == "logon_failed")
            )
        )
    ).scalar_one()

    # Privilege escalations (event_id 4672 or action = privileged_logon)
    priv_escalations: int = (
        await db.execute(
            select(func.count()).select_from(Event)
            .where(Event.received_at.between(period_from, period_to))
            .where(
                (Event.event_id == "4672")
                | (Event.action == "privileged_logon")
            )
        )
    ).scalar_one()

    # Audit log clears
    audit_clears: int = (
        await db.execute(
            select(func.count()).select_from(Event)
            .where(Event.received_at.between(period_from, period_to))
            .where(
                (Event.event_id == "1102")
                | (Event.event_id == "0100044546")
            )
        )
    ).scalar_one()

    # -----------------------------------------------------------------------
    # Log gaps: sources that have not sent an event in > 24 hours
    # -----------------------------------------------------------------------
    last_seen_rows = (
        await db.execute(
            select(Event.source_host, func.max(Event.received_at).label("last_seen"))
            .where(Event.received_at.between(period_from, period_to))
            .group_by(Event.source_host)
        )
    ).all()

    log_gaps: list[LogGap] = []
    gap_threshold = now - timedelta(hours=24)
    for host, last_seen in last_seen_rows:
        if last_seen and last_seen < gap_threshold:
            gap_hours = (now - last_seen).total_seconds() / 3600
            log_gaps.append(LogGap(source_host=host, last_seen=last_seen, gap_hours=round(gap_hours, 1)))

    # -----------------------------------------------------------------------
    # Retention posture
    # -----------------------------------------------------------------------
    oldest_event: datetime | None = (
        await db.execute(select(func.min(Event.received_at)))
    ).scalar_one()

    required_years = _HIPAA_RETENTION_YEARS if framework == "hipaa" else 2
    hot_months = 12 if framework == "hipaa" else _PCI_HOT_MONTHS

    if oldest_event:
        age_years = (now - oldest_event).days / 365.25
        compliant = age_years >= required_years
    else:
        compliant = False

    retention = RetentionPosture(
        oldest_event=oldest_event,
        required_retention_years=required_years,
        hot_storage_months=hot_months,
        compliant=compliant,
    )

    # -----------------------------------------------------------------------
    # PCI-specific metrics
    # -----------------------------------------------------------------------
    cardholder_events: int | None = None
    daily_gaps: list[str] | None = None

    if framework == "pci_dss":
        cardholder_events = (
            await db.execute(
                select(func.count()).select_from(Event)
                .where(Event.received_at.between(period_from, period_to))
                .where(Event.tags.contains(["pci_dss"]))
            )
        ).scalar_one()

        # Days with no events from any source (PCI Req 10.6 — daily review)
        days_in_period = (period_to - period_from).days + 1
        active_dates_rows = (
            await db.execute(
                select(func.date_trunc("day", Event.received_at).label("day"))
                .where(Event.received_at.between(period_from, period_to))
                .distinct()
            )
        ).all()
        active_dates = {r[0].date() for r in active_dates_rows if r[0]}
        all_dates = {
            (period_from + timedelta(days=i)).date()
            for i in range(days_in_period)
        }
        silent_dates = sorted(all_dates - active_dates)
        daily_gaps = [d.isoformat() for d in silent_dates]

    return ComplianceReport(
        framework=framework,
        period_from=period_from,
        period_to=period_to,
        generated_at=now,
        total_events=total,
        events_by_category=[CategoryCount(category=r[0], count=r[1]) for r in cat_rows],
        failed_logins=failed_logins,
        privilege_escalations=priv_escalations,
        audit_log_clears=audit_clears,
        log_gaps=log_gaps,
        retention_posture=retention,
        cardholder_env_events=cardholder_events,
        daily_review_gaps=daily_gaps,
    )
