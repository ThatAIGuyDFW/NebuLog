"""Correlation engine unit tests.

Uses asyncpg-stubs (mock connection/pool) to avoid a real database.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID, uuid4

import pytest
from pydantic import ValidationError

from correlation.rule_dsl import (
    ALLOWED_COLUMNS,
    AbsenceBody,
    AnomalyBody,
    BlacklistBody,
    EventFilter,
    SequenceBody,
    SequenceStep,
    ThresholdBody,
    OutsideHours,
    parse_rule_body,
)
from correlation.evaluators.base import AlertTrigger, QueryBuilder, build_event_filter, safe_col
from correlation.evaluators.threshold import ThresholdEvaluator
from correlation.evaluators.sequence import SequenceEvaluator
from correlation.evaluators.absence import AbsenceEvaluator
from correlation.evaluators.blacklist import BlacklistEvaluator
from correlation.evaluators.anomaly import AnomalyEvaluator


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_NOW = datetime(2026, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
_RULE_ID = uuid4()


def _row(**kwargs) -> dict:
    """Create a mock asyncpg Row-like dict."""
    return kwargs


# ---------------------------------------------------------------------------
# DSL validation tests
# ---------------------------------------------------------------------------

class TestDslValidation:
    def test_threshold_allowed_group_by(self):
        body = ThresholdBody(group_by="src_ip", count=5, window_seconds=600)
        assert body.group_by == "src_ip"

    def test_threshold_disallowed_group_by(self):
        with pytest.raises(ValidationError, match="allowed columns"):
            ThresholdBody(group_by="message", count=5, window_seconds=600)

    def test_threshold_distinct_users(self):
        body = ThresholdBody(distinct_users=3, window_seconds=300)
        assert body.distinct_users == 3
        assert body.count == 1  # default

    def test_threshold_outside_hours(self):
        body = ThresholdBody(
            count=1, window_seconds=3600,
            outside_hours=OutsideHours(start=6, end=20)
        )
        assert body.outside_hours.start == 6

    def test_sequence_requires_two_steps(self):
        with pytest.raises(ValidationError):
            SequenceBody(
                steps=[SequenceStep(event_id="4624")],
                group_by="src_ip",
                window_seconds=300,
            )

    def test_sequence_step_needs_one_field(self):
        with pytest.raises(ValidationError, match="at least one"):
            SequenceStep()

    def test_sequence_disallowed_group_by(self):
        with pytest.raises(ValidationError, match="allowed columns"):
            SequenceBody(
                steps=[SequenceStep(event_id="4624"), SequenceStep(event_id="4625")],
                group_by="raw_message",
                window_seconds=300,
            )

    def test_absence_body(self):
        body = AbsenceBody(window_seconds=86400)
        assert body.window_seconds == 86400

    def test_blacklist_field_validated(self):
        with pytest.raises(ValidationError, match="allowed columns"):
            BlacklistBody(field="raw_message", list_name="known_bad")

    def test_blacklist_allowed_field(self):
        body = BlacklistBody(field="src_ip", list_name="tor_exits")
        assert body.field == "src_ip"

    def test_anomaly_defaults(self):
        body = AnomalyBody()
        assert body.std_devs == 3.0
        assert body.baseline_days == 7

    def test_parse_rule_body_unknown_type(self):
        with pytest.raises(ValueError, match="Unknown rule_type"):
            parse_rule_body("magic", {})

    def test_parse_rule_body_threshold(self):
        body = parse_rule_body(
            "threshold",
            {"count": 10, "window_seconds": 60, "group_by": "user_name"}
        )
        assert isinstance(body, ThresholdBody)

    def test_allowed_columns_set(self):
        assert "src_ip" in ALLOWED_COLUMNS
        assert "message" not in ALLOWED_COLUMNS


# ---------------------------------------------------------------------------
# QueryBuilder tests
# ---------------------------------------------------------------------------

class TestQueryBuilder:
    def test_empty_where(self):
        qb = QueryBuilder()
        assert qb.where == "TRUE"
        assert qb.params == []

    def test_single_condition(self):
        qb = QueryBuilder()
        qb.add("received_at >= NOW() - ?::interval", "600 seconds")
        assert "$1" in qb.where
        assert qb.params == ["600 seconds"]

    def test_multiple_conditions(self):
        qb = QueryBuilder()
        qb.add("a = ?", 1)
        qb.add("b = ?", 2)
        assert "$1" in qb.where
        assert "$2" in qb.where
        assert len(qb.params) == 2

    def test_next_param_increments(self):
        qb = QueryBuilder()
        assert qb.next_param() == "$1"
        qb.add("x = ?", 99)
        assert qb.next_param() == "$2"


class TestSafeCol:
    def test_allowed(self):
        for col in ALLOWED_COLUMNS:
            assert safe_col(col) == col

    def test_not_allowed(self):
        with pytest.raises(ValueError, match="ALLOWED_COLUMNS"):
            safe_col("DROP TABLE events")


class TestBuildEventFilter:
    def test_basic_filter(self):
        qb = QueryBuilder()
        f = EventFilter(category="auth", source_type="windows")
        build_event_filter(qb, f, window_seconds=600)
        where = qb.where
        assert "received_at" in where
        assert "category" in where
        assert "source_type" in where

    def test_tags_filter(self):
        qb = QueryBuilder()
        f = EventFilter(tags=["hipaa:auth"])
        build_event_filter(qb, f, window_seconds=60)
        assert "tags" in qb.where


# ---------------------------------------------------------------------------
# ThresholdEvaluator tests
# ---------------------------------------------------------------------------

class TestThresholdEvaluator:
    _ev = ThresholdEvaluator()

    async def _conn_with_rows(self, rows):
        conn = AsyncMock()
        conn.fetch = AsyncMock(return_value=rows)
        conn.fetchrow = AsyncMock(return_value=rows[0] if rows else None)
        return conn

    @pytest.mark.asyncio
    async def test_grouped_threshold_fires(self):
        row = {
            "src_ip": "10.0.0.1",
            "cnt": 10,
            "first_seen": _NOW,
            "last_seen": _NOW,
        }
        conn = await self._conn_with_rows([row])
        body = ThresholdBody(group_by="src_ip", count=5, window_seconds=600)
        results = await self._ev.evaluate(_RULE_ID, "Test", "critical", body, conn)
        assert len(results) == 1
        assert results[0].src_ip == "10.0.0.1"
        assert results[0].event_count == 10

    @pytest.mark.asyncio
    async def test_ungrouped_below_threshold(self):
        row = {"cnt": 3, "first_seen": _NOW, "last_seen": _NOW}
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value=row)
        body = ThresholdBody(count=5, window_seconds=600)
        results = await self._ev.evaluate(_RULE_ID, "Test", "high", body, conn)
        assert results == []

    @pytest.mark.asyncio
    async def test_ungrouped_at_threshold(self):
        row = {"cnt": 5, "first_seen": _NOW, "last_seen": _NOW}
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value=row)
        body = ThresholdBody(count=5, window_seconds=600)
        results = await self._ev.evaluate(_RULE_ID, "Test", "high", body, conn)
        assert len(results) == 1

    @pytest.mark.asyncio
    async def test_outside_hours_filters_in_window(self):
        """Event at noon UTC — if outside_hours is 9–17, it should be excluded."""
        row = {
            "src_ip": "10.0.0.1",
            "cnt": 10,
            "first_seen": _NOW,  # 12:00 UTC
            "last_seen": _NOW,
        }
        conn = await self._conn_with_rows([row])
        body = ThresholdBody(
            group_by="src_ip", count=5, window_seconds=600,
            outside_hours=OutsideHours(start=9, end=17)
        )
        results = await self._ev.evaluate(_RULE_ID, "Test", "critical", body, conn)
        # noon is IN the window (9 ≤ 12 < 17) → NOT outside → filtered out
        assert results == []

    @pytest.mark.asyncio
    async def test_outside_hours_passes_after_hours(self):
        """Event at 22:00 UTC — outside 9–17 window → should fire."""
        late = datetime(2026, 1, 15, 22, 0, 0, tzinfo=timezone.utc)
        row = {
            "src_ip": "10.0.0.1",
            "cnt": 10,
            "first_seen": late,
            "last_seen": late,
        }
        conn = await self._conn_with_rows([row])
        body = ThresholdBody(
            group_by="src_ip", count=5, window_seconds=600,
            outside_hours=OutsideHours(start=9, end=17)
        )
        results = await self._ev.evaluate(_RULE_ID, "Test", "critical", body, conn)
        assert len(results) == 1


# ---------------------------------------------------------------------------
# AbsenceEvaluator tests
# ---------------------------------------------------------------------------

class TestAbsenceEvaluator:
    _ev = AbsenceEvaluator()

    @pytest.mark.asyncio
    async def test_fires_when_no_events(self):
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value={"cnt": 0})
        body = AbsenceBody(window_seconds=86400)
        results = await self._ev.evaluate(_RULE_ID, "Heartbeat", "medium", body, conn)
        assert len(results) == 1
        assert results[0].event_count == 0

    @pytest.mark.asyncio
    async def test_no_fire_when_events_exist(self):
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value={"cnt": 5})
        body = AbsenceBody(window_seconds=86400)
        results = await self._ev.evaluate(_RULE_ID, "Heartbeat", "medium", body, conn)
        assert results == []


# ---------------------------------------------------------------------------
# BlacklistEvaluator tests
# ---------------------------------------------------------------------------

class TestBlacklistEvaluator:
    _ev = BlacklistEvaluator()

    @pytest.mark.asyncio
    async def test_fires_on_match(self):
        conn = AsyncMock()
        conn.fetch = AsyncMock(return_value=[{
            "src_ip": "1.2.3.4",
            "first_seen": _NOW,
            "last_seen": _NOW,
            "cnt": 3,
        }])
        body = BlacklistBody(field="src_ip", list_name="threat_intel")
        results = await self._ev.evaluate(_RULE_ID, "ThreatIP", "critical", body, conn)
        assert len(results) == 1
        assert results[0].src_ip == "1.2.3.4"

    @pytest.mark.asyncio
    async def test_no_fire_on_empty(self):
        conn = AsyncMock()
        conn.fetch = AsyncMock(return_value=[])
        body = BlacklistBody(field="src_ip", list_name="threat_intel")
        results = await self._ev.evaluate(_RULE_ID, "ThreatIP", "critical", body, conn)
        assert results == []


# ---------------------------------------------------------------------------
# AnomalyEvaluator tests
# ---------------------------------------------------------------------------

class TestAnomalyEvaluator:
    _ev = AnomalyEvaluator()

    @pytest.mark.asyncio
    async def test_fires_on_anomaly(self):
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(side_effect=[
            {"cnt": 500},                              # current window
            {"mean": 50.0, "stddev": 10.0},           # baseline
        ])
        body = AnomalyBody(std_devs=3.0, baseline_days=7, window_seconds=3600)
        results = await self._ev.evaluate(_RULE_ID, "Spike", "high", body, conn)
        assert len(results) == 1
        assert results[0].extra["z_score"] == pytest.approx(45.0)

    @pytest.mark.asyncio
    async def test_no_fire_within_threshold(self):
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(side_effect=[
            {"cnt": 55},
            {"mean": 50.0, "stddev": 10.0},
        ])
        body = AnomalyBody(std_devs=3.0)
        results = await self._ev.evaluate(_RULE_ID, "Spike", "high", body, conn)
        assert results == []

    @pytest.mark.asyncio
    async def test_no_fire_without_baseline(self):
        conn = AsyncMock()
        conn.fetchrow = AsyncMock(side_effect=[
            {"cnt": 999},
            {"mean": None, "stddev": None},
        ])
        body = AnomalyBody()
        results = await self._ev.evaluate(_RULE_ID, "Spike", "high", body, conn)
        assert results == []


# ---------------------------------------------------------------------------
# SequenceEvaluator tests
# ---------------------------------------------------------------------------

class TestSequenceEvaluator:
    _ev = SequenceEvaluator()

    @pytest.mark.asyncio
    async def test_fires_on_sequence_match(self):
        conn = AsyncMock()
        conn.fetch = AsyncMock(return_value=[{
            "src_ip": "192.168.1.10",
            "first_seen": _NOW,
            "last_seen": _NOW,
        }])
        body = SequenceBody(
            steps=[SequenceStep(event_id="4625"), SequenceStep(event_id="4624")],
            group_by="src_ip",
            window_seconds=600,
        )
        results = await self._ev.evaluate(_RULE_ID, "Brute+Login", "critical", body, conn)
        assert len(results) == 1
        assert results[0].event_count == 2

    @pytest.mark.asyncio
    async def test_no_fire_on_empty(self):
        conn = AsyncMock()
        conn.fetch = AsyncMock(return_value=[])
        body = SequenceBody(
            steps=[SequenceStep(action="deny"), SequenceStep(action="allow")],
            group_by="src_ip",
            window_seconds=300,
        )
        results = await self._ev.evaluate(_RULE_ID, "Probe", "medium", body, conn)
        assert results == []


# ---------------------------------------------------------------------------
# Engine deduplication tests
# ---------------------------------------------------------------------------

class TestEngineDeduplication:
    """Test that the engine correctly deduplicates open alerts."""

    @pytest.mark.asyncio
    async def test_updates_existing_open_alert(self):
        from correlation.engine import CorrelationEngine

        engine = CorrelationEngine.__new__(CorrelationEngine)
        engine._dsn = "mock"

        conn = AsyncMock()
        existing_id = uuid4()
        conn.fetchrow = AsyncMock(return_value={"id": existing_id})
        conn.execute = AsyncMock()

        trigger = AlertTrigger(
            rule_id=_RULE_ID,
            severity="high",
            title="Test",
            description="Updated",
            src_ip="1.2.3.4",
            source_host=None,
            first_seen=_NOW,
            last_seen=_NOW,
            event_count=5,
            group_key=f"{_RULE_ID}:1.2.3.4",
        )

        await engine._upsert_alert(conn, trigger)

        # Should UPDATE, not INSERT
        conn.execute.assert_called_once()
        call_args = conn.execute.call_args[0]
        assert "UPDATE alerts" in call_args[0]

    @pytest.mark.asyncio
    async def test_inserts_new_alert(self):
        from correlation.engine import CorrelationEngine

        engine = CorrelationEngine.__new__(CorrelationEngine)
        engine._dsn = "mock"

        conn = AsyncMock()
        conn.fetchrow = AsyncMock(return_value=None)  # no existing open alert
        conn.execute = AsyncMock()

        trigger = AlertTrigger(
            rule_id=_RULE_ID,
            severity="critical",
            title="New Alert",
            description="First occurrence",
            src_ip="5.6.7.8",
            source_host=None,
            first_seen=_NOW,
            last_seen=_NOW,
            event_count=10,
            group_key=f"{_RULE_ID}:5.6.7.8",
        )

        await engine._upsert_alert(conn, trigger)

        conn.execute.assert_called_once()
        call_args = conn.execute.call_args[0]
        assert "INSERT INTO alerts" in call_args[0]
