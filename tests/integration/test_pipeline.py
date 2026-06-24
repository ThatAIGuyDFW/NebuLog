"""Integration test: 1000 sample events through the full ingest pipeline.

Tests the path:
  Parser → NormalizedEvent → Redis (events:normalized) → StorageWorker → PostgreSQL

The archive worker is exercised via a separate buffer-and-upload test that
writes to the local filesystem (no Azure credentials needed in CI).

Run with:
    docker compose up -d
    cd db && alembic upgrade head
    pytest tests/integration/ -v -m integration
"""

from __future__ import annotations

import asyncio
import json
import os
import random
import time
from datetime import datetime, timezone
from typing import Any

import pytest
import pytest_asyncio

from ingest.models import NormalizedEvent, SourceType

# ---------------------------------------------------------------------------
# Sample log generators (one per source type × 250 = 1000 total)
# ---------------------------------------------------------------------------

_FG_TEMPLATES = [
    '<190>date=2024-01-15 time=10:23:45 devname="FGT-HQ" logid="0000000013" '
    'type="traffic" subtype="forward" level="notice" vd="root" '
    'srcip={src} srcport={sp} dstip={dst} dstport={dp} proto=6 action="accept" msg="allowed"',
    '<182>date=2024-01-15 time=10:24:00 devname="FGT-HQ" logid="0000000022" '
    'type="traffic" subtype="forward" level="warning" vd="root" '
    'srcip={src} srcport={sp} dstip={dst} dstport={dp} proto=17 action="deny" msg="denied"',
    '<164>date=2024-01-15 time=12:00:00 devname="FGT-HQ" logid="0419016384" '
    'type="utm" subtype="ips" level="alert" vd="root" '
    'srcip={src} srcport={sp} dstip={dst} dstport=80 proto=6 action="blocked" msg="IPS alert"',
]

_CISCO_TEMPLATES = [
    "<134>Jan 15 10:23:45 asa.corp.com %ASA-6-302013: Built outbound TCP connection "
    "12345 for outside:{dst}/443 ({dst}/443) to inside:{src}/{sp} ({src}/{sp})",
    "<165>Jan 15 10:25:00 asa.corp.com %ASA-5-106023: Deny tcp src "
    "outside:{src}/{sp} dst inside:{dst}/22 by access-group \"outside_acl\"",
    "<166>Jan 15 12:01:00 asa.corp.com %ASA-6-611102: User authentication failed: Uname: badactor",
]

_WIN_TEMPLATES: list[dict[str, Any]] = [
    {"EventID": 4624, "TimeCreated": "2024-01-15T10:23:45Z", "Computer": "WS-{idx}",
     "Channel": "Security", "Level": 0,
     "EventData": {"TargetUserName": "user{idx}", "IpAddress": "{src}", "IpPort": "{sp}", "LogonType": "3"}},
    {"EventID": 4625, "TimeCreated": "2024-01-15T10:24:00Z", "Computer": "WS-{idx}",
     "Channel": "Security", "Level": 4,
     "EventData": {"TargetUserName": "badactor", "IpAddress": "{src}", "IpPort": "{sp}", "LogonType": "3"}},
    {"EventID": 4688, "TimeCreated": "2024-01-15T10:25:00Z", "Computer": "WS-{idx}",
     "Channel": "Security", "Level": 0,
     "EventData": {"SubjectUserName": "user{idx}", "NewProcessName": "C:\\Windows\\System32\\cmd.exe"}},
]

_LINUX_TEMPLATES: list[dict[str, Any]] = [
    {"__REALTIME_TIMESTAMP": "1705311825000000", "_HOSTNAME": "linux-{idx}",
     "SYSLOG_IDENTIFIER": "sshd", "PRIORITY": "6",
     "MESSAGE": "Accepted publickey for user{idx} from {src} port {sp} ssh2"},
    {"__REALTIME_TIMESTAMP": "1705311825000000", "_HOSTNAME": "linux-{idx}",
     "SYSLOG_IDENTIFIER": "sshd", "PRIORITY": "5",
     "MESSAGE": "Failed password for user{idx} from {src} port {sp} ssh2"},
    {"timestamp": "2024-01-15T10:30:00Z", "hostname": "linux-{idx}",
     "program": "sudo", "severity": 5,
     "message": "user{idx} : TTY=pts/1 ; PWD=/home/user ; USER=root ; COMMAND=/bin/bash"},
]


def _rand_ip() -> str:
    return f"10.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"


def _rand_port() -> int:
    return random.randint(1024, 65535)


def _fill(template, idx: int) -> Any:
    src, dst, sp = _rand_ip(), _rand_ip(), str(_rand_port())
    if isinstance(template, str):
        return template.format(src=src, dst=dst, sp=sp, dp=str(_rand_port()), idx=idx)
    # dict template — deep copy and fill strings
    import copy
    d = copy.deepcopy(template)
    def _sub(obj):
        if isinstance(obj, str):
            return obj.format(src=src, dst=dst, sp=sp, idx=idx)
        if isinstance(obj, dict):
            return {k: _sub(v) for k, v in obj.items()}
        return obj
    return _sub(d)


def _generate_events(n: int = 250) -> dict[SourceType, list[Any]]:
    rng = random.Random(42)
    fg = [_fill(rng.choice(_FG_TEMPLATES), i) for i in range(n)]
    cs = [_fill(rng.choice(_CISCO_TEMPLATES), i) for i in range(n)]
    win = [_fill(rng.choice(_WIN_TEMPLATES), i) for i in range(n)]
    lnx = [_fill(rng.choice(_LINUX_TEMPLATES), i) for i in range(n)]
    return {
        SourceType.fortigate: fg,
        SourceType.cisco_asa: cs,
        SourceType.windows: win,
        SourceType.linux: lnx,
    }


# ---------------------------------------------------------------------------
# Helper: parse all events to NormalizedEvent
# ---------------------------------------------------------------------------

def _parse_all(events_by_type: dict[SourceType, list[Any]]) -> list[NormalizedEvent]:
    from ingest.parsers import FortiGateParser, CiscoASAParser, WindowsParser, LinuxParser
    parsers = {
        SourceType.fortigate: FortiGateParser(),
        SourceType.cisco_asa: CiscoASAParser(),
        SourceType.windows: WindowsParser(),
        SourceType.linux: LinuxParser(),
    }
    now = datetime.now(tz=timezone.utc)
    results = []
    for source_type, items in events_by_type.items():
        parser = parsers[source_type]
        for item in items:
            try:
                evt = parser.parse(item, "10.0.0.1", now)
                results.append(evt)
            except Exception as exc:
                pytest.fail(f"Parser {source_type} failed: {exc}")
    return results


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

@pytest.mark.integration
class TestParseTo1000:
    """Parse 1000 events without errors (no external services needed)."""

    def test_parse_count(self):
        events = _generate_events(250)
        parsed = _parse_all(events)
        assert len(parsed) == 1000

    def test_all_have_source_type(self):
        events = _generate_events(250)
        parsed = _parse_all(events)
        assert all(e.source_type for e in parsed)

    def test_all_have_message(self):
        events = _generate_events(250)
        parsed = _parse_all(events)
        assert all(e.message for e in parsed)

    def test_source_type_distribution(self):
        events = _generate_events(250)
        parsed = _parse_all(events)
        counts = {}
        for e in parsed:
            counts[e.source_type] = counts.get(e.source_type, 0) + 1
        assert counts.get("fortigate", 0) == 250
        assert counts.get("cisco_asa", 0) == 250
        assert counts.get("windows", 0) == 250
        assert counts.get("linux", 0) == 250


@pytest.mark.integration
@pytest.mark.asyncio
class TestRedisPublish:
    """Publish 1000 events to Redis and verify stream lengths."""

    async def test_publish_normalized(self, redis_client):
        stream = "test:events:normalized"
        # Clean up from previous runs
        try:
            await redis_client.delete(stream)
        except Exception:
            pass

        from ingest.publisher import RedisPublisher
        pub = RedisPublisher(
            os.getenv("REDIS_URL", "redis://localhost:6379/0"),
            stream_normalized=stream,
            stream_raw="test:events:raw",
            stream_errors="test:sentinel:errors",
        )

        events = _generate_events(250)
        parsed = _parse_all(events)
        for evt in parsed:
            await pub.publish_normalized(evt)
        await pub.close()

        length = await redis_client.xlen(stream)
        assert length == 1000, f"Expected 1000 messages in stream, got {length}"

        # Cleanup
        await redis_client.delete(stream)
        await redis_client.delete("test:events:raw")
        await redis_client.delete("test:sentinel:errors")

    async def test_publish_raw(self, redis_client):
        stream = "test:events:raw2"
        try:
            await redis_client.delete(stream)
        except Exception:
            pass

        from ingest.publisher import RedisPublisher
        pub = RedisPublisher(
            os.getenv("REDIS_URL", "redis://localhost:6379/0"),
            stream_normalized="test:events:normalized2",
            stream_raw=stream,
            stream_errors="test:sentinel:errors2",
        )

        for i in range(50):
            await pub.publish_raw(f"raw syslog line {i}", "10.0.0.1", "fortigate")
        await pub.close()

        length = await redis_client.xlen(stream)
        assert length == 50

        await redis_client.delete(stream)
        await redis_client.delete("test:events:normalized2")
        await redis_client.delete("test:sentinel:errors2")


@pytest.mark.integration
@pytest.mark.asyncio
class TestStorageWorker:
    """Publish 1000 events to Redis and verify they land in PostgreSQL."""

    async def test_events_inserted_to_db(self, redis_client, db_conn):
        """Publish events to a test stream and run the storage worker to consume them."""
        import asyncpg
        from workers.storage_worker import StorageWorker, _ensure_consumer_group, FLUSH_INTERVAL

        test_stream = "test:pipeline:normalized"
        test_group = "test-storage"

        # Clean test stream
        try:
            await redis_client.delete(test_stream)
        except Exception:
            pass

        # Remove any test events from previous runs
        await db_conn.execute(
            "DELETE FROM events WHERE ingest_node = $1", "pipeline-test"
        )

        # Publish 1000 parsed events to the test stream
        events = _generate_events(250)
        parsed = _parse_all(events)
        for evt in parsed:
            evt.ingest_node = "pipeline-test"
            await redis_client.xadd(test_stream, {"data": evt.model_dump_json()})

        # Spin up a storage worker instance pointing at the test stream
        worker = StorageWorker(
            redis_url=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
            database_url=os.getenv("DATABASE_URL", "").replace("+asyncpg", ""),
            geoip_db_path=os.getenv("GEOIP_DB_PATH", ""),
            consumer_name="test-worker",
        )

        # Patch the stream name for this test
        import workers.storage_worker as sw_module
        original_stream = sw_module.STREAM
        sw_module.STREAM = test_stream

        # Ensure consumer group exists for test stream
        try:
            await redis_client.xgroup_create(test_stream, test_group, id="0")
        except Exception:
            pass

        # Run worker for just long enough to consume all 1000 messages
        # (FLUSH_INTERVAL is 5s; we give it 15s to be safe)
        try:
            await asyncio.wait_for(
                _run_worker_until_empty(worker, redis_client, test_stream, test_group),
                timeout=30.0,
            )
        except asyncio.TimeoutError:
            pytest.fail("Storage worker did not process all events within 30 seconds")
        finally:
            sw_module.STREAM = original_stream

        # Verify in DB
        count = await db_conn.fetchval(
            "SELECT COUNT(*) FROM events WHERE ingest_node = $1", "pipeline-test"
        )
        assert count == 1000, f"Expected 1000 events in DB, found {count}"

        # Clean up
        await db_conn.execute(
            "DELETE FROM events WHERE ingest_node = $1", "pipeline-test"
        )
        await redis_client.delete(test_stream)


async def _run_worker_until_empty(worker, redis_client, stream: str, group: str) -> None:
    """Run the storage worker until the stream is empty, then stop."""
    # We drive the worker manually rather than calling worker.run() (which loops forever)
    import asyncpg
    from workers.storage_worker import _batch_insert, BATCH_SIZE, FLUSH_INTERVAL

    db = await asyncpg.connect(
        os.getenv("DATABASE_URL", "").replace("+asyncpg", "")
    )
    batch = []
    ack_ids = []
    try:
        while True:
            messages = await redis_client.xreadgroup(
                group, "test-worker",
                {stream: ">"},
                count=BATCH_SIZE,
                block=500,
            )
            if not messages:
                # Stream empty — flush remaining and exit
                if batch:
                    await _batch_insert(db, batch)
                    if ack_ids:
                        await redis_client.xack(stream, group, *ack_ids)
                break
            _, entries = messages[0]
            for msg_id, fields in entries:
                try:
                    evt = NormalizedEvent.model_validate_json(fields["data"])
                    worker._enrich(evt)
                    from workers.storage_worker import _to_row
                    batch.append(_to_row(evt))
                    ack_ids.append(msg_id)
                except Exception:
                    ack_ids.append(msg_id)
            if len(batch) >= BATCH_SIZE:
                await _batch_insert(db, batch)
                if ack_ids:
                    await redis_client.xack(stream, group, *ack_ids)
                batch.clear()
                ack_ids.clear()
    finally:
        await db.close()


@pytest.mark.integration
@pytest.mark.asyncio
class TestComplianceTags:
    """Verify compliance tagging is applied during storage worker enrichment."""

    async def test_audit_clear_gets_pci_tag(self):
        from workers.storage_worker import StorageWorker
        worker = StorageWorker(
            redis_url="redis://localhost:6379/0",
            database_url="",
            geoip_db_path="",
            consumer_name="test",
        )
        evt = NormalizedEvent(
            received_at=datetime.now(tz=timezone.utc),
            source_host="WIN-01",
            source_type=SourceType.windows,
            message="Audit log cleared",
            event_id="1102",
        )
        worker._enrich(evt)
        assert "pci_dss" in evt.tags
        assert "hipaa:integrity" in evt.tags

    async def test_ssh_logon_gets_hipaa_auth(self):
        from ingest.models import Category
        from workers.compliance import apply_compliance_tags
        evt = NormalizedEvent(
            received_at=datetime.now(tz=timezone.utc),
            source_host="linux-01",
            source_type=SourceType.linux,
            category=Category.auth,
            message="SSH login",
        )
        apply_compliance_tags(evt)
        assert "hipaa:auth" in evt.tags


@pytest.mark.integration
@pytest.mark.asyncio
class TestArchiveWorker:
    """Verify archive worker writes compressed NDJSON to local filesystem."""

    async def test_local_archive(self, redis_client, tmp_path):
        import gzip
        from workers.archive_worker import ArchiveWorker

        test_stream = "test:archive:raw"
        test_group = "test-archive"
        try:
            await redis_client.delete(test_stream)
        except Exception:
            pass

        # Publish 100 raw log lines
        for i in range(100):
            await redis_client.xadd(test_stream, {
                "raw": f"raw syslog line {i} from 10.0.0.{i % 254 + 1}",
                "host": f"10.0.0.{i % 254 + 1}",
                "type": "fortigate",
            })

        worker = ArchiveWorker(
            redis_url=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
            azure_account="",
            azure_key="",
            azure_container="sentinel-raw",
            local_fallback=str(tmp_path),
            consumer_name="test-archive",
        )

        # Ensure consumer group
        try:
            await redis_client.xgroup_create(test_stream, test_group, id="0")
        except Exception:
            pass

        # Manually drive the worker for one cycle
        import workers.archive_worker as aw_module
        original_stream = aw_module.STREAM
        aw_module.STREAM = test_stream
        try:
            messages = await redis_client.xreadgroup(
                test_group, "test-archive",
                {test_stream: ">"},
                count=200,
                block=500,
            )
            if messages:
                _, entries = messages[0]
                for msg_id, fields in entries:
                    raw = fields.get("raw", "")
                    source_type = fields.get("type", "unknown")
                    worker._buffers.setdefault(source_type, []).append(raw)
                    worker._ack_ids.append(msg_id)

            await worker._flush(redis_client)
        finally:
            aw_module.STREAM = original_stream

        # Find the output file
        gz_files = list(tmp_path.rglob("*.ndjson.gz"))
        assert len(gz_files) >= 1, "Expected at least one .ndjson.gz archive file"

        with gzip.open(gz_files[0], "rt") as f:
            lines = f.readlines()
        assert len(lines) == 100, f"Expected 100 lines, got {len(lines)}"

        await redis_client.delete(test_stream)
