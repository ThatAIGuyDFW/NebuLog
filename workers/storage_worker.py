"""Storage Worker — events:normalized → PostgreSQL.

Consumes the Redis Stream 'events:normalized' using a consumer group,
applies GeoIP enrichment and compliance tags, then batch-inserts into the
PostgreSQL events table.

Tuning knobs (env-driven via config):
  BATCH_SIZE          — rows per INSERT (default 500)
  FLUSH_INTERVAL      — max seconds between flushes (default 5)

Consumer group: sentinel-storage
Consumer name:  <INGEST_NODE_NAME>-storage (allows multiple workers)
"""

from __future__ import annotations

import asyncio
import json
import os
from datetime import datetime, timezone

import asyncpg
import structlog
from redis.asyncio import Redis, from_url

from ingest.models import NormalizedEvent
from workers.compliance import apply_compliance_tags
from workers.geoip import GeoIPEnricher

log = structlog.get_logger()

STREAM = os.getenv("STREAM_NORMALIZED", "events:normalized")
GROUP = "sentinel-storage"
BATCH_SIZE = int(os.getenv("BATCH_SIZE", "500"))
FLUSH_INTERVAL = float(os.getenv("FLUSH_INTERVAL", "5.0"))

# All columns in the events table in order (must match INSERT below)
_COLUMNS = (
    "id", "received_at", "event_time", "source_host", "source_type",
    "log_level", "category", "action",
    "src_ip", "src_port", "dst_ip", "dst_port", "protocol",
    "user_name", "process_name", "event_id",
    "message", "raw_message", "tags", "geo_country", "geo_city",
    "alert_id", "ingest_node", "raw_hash", "extra",
)


def _to_row(event: NormalizedEvent) -> tuple:
    """Convert NormalizedEvent to a tuple matching _COLUMNS order."""
    return (
        str(event.id),
        event.received_at,
        event.event_time,
        event.source_host,
        event.source_type,
        event.log_level,
        event.category,
        event.action,
        event.src_ip,
        event.src_port,
        event.dst_ip,
        event.dst_port,
        event.protocol,
        event.user_name,
        event.process_name,
        event.event_id,
        event.message,
        event.raw_message,
        event.tags,
        event.geo_country,
        event.geo_city,
        str(event.alert_id) if event.alert_id else None,
        event.ingest_node,
        event.raw_hash,
        json.dumps(event.extra) if event.extra else "{}",
    )


async def _ensure_consumer_group(redis: Redis) -> None:
    try:
        await redis.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
        log.info("consumer_group_created", stream=STREAM, group=GROUP)
    except Exception as exc:
        if "BUSYGROUP" not in str(exc):
            raise


async def _batch_insert(conn: asyncpg.Connection, rows: list[tuple]) -> None:
    """Insert a batch of rows into the partitioned events table."""
    if not rows:
        return
    placeholders = ", ".join(
        f"(${i * len(_COLUMNS) + j + 1} {'::inet' if col in ('src_ip', 'dst_ip') else '::jsonb' if col == 'extra' else ''})"
        .replace("(", "").replace(")", "")
        for i, row in enumerate(rows)
        for j, col in enumerate(_COLUMNS)
    )
    # Build a multi-row INSERT using asyncpg's executemany for efficiency
    sql = f"""
        INSERT INTO events ({', '.join(_COLUMNS)})
        VALUES ({', '.join(f'${i+1}' for i in range(len(_COLUMNS)))})
        ON CONFLICT DO NOTHING
    """
    await conn.executemany(sql, rows)
    log.info("batch_inserted", count=len(rows))


class StorageWorker:
    """Async storage worker: Redis Stream → PostgreSQL."""

    def __init__(self, redis_url: str, database_url: str, geoip_db_path: str,
                 consumer_name: str) -> None:
        self._redis_url = redis_url
        self._database_url = database_url.replace("+asyncpg", "")
        self._geoip = GeoIPEnricher(geoip_db_path)
        self._consumer_name = consumer_name

    async def run(self) -> None:
        redis: Redis = from_url(self._redis_url, decode_responses=True)
        await _ensure_consumer_group(redis)

        db: asyncpg.Connection = await asyncpg.connect(self._database_url)
        log.info("storage_worker_started", consumer=self._consumer_name)

        batch: list[tuple] = []
        ack_ids: list[str] = []
        last_flush = asyncio.get_event_loop().time()

        try:
            while True:
                # Read up to BATCH_SIZE messages with a 1-second block
                messages = await redis.xreadgroup(
                    GROUP, self._consumer_name,
                    {STREAM: ">"},
                    count=BATCH_SIZE,
                    block=1000,
                )

                if messages:
                    _, entries = messages[0]
                    for msg_id, fields in entries:
                        try:
                            event = NormalizedEvent.model_validate_json(fields["data"])
                            self._enrich(event)
                            batch.append(_to_row(event))
                            ack_ids.append(msg_id)
                        except Exception as exc:
                            log.error("deserialize_error", msg_id=msg_id, exc=str(exc))
                            # Acknowledge anyway to prevent poison-pill loops
                            ack_ids.append(msg_id)

                now = asyncio.get_event_loop().time()
                should_flush = (len(batch) >= BATCH_SIZE or
                                (batch and now - last_flush >= FLUSH_INTERVAL))

                if should_flush:
                    try:
                        await _batch_insert(db, batch)
                        if ack_ids:
                            await redis.xack(STREAM, GROUP, *ack_ids)
                    except Exception as exc:
                        log.error("insert_error", exc=str(exc))
                        # Reconnect on DB error
                        try:
                            await db.close()
                        except Exception:
                            pass
                        db = await asyncpg.connect(self._database_url)
                    finally:
                        batch.clear()
                        ack_ids.clear()
                        last_flush = now

        finally:
            # Final flush on shutdown
            if batch:
                try:
                    await _batch_insert(db, batch)
                    if ack_ids:
                        await redis.xack(STREAM, GROUP, *ack_ids)
                except Exception as exc:
                    log.error("shutdown_flush_error", exc=str(exc))
            await db.close()
            await redis.aclose()
            self._geoip.close()

    def _enrich(self, event: NormalizedEvent) -> None:
        """Apply GeoIP and compliance tags in-place."""
        if event.src_ip and event.geo_country is None:
            event.geo_country, event.geo_city = self._geoip.lookup(event.src_ip)
        apply_compliance_tags(event)


async def main() -> None:
    from dotenv import load_dotenv
    import structlog
    load_dotenv()
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ]
    )
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    database_url = os.getenv("DATABASE_URL", "")
    geoip_path = os.getenv("GEOIP_DB_PATH", "")
    node_name = os.getenv("INGEST_NODE_NAME", "worker-01")

    worker = StorageWorker(redis_url, database_url, geoip_path,
                           consumer_name=f"{node_name}-storage")
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
