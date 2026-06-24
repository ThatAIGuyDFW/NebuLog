"""Redis Streams publisher.

Publishes to two streams:
  events:normalized  — JSON-serialised NormalizedEvent (consumed by storage worker)
  events:raw         — raw log line with metadata (consumed by archive worker)
  sentinel:errors    — ingest errors and warnings

Uses the redis-py asyncio client with connection pooling.
"""

from __future__ import annotations

import structlog
from redis.asyncio import Redis, from_url

from .models import NormalizedEvent

log = structlog.get_logger()


class RedisPublisher:
    """Async Redis Streams publisher."""

    def __init__(self, redis_url: str, stream_normalized: str, stream_raw: str,
                 stream_errors: str) -> None:
        self._redis: Redis = from_url(redis_url, decode_responses=True)
        self._stream_normalized = stream_normalized
        self._stream_raw = stream_raw
        self._stream_errors = stream_errors

    async def close(self) -> None:
        await self._redis.aclose()

    async def publish_normalized(self, event: NormalizedEvent) -> None:
        """Publish a serialised NormalizedEvent to events:normalized."""
        await self._redis.xadd(
            self._stream_normalized,
            {"data": event.model_dump_json()},
            maxlen=500_000,   # cap stream at ~500 k events in Redis memory
            approximate=True,
        )

    async def publish_raw(self, raw: str, source_host: str, source_type: str) -> None:
        """Publish the original unparsed log line to events:raw."""
        await self._redis.xadd(
            self._stream_raw,
            {"raw": raw, "host": source_host, "type": source_type},
            maxlen=500_000,
            approximate=True,
        )

    async def publish_error(self, error_type: str, detail: str,
                            source_ip: str = "", raw: str = "") -> None:
        """Publish an ingest error to sentinel:errors for monitoring."""
        await self._redis.xadd(
            self._stream_errors,
            {"error": error_type, "detail": detail,
             "source_ip": source_ip, "raw": raw[:500]},
            maxlen=10_000,
            approximate=True,
        )

    async def queue_depth(self) -> dict[str, int]:
        """Return current length of each stream (for /health endpoint)."""
        results = {}
        for stream in (self._stream_normalized, self._stream_raw, self._stream_errors):
            try:
                results[stream] = await self._redis.xlen(stream)
            except Exception:
                results[stream] = -1
        return results
