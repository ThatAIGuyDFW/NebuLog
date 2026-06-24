"""Per-source-IP token bucket rate limiter.

Each source IP gets an independent bucket.  The bucket is refilled at
`rate` tokens/second and has a burst capacity of `capacity` tokens.
Events that exceed the bucket are dropped and counted.

Hardening (Phase 7):
  - Stale bucket eviction: buckets untouched for `evict_after` seconds are
    removed to prevent unbounded memory growth from spoofed source IPs.
  - Structured drop logging: logs a structlog warning every `log_interval`
    seconds per source so the drop rate is visible in the event stream without
    flooding logs.

This is an in-process implementation sufficient for a single ingest node.
At multi-node scale, move counters to Redis with INCR + TTL.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Iterator

import structlog

log = structlog.get_logger()

# How often (seconds) to log rate-limit drops per source IP
_DROP_LOG_INTERVAL = 60.0


@dataclass
class _Bucket:
    capacity: float
    rate: float               # tokens added per second
    tokens: float = 0.0
    last_check: float = field(default_factory=time.monotonic)
    # Drop accounting
    drop_count: int = 0
    last_drop_log: float = field(default_factory=time.monotonic)

    def consume(self, source_ip: str) -> bool:
        """Return True if the event is allowed; False if rate-limited."""
        now = time.monotonic()
        elapsed = now - self.last_check
        self.last_check = now
        self.tokens = min(self.capacity, self.tokens + elapsed * self.rate)

        if self.tokens >= 1:
            self.tokens -= 1
            return True

        self.drop_count += 1
        if now - self.last_drop_log >= _DROP_LOG_INTERVAL:
            log.warning(
                "rate_limit_drop",
                source_ip=source_ip,
                drops_since_last_log=self.drop_count,
                rate=self.rate,
            )
            self.drop_count = 0
            self.last_drop_log = now
        return False

    @property
    def idle_seconds(self) -> float:
        return time.monotonic() - self.last_check


class RateLimiter:
    """Token bucket rate limiter keyed by source IP string.

    Parameters
    ----------
    rate:
        Sustained events per second allowed per source IP.
    capacity:
        Burst capacity (tokens in a full bucket).  Defaults to 2× rate.
    evict_after:
        Seconds of inactivity before a bucket is evicted.  Prevents unbounded
        memory growth when many spoofed source IPs send a handful of packets.
    """

    def __init__(
        self,
        rate: float = 10_000,
        capacity: float | None = None,
        evict_after: float = 300.0,
    ) -> None:
        self._rate = rate
        self._capacity = capacity if capacity is not None else rate * 2
        self._evict_after = evict_after
        self._buckets: dict[str, _Bucket] = {}
        self._last_eviction: float = time.monotonic()
        # Evict at most once per minute to amortise the scan cost
        self._evict_interval: float = 60.0

    def allow(self, source_ip: str) -> bool:
        """Return True if the datagram from source_ip should be processed."""
        self._maybe_evict()
        bucket = self._buckets.get(source_ip)
        if bucket is None:
            bucket = _Bucket(
                capacity=self._capacity,
                rate=self._rate,
                tokens=self._capacity,  # start full so first burst is allowed
            )
            self._buckets[source_ip] = bucket
        return bucket.consume(source_ip)

    def _maybe_evict(self) -> None:
        now = time.monotonic()
        if now - self._last_eviction < self._evict_interval:
            return
        self._last_eviction = now
        stale = [
            ip for ip, b in self._buckets.items()
            if b.idle_seconds > self._evict_after
        ]
        for ip in stale:
            del self._buckets[ip]
        if stale:
            log.debug("rate_limiter_evicted", count=len(stale))

    @property
    def bucket_count(self) -> int:
        """Current number of tracked source IPs (for monitoring)."""
        return len(self._buckets)
