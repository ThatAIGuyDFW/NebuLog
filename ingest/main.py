"""Sentinel Ingest Service — entry point.

Starts three concurrent listeners:
  1. UDP datagram listener on port 514 (asyncio DatagramProtocol)
  2. FastAPI HTTPS server on port 8001 (agent batch endpoint)
  3. Background task: periodic source registry reload from PostgreSQL

Phase 7 adds TLS TCP listener on port 6514.

Env vars consumed:
  INGEST_HOST, INGEST_UDP_PORT, INGEST_API_PORT
  REDIS_URL, DATABASE_URL
  INGEST_NODE_NAME, LOG_LEVEL
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import socket
from datetime import datetime, timezone
from typing import Any

import structlog
import uvicorn
from fastapi import FastAPI, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse

from .config import settings
from .models import NormalizedEvent, SourceType
from .publisher import RedisPublisher
from .rate_limiter import RateLimiter
from .source_registry import SourceRegistry

log = structlog.get_logger()

# --- Singletons shared across UDP handler and FastAPI app ---
publisher: RedisPublisher | None = None
registry: SourceRegistry | None = None
rate_limiter: RateLimiter = RateLimiter(
    rate=settings.rate_limit_per_source,
    capacity=settings.rate_limit_per_source * 2,
)


# ---------------------------------------------------------------------------
# UDP Datagram Protocol
# ---------------------------------------------------------------------------

class _SyslogProtocol(asyncio.DatagramProtocol):
    """asyncio DatagramProtocol for high-throughput syslog reception."""

    def connection_made(self, transport: asyncio.DatagramTransport) -> None:
        self.transport = transport
        log.info("udp_listener_ready", port=settings.udp_port)

    def datagram_received(self, data: bytes, addr: tuple[str, int]) -> None:
        source_ip, _port = addr
        if not rate_limiter.allow(source_ip):
            # Drop silently; rate limiter will log periodic warnings
            return
        try:
            raw = data.decode("utf-8", errors="replace").strip()
        except Exception:
            return
        if raw:
            asyncio.create_task(_process_syslog(raw, source_ip))

    def error_received(self, exc: Exception) -> None:
        log.error("udp_error", exc=str(exc))


async def _process_syslog(raw: str, source_ip: str) -> None:
    """Parse one syslog datagram and publish to Redis Streams."""
    if publisher is None or registry is None:
        return
    received_at = datetime.now(tz=timezone.utc)
    try:
        parser, meta = registry.get_parser(source_ip, raw)
        event: NormalizedEvent = parser.parse(raw, source_ip, received_at)
    except Exception as exc:
        await publisher.publish_error("parse_error", str(exc), source_ip, raw)
        log.warning("parse_error", source_ip=source_ip, exc=str(exc))
        return

    _stamp_event(event, raw, source_ip)
    await asyncio.gather(
        publisher.publish_normalized(event),
        publisher.publish_raw(raw, source_ip, event.source_type),
    )


def _stamp_event(event: NormalizedEvent, raw: str, source_ip: str) -> None:
    """Fill server-side fields that parsers don't set."""
    event.ingest_node = settings.ingest_node
    if raw and event.raw_hash is None:
        event.raw_hash = hashlib.sha256(raw.encode()).hexdigest()


# ---------------------------------------------------------------------------
# FastAPI — agent batch endpoint
# ---------------------------------------------------------------------------

app = FastAPI(title="Sentinel Ingest API", version="1.0.0")


@app.on_event("startup")
async def _startup() -> None:
    global publisher, registry
    publisher = RedisPublisher(
        settings.redis_url,
        settings.stream_normalized,
        settings.stream_raw,
        settings.stream_errors,
    )
    registry = SourceRegistry()
    # Attempt to load sources from DB; swallow error so ingest starts even
    # before the first migration run (CI/dev convenience).
    try:
        await _load_registry()
    except Exception as exc:
        log.warning("registry_load_skipped", reason=str(exc))


async def _load_registry() -> None:
    """Load sources table into the in-memory registry."""
    import asyncpg  # imported lazily so the module loads without a DB
    conn = await asyncpg.connect(settings.database_url.replace("+asyncpg", ""))
    try:
        rows = await conn.fetch(
            "SELECT ip_address::text, source_type::text, label, enabled FROM sources"
        )
        if registry is not None:
            registry.load([dict(r) for r in rows])
    finally:
        await conn.close()


@app.post("/ingest", status_code=status.HTTP_202_ACCEPTED)
async def ingest_batch(
    request: Request,
    x_source_type: str = Header(..., description="'windows' or 'linux'"),
    x_source_ip: str | None = Header(None, description="Originating host IP (optional)"),
) -> JSONResponse:
    """Accept a JSON batch from a Windows or Linux agent.

    Request body: JSON array of event objects.
    Headers:
        X-Source-Type: windows | linux
        X-Source-IP:   originating host IP (falls back to request client host)
    """
    if publisher is None:
        raise HTTPException(503, "Publisher not ready")

    try:
        body = await request.json()
    except Exception:
        raise HTTPException(400, "Invalid JSON body")

    if not isinstance(body, list):
        raise HTTPException(400, "Body must be a JSON array")

    source_ip = x_source_ip or (request.client.host if request.client else "unknown")
    try:
        source_type = SourceType(x_source_type.lower())
    except ValueError:
        raise HTTPException(400, f"Unknown source type: {x_source_type}")

    if source_type not in (SourceType.windows, SourceType.linux):
        raise HTTPException(400, "Only 'windows' and 'linux' source types accepted at this endpoint")

    from .parsers import WindowsParser, LinuxParser
    parser_cls = WindowsParser if source_type == SourceType.windows else LinuxParser
    parser = parser_cls()

    received_at = datetime.now(tz=timezone.utc)
    processed = 0
    errors = 0

    for raw_event in body:
        if not isinstance(raw_event, dict):
            errors += 1
            continue
        try:
            event: NormalizedEvent = parser.parse(raw_event, source_ip, received_at)
            raw_str = json.dumps(raw_event)
            _stamp_event(event, raw_str, source_ip)
            await asyncio.gather(
                publisher.publish_normalized(event),
                publisher.publish_raw(raw_str, source_ip, source_type),
            )
            processed += 1
        except Exception as exc:
            errors += 1
            await publisher.publish_error("agent_parse_error", str(exc), source_ip)

    return JSONResponse({"accepted": processed, "errors": errors})


@app.get("/ingest/reload-sources", status_code=200)
async def reload_sources() -> JSONResponse:
    """Hot-reload the source registry from the DB (called by the API service
    after a POST /sources)."""
    try:
        await _load_registry()
        return JSONResponse({"status": "ok", "sources": len(registry._sources) if registry else 0})
    except Exception as exc:
        raise HTTPException(500, str(exc))


@app.get("/health")
async def health() -> JSONResponse:
    depths: dict[str, Any] = {}
    if publisher:
        depths = await publisher.queue_depth()
    return JSONResponse({
        "status": "ok",
        "node": settings.ingest_node,
        "queue_depth": depths,
    })


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

async def _run() -> None:
    from .tls_listener import build_ssl_context, start_tls_listener

    loop = asyncio.get_running_loop()

    # 1. UDP listener
    transport, _ = await loop.create_datagram_endpoint(
        _SyslogProtocol,
        local_addr=(settings.host, settings.udp_port),
        family=socket.AF_INET,
    )

    # 2. TLS TCP listener on port 6514 (optional — skipped if cert not configured)
    tls_server = None
    ssl_ctx = build_ssl_context()
    if ssl_ctx:
        tls_server = await start_tls_listener(
            settings.host, settings.tcp_port, _process_syslog, ssl_ctx
        )
        log.info("tls_listener_started", port=settings.tcp_port)
    else:
        log.info("tls_listener_skipped", reason="INGEST_TLS_CERT not set")

    log.info("sentinel_ingest_starting",
             udp=f"{settings.host}:{settings.udp_port}",
             tcp_tls=f"{settings.host}:{settings.tcp_port}" if tls_server else "disabled",
             api=f"{settings.host}:{settings.api_port}")

    # 3. FastAPI via uvicorn (shares the same asyncio loop)
    config = uvicorn.Config(
        app,
        host=settings.host,
        port=settings.api_port,
        loop="none",          # tell uvicorn not to create its own loop
        log_level=settings.log_level.lower(),
    )
    server = uvicorn.Server(config)

    try:
        await server.serve()
    finally:
        transport.close()
        if tls_server:
            tls_server.close()
            await tls_server.wait_closed()
        if publisher:
            await publisher.close()


def main() -> None:
    import structlog
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ]
    )
    asyncio.run(_run())


if __name__ == "__main__":
    main()
