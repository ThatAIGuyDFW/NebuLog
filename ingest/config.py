"""Ingest service configuration.

Loaded from environment variables (dev: .env file via python-dotenv).
The source registry maps source IP → parser class and is seeded from the
'sources' table in PostgreSQL at startup.
"""

from __future__ import annotations

import os
from dotenv import load_dotenv

load_dotenv()


class Settings:
    """Runtime configuration for the ingest service."""

    host: str = os.getenv("INGEST_HOST", "0.0.0.0")
    udp_port: int = int(os.getenv("INGEST_UDP_PORT", "514"))
    tcp_port: int = int(os.getenv("INGEST_TCP_PORT", "6514"))
    api_port: int = int(os.getenv("INGEST_API_PORT", "8001"))

    redis_url: str = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    database_url: str = os.getenv("DATABASE_URL", "")

    ingest_node: str = os.getenv("INGEST_NODE_NAME", "ingest-01")
    log_level: str = os.getenv("LOG_LEVEL", "INFO")
    geoip_db_path: str = os.getenv("GEOIP_DB_PATH", "/opt/geoip/GeoLite2-City.mmdb")

    # Redis stream names
    stream_normalized: str = "events:normalized"
    stream_raw: str = "events:raw"
    stream_errors: str = "sentinel:errors"

    # Ingest tuning
    batch_size: int = 500
    flush_interval_seconds: float = 5.0
    rate_limit_per_source: int = 10_000  # events per second


settings = Settings()
