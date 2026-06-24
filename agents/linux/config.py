"""Linux agent configuration — loaded from environment / .env file."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

load_dotenv(Path(__file__).parent / ".env")


@dataclass
class AgentConfig:
    # Ingest service
    ingest_url: str = field(default_factory=lambda: os.environ["SENTINEL_INGEST_URL"])
    api_token: str | None = field(default_factory=lambda: os.getenv("SENTINEL_API_TOKEN"))
    verify_tls: bool = field(
        default_factory=lambda: os.getenv("SENTINEL_VERIFY_TLS", "true").lower() != "false"
    )

    # Collection mode: "journald" (default) or "syslog" (/var/log/syslog)
    mode: str = field(default_factory=lambda: os.getenv("SENTINEL_MODE", "journald"))

    # journald units to filter (empty = all units)
    units: list[str] = field(
        default_factory=lambda: [
            u.strip()
            for u in os.getenv("SENTINEL_UNITS", "").split(",")
            if u.strip()
        ]
    )

    # syslog file path (used when mode=syslog)
    syslog_path: Path = field(
        default_factory=lambda: Path(os.getenv("SENTINEL_SYSLOG_PATH", "/var/log/syslog"))
    )

    # Batching & polling
    batch_size: int = field(default_factory=lambda: int(os.getenv("SENTINEL_BATCH_SIZE", "200")))
    poll_interval: float = field(
        default_factory=lambda: float(os.getenv("SENTINEL_POLL_INTERVAL", "5"))
    )

    # Checkpoint — cursor file for journald, byte offset file for syslog
    checkpoint_dir: Path = field(
        default_factory=lambda: Path(
            os.getenv("SENTINEL_CHECKPOINT_DIR", "/var/lib/sentinel")
        )
    )

    # Source identity
    source_ip: str | None = field(default_factory=lambda: os.getenv("SENTINEL_SOURCE_IP"))

    # Retry
    max_retries: int = field(default_factory=lambda: int(os.getenv("SENTINEL_MAX_RETRIES", "5")))
    retry_wait: float = field(default_factory=lambda: float(os.getenv("SENTINEL_RETRY_WAIT", "2")))


settings = AgentConfig()
