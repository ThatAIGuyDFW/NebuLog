"""Windows agent configuration — loaded from environment / .env file."""

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
    verify_tls: bool = field(default_factory=lambda: os.getenv("SENTINEL_VERIFY_TLS", "true").lower() != "false")

    # Collection
    channels: list[str] = field(default_factory=lambda: [
        c.strip()
        for c in os.getenv("SENTINEL_CHANNELS", "Security,System,Application").split(",")
        if c.strip()
    ])
    batch_size: int = field(default_factory=lambda: int(os.getenv("SENTINEL_BATCH_SIZE", "200")))
    poll_interval: float = field(default_factory=lambda: float(os.getenv("SENTINEL_POLL_INTERVAL", "5")))

    # Checkpoint: persists the last-read record number per channel
    checkpoint_dir: Path = field(
        default_factory=lambda: Path(
            os.getenv("SENTINEL_CHECKPOINT_DIR", r"C:\ProgramData\Sentinel\checkpoints")
        )
    )

    # Source identity — defaults to the machine's hostname/IP
    source_ip: str | None = field(default_factory=lambda: os.getenv("SENTINEL_SOURCE_IP"))

    # Retry
    max_retries: int = field(default_factory=lambda: int(os.getenv("SENTINEL_MAX_RETRIES", "5")))
    retry_wait: float = field(default_factory=lambda: float(os.getenv("SENTINEL_RETRY_WAIT", "2")))


settings = AgentConfig()
