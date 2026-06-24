"""Paths and constants for the Sentinel launcher.

All runtime data (PostgreSQL cluster, Redis dump, logs, .env) lives in a
platform-appropriate user-writable directory — never inside the bundle.
"""

from __future__ import annotations

import os
import sys
import platform
from pathlib import Path


def _bundle_dir() -> Path:
    """Return the directory containing the PyInstaller bundle (or source root in dev)."""
    if getattr(sys, "frozen", False):
        return Path(sys._MEIPASS)  # type: ignore[attr-defined]
    return Path(__file__).resolve().parents[2]


def _data_dir() -> Path:
    """Return the platform-appropriate writable data directory."""
    system = platform.system()
    if system == "Windows":
        base = Path(os.environ.get("PROGRAMDATA", "C:/ProgramData"))
        return base / "Sentinel"
    if system == "Darwin":
        return Path.home() / "Library" / "Application Support" / "Sentinel"
    # Linux
    return Path("/var/lib/sentinel")


def _log_dir() -> Path:
    system = platform.system()
    if system == "Windows":
        base = Path(os.environ.get("PROGRAMDATA", "C:/ProgramData"))
        return base / "Sentinel" / "logs"
    if system == "Darwin":
        return Path.home() / "Library" / "Logs" / "Sentinel"
    return Path("/var/log/sentinel")


BUNDLE_DIR: Path = _bundle_dir()
DATA_DIR: Path = _data_dir()
LOG_DIR: Path = _log_dir()

# Embedded binaries (inside the bundle)
EMBEDDED_DIR: Path = BUNDLE_DIR / "embedded"
PG_BIN_DIR: Path = EMBEDDED_DIR / "postgresql" / "bin"
REDIS_BIN: Path = EMBEDDED_DIR / "redis" / (
    "redis-server.exe" if platform.system() == "Windows" else "redis-server"
)

# PostgreSQL cluster (user-writable, outside the bundle)
PG_DATA_DIR: Path = DATA_DIR / "pgdata"
PG_LOG: Path = LOG_DIR / "postgresql.log"
PG_PORT: int = 55432          # non-standard to avoid conflicts with any system PG
PG_USER: str = "sentinel"
PG_DB: str = "sentinel"

# Redis
REDIS_PORT: int = 56379       # non-standard
REDIS_LOG: Path = LOG_DIR / "redis.log"

# Service ports
INGEST_UDP_PORT: int = 514
INGEST_TCP_PORT: int = 6514
INGEST_API_PORT: int = 8001
API_PORT: int = 8000

# Environment file written on first run
ENV_FILE: Path = DATA_DIR / ".env"

# Pre-built React UI (inside the bundle)
UI_DIST_DIR: Path = BUNDLE_DIR / "ui"

# Sentinel version
VERSION: str = "1.0.0"
