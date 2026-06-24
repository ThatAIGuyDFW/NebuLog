"""Manage the embedded Redis server lifecycle."""

from __future__ import annotations

import os
import subprocess
import time
from pathlib import Path

import structlog

from launcher.config import REDIS_BIN, REDIS_PORT, REDIS_LOG, DATA_DIR, LOG_DIR

log = structlog.get_logger()


def start() -> subprocess.Popen:
    """Start the embedded Redis server and return its Popen handle."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    redis_dir = DATA_DIR / "redis"
    redis_dir.mkdir(parents=True, exist_ok=True)

    log_fh = open(REDIS_LOG, "a")

    proc = subprocess.Popen(
        [
            str(REDIS_BIN),
            "--port", str(REDIS_PORT),
            "--bind", "127.0.0.1",
            "--dir", str(redis_dir),
            "--dbfilename", "sentinel.rdb",
            "--loglevel", "notice",
            "--maxmemory", "256mb",
            "--maxmemory-policy", "allkeys-lru",
        ],
        stdout=log_fh,
        stderr=log_fh,
    )

    # Wait until Redis is accepting connections (up to 15 s)
    deadline = time.monotonic() + 15
    while time.monotonic() < deadline:
        if _ping():
            log.info("redis_started", port=REDIS_PORT, pid=proc.pid)
            return proc
        time.sleep(0.3)

    proc.terminate()
    raise RuntimeError("Redis did not start within 15 seconds")


def stop(proc: subprocess.Popen) -> None:
    if proc and proc.poll() is None:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.info("redis_stopped")


def _ping() -> bool:
    import socket
    try:
        with socket.create_connection(("127.0.0.1", REDIS_PORT), timeout=1) as s:
            s.sendall(b"PING\r\n")
            return b"+PONG" in s.recv(128)
    except Exception:
        return False


def connection_url() -> str:
    return f"redis://127.0.0.1:{REDIS_PORT}/0"
