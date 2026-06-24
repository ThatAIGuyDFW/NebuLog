"""Manage the embedded PostgreSQL server lifecycle."""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import time
from pathlib import Path

import structlog

from launcher.config import (
    PG_BIN_DIR, PG_DATA_DIR, PG_LOG, PG_PORT,
    PG_USER, PG_DB, LOG_DIR,
)

log = structlog.get_logger()

_IS_WIN = platform.system() == "Windows"
_EXE = ".exe" if _IS_WIN else ""


def _bin(name: str) -> str:
    return str(PG_BIN_DIR / f"{name}{_EXE}")


def is_initialized() -> bool:
    return (PG_DATA_DIR / "PG_VERSION").exists()


def initialize(password: str) -> None:
    """Run initdb to create a new PostgreSQL cluster."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    PG_DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Write password to temp file so it never appears on the command line
    pw_file = PG_DATA_DIR / ".pwfile"
    pw_file.write_text(password)

    try:
        result = subprocess.run(
            [
                _bin("initdb"),
                "--pgdata", str(PG_DATA_DIR),
                "--username", PG_USER,
                "--pwfile", str(pw_file),
                "--encoding", "UTF8",
                "--auth", "md5",
            ],
            capture_output=True, text=True, timeout=120,
            env=_pg_env(),
        )
        if result.returncode != 0:
            raise RuntimeError(f"initdb failed:\n{result.stderr}")
    finally:
        pw_file.unlink(missing_ok=True)

    # Configure to listen only on localhost
    pg_conf = PG_DATA_DIR / "postgresql.conf"
    with open(pg_conf, "a") as f:
        f.write(
            f"\n# Sentinel configuration\n"
            f"port = {PG_PORT}\n"
            f"listen_addresses = '127.0.0.1'\n"
            f"log_destination = 'stderr'\n"
            f"logging_collector = off\n"
        )

    log.info("pg_initialized", data_dir=str(PG_DATA_DIR))


def _pg_env() -> dict[str, str]:
    """Build an environment that lets the bundled postgres.exe find its own files."""
    pg_root = PG_BIN_DIR.parent
    return {
        **os.environ,
        "PGPASSWORD": "",
        # Override compile-time paths so postgres finds share/ and lib/ inside bundle
        "PGSHAREDIR": str(pg_root / "share"),
        "PGLIBDIR": str(pg_root / "lib"),
        # Prepend bin/ to PATH so postgres.exe loads its own DLLs first
        "PATH": str(PG_BIN_DIR) + os.pathsep + os.environ.get("PATH", ""),
    }


def start() -> subprocess.Popen:
    """Start the PostgreSQL server and return its Popen handle."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    log_fh = open(PG_LOG, "a")

    proc = subprocess.Popen(
        [
            _bin("postgres"),
            "-D", str(PG_DATA_DIR),
            "-p", str(PG_PORT),
        ],
        stdout=log_fh,
        stderr=log_fh,
        env=_pg_env(),
    )

    # Wait until accepting connections (up to 30 s)
    deadline = time.monotonic() + 30
    while time.monotonic() < deadline:
        if _ping():
            log.info("pg_started", port=PG_PORT, pid=proc.pid)
            return proc
        time.sleep(0.5)

    proc.terminate()
    raise RuntimeError("PostgreSQL did not start within 30 seconds")


def stop(proc: subprocess.Popen) -> None:
    if proc and proc.poll() is None:
        subprocess.run(
            [_bin("pg_ctl"), "stop", "-D", str(PG_DATA_DIR), "-m", "fast"],
            capture_output=True, timeout=30,
        )
        proc.wait(timeout=10)
        log.info("pg_stopped")


def create_database(password: str) -> None:
    """Create the sentinel database and user (idempotent)."""
    env = {**_pg_env(), "PGPASSWORD": password, "PGPORT": str(PG_PORT)}
    psql = _bin("psql")

    def _run(sql: str) -> None:
        subprocess.run(
            [psql, "-U", PG_USER, "-d", "postgres", "-c", sql],
            capture_output=True, env=env, timeout=30,
        )

    _run(f"CREATE DATABASE {PG_DB};")
    _run(f"CREATE EXTENSION IF NOT EXISTS vector;")
    log.info("pg_database_ready", db=PG_DB)


def _ping() -> bool:
    import socket
    try:
        with socket.create_connection(("127.0.0.1", PG_PORT), timeout=1):
            return True
    except OSError:
        return False


def connection_url(password: str) -> str:
    return (
        f"postgresql+asyncpg://{PG_USER}:{password}"
        f"@127.0.0.1:{PG_PORT}/{PG_DB}"
    )
