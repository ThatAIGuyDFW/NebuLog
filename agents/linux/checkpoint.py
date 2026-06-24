"""Checkpoint persistence for the Linux agent.

Two checkpoint types:
  - JournaldCheckpoint: stores the last journald cursor string
  - SyslogCheckpoint:   stores the last byte offset into the syslog file
"""

from __future__ import annotations

import json
from pathlib import Path


class JournaldCheckpoint:
    """Persist the journald cursor so reads resume without duplicates."""

    def __init__(self, checkpoint_dir: Path) -> None:
        checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self._path = checkpoint_dir / "journald_cursor.json"
        self._cursor: str | None = self._load()

    def _load(self) -> str | None:
        try:
            data = json.loads(self._path.read_text())
            return data.get("cursor") or None
        except (FileNotFoundError, ValueError):
            return None

    @property
    def cursor(self) -> str | None:
        return self._cursor

    def save(self, cursor: str) -> None:
        self._cursor = cursor
        self._path.write_text(json.dumps({"cursor": cursor}))


class SyslogCheckpoint:
    """Persist the byte offset into a syslog file."""

    def __init__(self, checkpoint_dir: Path) -> None:
        checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self._path = checkpoint_dir / "syslog_offset.json"
        self._offset: int = self._load()

    def _load(self) -> int:
        try:
            data = json.loads(self._path.read_text())
            return int(data.get("offset", 0))
        except (FileNotFoundError, ValueError):
            return 0

    @property
    def offset(self) -> int:
        return self._offset

    def save(self, offset: int) -> None:
        self._offset = offset
        self._path.write_text(json.dumps({"offset": offset}))
