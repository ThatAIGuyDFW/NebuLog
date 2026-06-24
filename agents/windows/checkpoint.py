"""Checkpoint persistence — tracks the last EventRecordID read per channel.

Checkpoints are stored as plain JSON files in `checkpoint_dir` so that the
agent picks up exactly where it left off after a restart, with no duplicate
or missed events.
"""

from __future__ import annotations

import json
from pathlib import Path


class Checkpoint:
    """Read / write the last-read record ID for one channel."""

    def __init__(self, channel: str, checkpoint_dir: Path) -> None:
        safe_name = channel.replace("/", "_").replace("\\", "_")
        self._path = checkpoint_dir / f"{safe_name}.json"
        checkpoint_dir.mkdir(parents=True, exist_ok=True)
        self._record_id: int = self._load()

    def _load(self) -> int:
        try:
            data = json.loads(self._path.read_text())
            return int(data.get("record_id", 0))
        except (FileNotFoundError, ValueError, KeyError):
            return 0

    @property
    def record_id(self) -> int:
        return self._record_id

    def save(self, record_id: int) -> None:
        self._record_id = record_id
        self._path.write_text(json.dumps({"record_id": record_id}))
