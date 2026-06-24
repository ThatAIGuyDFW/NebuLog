"""Linux log collectors.

JournaldCollector — uses `journalctl --output=json --after-cursor` to read
  new entries from journald as JSON.  Each entry is the native journald JSON
  export format, which the server-side linux parser already understands.

SyslogCollector — tails /var/log/syslog (or configured path) from a byte
  offset.  Each line is wrapped in a minimal rsyslog-style JSON dict.
"""

from __future__ import annotations

import json
import socket
import subprocess
from pathlib import Path

import structlog

from .checkpoint import JournaldCheckpoint, SyslogCheckpoint

log = structlog.get_logger()

_HOSTNAME = socket.getfqdn()


class JournaldCollector:
    """Read new journald entries since the last cursor."""

    def __init__(self, units: list[str], batch_size: int, checkpoint: JournaldCheckpoint) -> None:
        self._units = units
        self._batch_size = batch_size
        self._cp = checkpoint

    def collect(self) -> list[dict]:
        """Return up to batch_size new journald entries as dicts."""
        cmd = [
            "journalctl",
            "--output=json",
            "--no-pager",
            f"-n{self._batch_size}",
        ]
        if self._cp.cursor:
            cmd += ["--after-cursor", self._cp.cursor]
        else:
            # First run — only send last 1000 entries to avoid flooding
            cmd += ["-n1000"]

        for unit in self._units:
            cmd += ["-u", unit]

        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            log.error("journalctl_failed", exc=str(exc))
            return []

        if result.returncode not in (0, 1):  # 1 = no entries (empty result)
            log.warning("journalctl_nonzero", rc=result.returncode, stderr=result.stderr[:200])
            return []

        entries: list[dict] = []
        last_cursor: str | None = None

        for line in result.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError:
                continue
            last_cursor = entry.get("__CURSOR") or last_cursor
            entries.append(entry)

        if last_cursor:
            self._cp.save(last_cursor)

        return entries


class SyslogCollector:
    """Tail a syslog file from the last checkpoint offset."""

    def __init__(self, path: Path, batch_size: int, checkpoint: SyslogCheckpoint) -> None:
        self._path = path
        self._batch_size = batch_size
        self._cp = checkpoint

    def collect(self) -> list[dict]:
        """Return up to batch_size new log lines wrapped as JSON dicts."""
        if not self._path.exists():
            log.warning("syslog_not_found", path=str(self._path))
            return []

        entries: list[dict] = []
        try:
            with self._path.open("r", errors="replace") as fh:
                fh.seek(self._cp.offset)
                # Use readline() so fh.tell() remains accurate (the for-loop
                # iterator calls next() which disables tell()).
                while len(entries) < self._batch_size:
                    line = fh.readline()
                    if not line:
                        break
                    line = line.rstrip("\n")
                    if line:
                        entries.append(_wrap_syslog_line(line))
                new_offset = fh.tell()
        except OSError as exc:
            log.error("syslog_read_failed", exc=str(exc))
            return []

        if entries:
            self._cp.save(new_offset)

        return entries


def _wrap_syslog_line(line: str) -> dict:
    """Wrap a raw syslog line into a minimal rsyslog-style JSON dict.

    The server-side linux parser's rsyslog branch accepts:
        { "timestamp": ..., "hostname": ..., "program": ..., "message": ... }
    """
    from datetime import datetime, timezone

    # Best-effort parse of BSD syslog prefix: "Jan 15 10:23:45 host prog[pid]: msg"
    # split(" ", 4) → ['Jan', '15', '10:23:45', 'host', 'prog[pid]: msg rest']
    parts = line.split(" ", 4)
    program = "syslog"
    hostname = _HOSTNAME
    message = line
    timestamp = datetime.now(tz=timezone.utc).isoformat()

    if len(parts) >= 5:
        try:
            hostname = parts[3]
            rest = parts[4]  # "prog[pid]: message body"
            if ":" in rest:
                program, _, message = rest.partition(":")
                message = message.strip()
                program = program.strip()
            else:
                message = rest
        except Exception:
            pass

    return {
        "timestamp": timestamp,
        "hostname": hostname,
        "program": program.strip(),
        "message": message,
    }
