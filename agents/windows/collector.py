"""Windows Event Log collector using the win32evtlog API.

Reads events from a Windows Event Log channel newer than the last checkpoint
and yields them as dicts matching the format the ingest parser expects:

{
    "EventID": 4624,
    "TimeCreated": "2024-01-15T10:23:45.123456Z",
    "Computer": "WORKSTATION-01",
    "Channel": "Security",
    "Level": 0,
    "EventData": { ... }
}
"""

from __future__ import annotations

import socket
from datetime import datetime, timezone
from typing import Generator

import structlog

log = structlog.get_logger()

# win32evtlog is only available on Windows — guard so the module can be imported
# in tests on non-Windows platforms with a stub.
try:
    import win32evtlog          # type: ignore[import]
    import win32evtlogutil      # type: ignore[import]
    import win32con             # type: ignore[import]
    import pywintypes           # type: ignore[import]
    _WIN32_AVAILABLE = True
except ImportError:
    _WIN32_AVAILABLE = False

_HOSTNAME = socket.getfqdn()

# Flags for ReadEventLog: SEEK + FORWARDS starting from a specific record ID
_READ_FLAGS = (
    0x0002 |  # EVENTLOG_SEEK_READ
    0x0004    # EVENTLOG_FORWARDS_READ
) if _WIN32_AVAILABLE else 0


def _event_to_dict(ev, channel: str) -> dict:
    """Convert a win32evtlog event object to the ingest JSON schema."""
    # TimeGenerated is a pywintypes.datetime; convert to UTC ISO-8601
    ts: datetime = ev.TimeGenerated
    if hasattr(ts, "utctimetuple"):
        ts_str = datetime(
            ts.year, ts.month, ts.day,
            ts.hour, ts.minute, ts.second,
            tzinfo=timezone.utc,
        ).isoformat()
    else:
        ts_str = datetime.now(tz=timezone.utc).isoformat()

    # EventData: list of insertion strings keyed by position
    strings = ev.StringInserts or []
    event_data: dict[str, str] = {str(i): s for i, s in enumerate(strings) if s is not None}

    return {
        "EventID": ev.EventID & 0xFFFF,  # strip qualifier bits
        "TimeCreated": ts_str,
        "Computer": _HOSTNAME,
        "Channel": channel,
        "Level": ev.EventType,
        "RecordNumber": ev.RecordNumber,
        "SourceName": ev.SourceName,
        "EventData": event_data,
    }


def collect(channel: str, after_record_id: int, batch_size: int) -> list[dict]:
    """Return up to `batch_size` events from `channel` after `after_record_id`.

    Returns an empty list if win32evtlog is unavailable (non-Windows host).
    """
    if not _WIN32_AVAILABLE:
        log.warning("win32evtlog_unavailable", channel=channel)
        return []

    try:
        handle = win32evtlog.OpenEventLog(None, channel)
    except Exception as exc:
        log.error("open_event_log_failed", channel=channel, exc=str(exc))
        return []

    events: list[dict] = []
    try:
        # Position to after_record_id + 1 if we have a checkpoint
        offset = after_record_id + 1 if after_record_id > 0 else 0
        try:
            raw_events = win32evtlog.ReadEventLog(
                handle,
                _READ_FLAGS,
                offset,
            )
        except Exception:
            # If SEEK fails (e.g., record rotated away), start from beginning
            raw_events = win32evtlog.ReadEventLog(
                handle,
                win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ,
                0,
            )

        for ev in (raw_events or []):
            if ev.RecordNumber <= after_record_id:
                continue
            events.append(_event_to_dict(ev, channel))
            if len(events) >= batch_size:
                break
    finally:
        win32evtlog.CloseEventLog(handle)

    return events
