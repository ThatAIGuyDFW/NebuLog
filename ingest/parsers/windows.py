"""Windows Event Log parser.

The Windows agent ships JSON batches to the ingest HTTPS endpoint.
Each event in the batch follows this structure:

{
    "EventID": 4624,
    "TimeCreated": "2024-01-15T10:23:45.123456Z",
    "Computer": "WORKSTATION-01",
    "Channel": "Security",
    "Level": 0,
    "EventData": {
        "SubjectUserName": "SYSTEM",
        "TargetUserName": "jsmith",
        "IpAddress": "192.168.1.50",
        "IpPort": "49201",
        "LogonType": "3",
        "ProcessName": "C:\\\\Windows\\\\System32\\\\svchost.exe"
    }
}

Windows event Level values:
    0=LogAlways, 1=Critical, 2=Error, 3=Warning, 4=Info, 5=Verbose
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from ..models import Category, LogLevel, NormalizedEvent, SourceType

# Windows Level → LogLevel
_WIN_LEVEL_MAP: dict[int, LogLevel] = {
    0: LogLevel.info,       # LogAlways
    1: LogLevel.critical,
    2: LogLevel.error,
    3: LogLevel.warning,
    4: LogLevel.info,
    5: LogLevel.debug,
}

# Event ID → (Category, action, human message template)
# %KEY% tokens are replaced from EventData
_EVENT_ID_MAP: dict[int, tuple[Category, str | None, str]] = {
    4624: (Category.auth,     "logon",            "Successful account logon: %TargetUserName%"),
    4625: (Category.auth,     "logon_failed",     "Failed account logon: %TargetUserName% (Logon type %LogonType%)"),
    4634: (Category.auth,     "logoff",           "Account logoff: %TargetUserName%"),
    4647: (Category.auth,     "logoff",           "User-initiated logoff: %TargetUserName%"),
    4648: (Category.auth,     "logon",            "Explicit credential logon attempt by %SubjectUserName% as %TargetUserName%"),
    4672: (Category.auth,     "privileged_logon", "Special privileges assigned to new logon: %SubjectUserName%"),
    4688: (Category.endpoint, None,               "Process created: %NewProcessName% by %SubjectUserName%"),
    4698: (Category.endpoint, None,               "Scheduled task created: %TaskName%"),
    4702: (Category.endpoint, None,               "Scheduled task updated: %TaskName%"),
    4720: (Category.auth,     None,               "User account created: %TargetUserName% by %SubjectUserName%"),
    4722: (Category.auth,     None,               "User account enabled: %TargetUserName%"),
    4725: (Category.auth,     None,               "User account disabled: %TargetUserName%"),
    4726: (Category.auth,     None,               "User account deleted: %TargetUserName% by %SubjectUserName%"),
    4740: (Category.auth,     None,               "User account locked out: %TargetUserName%"),
    4756: (Category.auth,     None,               "Member added to security-enabled universal group: %MemberName%"),
    4771: (Category.auth,     "logon_failed",     "Kerberos pre-authentication failed: %TargetUserName%"),
    4776: (Category.auth,     "logon_failed",     "NTLM authentication failure: %TargetUserName%"),
    1102: (Category.compliance, None,             "Audit log was cleared by %SubjectUserName%"),
    7045: (Category.system,   None,               "New service installed: %ServiceName% (%ImagePath%)"),
    4697: (Category.system,   None,               "Service installed in the system: %ServiceName%"),
}

# Logon type codes
_LOGON_TYPE = {
    "2": "Interactive",
    "3": "Network",
    "4": "Batch",
    "5": "Service",
    "7": "Unlock",
    "8": "NetworkCleartext",
    "9": "NewCredentials",
    "10": "RemoteInteractive",
    "11": "CachedInteractive",
}


def _format_message(template: str, event_data: dict[str, str]) -> str:
    """Replace %KEY% tokens in template with values from EventData."""
    result = template
    for key, value in event_data.items():
        result = result.replace(f"%{key}%", value or "-")
    # Remove any unreplaced tokens
    result = result.replace("%", "")
    return result.strip()


def _parse_timestamp(ts: str | None) -> datetime | None:
    if not ts:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


class WindowsParser:
    """Parse Windows Event Log JSON objects into NormalizedEvent."""

    source_type = SourceType.windows

    def parse(self, event: dict[str, Any], source_host: str, received_at: datetime) -> NormalizedEvent:
        """Parse a single Windows event JSON dict.

        Args:
            event: Parsed JSON dict from the Windows agent.
            source_host: IP or hostname of the Windows host (from agent registration).
            received_at: UTC timestamp when the ingest service received the batch.

        Returns:
            NormalizedEvent with all extractable fields populated.
        """
        event_id_int: int = int(event.get("EventID", 0))
        event_data: dict[str, str] = event.get("EventData", {})
        computer: str = event.get("Computer", source_host)
        channel: str = event.get("Channel", "")
        level_int: int = int(event.get("Level", 4))

        event_time = _parse_timestamp(event.get("TimeCreated"))
        log_level = _WIN_LEVEL_MAP.get(level_int, LogLevel.info)

        mapping = _EVENT_ID_MAP.get(event_id_int)
        category = mapping[0] if mapping else Category.system
        action = mapping[1] if mapping else None
        msg_template = mapping[2] if mapping else f"Windows Event {event_id_int} ({channel})"

        # Resolve user name — prefer target, fall back to subject
        user_name = (
            event_data.get("TargetUserName")
            or event_data.get("SubjectUserName")
            or None
        )
        # Strip machine accounts (end with $) for cleanliness
        if user_name and user_name.endswith("$"):
            user_name = None

        src_ip = event_data.get("IpAddress") or event_data.get("SourceAddress") or None
        if src_ip in ("-", "::1", "127.0.0.1", ""):
            src_ip = None

        src_port_str = event_data.get("IpPort", "")
        src_port = int(src_port_str) if src_port_str.isdigit() else None

        process_name = (
            event_data.get("NewProcessName")
            or event_data.get("ProcessName")
            or None
        )
        if process_name:
            # Normalise to executable name only
            process_name = process_name.replace("\\", "/").split("/")[-1]

        # Build extra: anything not in the core schema
        core_keys = {"SubjectUserName", "TargetUserName", "IpAddress", "IpPort",
                     "NewProcessName", "ProcessName", "LogonType"}
        extra: dict[str, Any] = {
            k: v for k, v in event_data.items() if k not in core_keys
        }
        extra["Channel"] = channel
        if "LogonType" in event_data:
            extra["LogonType"] = _LOGON_TYPE.get(event_data["LogonType"], event_data["LogonType"])

        message = _format_message(msg_template, event_data)

        tags = []
        if event_id_int in (4624, 4625, 4648, 4672, 4634, 4647, 4771, 4776):
            tags.append("hipaa:auth")
        if event_id_int == 1102:
            tags.extend(["hipaa:integrity", "pci_dss"])

        return NormalizedEvent(
            received_at=received_at,
            event_time=event_time,
            source_host=computer,
            source_type=SourceType.windows,
            log_level=log_level,
            category=category,
            action=action,
            src_ip=src_ip,
            src_port=src_port,
            user_name=user_name,
            process_name=process_name,
            event_id=str(event_id_int),
            message=message,
            raw_message=None,  # Set by caller from raw JSON string if needed
            tags=tags,
            extra=extra,
        )
