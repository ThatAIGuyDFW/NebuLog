"""Linux syslog / journald parser.

The Linux agent ships JSON events to the ingest HTTPS endpoint.
Each event follows the journald JSON export format, with additional
normalised fields added by the agent:

{
    "__REALTIME_TIMESTAMP": "1705311825000000",
    "__MONOTONIC_TIMESTAMP": "123456789",
    "_HOSTNAME": "web-server-01",
    "_COMM": "sshd",
    "_PID": "12345",
    "PRIORITY": "6",
    "SYSLOG_FACILITY": "10",
    "SYSLOG_IDENTIFIER": "sshd",
    "MESSAGE": "Accepted publickey for jsmith from 192.168.1.50 port 49201 ssh2",
    "_SOURCE_REALTIME_TIMESTAMP": "1705311825000000"
}

The parser also handles plain rsyslog-forwarded BSD syslog JSON dicts:
{
    "timestamp": "2024-01-15T10:23:45Z",
    "hostname": "web-server-01",
    "program": "sudo",
    "pid": "12345",
    "severity": 5,
    "facility": 1,
    "message": "jsmith : TTY=pts/1 ; PWD=/home/jsmith ; USER=root ; COMMAND=/bin/bash"
}
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from ..models import Category, LogLevel, NormalizedEvent, SourceType, SYSLOG_SEVERITY_MAP

# sshd message patterns
_SSH_ACCEPT_RE = re.compile(
    r"Accepted (?P<method>\S+) for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)"
)
_SSH_FAIL_RE = re.compile(
    r"(?:Failed|Invalid user)\s+(?:\S+\s+)?(?:for\s+)?(?P<user>\S+)?\s+from\s+(?P<ip>\S+)\s+port\s+(?P<port>\d+)"
)
_SSH_DISCONNECT_RE = re.compile(
    r"Disconnected from (?:authenticating\s+)?(?:user\s+)?(?P<user>\S+)? (?P<ip>\S+) port (?P<port>\d+)"
)

# sudo pattern: user -> root
_SUDO_RE = re.compile(r"(?P<user>\S+)\s+:.*USER=(?P<runas>\S+)\s+;\s+COMMAND=(?P<cmd>.+)")

# PAM authentication
_PAM_AUTH_RE = re.compile(
    r"(?P<result>Accepted|Failed|Authentication failure)\s+(?:password\s+)?(?:for\s+)?(?:user\s+)?(?P<user>\S+)"
)

# auditd USER_AUTH / USER_LOGIN
_AUDIT_RE = re.compile(
    r"type=(?P<type>\w+).*?acct=\"(?P<user>[^\"]+)\".*?addr=(?P<ip>\S+)"
)

# kernel OOM killer
_OOM_RE = re.compile(r"Out of memory: Kill process (\d+) \((\S+)\)")

# Program → Category hint
_PROGRAM_CATEGORY: dict[str, Category] = {
    "sshd": Category.auth,
    "sudo": Category.auth,
    "su": Category.auth,
    "login": Category.auth,
    "passwd": Category.auth,
    "pam": Category.auth,
    "useradd": Category.auth,
    "userdel": Category.auth,
    "groupadd": Category.auth,
    "kernel": Category.system,
    "systemd": Category.system,
    "auditd": Category.compliance,
    "cron": Category.system,
    "crond": Category.system,
    "rsyslogd": Category.system,
}


def _parse_ts_usec(ts_usec: str | None) -> datetime | None:
    """Parse journald __REALTIME_TIMESTAMP (microseconds since epoch)."""
    if not ts_usec:
        return None
    try:
        return datetime.fromtimestamp(int(ts_usec) / 1_000_000, tz=timezone.utc)
    except (ValueError, OverflowError, OSError):
        return None


def _parse_iso_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%S.%fZ", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
        try:
            return datetime.strptime(ts, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _classify_message(program: str, message: str) -> tuple[Category, str | None, str | None, str | None, int | None]:
    """Return (category, action, src_ip, user_name, src_port)."""
    prog = program.lower()
    message_lower = message.lower()

    # SSH
    if prog in ("sshd",):
        m = _SSH_ACCEPT_RE.search(message)
        if m:
            return Category.auth, "logon", m.group("ip"), m.group("user"), int(m.group("port"))
        m = _SSH_FAIL_RE.search(message)
        if m:
            return Category.auth, "logon_failed", m.group("ip"), m.group("user"), int(m.group("port"))
        m = _SSH_DISCONNECT_RE.search(message)
        if m:
            return Category.auth, "logoff", m.group("ip"), m.group("user"), int(m.group("port")) if m.group("port") else None

    # sudo
    if prog == "sudo":
        m = _SUDO_RE.search(message)
        if m:
            return Category.auth, "privileged_exec", None, m.group("user"), None

    # PAM
    if "pam" in prog:
        m = _PAM_AUTH_RE.search(message)
        if m:
            result = m.group("result").lower()
            action = "logon" if result == "accepted" else "logon_failed"
            return Category.auth, action, None, m.group("user"), None

    # auditd
    if prog == "auditd":
        m = _AUDIT_RE.search(message)
        if m:
            return Category.compliance, None, m.group("ip"), m.group("user"), None

    # kernel OOM
    if prog == "kernel" and "out of memory" in message_lower:
        return Category.system, None, None, None, None

    # cron
    if prog in ("cron", "crond") and ("started" in message_lower or "session opened" in message_lower):
        return Category.system, None, None, None, None

    return _PROGRAM_CATEGORY.get(prog, Category.system), None, None, None, None


class LinuxParser:
    """Parse Linux journald/syslog JSON events into NormalizedEvent."""

    source_type = SourceType.linux

    def parse(self, event: dict[str, Any], source_host: str, received_at: datetime) -> NormalizedEvent:
        """Parse a single Linux agent JSON event dict.

        Handles both journald-native format (journald field names) and
        rsyslog JSON format (lowercase field names).

        Args:
            event: Parsed JSON dict from the Linux agent.
            source_host: IP or hostname of the Linux host.
            received_at: UTC timestamp when the ingest service received the batch.

        Returns:
            NormalizedEvent with all extractable fields populated.
        """
        # Detect format: journald uses ALL_CAPS field names prefixed with _ or __
        is_journald = "_HOSTNAME" in event or "__REALTIME_TIMESTAMP" in event

        if is_journald:
            hostname = event.get("_HOSTNAME", source_host)
            message = event.get("MESSAGE", "")
            program = (
                event.get("SYSLOG_IDENTIFIER")
                or event.get("_COMM")
                or "unknown"
            )
            priority = int(event.get("PRIORITY", 6))
            pid_str = event.get("_PID", "")
            event_time = _parse_ts_usec(event.get("__REALTIME_TIMESTAMP"))
        else:
            # rsyslog JSON format
            hostname = event.get("hostname", source_host)
            message = event.get("message", "")
            program = event.get("program", event.get("app-name", "unknown"))
            priority = int(event.get("severity", 6))
            pid_str = str(event.get("pid", ""))
            event_time = _parse_iso_ts(event.get("timestamp"))

        log_level = SYSLOG_SEVERITY_MAP.get(priority & 0x07, LogLevel.info)

        category, action, src_ip, user_name, src_port = _classify_message(program, message)

        # Build extra: preserve raw journald metadata
        extra: dict[str, Any] = {}
        if is_journald:
            for key in ("_SYSTEMD_UNIT", "_BOOT_ID", "SYSLOG_FACILITY",
                        "_UID", "_GID", "_EXE", "_CMDLINE", "_TRANSPORT"):
                if key in event:
                    extra[key] = event[key]
        else:
            for key in ("facility", "app-name", "procid", "msgid", "structured-data"):
                if key in event:
                    extra[key] = event[key]

        if pid_str:
            extra["pid"] = pid_str

        tags: list[str] = []
        if category == Category.auth:
            tags.append("hipaa:auth")
        if program.lower() == "auditd":
            tags.append("hipaa:audit")

        return NormalizedEvent(
            received_at=received_at,
            event_time=event_time,
            source_host=hostname,
            source_type=SourceType.linux,
            log_level=log_level,
            category=category,
            action=action,
            src_ip=src_ip,
            src_port=src_port,
            user_name=user_name,
            process_name=program,
            message=message,
            raw_message=None,  # Set by caller
            tags=tags,
            extra=extra,
        )
