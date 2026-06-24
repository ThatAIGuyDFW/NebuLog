"""FortiGate extended syslog parser.

FortiGate emits logs as space-separated key=value pairs, optionally wrapped in a
BSD-syslog priority header.  The format is NOT CEF.

Example raw line:
    <190>date=2024-01-15 time=10:23:45 devname="FGT-HQ" devid="FGT60E4Q12345678"
    logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root"
    eventtime=1705311825 srcip=192.168.1.100 srcport=12345 dstip=8.8.8.8 dstport=53
    proto=17 action="accept" policyid=1 sentbyte=68 rcvdbyte=132 duration=0
    user="jsmith" msg="Traffic was allowed"
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import Any

from ..models import Category, LogLevel, NormalizedEvent, SourceType, SYSLOG_SEVERITY_MAP

# Matches  key=value  or  key="quoted value"  pairs
_KV_RE = re.compile(r'(\w+)=(?:"([^"]*?)"|(\S+))')

# Syslog priority header  <N>
_PRIORITY_RE = re.compile(r"^<(\d+)>")

# FortiGate log level strings → LogLevel
_LEVEL_MAP: dict[str, LogLevel] = {
    "emergency": LogLevel.emergency,
    "alert": LogLevel.alert,
    "critical": LogLevel.critical,
    "error": LogLevel.error,
    "warning": LogLevel.warning,
    "notice": LogLevel.notice,
    "information": LogLevel.info,
    "info": LogLevel.info,
    "debug": LogLevel.debug,
}

# FortiGate type/subtype → Category
_CATEGORY_MAP: dict[tuple[str, str], Category] = {
    ("traffic", "forward"): Category.network,
    ("traffic", "local"): Category.network,
    ("traffic", "sniffer"): Category.network,
    ("event", "system"): Category.system,
    ("event", "user"): Category.auth,
    ("event", "admin"): Category.auth,
    ("event", "vpn"): Category.auth,
    ("event", "endpoint"): Category.endpoint,
    ("utm", "virus"): Category.threat,
    ("utm", "webfilter"): Category.threat,
    ("utm", "ips"): Category.threat,
    ("utm", "app-ctrl"): Category.threat,
}


def _parse_kv(raw: str) -> dict[str, str]:
    """Extract all key=value pairs from a FortiGate log line.

    Uses finditer so non-participating groups return None (not ''), letting us
    distinguish between an empty quoted value and a missing alternate branch.
    """
    result = {}
    for m in _KV_RE.finditer(raw):
        key = m.group(1)
        # group(2) = quoted value; group(3) = bare/unquoted value
        value = m.group(2) if m.group(2) is not None else (m.group(3) or "")
        result[key] = value
    return result


def _strip_priority(raw: str) -> tuple[int | None, str]:
    """Remove <priority> prefix; return (priority_int, remainder)."""
    m = _PRIORITY_RE.match(raw)
    if m:
        return int(m.group(1)), raw[m.end():].strip()
    return None, raw


def _parse_event_time(fields: dict[str, str]) -> datetime | None:
    """Build UTC datetime from FortiGate date/time or eventtime epoch fields."""
    if "eventtime" in fields:
        try:
            # eventtime is a Unix timestamp in microseconds on newer firmware,
            # seconds on older.  Values > 1e12 are microseconds.
            ts = int(fields["eventtime"])
            if ts > 10_000_000_000:
                ts = ts // 1_000_000
            return datetime.fromtimestamp(ts, tz=timezone.utc)
        except (ValueError, OverflowError, OSError):
            pass
    if "date" in fields and "time" in fields:
        try:
            return datetime.strptime(
                f"{fields['date']} {fields['time']}", "%Y-%m-%d %H:%M:%S"
            ).replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    return None


def _map_action(fields: dict[str, str]) -> str | None:
    action = fields.get("action", "").lower()
    if not action:
        return None
    mapping = {
        "accept": "allow",
        "allowed": "allow",
        "deny": "deny",
        "blocked": "deny",
        "drop": "drop",
        "close": "close",
        "timeout": "timeout",
        "server-rst": "reset",
        "client-rst": "reset",
    }
    return mapping.get(action, action)


class FortiGateParser:
    """Parse FortiGate extended syslog (key=value) messages into NormalizedEvent."""

    source_type = SourceType.fortigate

    def parse(self, raw: str, source_host: str, received_at: datetime) -> NormalizedEvent:
        """Parse a single raw FortiGate log line.

        Args:
            raw: The complete raw log string.
            source_host: IP or hostname of the sending device.
            received_at: UTC timestamp when the ingest service received the packet.

        Returns:
            NormalizedEvent with all extractable fields populated.
        """
        priority, body = _strip_priority(raw)
        fields = _parse_kv(body)

        log_level: LogLevel | None = _LEVEL_MAP.get(fields.get("level", "").lower())
        if log_level is None and priority is not None:
            log_level = SYSLOG_SEVERITY_MAP.get(priority & 0x07)

        fg_type = fields.get("type", "").lower()
        fg_subtype = fields.get("subtype", "").lower()
        category = _CATEGORY_MAP.get((fg_type, fg_subtype))

        proto_num = fields.get("proto", "")
        proto_map = {"6": "tcp", "17": "udp", "1": "icmp", "47": "gre", "50": "esp"}
        protocol = proto_map.get(proto_num, proto_num.lower() or None)

        extra: dict[str, Any] = {}
        for key in ("devname", "devid", "logid", "vd", "policyid", "policytype",
                    "service", "dstcountry", "srccountry", "sessionid",
                    "sentbyte", "rcvdbyte", "sentpkt", "rcvdpkt", "duration",
                    "subtype", "type"):
            if key in fields:
                extra[key] = fields[key]

        message = fields.get("msg") or (
            f"{fg_type}/{fg_subtype} action={fields.get('action', 'unknown')}"
        )

        return NormalizedEvent(
            received_at=received_at,
            event_time=_parse_event_time(fields),
            source_host=fields.get("devname") or source_host,
            source_type=SourceType.fortigate,
            log_level=log_level,
            category=category,
            action=_map_action(fields),
            src_ip=fields.get("srcip"),
            src_port=int(fields["srcport"]) if fields.get("srcport", "").isdigit() else None,
            dst_ip=fields.get("dstip"),
            dst_port=int(fields["dstport"]) if fields.get("dstport", "").isdigit() else None,
            protocol=protocol,
            user_name=fields.get("user") or fields.get("unauthuser") or None,
            event_id=fields.get("logid"),
            message=message,
            raw_message=raw,
            extra=extra,
        )
