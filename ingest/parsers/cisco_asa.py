"""Cisco ASA / IOS syslog parser.

Cisco syslog format:
    <priority>Mmm DD HH:MM:SS hostname %ASA-severity-mnemonic: message body

Examples:
    <134>Jan 15 10:23:45 asa.corp.com %ASA-6-302013: Built outbound TCP connection 12345
        for outside:8.8.8.8/53 (8.8.8.8/53) to inside:192.168.1.100/12345 (10.0.0.1/12345)
    <165>Jan 15 10:24:01 asa.corp.com %ASA-5-713172: Group = GroupVPN, Username = jsmith,
        IP = 203.0.113.5, Freeing previously allocated memory for authorization-dn-attributes
"""

from __future__ import annotations

import re
from datetime import datetime, timezone
from typing import NamedTuple

from ..models import Category, LogLevel, NormalizedEvent, SourceType, SYSLOG_SEVERITY_MAP

# BSD syslog header: optional <priority>, optional timestamp + hostname
_BSD_RE = re.compile(
    r"^(?:<(\d+)>)?"
    r"(?:(\w{3}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+(\S+)\s+)?"
)

# Cisco message tag: %ASA-severity-mnemonic:
_CISCO_TAG_RE = re.compile(r"%(?:ASA|PIX|FWSM|FTD)-(\d)-(\w+):\s*(.*)", re.DOTALL)

# --- Connection-log IP/port extractor ---
_IP_PORT_RE = re.compile(r"(\d{1,3}(?:\.\d{1,3}){3})/(\d+)")

# Severity digit → LogLevel
_SEVERITY_MAP: dict[str, LogLevel] = {
    "0": LogLevel.emergency,
    "1": LogLevel.alert,
    "2": LogLevel.critical,
    "3": LogLevel.error,
    "4": LogLevel.warning,
    "5": LogLevel.notice,
    "6": LogLevel.info,
    "7": LogLevel.debug,
}

# Mnemonic → (Category, human-readable action, normalized action)
class _MnemonicInfo(NamedTuple):
    category: Category
    description: str
    action: str | None = None


_MNEMONIC_MAP: dict[str, _MnemonicInfo] = {
    # TCP connections
    "302013": _MnemonicInfo(Category.network, "Built TCP connection", "allow"),
    "302014": _MnemonicInfo(Category.network, "Teardown TCP connection", "close"),
    # UDP connections
    "302015": _MnemonicInfo(Category.network, "Built UDP connection", "allow"),
    "302016": _MnemonicInfo(Category.network, "Teardown UDP connection", "close"),
    # ACL deny
    "106001": _MnemonicInfo(Category.network, "ACL deny (inbound)", "deny"),
    "106006": _MnemonicInfo(Category.network, "ACL deny (outbound)", "deny"),
    "106007": _MnemonicInfo(Category.network, "Deny UDP reverse path", "deny"),
    "106014": _MnemonicInfo(Category.network, "Deny inbound ICMP", "deny"),
    "106023": _MnemonicInfo(Category.network, "ACL deny (no nat)", "deny"),
    # VPN
    "713172": _MnemonicInfo(Category.auth, "VPN session event"),
    "713228": _MnemonicInfo(Category.auth, "VPN group policy applied"),
    "722051": _MnemonicInfo(Category.auth, "AnyConnect session established", "allow"),
    "722052": _MnemonicInfo(Category.auth, "AnyConnect session terminated", "logoff"),
    # Authentication
    "611101": _MnemonicInfo(Category.auth, "AAA user authentication succeeded", "logon"),
    "611102": _MnemonicInfo(Category.auth, "AAA user authentication failed", "logon_failed"),
    "611103": _MnemonicInfo(Category.auth, "AAA user logout", "logoff"),
    # Threat / IDS
    "733100": _MnemonicInfo(Category.threat, "Threat detection drop rate exceeded"),
    "733101": _MnemonicInfo(Category.threat, "Threat detection burst rate exceeded"),
    "400000": _MnemonicInfo(Category.threat, "IPS alert triggered"),
}


def _parse_timestamp(ts_str: str) -> datetime | None:
    """Parse BSD syslog timestamp 'Mmm DD HH:MM:SS' (no year — use current year)."""
    try:
        now = datetime.now(tz=timezone.utc)
        dt = datetime.strptime(ts_str, "%b %d %H:%M:%S")
        return dt.replace(year=now.year, tzinfo=timezone.utc)
    except ValueError:
        return None


def _extract_connection_ips(body: str) -> tuple[str | None, int | None, str | None, int | None]:
    """Pull src and dst IP/port from ASA connection log bodies."""
    # Patterns like: 'for outside:8.8.8.8/53 ... to inside:192.168.1.100/12345'
    matches = _IP_PORT_RE.findall(body)
    if len(matches) >= 2:
        src_ip, src_port = matches[-1]   # inner (translated) src
        dst_ip, dst_port = matches[0]    # first appearance is dst
        return src_ip, int(src_port), dst_ip, int(dst_port)
    if len(matches) == 1:
        ip, port = matches[0]
        return ip, int(port), None, None
    return None, None, None, None


def _extract_user(body: str) -> str | None:
    """Try to pull Username from various ASA log patterns."""
    m = re.search(r"[Uu]sername\s*[=:]\s*(\S+)", body)
    return m.group(1).rstrip(",") if m else None


class CiscoASAParser:
    """Parse Cisco ASA (and PIX/FTD) syslog messages into NormalizedEvent."""

    source_type = SourceType.cisco_asa

    def parse(self, raw: str, source_host: str, received_at: datetime) -> NormalizedEvent:
        """Parse a single raw Cisco ASA syslog line.

        Args:
            raw: The complete raw log string.
            source_host: IP or hostname of the sending device.
            received_at: UTC timestamp when the ingest service received the packet.

        Returns:
            NormalizedEvent with all extractable fields populated.
        """
        priority: int | None = None
        event_time: datetime | None = None
        detected_host = source_host

        bsd_m = _BSD_RE.match(raw)
        remaining = raw
        if bsd_m:
            if bsd_m.group(1):
                priority = int(bsd_m.group(1))
            if bsd_m.group(2):
                event_time = _parse_timestamp(bsd_m.group(2))
            if bsd_m.group(3):
                detected_host = bsd_m.group(3)
            remaining = raw[bsd_m.end():]

        cisco_m = _CISCO_TAG_RE.search(remaining)
        if not cisco_m:
            # Not a Cisco-tagged message; store as generic
            log_level = SYSLOG_SEVERITY_MAP.get(priority & 0x07) if priority is not None else None
            return NormalizedEvent(
                received_at=received_at,
                event_time=event_time,
                source_host=detected_host,
                source_type=SourceType.cisco_asa,
                log_level=log_level,
                message=remaining.strip() or raw,
                raw_message=raw,
            )

        severity_digit = cisco_m.group(1)
        mnemonic = cisco_m.group(2)
        body = cisco_m.group(3).strip()

        log_level = _SEVERITY_MAP.get(severity_digit)
        mnemonic_info = _MNEMONIC_MAP.get(mnemonic)

        category = mnemonic_info.category if mnemonic_info else Category.system
        action = mnemonic_info.action if mnemonic_info else None
        description = mnemonic_info.description if mnemonic_info else f"ASA-{severity_digit}-{mnemonic}"

        src_ip, src_port, dst_ip, dst_port = _extract_connection_ips(body)
        user_name = _extract_user(body)

        # Determine protocol from mnemonic
        protocol: str | None = None
        if mnemonic in ("302013", "302014"):
            protocol = "tcp"
        elif mnemonic in ("302015", "302016"):
            protocol = "udp"

        message = f"{description}: {body}" if body else description

        return NormalizedEvent(
            received_at=received_at,
            event_time=event_time,
            source_host=detected_host,
            source_type=SourceType.cisco_asa,
            log_level=log_level,
            category=category,
            action=action,
            src_ip=src_ip,
            src_port=src_port,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            user_name=user_name,
            event_id=mnemonic,
            message=message,
            raw_message=raw,
            extra={"mnemonic": mnemonic, "severity_digit": severity_digit},
        )
