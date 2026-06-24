"""Source registry — maps source IP to parser class and metadata.

Loaded from the PostgreSQL 'sources' table at startup.  The registry is
held in memory as a dict; the ingest API can trigger a hot-reload when a
new source is registered via the REST API.

If a source IP is not found in the registry the ingest service attempts
format auto-detection and logs an 'unregistered_source' warning to the
sentinel:errors stream.
"""

from __future__ import annotations

import re
from typing import Any

import structlog

from .models import SourceType
from .parsers import CiscoASAParser, FortiGateParser, LinuxParser, WindowsParser

log = structlog.get_logger()

# The four parser singletons — stateless, thread-safe
_PARSERS = {
    SourceType.fortigate: FortiGateParser(),
    SourceType.cisco_asa: CiscoASAParser(),
    SourceType.cisco_ios: CiscoASAParser(),   # IOS uses same BSD syslog format
    SourceType.windows: WindowsParser(),
    SourceType.linux: LinuxParser(),
}

# Heuristics for auto-detection when source IP is unregistered
_FORTI_RE = re.compile(r"type=|devname=|logid=")
_CISCO_RE = re.compile(r"%(?:ASA|PIX|FTD|IOS)-\d-\w+:")
_WINDOWS_RE = re.compile(r'"EventID"')
_LINUX_RE = re.compile(r'"__REALTIME_TIMESTAMP"|"_HOSTNAME"')


def _autodetect(raw: str) -> SourceType:
    if _FORTI_RE.search(raw):
        return SourceType.fortigate
    if _CISCO_RE.search(raw):
        return SourceType.cisco_asa
    if _WINDOWS_RE.search(raw):
        return SourceType.windows
    if _LINUX_RE.search(raw):
        return SourceType.linux
    return SourceType.linux   # generic syslog fallback


class SourceRegistry:
    """Thread-safe in-memory source registry."""

    def __init__(self) -> None:
        # ip_address -> {"source_type": SourceType, "label": str, "pci_env": bool, ...}
        self._sources: dict[str, dict[str, Any]] = {}

    def load(self, rows: list[dict[str, Any]]) -> None:
        """Replace registry contents from DB rows."""
        self._sources = {
            row["ip_address"]: {
                "source_type": SourceType(row["source_type"]),
                "label": row.get("label") or row["ip_address"],
                "pci_env": "pci:cardholder_env" in (row.get("tags") or []),
            }
            for row in rows
            if row.get("enabled", True)
        }
        log.info("source_registry_loaded", count=len(self._sources))

    def get_parser(self, source_ip: str, raw: str):
        """Return the parser for source_ip, auto-detecting if unregistered."""
        entry = self._sources.get(source_ip)
        if entry:
            return _PARSERS[entry["source_type"]], entry
        # Unknown source — auto-detect and warn
        detected = _autodetect(raw)
        log.warning("unregistered_source", source_ip=source_ip, detected_type=detected)
        return _PARSERS[detected], {"source_type": detected, "label": source_ip, "pci_env": False}

    def is_pci_env(self, source_ip: str) -> bool:
        entry = self._sources.get(source_ip)
        return bool(entry and entry.get("pci_env"))

    def register(self, row: dict[str, Any]) -> None:
        """Add or update a single source (called on POST /sources)."""
        ip = row["ip_address"]
        self._sources[ip] = {
            "source_type": SourceType(row["source_type"]),
            "label": row.get("label") or ip,
            "pci_env": "pci:cardholder_env" in (row.get("tags") or []),
        }
