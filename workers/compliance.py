"""Compliance tag engine.

Adds HIPAA and PCI DSS tags to NormalizedEvent objects before they are
persisted to PostgreSQL.  Tags are cumulative — the parser may already have
added some; this module adds any that the parser couldn't know (e.g. whether
the source is in the PCI cardholder environment).

Tag conventions used throughout:
  hipaa:auth         — authentication events (logins, failures, logoffs)
  hipaa:session      — session lifecycle (4634/4647 Windows logoff)
  hipaa:integrity    — log-tampering events (audit log cleared)
  hipaa:audit        — auditd / system audit trail events
  pci_dss            — event from a PCI cardholder-environment source
  pci:cardholder_env — (set at source-registration time, not here)
"""

from __future__ import annotations

from ingest.models import Category, NormalizedEvent

# Windows Event IDs that map to HIPAA session tracking
_HIPAA_SESSION_IDS = {"4634", "4647"}

# Windows Event IDs that map to HIPAA integrity
_HIPAA_INTEGRITY_IDS = {"1102"}    # audit log cleared

# Categories that always get hipaa:auth
_HIPAA_AUTH_CATEGORIES = {Category.auth}


def apply_compliance_tags(event: NormalizedEvent, is_pci_env: bool = False) -> None:
    """Mutate event.tags in-place to add all applicable compliance tags."""
    tags = set(event.tags)

    # --- HIPAA ---
    if event.category in _HIPAA_AUTH_CATEGORIES and "hipaa:auth" not in tags:
        tags.add("hipaa:auth")

    if event.event_id in _HIPAA_SESSION_IDS:
        tags.add("hipaa:session")

    if event.event_id in _HIPAA_INTEGRITY_IDS:
        tags.add("hipaa:integrity")

    # FortiGate audit log cleared
    if event.event_id == "0100044546":
        tags.add("hipaa:integrity")
        tags.add("pci_dss")

    # --- PCI DSS ---
    if is_pci_env:
        tags.add("pci_dss")
        tags.add("pci:cardholder_env")

    # PCI Req 10.3 — any audit-log-cleared event
    if "hipaa:integrity" in tags:
        tags.add("pci_dss")

    event.tags = sorted(tags)
