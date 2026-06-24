"""Unit tests for WindowsParser.

Each test uses a realistic Windows Event Log JSON dict as produced by the Windows agent.
"""

import pytest
from datetime import datetime, timezone

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from ingest.parsers.windows import WindowsParser
from ingest.models import Category, LogLevel, SourceType

PARSER = WindowsParser()
NOW = datetime(2024, 1, 15, 10, 23, 45, tzinfo=timezone.utc)
HOST = "192.168.1.50"


def parse(event: dict):
    return PARSER.parse(event, HOST, NOW)


# ---------------------------------------------------------------------------
# 1. Successful logon (4624)
# ---------------------------------------------------------------------------
LOGON_SUCCESS = {
    "EventID": 4624,
    "TimeCreated": "2024-01-15T10:23:45.000000Z",
    "Computer": "WORKSTATION-01",
    "Channel": "Security",
    "Level": 0,
    "EventData": {
        "SubjectUserName": "SYSTEM",
        "TargetUserName": "jsmith",
        "IpAddress": "192.168.1.50",
        "IpPort": "49201",
        "LogonType": "3",
    },
}


def test_logon_success_source_type():
    assert parse(LOGON_SUCCESS).source_type == SourceType.windows


def test_logon_success_category():
    assert parse(LOGON_SUCCESS).category == Category.auth


def test_logon_success_action():
    assert parse(LOGON_SUCCESS).action == "logon"


def test_logon_success_user():
    assert parse(LOGON_SUCCESS).user_name == "jsmith"


def test_logon_success_src_ip():
    assert parse(LOGON_SUCCESS).src_ip == "192.168.1.50"


def test_logon_success_event_id():
    assert parse(LOGON_SUCCESS).event_id == "4624"


def test_logon_success_hipaa_tag():
    assert "hipaa:auth" in parse(LOGON_SUCCESS).tags


def test_logon_success_host():
    assert parse(LOGON_SUCCESS).source_host == "WORKSTATION-01"


# ---------------------------------------------------------------------------
# 2. Failed logon (4625)
# ---------------------------------------------------------------------------
LOGON_FAIL = {
    "EventID": 4625,
    "TimeCreated": "2024-01-15T10:24:00.000000Z",
    "Computer": "WORKSTATION-01",
    "Channel": "Security",
    "Level": 4,
    "EventData": {
        "TargetUserName": "badactor",
        "IpAddress": "198.51.100.77",
        "IpPort": "55000",
        "LogonType": "3",
        "FailureReason": "Unknown user name or bad password",
    },
}


def test_logon_fail_action():
    assert parse(LOGON_FAIL).action == "logon_failed"


def test_logon_fail_user():
    assert parse(LOGON_FAIL).user_name == "badactor"


def test_logon_fail_src_ip():
    assert parse(LOGON_FAIL).src_ip == "198.51.100.77"


# ---------------------------------------------------------------------------
# 3. Privileged logon (4672) — special privileges assigned
# ---------------------------------------------------------------------------
PRIV_LOGON = {
    "EventID": 4672,
    "TimeCreated": "2024-01-15T20:30:00.000000Z",
    "Computer": "DC-01",
    "Channel": "Security",
    "Level": 0,
    "EventData": {
        "SubjectUserName": "DomainAdmin",
        "PrivilegeList": "SeDebugPrivilege\tSeImpersonatePrivilege",
    },
}


def test_priv_logon_action():
    assert parse(PRIV_LOGON).action == "privileged_logon"


def test_priv_logon_user():
    assert parse(PRIV_LOGON).user_name == "DomainAdmin"


def test_priv_logon_category():
    assert parse(PRIV_LOGON).category == Category.auth


# ---------------------------------------------------------------------------
# 4. Process creation (4688)
# ---------------------------------------------------------------------------
PROCESS_CREATE = {
    "EventID": 4688,
    "TimeCreated": "2024-01-15T10:25:00.000000Z",
    "Computer": "WORKSTATION-01",
    "Channel": "Security",
    "Level": 0,
    "EventData": {
        "SubjectUserName": "jsmith",
        "NewProcessName": "C:\\Windows\\System32\\cmd.exe",
        "CommandLine": "cmd.exe /c whoami",
        "ParentProcessName": "C:\\Windows\\explorer.exe",
    },
}


def test_process_create_category():
    assert parse(PROCESS_CREATE).category == Category.endpoint


def test_process_create_process_name():
    assert parse(PROCESS_CREATE).process_name == "cmd.exe"


def test_process_create_event_id():
    assert parse(PROCESS_CREATE).event_id == "4688"


# ---------------------------------------------------------------------------
# 5. Audit log cleared (1102)
# ---------------------------------------------------------------------------
AUDIT_CLEARED = {
    "EventID": 1102,
    "TimeCreated": "2024-01-15T11:00:00.000000Z",
    "Computer": "WORKSTATION-01",
    "Channel": "Security",
    "Level": 4,
    "EventData": {
        "SubjectUserName": "badactor",
        "SubjectDomainName": "CORP",
    },
}


def test_audit_cleared_category():
    assert parse(AUDIT_CLEARED).category == Category.compliance


def test_audit_cleared_user():
    assert parse(AUDIT_CLEARED).user_name == "badactor"


def test_audit_cleared_pci_tag():
    assert "pci_dss" in parse(AUDIT_CLEARED).tags


def test_audit_cleared_message():
    assert "cleared" in parse(AUDIT_CLEARED).message.lower()


# ---------------------------------------------------------------------------
# 6. New service installed (7045)
# ---------------------------------------------------------------------------
SERVICE_INSTALLED = {
    "EventID": 7045,
    "TimeCreated": "2024-01-15T09:00:00.000000Z",
    "Computer": "SERVER-01",
    "Channel": "System",
    "Level": 4,
    "EventData": {
        "ServiceName": "EvilService",
        "ImagePath": "C:\\Temp\\evil.exe",
        "ServiceType": "user mode service",
        "StartType": "auto start",
    },
}


def test_service_installed_category():
    assert parse(SERVICE_INSTALLED).category == Category.system


def test_service_installed_event_id():
    assert parse(SERVICE_INSTALLED).event_id == "7045"


def test_service_installed_message():
    msg = parse(SERVICE_INSTALLED).message
    assert "EvilService" in msg or "service" in msg.lower()


# ---------------------------------------------------------------------------
# 7. Account created (4720)
# ---------------------------------------------------------------------------
ACCOUNT_CREATED = {
    "EventID": 4720,
    "TimeCreated": "2024-01-15T08:30:00.000000Z",
    "Computer": "DC-01",
    "Channel": "Security",
    "Level": 0,
    "EventData": {
        "SubjectUserName": "DomainAdmin",
        "TargetUserName": "newuser",
    },
}


def test_account_created_category():
    assert parse(ACCOUNT_CREATED).category == Category.auth


def test_account_created_message():
    msg = parse(ACCOUNT_CREATED).message.lower()
    assert "created" in msg or "newuser" in msg


# ---------------------------------------------------------------------------
# 8. Machine account not reported as user (ends with $)
# ---------------------------------------------------------------------------
MACHINE_LOGON = {
    "EventID": 4624,
    "TimeCreated": "2024-01-15T10:00:00.000000Z",
    "Computer": "SERVER-01",
    "Channel": "Security",
    "Level": 0,
    "EventData": {
        "TargetUserName": "SERVER-01$",
        "IpAddress": "-",
        "IpPort": "0",
        "LogonType": "3",
    },
}


def test_machine_account_user_stripped():
    assert parse(MACHINE_LOGON).user_name is None


def test_machine_account_loopback_ip_stripped():
    assert parse(MACHINE_LOGON).src_ip is None
