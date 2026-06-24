"""Unit tests for LinuxParser.

Tests cover both journald-native format (uppercase _KEY fields) and
rsyslog JSON format (lowercase keys).
"""

import pytest
from datetime import datetime, timezone

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from ingest.parsers.linux import LinuxParser
from ingest.models import Category, LogLevel, SourceType

PARSER = LinuxParser()
NOW = datetime(2024, 1, 15, 10, 23, 45, tzinfo=timezone.utc)
HOST = "10.0.1.50"


def parse(event: dict):
    return PARSER.parse(event, HOST, NOW)


# ---------------------------------------------------------------------------
# 1. journald — SSH successful login
# ---------------------------------------------------------------------------
SSH_ACCEPT_JOURNALD = {
    "__REALTIME_TIMESTAMP": "1705311825000000",
    "_HOSTNAME": "web-server-01",
    "_COMM": "sshd",
    "SYSLOG_IDENTIFIER": "sshd",
    "PRIORITY": "6",
    "MESSAGE": "Accepted publickey for jsmith from 192.168.1.50 port 49201 ssh2",
    "_SYSTEMD_UNIT": "sshd.service",
    "_PID": "12345",
}


def test_ssh_accept_source_type():
    assert parse(SSH_ACCEPT_JOURNALD).source_type == SourceType.linux


def test_ssh_accept_category():
    assert parse(SSH_ACCEPT_JOURNALD).category == Category.auth


def test_ssh_accept_action():
    assert parse(SSH_ACCEPT_JOURNALD).action == "logon"


def test_ssh_accept_user():
    assert parse(SSH_ACCEPT_JOURNALD).user_name == "jsmith"


def test_ssh_accept_src_ip():
    assert parse(SSH_ACCEPT_JOURNALD).src_ip == "192.168.1.50"


def test_ssh_accept_src_port():
    assert parse(SSH_ACCEPT_JOURNALD).src_port == 49201


def test_ssh_accept_hostname():
    assert parse(SSH_ACCEPT_JOURNALD).source_host == "web-server-01"


def test_ssh_accept_hipaa_tag():
    assert "hipaa:auth" in parse(SSH_ACCEPT_JOURNALD).tags


def test_ssh_accept_event_time():
    evt = parse(SSH_ACCEPT_JOURNALD)
    assert evt.event_time is not None
    assert evt.event_time.year == 2024


# ---------------------------------------------------------------------------
# 2. journald — SSH failed login (wrong password)
# ---------------------------------------------------------------------------
SSH_FAIL_JOURNALD = {
    "__REALTIME_TIMESTAMP": "1705311900000000",
    "_HOSTNAME": "web-server-01",
    "SYSLOG_IDENTIFIER": "sshd",
    "PRIORITY": "5",
    "MESSAGE": "Failed password for jsmith from 198.51.100.77 port 55000 ssh2",
    "_PID": "12346",
}


def test_ssh_fail_action():
    assert parse(SSH_FAIL_JOURNALD).action == "logon_failed"


def test_ssh_fail_user():
    assert parse(SSH_FAIL_JOURNALD).user_name == "jsmith"


def test_ssh_fail_src_ip():
    assert parse(SSH_FAIL_JOURNALD).src_ip == "198.51.100.77"


# ---------------------------------------------------------------------------
# 3. journald — SSH invalid user (brute force attempt)
# ---------------------------------------------------------------------------
SSH_INVALID_USER = {
    "__REALTIME_TIMESTAMP": "1705312000000000",
    "_HOSTNAME": "web-server-01",
    "SYSLOG_IDENTIFIER": "sshd",
    "PRIORITY": "5",
    "MESSAGE": "Invalid user admin from 203.0.113.5 port 44444",
    "_PID": "12347",
}


def test_ssh_invalid_user_action():
    assert parse(SSH_INVALID_USER).action == "logon_failed"


def test_ssh_invalid_user_src_ip():
    assert parse(SSH_INVALID_USER).src_ip == "203.0.113.5"


# ---------------------------------------------------------------------------
# 4. rsyslog JSON — sudo privilege escalation
# ---------------------------------------------------------------------------
SUDO_RSYSLOG = {
    "timestamp": "2024-01-15T10:30:00Z",
    "hostname": "db-server-01",
    "program": "sudo",
    "pid": "9999",
    "severity": 5,
    "facility": 1,
    "message": "jsmith : TTY=pts/1 ; PWD=/home/jsmith ; USER=root ; COMMAND=/bin/bash",
}


def test_sudo_category():
    assert parse(SUDO_RSYSLOG).category == Category.auth


def test_sudo_action():
    assert parse(SUDO_RSYSLOG).action == "privileged_exec"


def test_sudo_user():
    assert parse(SUDO_RSYSLOG).user_name == "jsmith"


def test_sudo_hostname():
    assert parse(SUDO_RSYSLOG).source_host == "db-server-01"


def test_sudo_event_time():
    evt = parse(SUDO_RSYSLOG)
    assert evt.event_time == datetime(2024, 1, 15, 10, 30, 0, tzinfo=timezone.utc)


# ---------------------------------------------------------------------------
# 5. rsyslog JSON — PAM authentication success
# ---------------------------------------------------------------------------
PAM_SUCCESS_RSYSLOG = {
    "timestamp": "2024-01-15T10:31:00Z",
    "hostname": "app-server-01",
    "program": "pam_unix",
    "severity": 6,
    "facility": 10,
    "message": "Accepted password for jdoe",
}


def test_pam_success_category():
    assert parse(PAM_SUCCESS_RSYSLOG).category == Category.auth


def test_pam_success_action():
    assert parse(PAM_SUCCESS_RSYSLOG).action == "logon"


def test_pam_success_user():
    assert parse(PAM_SUCCESS_RSYSLOG).user_name == "jdoe"


# ---------------------------------------------------------------------------
# 6. journald — auditd USER_AUTH event
# ---------------------------------------------------------------------------
AUDITD_AUTH = {
    "__REALTIME_TIMESTAMP": "1705312200000000",
    "_HOSTNAME": "secure-server-01",
    "SYSLOG_IDENTIFIER": "auditd",
    "PRIORITY": "6",
    "MESSAGE": 'type=USER_AUTH msg=audit(1705312200.000:123): pid=12345 uid=0 auid=1001 ses=5 acct="jsmith" exe="/usr/sbin/sshd" addr=192.168.1.50 terminal=ssh res=success',
    "_PID": "1001",
}


def test_auditd_category():
    assert parse(AUDITD_AUTH).category == Category.compliance


def test_auditd_user():
    assert parse(AUDITD_AUTH).user_name == "jsmith"


def test_auditd_src_ip():
    assert parse(AUDITD_AUTH).src_ip == "192.168.1.50"


def test_auditd_hipaa_audit_tag():
    assert "hipaa:audit" in parse(AUDITD_AUTH).tags


# ---------------------------------------------------------------------------
# 7. journald — systemd service start (system category)
# ---------------------------------------------------------------------------
SYSTEMD_START = {
    "__REALTIME_TIMESTAMP": "1705312300000000",
    "_HOSTNAME": "app-server-01",
    "SYSLOG_IDENTIFIER": "systemd",
    "PRIORITY": "6",
    "MESSAGE": "Started OpenSSH Server Daemon.",
    "_SYSTEMD_UNIT": "sshd.service",
    "_PID": "1",
}


def test_systemd_category():
    assert parse(SYSTEMD_START).category == Category.system


def test_systemd_process_name():
    assert parse(SYSTEMD_START).process_name == "systemd"


def test_systemd_no_src_ip():
    assert parse(SYSTEMD_START).src_ip is None


# ---------------------------------------------------------------------------
# 8. rsyslog JSON — SSH root login
# ---------------------------------------------------------------------------
SSH_ROOT = {
    "timestamp": "2024-01-15T22:00:00Z",
    "hostname": "server-02",
    "program": "sshd",
    "severity": 5,
    "facility": 10,
    "message": "Accepted password for root from 10.0.0.99 port 22222 ssh2",
}


def test_ssh_root_user():
    assert parse(SSH_ROOT).user_name == "root"


def test_ssh_root_action():
    assert parse(SSH_ROOT).action == "logon"


def test_ssh_root_category():
    assert parse(SSH_ROOT).category == Category.auth
