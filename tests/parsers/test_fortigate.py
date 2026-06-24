"""Unit tests for FortiGateParser.

Sample log lines sourced from FortiOS 7.x syslog output.
Each test validates field extraction without needing live infrastructure.
"""

import pytest
from datetime import datetime, timezone

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from ingest.parsers.fortigate import FortiGateParser
from ingest.models import Category, LogLevel, SourceType

PARSER = FortiGateParser()
NOW = datetime(2024, 1, 15, 10, 23, 45, tzinfo=timezone.utc)
HOST = "192.168.1.1"


def parse(raw: str):
    return PARSER.parse(raw, HOST, NOW)


# ---------------------------------------------------------------------------
# 1. Forward traffic — accepted connection (DNS)
# ---------------------------------------------------------------------------
TRAFFIC_ACCEPT = (
    '<190>date=2024-01-15 time=10:23:45 devname="FGT-HQ" devid="FGT60E4Q12345678" '
    'logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" '
    'eventtime=1705311825 srcip=192.168.1.100 srcport=12345 dstip=8.8.8.8 dstport=53 '
    'proto=17 action="accept" policyid=1 sentbyte=68 rcvdbyte=132 duration=0 '
    'user="jsmith" msg="Traffic allowed by policy"'
)


def test_traffic_accept_source_type():
    assert parse(TRAFFIC_ACCEPT).source_type == SourceType.fortigate


def test_traffic_accept_action():
    assert parse(TRAFFIC_ACCEPT).action == "allow"


def test_traffic_accept_src_ip():
    assert parse(TRAFFIC_ACCEPT).src_ip == "192.168.1.100"


def test_traffic_accept_dst_ip():
    assert parse(TRAFFIC_ACCEPT).dst_ip == "8.8.8.8"


def test_traffic_accept_dst_port():
    assert parse(TRAFFIC_ACCEPT).dst_port == 53


def test_traffic_accept_protocol():
    assert parse(TRAFFIC_ACCEPT).protocol == "udp"


def test_traffic_accept_user():
    assert parse(TRAFFIC_ACCEPT).user_name == "jsmith"


def test_traffic_accept_category():
    assert parse(TRAFFIC_ACCEPT).category == Category.network


def test_traffic_accept_log_level():
    assert parse(TRAFFIC_ACCEPT).log_level == LogLevel.notice


def test_traffic_accept_event_time():
    evt = parse(TRAFFIC_ACCEPT)
    # eventtime epoch (1705311825) takes priority over date/time string fields
    assert evt.event_time == datetime.fromtimestamp(1705311825, tz=timezone.utc)


# ---------------------------------------------------------------------------
# 2. Forward traffic — denied by ACL
# ---------------------------------------------------------------------------
TRAFFIC_DENY = (
    '<182>date=2024-01-15 time=11:00:00 devname="FGT-HQ" devid="FGT60E4Q12345678" '
    'logid="0000000022" type="traffic" subtype="forward" level="warning" vd="root" '
    'srcip=10.10.10.50 srcport=44123 dstip=203.0.113.25 dstport=443 proto=6 '
    'action="deny" policyid=0 msg="no matching policy"'
)


def test_traffic_deny_action():
    assert parse(TRAFFIC_DENY).action == "deny"


def test_traffic_deny_protocol():
    assert parse(TRAFFIC_DENY).protocol == "tcp"


def test_traffic_deny_message():
    assert "no matching policy" in parse(TRAFFIC_DENY).message


def test_traffic_deny_log_level():
    assert parse(TRAFFIC_DENY).log_level == LogLevel.warning


# ---------------------------------------------------------------------------
# 3. Admin login event
# ---------------------------------------------------------------------------
ADMIN_LOGIN = (
    '<134>date=2024-01-15 time=08:00:00 devname="FGT-HQ" devid="FGT60E4Q12345678" '
    'logid="0100032001" type="event" subtype="admin" level="information" vd="root" '
    'user="admin" ui="GUI" srcip=192.168.0.10 msg="Administrator admin logged in"'
)


def test_admin_login_category():
    assert parse(ADMIN_LOGIN).category == Category.auth


def test_admin_login_user():
    assert parse(ADMIN_LOGIN).user_name == "admin"


def test_admin_login_src_ip():
    assert parse(ADMIN_LOGIN).src_ip == "192.168.0.10"


def test_admin_login_log_level():
    assert parse(ADMIN_LOGIN).log_level == LogLevel.info


# ---------------------------------------------------------------------------
# 4. IPS / UTM threat event
# ---------------------------------------------------------------------------
UTM_IPS = (
    '<164>date=2024-01-15 time=12:30:00 devname="FGT-HQ" devid="FGT60E4Q12345678" '
    'logid="0419016384" type="utm" subtype="ips" level="alert" vd="root" '
    'srcip=198.51.100.77 srcport=0 dstip=192.168.1.200 dstport=80 '
    'proto=6 action="blocked" msg="Mimikatz credential dumping detected"'
)


def test_ips_category():
    assert parse(UTM_IPS).category == Category.threat


def test_ips_action():
    assert parse(UTM_IPS).action == "deny"


def test_ips_message():
    assert "Mimikatz" in parse(UTM_IPS).message


# ---------------------------------------------------------------------------
# 5. VPN event (no syslog priority header)
# ---------------------------------------------------------------------------
VPN_EVENT = (
    'date=2024-01-15 time=14:05:22 devname="FGT-HQ" devid="FGT60E4Q12345678" '
    'logid="0101039424" type="event" subtype="vpn" level="notice" vd="root" '
    'tunneltype="ssl-web" user="jdoe" srcip=203.0.113.15 msg="SSL VPN tunnel up"'
)


def test_vpn_no_priority_header():
    evt = parse(VPN_EVENT)
    assert evt.source_type == SourceType.fortigate


def test_vpn_user():
    assert parse(VPN_EVENT).user_name == "jdoe"


def test_vpn_category():
    assert parse(VPN_EVENT).category == Category.auth


def test_vpn_src_ip():
    assert parse(VPN_EVENT).src_ip == "203.0.113.15"


# ---------------------------------------------------------------------------
# 6. Outbound data exfil candidate (large sentbyte)
# ---------------------------------------------------------------------------
EXFIL_EVENT = (
    '<190>date=2024-01-15 time=15:00:00 devname="FGT-HQ" devid="FGT60E4Q12345678" '
    'logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" '
    'srcip=192.168.1.99 srcport=55000 dstip=104.21.10.1 dstport=443 proto=6 '
    'action="accept" sentbyte=600000000 rcvdbyte=1024 duration=7200 '
    'msg="Large outbound transfer"'
)


def test_exfil_extra_sentbyte():
    evt = parse(EXFIL_EVENT)
    assert int(evt.extra["sentbyte"]) > 500_000_000


def test_exfil_raw_message_preserved():
    evt = parse(EXFIL_EVENT)
    assert evt.raw_message == EXFIL_EVENT


# ---------------------------------------------------------------------------
# 7. Eventtime in microseconds (newer FortiOS firmware)
# ---------------------------------------------------------------------------
MICROSECOND_EVENTTIME = (
    '<190>date=2024-01-15 time=10:23:45 devname="FGT-HQ" devid="FGT60E4Q12345678" '
    'logid="0000000013" type="traffic" subtype="forward" level="notice" vd="root" '
    'eventtime=1705311825123456 srcip=10.0.0.1 dstip=1.1.1.1 '
    'proto=6 action="accept" msg="test"'
)


def test_microsecond_eventtime_parsed():
    evt = parse(MICROSECOND_EVENTTIME)
    assert evt.event_time is not None
    assert evt.event_time.year == 2024
