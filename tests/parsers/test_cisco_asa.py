"""Unit tests for CiscoASAParser.

Sample log lines represent real Cisco ASA syslog output patterns.
"""

import pytest
from datetime import datetime, timezone

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from ingest.parsers.cisco_asa import CiscoASAParser
from ingest.models import Category, LogLevel, SourceType

PARSER = CiscoASAParser()
NOW = datetime(2024, 1, 15, 10, 23, 45, tzinfo=timezone.utc)
HOST = "10.0.0.254"


def parse(raw: str):
    return PARSER.parse(raw, HOST, NOW)


# ---------------------------------------------------------------------------
# 1. Built TCP connection (302013)
# ---------------------------------------------------------------------------
TCP_BUILT = (
    "<134>Jan 15 10:23:45 asa.corp.com %ASA-6-302013: Built outbound TCP connection "
    "12345 for outside:8.8.8.8/53 (8.8.8.8/53) to inside:192.168.1.100/49201 "
    "(192.168.1.100/49201)"
)


def test_tcp_built_source_type():
    assert parse(TCP_BUILT).source_type == SourceType.cisco_asa


def test_tcp_built_event_id():
    assert parse(TCP_BUILT).event_id == "302013"


def test_tcp_built_category():
    assert parse(TCP_BUILT).category == Category.network


def test_tcp_built_action():
    assert parse(TCP_BUILT).action == "allow"


def test_tcp_built_protocol():
    assert parse(TCP_BUILT).protocol == "tcp"


def test_tcp_built_log_level():
    assert parse(TCP_BUILT).log_level == LogLevel.info


def test_tcp_built_src_ip_extracted():
    evt = parse(TCP_BUILT)
    # One of the extracted IPs should be 192.168.1.100
    assert evt.src_ip is not None


# ---------------------------------------------------------------------------
# 2. Teardown TCP connection (302014)
# ---------------------------------------------------------------------------
TCP_TEARDOWN = (
    "<134>Jan 15 10:25:00 asa.corp.com %ASA-6-302014: Teardown TCP connection "
    "12345 for outside:8.8.8.8/53 to inside:192.168.1.100/49201 duration 0:00:05 "
    "bytes 680 TCP FINs"
)


def test_tcp_teardown_event_id():
    assert parse(TCP_TEARDOWN).event_id == "302014"


def test_tcp_teardown_action():
    assert parse(TCP_TEARDOWN).action == "close"


# ---------------------------------------------------------------------------
# 3. ACL deny (106023)
# ---------------------------------------------------------------------------
ACL_DENY = (
    "<165>Jan 15 10:30:00 asa.corp.com %ASA-5-106023: Deny tcp src "
    "outside:198.51.100.77/12345 dst inside:192.168.1.50/22 by access-group "
    '"outside_access_in" [0x7d17b8c6, 0x0]'
)


def test_acl_deny_category():
    assert parse(ACL_DENY).category == Category.network


def test_acl_deny_action():
    assert parse(ACL_DENY).action == "deny"


def test_acl_deny_event_id():
    assert parse(ACL_DENY).event_id == "106023"


def test_acl_deny_message_content():
    assert "ACL deny" in parse(ACL_DENY).message


# ---------------------------------------------------------------------------
# 4. VPN session (713172)
# ---------------------------------------------------------------------------
VPN_SESSION = (
    "<165>Jan 15 11:00:00 asa.corp.com %ASA-5-713172: Group = GroupVPN, "
    "Username = jsmith, IP = 203.0.113.5, Freeing previously allocated memory "
    "for authorization-dn-attributes"
)


def test_vpn_category():
    assert parse(VPN_SESSION).category == Category.auth


def test_vpn_user():
    assert parse(VPN_SESSION).user_name == "jsmith"


def test_vpn_event_id():
    assert parse(VPN_SESSION).event_id == "713172"


# ---------------------------------------------------------------------------
# 5. AAA authentication success (611101)
# ---------------------------------------------------------------------------
AAA_SUCCESS = (
    "<166>Jan 15 12:00:00 asa.corp.com %ASA-6-611101: User authentication succeeded: "
    "Uname: jdoe"
)


def test_aaa_success_category():
    assert parse(AAA_SUCCESS).category == Category.auth


def test_aaa_success_action():
    assert parse(AAA_SUCCESS).action == "logon"


def test_aaa_success_event_id():
    assert parse(AAA_SUCCESS).event_id == "611101"


# ---------------------------------------------------------------------------
# 6. AAA authentication failure (611102)
# ---------------------------------------------------------------------------
AAA_FAIL = (
    "<165>Jan 15 12:01:00 asa.corp.com %ASA-5-611102: User authentication failed: "
    "Uname: badactor"
)


def test_aaa_fail_action():
    assert parse(AAA_FAIL).action == "logon_failed"


def test_aaa_fail_event_id():
    assert parse(AAA_FAIL).event_id == "611102"


# ---------------------------------------------------------------------------
# 7. Threat detection (733100)
# ---------------------------------------------------------------------------
THREAT_DETECT = (
    "<163>Jan 15 13:00:00 asa.corp.com %ASA-3-733100: Object drop rate-1 exceeded. "
    "Current burst rate is 30 per second, max configured rate is 10; "
    "Current average rate is 20 per second, max configured rate is 5; Cumulative "
    "total count is 1500"
)


def test_threat_detect_category():
    assert parse(THREAT_DETECT).category == Category.threat


def test_threat_detect_log_level():
    assert parse(THREAT_DETECT).log_level == LogLevel.error


# ---------------------------------------------------------------------------
# 8. No Cisco tag — generic BSD syslog fallback
# ---------------------------------------------------------------------------
GENERIC_SYSLOG = (
    "<134>Jan 15 14:00:00 asa.corp.com this is some unexpected syslog message"
)


def test_generic_fallback_source_type():
    assert parse(GENERIC_SYSLOG).source_type == SourceType.cisco_asa


def test_generic_fallback_no_event_id():
    assert parse(GENERIC_SYSLOG).event_id is None


def test_generic_raw_preserved():
    assert parse(GENERIC_SYSLOG).raw_message == GENERIC_SYSLOG
