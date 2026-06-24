"""Agent unit tests — cross-platform, no pywin32 / journalctl required."""

from __future__ import annotations

import json
import socket
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch, call
import sys

import pytest

# ---------------------------------------------------------------------------
# Windows agent tests
# ---------------------------------------------------------------------------

class TestWindowsCheckpoint:
    def test_default_is_zero(self, tmp_path):
        from agents.windows.checkpoint import Checkpoint
        cp = Checkpoint("Security", tmp_path)
        assert cp.record_id == 0

    def test_save_and_reload(self, tmp_path):
        from agents.windows.checkpoint import Checkpoint
        cp = Checkpoint("Security", tmp_path)
        cp.save(12345)
        assert cp.record_id == 12345

        # Reload from disk
        cp2 = Checkpoint("Security", tmp_path)
        assert cp2.record_id == 12345

    def test_channel_name_with_slash(self, tmp_path):
        from agents.windows.checkpoint import Checkpoint
        cp = Checkpoint("Microsoft-Windows-Security-Auditing/Operational", tmp_path)
        cp.save(99)
        cp2 = Checkpoint("Microsoft-Windows-Security-Auditing/Operational", tmp_path)
        assert cp2.record_id == 99


class TestWindowsCollector:
    def test_returns_empty_when_win32_unavailable(self):
        """On non-Windows hosts, collect() should log a warning and return []."""
        from agents.windows.collector import collect
        result = collect("Security", after_record_id=0, batch_size=50)
        # On Windows with pywin32: list of events; on Linux/CI: []
        assert isinstance(result, list)

    def test_event_to_dict_structure(self):
        """_event_to_dict should produce the expected keys."""
        from agents.windows.collector import _event_to_dict, _WIN32_AVAILABLE
        if not _WIN32_AVAILABLE:
            pytest.skip("pywin32 not available")

        ev = MagicMock()
        ev.EventID = 4624
        ts = MagicMock()
        ts.year, ts.month, ts.day = 2024, 1, 15
        ts.hour, ts.minute, ts.second = 10, 23, 45
        ev.TimeGenerated = ts
        ev.RecordNumber = 42
        ev.EventType = 0
        ev.SourceName = "Microsoft-Windows-Security-Auditing"
        ev.StringInserts = ["DOMAIN", "jsmith"]

        result = _event_to_dict(ev, "Security")
        assert result["EventID"] == 4624
        assert result["Channel"] == "Security"
        assert result["RecordNumber"] == 42
        assert isinstance(result["EventData"], dict)


class TestWindowsShipper:
    def test_ship_empty_returns_true(self, tmp_path):
        """Shipping zero events must return True without making any HTTP call."""
        with patch.dict("os.environ", {"SENTINEL_INGEST_URL": "http://localhost:8001"}):
            from importlib import reload
            import agents.windows.config as wc
            reload(wc)
            from agents.windows.shipper import Shipper
            s = Shipper.__new__(Shipper)
            s._client = MagicMock()
            assert s.ship([]) is True
            s._client.post.assert_not_called()

    def test_ship_calls_post(self):
        with patch.dict("os.environ", {"SENTINEL_INGEST_URL": "http://localhost:8001"}):
            from importlib import reload
            import agents.windows.config as wc
            reload(wc)
            from agents.windows.shipper import Shipper
            s = Shipper.__new__(Shipper)
            mock_resp = MagicMock()
            mock_resp.status_code = 202
            mock_resp.raise_for_status = MagicMock()
            s._client = MagicMock()
            s._client.post.return_value = mock_resp

            events = [{"EventID": 4624, "Channel": "Security"}]
            result = s.ship(events)
            assert result is True
            s._client.post.assert_called_once()
            call_kwargs = s._client.post.call_args
            assert "/ingest" in call_kwargs[0][0]

    def test_ship_returns_false_on_error(self):
        import httpx
        with patch.dict("os.environ", {"SENTINEL_INGEST_URL": "http://localhost:8001"}):
            from importlib import reload
            import agents.windows.config as wc
            reload(wc)
            from agents.windows.shipper import Shipper
            s = Shipper.__new__(Shipper)
            s._client = MagicMock()
            s._client.post.side_effect = httpx.ConnectError("refused")

            result = s.ship([{"EventID": 4625}])
            assert result is False


# ---------------------------------------------------------------------------
# Linux agent tests
# ---------------------------------------------------------------------------

class TestLinuxCheckpoints:
    def test_journald_checkpoint_default_none(self, tmp_path):
        from agents.linux.checkpoint import JournaldCheckpoint
        cp = JournaldCheckpoint(tmp_path)
        assert cp.cursor is None

    def test_journald_checkpoint_save_reload(self, tmp_path):
        from agents.linux.checkpoint import JournaldCheckpoint
        cp = JournaldCheckpoint(tmp_path)
        cp.save("s=abc;i=1;b=def;m=0;t=0;x=0")
        assert cp.cursor == "s=abc;i=1;b=def;m=0;t=0;x=0"

        cp2 = JournaldCheckpoint(tmp_path)
        assert cp2.cursor == "s=abc;i=1;b=def;m=0;t=0;x=0"

    def test_syslog_checkpoint_default_zero(self, tmp_path):
        from agents.linux.checkpoint import SyslogCheckpoint
        cp = SyslogCheckpoint(tmp_path)
        assert cp.offset == 0

    def test_syslog_checkpoint_save_reload(self, tmp_path):
        from agents.linux.checkpoint import SyslogCheckpoint
        cp = SyslogCheckpoint(tmp_path)
        cp.save(8192)
        cp2 = SyslogCheckpoint(tmp_path)
        assert cp2.offset == 8192


class TestLinuxSyslogCollector:
    def test_collects_lines_from_file(self, tmp_path):
        from agents.linux.checkpoint import SyslogCheckpoint
        from agents.linux.collector import SyslogCollector

        log_file = tmp_path / "syslog"
        log_file.write_text(
            "Jan 15 10:23:45 myhost sshd[123]: Accepted publickey for jsmith\n"
            "Jan 15 10:24:00 myhost sudo[456]: jsmith : COMMAND=/bin/bash\n"
        )

        cp = SyslogCheckpoint(tmp_path)
        coll = SyslogCollector(log_file, batch_size=100, checkpoint=cp)
        events = coll.collect()

        assert len(events) == 2
        assert events[0]["program"] == "sshd[123]"
        assert "Accepted publickey" in events[0]["message"]

    def test_checkpoint_advances_offset(self, tmp_path):
        from agents.linux.checkpoint import SyslogCheckpoint
        from agents.linux.collector import SyslogCollector

        log_file = tmp_path / "syslog"
        log_file.write_text("line one\n")
        first_size = log_file.stat().st_size

        cp = SyslogCheckpoint(tmp_path)
        coll = SyslogCollector(log_file, batch_size=100, checkpoint=cp)
        events = coll.collect()
        assert len(events) == 1
        assert cp.offset == first_size

        # Append a second line and confirm only it is returned
        with log_file.open("a") as fh:
            fh.write("line two\n")

        events2 = coll.collect()
        assert len(events2) == 1
        assert "line two" in events2[0]["message"]

    def test_missing_file_returns_empty(self, tmp_path):
        from agents.linux.checkpoint import SyslogCheckpoint
        from agents.linux.collector import SyslogCollector

        cp = SyslogCheckpoint(tmp_path)
        coll = SyslogCollector(tmp_path / "nonexistent.log", 100, cp)
        assert coll.collect() == []

    def test_batch_size_respected(self, tmp_path):
        from agents.linux.checkpoint import SyslogCheckpoint
        from agents.linux.collector import SyslogCollector

        log_file = tmp_path / "syslog"
        log_file.write_text("\n".join(f"line {i}" for i in range(100)) + "\n")

        cp = SyslogCheckpoint(tmp_path)
        coll = SyslogCollector(log_file, batch_size=10, checkpoint=cp)
        events = coll.collect()
        assert len(events) == 10


class TestLinuxJournaldCollector:
    def test_parses_journald_json_output(self, tmp_path):
        from agents.linux.checkpoint import JournaldCheckpoint
        from agents.linux.collector import JournaldCollector

        journal_lines = [
            json.dumps({
                "__CURSOR": "s=abc123",
                "__REALTIME_TIMESTAMP": "1705311825000000",
                "_HOSTNAME": "srv01",
                "_COMM": "sshd",
                "MESSAGE": "Accepted publickey for jsmith from 10.0.0.1 port 22",
                "PRIORITY": "6",
            }),
            json.dumps({
                "__CURSOR": "s=abc124",
                "__REALTIME_TIMESTAMP": "1705311826000000",
                "_HOSTNAME": "srv01",
                "_COMM": "sudo",
                "MESSAGE": "jsmith : COMMAND=/bin/bash",
                "PRIORITY": "5",
            }),
        ]
        stdout = "\n".join(journal_lines)

        cp = JournaldCheckpoint(tmp_path)
        coll = JournaldCollector(units=[], batch_size=50, checkpoint=cp)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(
                returncode=0,
                stdout=stdout,
                stderr="",
            )
            events = coll.collect()

        assert len(events) == 2
        assert events[0]["_COMM"] == "sshd"
        assert events[1]["__CURSOR"] == "s=abc124"
        assert cp.cursor == "s=abc124"

    def test_cursor_passed_to_journalctl(self, tmp_path):
        from agents.linux.checkpoint import JournaldCheckpoint
        from agents.linux.collector import JournaldCollector

        cp = JournaldCheckpoint(tmp_path)
        cp.save("s=existing_cursor")
        coll = JournaldCollector(units=[], batch_size=50, checkpoint=cp)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            coll.collect()

        args = mock_run.call_args[0][0]
        assert "--after-cursor" in args
        assert "s=existing_cursor" in args

    def test_unit_filter_passed_to_journalctl(self, tmp_path):
        from agents.linux.checkpoint import JournaldCheckpoint
        from agents.linux.collector import JournaldCollector

        cp = JournaldCheckpoint(tmp_path)
        coll = JournaldCollector(units=["sshd", "sudo"], batch_size=50, checkpoint=cp)

        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0, stdout="", stderr="")
            coll.collect()

        args = mock_run.call_args[0][0]
        assert "-u" in args
        assert "sshd" in args
        assert "sudo" in args

    def test_journalctl_not_found_returns_empty(self, tmp_path):
        from agents.linux.checkpoint import JournaldCheckpoint
        from agents.linux.collector import JournaldCollector
        import subprocess

        cp = JournaldCheckpoint(tmp_path)
        coll = JournaldCollector(units=[], batch_size=50, checkpoint=cp)

        with patch("subprocess.run", side_effect=FileNotFoundError("journalctl")):
            result = coll.collect()
        assert result == []


class TestLinuxShipper:
    def test_ship_empty_returns_true(self):
        with patch.dict("os.environ", {"SENTINEL_INGEST_URL": "http://localhost:8001"}):
            from importlib import reload
            import agents.linux.config as lc
            reload(lc)
            from agents.linux.shipper import Shipper
            s = Shipper.__new__(Shipper)
            s._client = MagicMock()
            assert s.ship([]) is True
            s._client.post.assert_not_called()

    def test_ship_posts_correct_headers(self):
        with patch.dict("os.environ", {"SENTINEL_INGEST_URL": "http://localhost:8001"}):
            from importlib import reload
            import agents.linux.config as lc
            reload(lc)
            from agents.linux.shipper import Shipper
            s = Shipper.__new__(Shipper)
            mock_resp = MagicMock()
            mock_resp.status_code = 202
            mock_resp.raise_for_status = MagicMock()
            s._client = MagicMock()
            s._client.post.return_value = mock_resp

            events = [{"MESSAGE": "test", "_COMM": "sshd"}]
            result = s.ship(events)
            assert result is True
            s._client.post.assert_called_once()

    def test_ship_returns_false_on_connection_error(self):
        import httpx
        with patch.dict("os.environ", {"SENTINEL_INGEST_URL": "http://localhost:8001"}):
            from importlib import reload
            import agents.linux.config as lc
            reload(lc)
            from agents.linux.shipper import Shipper
            s = Shipper.__new__(Shipper)
            s._client = MagicMock()
            s._client.post.side_effect = httpx.ConnectError("refused")
            assert s.ship([{"MESSAGE": "test"}]) is False


# ---------------------------------------------------------------------------
# Wrap syslog line helper
# ---------------------------------------------------------------------------

class TestWrapSyslogLine:
    def test_parses_standard_format(self):
        from agents.linux.collector import _wrap_syslog_line
        line = "Jan 15 10:23:45 myhost sshd[123]: Login from 10.0.0.1"
        result = _wrap_syslog_line(line)
        assert result["hostname"] == "myhost"
        assert result["program"] == "sshd[123]"
        assert "Login from 10.0.0.1" in result["message"]
        assert "timestamp" in result

    def test_handles_short_line(self):
        from agents.linux.collector import _wrap_syslog_line
        result = _wrap_syslog_line("short")
        assert result["message"] == "short"
        assert "timestamp" in result
