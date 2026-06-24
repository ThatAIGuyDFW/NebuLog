"""Windows Service wrapper for the Sentinel agent.

Uses pywin32's win32serviceutil so the agent runs as a proper Windows service
under the SYSTEM account (or a dedicated service account).

Usage (run from this directory as Administrator):
    python service.py install   — install the service
    python service.py start     — start it
    python service.py stop      — stop it
    python service.py remove    — uninstall
    python service.py debug     — run in foreground with service framework
"""

from __future__ import annotations

import threading

import structlog

log = structlog.get_logger()

try:
    import win32service          # type: ignore[import]
    import win32serviceutil      # type: ignore[import]
    import win32event            # type: ignore[import]
    import servicemanager        # type: ignore[import]

    class SentinelWindowsService(win32serviceutil.ServiceFramework):
        _svc_name_ = "SentinelAgent"
        _svc_display_name_ = "Sentinel SIEM Windows Agent"
        _svc_description_ = "Collects Windows Event Logs and ships them to Sentinel SIEM."

        def __init__(self, args):
            win32serviceutil.ServiceFramework.__init__(self, args)
            self._stop_event = win32event.CreateEvent(None, 0, 0, None)
            self._thread: threading.Thread | None = None

        def SvcStop(self):
            self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
            import agents.windows.agent as agent_module
            agent_module._RUNNING = False
            win32event.SetEvent(self._stop_event)

        def SvcDoRun(self):
            servicemanager.LogMsg(
                servicemanager.EVENTLOG_INFORMATION_TYPE,
                servicemanager.PYS_SERVICE_STARTED,
                (self._svc_name_, ""),
            )
            from agents.windows.agent import run
            self._thread = threading.Thread(target=run, daemon=True)
            self._thread.start()
            win32event.WaitForSingleObject(self._stop_event, win32event.INFINITE)
            if self._thread:
                self._thread.join(timeout=10)

    if __name__ == "__main__":
        win32serviceutil.HandleCommandLine(SentinelWindowsService)

except ImportError:
    # Not on Windows — provide a helpful error
    if __name__ == "__main__":
        raise SystemExit("pywin32 is required to manage the Windows service. "
                         "Install with: pip install pywin32")
