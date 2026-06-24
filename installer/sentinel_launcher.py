"""PyInstaller entry point for Sentinel SIEM.

Two operating modes:

  sentinel_launcher               Normal launch (tray app / headless)
  sentinel_launcher --run-module <dotted.module>
                                  Service runner: executes <module> as __main__
                                  Used by ProcessManager to start services inside
                                  the frozen bundle without a separate Python.
"""
import os
import sys
import traceback
from pathlib import Path


def _crash_log_path() -> Path:
    base = Path(os.environ.get("PROGRAMDATA", "C:/ProgramData")) / "Sentinel" / "logs"
    base.mkdir(parents=True, exist_ok=True)
    return base / "launcher_crash.log"


if len(sys.argv) >= 3 and sys.argv[1] == "--run-module":
    import runpy
    _module = sys.argv[2]
    sys.argv = [sys.argv[0]] + sys.argv[3:]
    try:
        runpy.run_module(_module, run_name="__main__", alter_sys=True)
    except Exception:
        crash = _crash_log_path().parent / f"crash_{_module.replace('.', '_')}.log"
        crash.write_text(traceback.format_exc())
        raise
    sys.exit(0)

try:
    from launcher.main import main
    main()
except Exception:
    tb = traceback.format_exc()
    _crash_log_path().write_text(tb)
    # Also print so the console window (console=True) shows it
    print(tb, file=sys.stderr)
    raise
