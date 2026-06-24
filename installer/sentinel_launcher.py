"""PyInstaller entry point for Sentinel SIEM.

Two operating modes:

  sentinel_launcher               Normal launch (tray app / headless)
  sentinel_launcher --run-module <dotted.module>
                                  Service runner: executes <module> as __main__
                                  Used by ProcessManager to start services inside
                                  the frozen bundle without a separate Python.
"""
import sys

if len(sys.argv) >= 3 and sys.argv[1] == "--run-module":
    import runpy
    _module = sys.argv[2]
    sys.argv = [sys.argv[0]] + sys.argv[3:]
    runpy.run_module(_module, run_name="__main__", alter_sys=True)
    sys.exit(0)

from launcher.main import main
main()
