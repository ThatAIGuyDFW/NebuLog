"""PyInstaller entry point for Sentinel SIEM.

This thin wrapper exists so PyInstaller runs a top-level script (no relative
imports) and the launcher package can still use absolute package imports.
"""
from launcher.main import main

main()
