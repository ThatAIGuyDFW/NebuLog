"""Sentinel SIEM launcher.

Entry point for the PyInstaller bundle. Handles three modes:

  sentinel                 → GUI tray app (Windows / macOS)
  sentinel --headless      → headless mode for Linux servers / systemd
  sentinel --setup         → re-run the first-time setup wizard
"""

from __future__ import annotations

import argparse
import platform
import signal
import sys
import threading
import time
import traceback
from pathlib import Path

import structlog

log = structlog.get_logger()


# ── Argument parsing ──────────────────────────────────────────────────────────

def _parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(prog="sentinel", description="Sentinel SIEM Launcher")
    p.add_argument("--headless", action="store_true",
                   help="Run without a system tray (suitable for Linux servers)")
    p.add_argument("--setup", action="store_true",
                   help="Re-run the first-time setup wizard")
    return p.parse_args()


# ── First-run setup ───────────────────────────────────────────────────────────

def _first_run_setup() -> bool:
    """Run the setup wizard. Returns False if the user cancelled."""
    from .setup_wizard import run_wizard, write_env
    from .config import ENV_FILE

    result = run_wizard()
    if result.cancelled:
        return False

    # Write the .env file
    write_env(result)

    # Initialise PostgreSQL cluster
    from . import embedded_pg as pg
    if not pg.is_initialized():
        pg.initialize(result.db_password)

    return True


# ── Startup sequence ──────────────────────────────────────────────────────────

def _startup(headless: bool = False) -> tuple:
    """Start embedded services and return (pg_proc, redis_proc, manager)."""
    from .config import ENV_FILE, DATA_DIR, LOG_DIR
    from . import embedded_pg as pg, embedded_redis as redis
    from .process_manager import ProcessManager

    DATA_DIR.mkdir(parents=True, exist_ok=True)
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    if not ENV_FILE.exists():
        raise RuntimeError(
            "Sentinel is not configured. Run 'sentinel --setup' to complete setup."
        )

    # Load the DB password from the env file (written by wizard)
    db_password = ""
    for line in ENV_FILE.read_text().splitlines():
        if line.startswith("_SENTINEL_DB_PASSWORD="):
            db_password = line.partition("=")[2].strip()
            break

    log.info("starting_embedded_redis")
    redis_proc = redis.start()

    log.info("starting_embedded_postgresql")
    pg_proc = pg.start()
    pg.create_database(db_password)

    log.info("starting_sentinel_services")
    manager = ProcessManager()
    manager.start_all()

    return pg_proc, redis_proc, manager


# ── Health monitor (background thread) ───────────────────────────────────────

def _monitor_loop(manager, stop_event: threading.Event) -> None:
    while not stop_event.is_set():
        try:
            manager.health_check()
        except Exception:
            log.error("health_check_error", exc=traceback.format_exc())
        stop_event.wait(timeout=10)


# ── Headless mode ─────────────────────────────────────────────────────────────

def _run_headless() -> None:
    from . import embedded_pg as pg, embedded_redis as redis

    pg_proc, redis_proc, manager = _startup(headless=True)

    stop_event = threading.Event()
    monitor = threading.Thread(target=_monitor_loop, args=(manager, stop_event), daemon=True)
    monitor.start()

    def _shutdown(sig, frame):
        log.info("shutdown_signal_received", signal=sig)
        stop_event.set()
        manager.stop_all()
        redis.stop(redis_proc)
        pg.stop(pg_proc)
        sys.exit(0)

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    log.info("sentinel_running_headless")
    print("Sentinel SIEM is running. Press Ctrl+C to stop.")
    while True:
        time.sleep(1)


# ── Tray app (Windows / macOS) ────────────────────────────────────────────────

def _run_tray() -> None:
    try:
        import pystray
        from PIL import Image, ImageDraw
    except ImportError:
        log.warning("pystray_not_available", fallback="headless")
        _run_headless()
        return

    from . import embedded_pg as pg, embedded_redis as redis
    from .config import API_PORT

    pg_proc, redis_proc, manager = _startup()

    stop_event = threading.Event()
    monitor = threading.Thread(target=_monitor_loop, args=(manager, stop_event), daemon=True)
    monitor.start()

    # ── Tray icon image (simple shield shape) ─────────────────────────────────
    def _make_icon() -> Image.Image:
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        d = ImageDraw.Draw(img)
        d.rectangle([8, 8, 56, 56], fill=(37, 99, 235))  # blue shield
        d.polygon([(32, 14), (50, 22), (50, 38), (32, 52), (14, 38), (14, 22)],
                  fill=(59, 130, 246))
        d.text((22, 26), "S", fill="white")
        return img

    icon_image = _make_icon()

    def _open_dashboard(icon, item):
        import webbrowser
        webbrowser.open(f"http://localhost:{API_PORT}")

    def _open_logs(icon, item):
        from .config import LOG_DIR
        import subprocess, platform
        if platform.system() == "Windows":
            subprocess.Popen(["explorer", str(LOG_DIR)])
        elif platform.system() == "Darwin":
            subprocess.Popen(["open", str(LOG_DIR)])

    def _restart(icon, item):
        icon.notify("Sentinel", "Restarting services…")
        manager.restart_all()
        icon.notify("Sentinel", "Services restarted.")

    def _status(icon, item):
        lines = "\n".join(f"{k}: {v}" for k, v in manager.status().items())
        icon.notify("Sentinel — Service Status", lines)

    def _stop(icon, item):
        stop_event.set()
        manager.stop_all()
        redis.stop(redis_proc)
        pg.stop(pg_proc)
        icon.stop()

    menu = pystray.Menu(
        pystray.MenuItem("Open Dashboard", _open_dashboard, default=True),
        pystray.MenuItem("Service Status", _status),
        pystray.MenuItem("Open Log Folder", _open_logs),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Restart Services", _restart),
        pystray.Menu.SEPARATOR,
        pystray.MenuItem("Stop Sentinel", _stop),
    )

    tray = pystray.Icon("Sentinel SIEM", icon_image, "Sentinel SIEM", menu)
    tray.run()


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    import structlog
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.processors.JSONRenderer(),
        ]
    )

    args = _parse_args()

    from .config import ENV_FILE

    # First-run or --setup
    if args.setup or not ENV_FILE.exists():
        ok = _first_run_setup()
        if not ok:
            print("Setup cancelled. Exiting.")
            sys.exit(1)
        if args.setup:
            print("Setup complete. Restart Sentinel to apply changes.")
            sys.exit(0)

    if args.headless or platform.system() == "Linux":
        _run_headless()
    else:
        _run_tray()


if __name__ == "__main__":
    main()
