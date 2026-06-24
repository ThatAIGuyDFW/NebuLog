"""Start, monitor, and stop all Sentinel services as subprocesses."""

from __future__ import annotations

import os
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import structlog

from launcher.config import DATA_DIR, LOG_DIR, ENV_FILE

log = structlog.get_logger()


@dataclass
class ServiceConfig:
    name: str
    module: str          # e.g. "ingest.main" — passed as python -m <module>
    log_file: str        # relative to LOG_DIR
    startup_delay: float = 1.0   # seconds to wait after starting before next service


@dataclass
class ManagedService:
    config: ServiceConfig
    proc: subprocess.Popen | None = None
    restarts: int = 0
    started_at: float = field(default_factory=time.monotonic)


_SERVICES: list[ServiceConfig] = [
    ServiceConfig("ingest",      "ingest.main",          "ingest.log",      startup_delay=1.0),
    ServiceConfig("api",         "api.main",             "api.log",         startup_delay=2.0),
    ServiceConfig("storage",     "workers.storage_worker", "storage.log",   startup_delay=0.5),
    ServiceConfig("archive",     "workers.archive_worker", "archive.log",   startup_delay=0.5),
    ServiceConfig("correlation", "correlation.engine",    "correlation.log", startup_delay=1.0),
]

_MAX_RESTARTS = 5
_RESTART_COOLDOWN = 30.0   # seconds before resetting restart counter


class ProcessManager:
    def __init__(self, on_status_change: Callable[[str, str], None] | None = None) -> None:
        self._services: list[ManagedService] = [ManagedService(c) for c in _SERVICES]
        self._env = self._build_env()
        self._on_status_change = on_status_change or (lambda name, status: None)
        self._running = False

    def _build_env(self) -> dict[str, str]:
        """Load the .env file and merge with the OS environment."""
        env = dict(os.environ)
        if ENV_FILE.exists():
            for line in ENV_FILE.read_text().splitlines():
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, _, v = line.partition("=")
                    env[k.strip()] = v.strip()
        return env

    def _module_cmd(self, module: str) -> list[str]:
        """Return the command list to run a Python module.

        In a PyInstaller frozen bundle sys.executable is the launcher exe, not
        Python.  We teach it to act as a module runner via --run-module so that
        each service subprocess runs inside the same frozen environment.
        """
        if getattr(sys, "frozen", False):
            return [sys.executable, "--run-module", module]
        return [sys.executable, "-m", module]

    def start_all(self) -> None:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        self._running = True
        for svc in self._services:
            self._start(svc)
            time.sleep(svc.config.startup_delay)

    def _start(self, svc: ManagedService) -> None:
        log_path = LOG_DIR / svc.config.log_file
        log_fh = open(log_path, "a")

        svc.proc = subprocess.Popen(
            self._module_cmd(svc.config.module),
            env=self._env,
            stdout=log_fh,
            stderr=log_fh,
            cwd=str(DATA_DIR),
        )
        svc.started_at = time.monotonic()
        log.info("service_started", name=svc.config.name, pid=svc.proc.pid)
        self._on_status_change(svc.config.name, "running")

    def stop_all(self) -> None:
        self._running = False
        for svc in reversed(self._services):
            self._stop(svc)

    def _stop(self, svc: ManagedService) -> None:
        if svc.proc and svc.proc.poll() is None:
            svc.proc.terminate()
            try:
                svc.proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                svc.proc.kill()
            log.info("service_stopped", name=svc.config.name)
            self._on_status_change(svc.config.name, "stopped")

    def restart_all(self) -> None:
        self.stop_all()
        time.sleep(1)
        self._env = self._build_env()
        self.start_all()

    def health_check(self) -> None:
        """Called periodically — restart crashed services."""
        if not self._running:
            return
        for svc in self._services:
            if svc.proc is None:
                continue
            if svc.proc.poll() is not None:
                # Service has exited unexpectedly
                uptime = time.monotonic() - svc.started_at
                if uptime > _RESTART_COOLDOWN:
                    svc.restarts = 0
                if svc.restarts < _MAX_RESTARTS:
                    svc.restarts += 1
                    log.warning(
                        "service_crashed_restarting",
                        name=svc.config.name,
                        exit_code=svc.proc.returncode,
                        attempt=svc.restarts,
                    )
                    self._on_status_change(svc.config.name, "restarting")
                    time.sleep(2)
                    self._start(svc)
                else:
                    log.error(
                        "service_max_restarts",
                        name=svc.config.name,
                        max=_MAX_RESTARTS,
                    )
                    self._on_status_change(svc.config.name, "failed")

    def status(self) -> dict[str, str]:
        out: dict[str, str] = {}
        for svc in self._services:
            if svc.proc is None:
                out[svc.config.name] = "not started"
            elif svc.proc.poll() is None:
                out[svc.config.name] = "running"
            else:
                out[svc.config.name] = f"stopped (exit {svc.proc.returncode})"
        return out
