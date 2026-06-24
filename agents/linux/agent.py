"""Sentinel Linux Agent — main loop.

Polls journald (default) or a syslog file every SENTINEL_POLL_INTERVAL seconds,
batches new events, ships them to the ingest service, and advances the
checkpoint cursor / byte offset.

Run as a regular process or via the included systemd unit file.
"""

from __future__ import annotations

import signal
import time

import structlog
import structlog.dev

from .checkpoint import JournaldCheckpoint, SyslogCheckpoint
from .collector import JournaldCollector, SyslogCollector
from .config import settings
from .shipper import Shipper

structlog.configure(
    processors=[
        structlog.processors.TimeStamper(fmt="iso"),
        structlog.dev.ConsoleRenderer(),
    ]
)

log = structlog.get_logger()

_RUNNING = True


def _stop(*_) -> None:
    global _RUNNING
    log.info("agent_stopping")
    _RUNNING = False


def run() -> None:
    signal.signal(signal.SIGINT, _stop)
    signal.signal(signal.SIGTERM, _stop)

    log.info(
        "agent_starting",
        mode=settings.mode,
        ingest_url=settings.ingest_url,
        poll_interval=settings.poll_interval,
    )

    shipper = Shipper()

    if settings.mode == "syslog":
        cp = SyslogCheckpoint(settings.checkpoint_dir)
        collector: JournaldCollector | SyslogCollector = SyslogCollector(
            settings.syslog_path, settings.batch_size, cp
        )
    else:
        cp_j = JournaldCheckpoint(settings.checkpoint_dir)
        collector = JournaldCollector(settings.units, settings.batch_size, cp_j)

    try:
        while _RUNNING:
            events = collector.collect()
            if events:
                if not shipper.ship(events):
                    log.warning("ship_failed_will_retry_next_poll", count=len(events))
                    # Don't advance checkpoint — retry on next poll
                else:
                    log.debug("poll_complete", count=len(events))
            if _RUNNING:
                time.sleep(settings.poll_interval)
    finally:
        shipper.close()
        log.info("agent_stopped")


if __name__ == "__main__":
    run()
