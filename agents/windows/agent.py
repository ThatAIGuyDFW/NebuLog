"""Sentinel Windows Agent — main loop.

Polls each configured Event Log channel every SENTINEL_POLL_INTERVAL seconds,
batches new events, ships them to the ingest service, and advances the
per-channel checkpoint.

Run modes:
    python agent.py           — foreground (CTRL-C to stop)
    python service.py install — install as a Windows service
    python service.py start   — start the service
"""

from __future__ import annotations

import signal
import time

import structlog
import structlog.dev

from .checkpoint import Checkpoint
from .collector import collect
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
        channels=settings.channels,
        ingest_url=settings.ingest_url,
        poll_interval=settings.poll_interval,
    )

    checkpoints = {ch: Checkpoint(ch, settings.checkpoint_dir) for ch in settings.channels}
    shipper = Shipper()

    try:
        while _RUNNING:
            for channel in settings.channels:
                if not _RUNNING:
                    break
                cp = checkpoints[channel]
                events = collect(channel, cp.record_id, settings.batch_size)
                if not events:
                    continue
                if shipper.ship(events):
                    last_id = events[-1].get("RecordNumber", 0)
                    if last_id:
                        cp.save(last_id)
                    log.debug("channel_polled", channel=channel, count=len(events))
                else:
                    log.warning("ship_failed_checkpoint_held", channel=channel)

            if _RUNNING:
                time.sleep(settings.poll_interval)
    finally:
        shipper.close()
        log.info("agent_stopped")


if __name__ == "__main__":
    run()
