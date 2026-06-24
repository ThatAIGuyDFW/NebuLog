"""HTTP batch shipper for the Linux agent.

Posts collected events to the Sentinel ingest endpoint:
    POST <SENTINEL_INGEST_URL>/ingest
    X-Source-Type: linux
    Content-Type: application/json
    Authorization: Bearer <token>   (if SENTINEL_API_TOKEN is set)
"""

from __future__ import annotations

import json
import socket
from typing import Sequence

import httpx
import structlog
from tenacity import (
    retry,
    stop_after_attempt,
    wait_exponential,
    retry_if_exception_type,
    before_sleep_log,
)

from .config import settings

log = structlog.get_logger()


def _get_local_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


def _make_client() -> httpx.Client:
    headers: dict[str, str] = {
        "X-Source-Type": "linux",
        "X-Source-IP": settings.source_ip or _get_local_ip(),
        "Content-Type": "application/json",
    }
    if settings.api_token:
        headers["Authorization"] = f"Bearer {settings.api_token}"
    return httpx.Client(
        base_url=settings.ingest_url,
        headers=headers,
        verify=settings.verify_tls,
        timeout=30.0,
    )


class Shipper:
    def __init__(self) -> None:
        self._client = _make_client()

    def ship(self, events: Sequence[dict]) -> bool:
        if not events:
            return True
        try:
            _post_with_retry(self._client, list(events))
            log.info("batch_shipped", count=len(events))
            return True
        except Exception as exc:
            log.error("ship_failed", count=len(events), exc=str(exc))
            return False

    def close(self) -> None:
        self._client.close()


@retry(
    stop=stop_after_attempt(settings.max_retries),
    wait=wait_exponential(multiplier=settings.retry_wait, min=2, max=60),
    retry=retry_if_exception_type((httpx.TransportError, httpx.TimeoutException)),
    before_sleep=before_sleep_log(log, "warning"),  # type: ignore[arg-type]
    reraise=True,
)
def _post_with_retry(client: httpx.Client, events: list[dict]) -> None:
    resp = client.post("/ingest", content=json.dumps(events))
    if resp.status_code >= 500:
        raise httpx.HTTPStatusError(
            f"Server error {resp.status_code}",
            request=resp.request,
            response=resp,
        )
    resp.raise_for_status()
