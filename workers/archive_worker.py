"""Archive Worker — events:raw → Azure Blob Storage.

Subscribes to the Redis Stream 'events:raw', batches raw log lines into
gzip-compressed NDJSON files, and uploads them to Azure Blob Storage under:

    raw/{source_type}/{YYYY}/{MM}/{DD}/{uuid}.ndjson.gz

Blob upload target: within 60 seconds of receipt.
Immutability: blobs tagged with immutable=true (policy enforced at container level).

Consumer group: sentinel-archive
"""

from __future__ import annotations

import asyncio
import gzip
import io
import json
import os
import uuid
from datetime import datetime, timezone

import structlog
from redis.asyncio import Redis, from_url

log = structlog.get_logger()

STREAM = os.getenv("STREAM_RAW", "events:raw")
GROUP = "sentinel-archive"
UPLOAD_INTERVAL = 60.0          # seconds between forced uploads
MAX_BATCH_BYTES = 50 * 1024 * 1024  # 50 MB uncompressed before forced upload


def _blob_path(source_type: str, now: datetime, batch_id: str) -> str:
    return (
        f"raw/{source_type}/"
        f"{now.year:04d}/{now.month:02d}/{now.day:02d}/"
        f"{batch_id}.ndjson.gz"
    )


def _compress(lines: list[str]) -> bytes:
    buf = io.BytesIO()
    with gzip.GzipFile(fileobj=buf, mode="wb") as gz:
        for line in lines:
            gz.write((line + "\n").encode("utf-8"))
    return buf.getvalue()


class _BlobUploader:
    """Wraps azure-storage-blob AsyncBlobServiceClient."""

    def __init__(self, account: str, key: str, container: str) -> None:
        self._account = account
        self._key = key
        self._container = container
        self._client = None

    def _get_client(self):
        if self._client is None:
            from azure.storage.blob.aio import BlobServiceClient  # type: ignore
            conn_str = (
                f"DefaultEndpointsProtocol=https;"
                f"AccountName={self._account};"
                f"AccountKey={self._key};"
                f"EndpointSuffix=core.windows.net"
            )
            self._client = BlobServiceClient.from_connection_string(conn_str)
        return self._client

    async def upload(self, blob_name: str, data: bytes) -> None:
        client = self._get_client()
        container_client = client.get_container_client(self._container)
        blob_client = container_client.get_blob_client(blob_name)
        await blob_client.upload_blob(
            data,
            overwrite=False,
            tags={"immutable": "true", "retention": "6years"},
        )
        log.info("blob_uploaded", blob=blob_name, bytes=len(data))

    async def close(self) -> None:
        if self._client is not None:
            await self._client.close()


class _FilesystemUploader:
    """Local fallback for dev environments without Azure credentials."""

    def __init__(self, base_dir: str) -> None:
        self._base = base_dir

    async def upload(self, blob_name: str, data: bytes) -> None:
        path = os.path.join(self._base, blob_name.replace("/", os.sep))
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "wb") as f:
            f.write(data)
        log.info("blob_saved_locally", path=path, bytes=len(data))

    async def close(self) -> None:
        pass


def _make_uploader(account: str, key: str, container: str, local_fallback: str):
    if account and key:
        return _BlobUploader(account, key, container)
    log.warning("azure_blob_not_configured", fallback=local_fallback)
    return _FilesystemUploader(local_fallback)


async def _ensure_consumer_group(redis: Redis) -> None:
    try:
        await redis.xgroup_create(STREAM, GROUP, id="0", mkstream=True)
        log.info("consumer_group_created", stream=STREAM, group=GROUP)
    except Exception as exc:
        if "BUSYGROUP" not in str(exc):
            raise


class ArchiveWorker:
    """Async archive worker: Redis Stream → Azure Blob Storage."""

    def __init__(self, redis_url: str, azure_account: str, azure_key: str,
                 azure_container: str, local_fallback: str,
                 consumer_name: str) -> None:
        self._redis_url = redis_url
        self._uploader = _make_uploader(azure_account, azure_key,
                                        azure_container, local_fallback)
        self._consumer_name = consumer_name

        # Per-source-type accumulator: source_type -> list of raw lines
        self._buffers: dict[str, list[str]] = {}
        self._buffer_bytes: dict[str, int] = {}
        self._ack_ids: list[str] = []

    async def run(self) -> None:
        redis: Redis = from_url(self._redis_url, decode_responses=True)
        await _ensure_consumer_group(redis)
        log.info("archive_worker_started", consumer=self._consumer_name)

        last_upload = asyncio.get_event_loop().time()

        try:
            while True:
                messages = await redis.xreadgroup(
                    GROUP, self._consumer_name,
                    {STREAM: ">"},
                    count=200,
                    block=1000,
                )

                if messages:
                    _, entries = messages[0]
                    for msg_id, fields in entries:
                        raw = fields.get("raw", "")
                        source_type = fields.get("type", "unknown")
                        if raw:
                            self._buffers.setdefault(source_type, []).append(raw)
                            self._buffer_bytes[source_type] = (
                                self._buffer_bytes.get(source_type, 0) + len(raw)
                            )
                        self._ack_ids.append(msg_id)

                now = asyncio.get_event_loop().time()
                has_data = any(self._buffers.values())
                should_upload = has_data and (
                    now - last_upload >= UPLOAD_INTERVAL
                    or any(b >= MAX_BATCH_BYTES for b in self._buffer_bytes.values())
                )

                if should_upload:
                    await self._flush(redis)
                    last_upload = now

        finally:
            if any(self._buffers.values()):
                await self._flush(redis)
            await redis.aclose()
            await self._uploader.close()

    async def _flush(self, redis: Redis) -> None:
        upload_time = datetime.now(tz=timezone.utc)
        for source_type, lines in list(self._buffers.items()):
            if not lines:
                continue
            batch_id = str(uuid.uuid4())
            blob_name = _blob_path(source_type, upload_time, batch_id)
            compressed = _compress(lines)
            try:
                await self._uploader.upload(blob_name, compressed)
            except Exception as exc:
                log.error("blob_upload_error", blob=blob_name, exc=str(exc))
                # Don't ack — messages will be reprocessed
                self._buffers[source_type] = []
                self._buffer_bytes[source_type] = 0
                return

            self._buffers[source_type] = []
            self._buffer_bytes[source_type] = 0

        # Acknowledge all consumed messages after successful upload
        if self._ack_ids:
            await redis.xack(STREAM, GROUP, *self._ack_ids)
            self._ack_ids.clear()


async def main() -> None:
    from dotenv import load_dotenv
    import structlog
    load_dotenv()
    structlog.configure(
        processors=[
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ]
    )
    worker = ArchiveWorker(
        redis_url=os.getenv("REDIS_URL", "redis://localhost:6379/0"),
        azure_account=os.getenv("AZURE_STORAGE_ACCOUNT", ""),
        azure_key=os.getenv("AZURE_STORAGE_KEY", ""),
        azure_container=os.getenv("AZURE_STORAGE_CONTAINER", "sentinel-raw"),
        local_fallback=os.getenv("ARCHIVE_LOCAL_PATH", "/tmp/sentinel-archive"),
        consumer_name=f"{os.getenv('INGEST_NODE_NAME', 'worker-01')}-archive",
    )
    await worker.run()


if __name__ == "__main__":
    asyncio.run(main())
