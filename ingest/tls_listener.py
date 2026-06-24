"""TLS TCP syslog listener on port 6514 (RFC 5425).

Accepts TLS-wrapped TCP connections, reads framed syslog messages (octet-count
framing per RFC 6587 or newline-delimited), and feeds them into the same
`_process_syslog` pipeline as the UDP listener.

TLS configuration (env vars):
    INGEST_TLS_CERT  — path to PEM certificate file
    INGEST_TLS_KEY   — path to PEM private key file
    INGEST_TLS_CA    — path to CA bundle for mTLS client verification (optional)

If INGEST_TLS_CERT is not set, the TLS listener is silently skipped (dev mode).
"""

from __future__ import annotations

import asyncio
import os
import ssl
import struct
from typing import Callable, Awaitable

import structlog

log = structlog.get_logger()

# Maximum syslog message size (RFC 5424 §6.1 recommends ≥480; we allow up to 64 KB)
_MAX_MSG = 65536
# Octet-count framing: leading ASCII digits followed by SP and the message
_MAX_FRAME_DIGITS = 6


def build_ssl_context() -> ssl.SSLContext | None:
    """Create an SSLContext from env-configured cert/key paths.

    Returns None when TLS is not configured (dev mode).
    """
    cert = os.getenv("INGEST_TLS_CERT")
    key = os.getenv("INGEST_TLS_KEY")
    if not cert or not key:
        return None

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.load_cert_chain(certfile=cert, keyfile=key)

    ca = os.getenv("INGEST_TLS_CA")
    if ca:
        # mTLS: require a valid client certificate
        ctx.load_verify_locations(cafile=ca)
        ctx.verify_mode = ssl.CERT_REQUIRED
    else:
        ctx.verify_mode = ssl.CERT_NONE

    return ctx


class _TlsSyslogProtocol(asyncio.Protocol):
    """asyncio Protocol that handles one TLS TCP syslog connection.

    Supports two framing modes (auto-detected per connection):
      1. Octet-count framing: "<count> <message>" (RFC 6587 §3.4.1)
      2. Newline-delimited:   "<message>\n"       (RFC 6587 §3.4.2)
    """

    def __init__(
        self,
        process_fn: Callable[[str, str], Awaitable[None]],
        source_ip: str,
    ) -> None:
        self._process = process_fn
        self._source_ip = source_ip
        self._buf = b""
        self._use_octet_framing: bool | None = None  # detected on first byte

    def data_received(self, data: bytes) -> None:
        self._buf += data
        asyncio.create_task(self._drain())

    async def _drain(self) -> None:
        while self._buf:
            msg = self._next_message()
            if msg is None:
                break
            raw = msg.decode("utf-8", errors="replace").strip()
            if raw:
                await self._process(raw, self._source_ip)

    def _next_message(self) -> bytes | None:
        """Extract one complete syslog message from the buffer, or None if incomplete."""
        if not self._buf:
            return None

        # Auto-detect framing on first byte
        if self._use_octet_framing is None:
            self._use_octet_framing = chr(self._buf[0]).isdigit()

        if self._use_octet_framing:
            return self._next_octet_framed()
        return self._next_newline_framed()

    def _next_octet_framed(self) -> bytes | None:
        # Find the space that separates count from message
        sp = self._buf.find(b" ", 0, _MAX_FRAME_DIGITS + 1)
        if sp < 0:
            if len(self._buf) > _MAX_FRAME_DIGITS:
                # Malformed — reset framing detection
                self._buf = b""
            return None
        try:
            count = int(self._buf[:sp])
        except ValueError:
            self._buf = b""
            return None
        start = sp + 1
        end = start + count
        if len(self._buf) < end:
            return None
        msg = self._buf[start:end]
        self._buf = self._buf[end:]
        return msg

    def _next_newline_framed(self) -> bytes | None:
        nl = self._buf.find(b"\n")
        if nl < 0:
            if len(self._buf) > _MAX_MSG:
                self._buf = b""  # discard oversized line
            return None
        msg = self._buf[:nl]
        self._buf = self._buf[nl + 1:]
        return msg

    def connection_lost(self, exc: Exception | None) -> None:
        if exc:
            log.debug("tls_connection_lost", source_ip=self._source_ip, exc=str(exc))


async def start_tls_listener(
    host: str,
    port: int,
    process_fn: Callable[[str, str], Awaitable[None]],
    ssl_context: ssl.SSLContext,
) -> asyncio.Server:
    """Start the TLS TCP listener and return the asyncio.Server handle."""

    def factory() -> _TlsSyslogProtocol:
        # client_address not available in factory; filled in connection_made
        proto = _TlsSyslogProtocol(process_fn, "unknown")
        return proto

    # We need the client IP, so use a wrapper that patches it after connection
    def protocol_factory() -> asyncio.Protocol:
        return _ConnectionTracker(process_fn)

    server = await asyncio.get_event_loop().create_server(
        protocol_factory,
        host=host,
        port=port,
        ssl=ssl_context,
    )
    log.info("tls_listener_ready", host=host, port=port)
    return server


class _ConnectionTracker(asyncio.Protocol):
    """Thin wrapper that extracts the peer IP before delegating to _TlsSyslogProtocol."""

    def __init__(self, process_fn: Callable[[str, str], Awaitable[None]]) -> None:
        self._process_fn = process_fn
        self._delegate: _TlsSyslogProtocol | None = None
        self._transport: asyncio.Transport | None = None

    def connection_made(self, transport: asyncio.Transport) -> None:
        self._transport = transport
        peer = transport.get_extra_info("peername")
        source_ip = peer[0] if peer else "unknown"
        self._delegate = _TlsSyslogProtocol(self._process_fn, source_ip)

    def data_received(self, data: bytes) -> None:
        if self._delegate:
            self._delegate.data_received(data)

    def connection_lost(self, exc: Exception | None) -> None:
        if self._delegate:
            self._delegate.connection_lost(exc)
