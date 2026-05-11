from __future__ import annotations

import asyncio
import struct
from dataclasses import dataclass
from typing import Any, Callable, Generic, TypeVar, overload

import lz4.block
import msgpack

T = TypeVar("T")

PROTOCOL_VERSION = 11
MAX_DECOMPRESSED_SIZE = 8 * 1024 * 1024
COMPRESSION_THRESHOLD = 4096


@dataclass
class Packet(Generic[T]):
    """Represents a generic protocol packet."""

    ver: int
    cmd: int
    seq: int
    opcode: int
    payload: T
    raw_payload: bytes = b""


class ApiError(Exception):
    """API error returned by the server."""

    def __init__(
        self,
        *,
        error: str = "",
        message: str = "",
        title: str = "",
        localized_message: str = "",
    ) -> None:
        self.error = error
        self.message = message
        self.title = title
        self.localized_message = localized_message
        super().__init__(self._format_message())

    def _format_message(self) -> str:
        if self.title:
            return f"{self.title}: {self.message}"
        return self.message


def pack_packet(ver: int, cmd: int, seq: int, opcode: int, payload: Any) -> bytes:
    """Pack a packet for TCP transport (msgpack + optional lz4 raw block)."""
    payload_bytes = msgpack.packb(payload, use_bin_type=True)

    comp_flag = 0
    if len(payload_bytes) > COMPRESSION_THRESHOLD:
        compressed = lz4.block.compress(payload_bytes, store_size=False)
        if len(compressed) < len(payload_bytes):
            payload_bytes = compressed
            comp_flag = 1

    payload_len = len(payload_bytes) & 0xFFFFFF
    packed_len = (comp_flag << 24) | payload_len

    header = struct.pack("!BHBHI", ver, cmd, seq, opcode, packed_len)
    return header + payload_bytes


def unpack_packet(data: bytes) -> Packet[Any]:
    """Unpack a TCP packet."""
    if len(data) < 10:
        raise ValueError(f"packet too short: {len(data)} bytes")

    ver, cmd, seq, opcode, packed_len = struct.unpack("!BHBHI", data[:10])
    comp_flag = packed_len >> 24
    payload_len = packed_len & 0xFFFFFF

    if len(data) < 10 + payload_len:
        raise ValueError(
            f"packet body incomplete: need {10 + payload_len}, have {len(data)}"
        )

    payload_bytes = data[10 : 10 + payload_len]

    if comp_flag != 0:
        payload_bytes = lz4.block.decompress(
            payload_bytes,
            uncompressed_size=MAX_DECOMPRESSED_SIZE,
        )

    payload: Any = None
    if len(payload_bytes) > 0:
        payload = msgpack.unpackb(payload_bytes, raw=False, strict_map_key=False)

    return Packet(
        ver=ver,
        cmd=cmd,
        seq=seq,
        opcode=opcode,
        payload=payload,
        raw_payload=payload_bytes,
    )


class BaseClient:
    """Async TCP client with msgpack + lz4 transport."""

    def __init__(self, app_version: str = "", build_number: int = 0) -> None:
        self.app_version = app_version
        self.build_number = build_number
        self.verbose_log = False
        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self._seq = 0
        self._pending: dict[int, asyncio.Future[Packet]] = {}
        self._handlers: dict[int, list[Callable[[Packet], Any]]] = {}
        self._notification_opcodes: set[int] = set()
        self._write_lock = asyncio.Lock()
        self._close_event = asyncio.Event()
        self._read_task: asyncio.Task[Any] | None = None
        self._interval_tasks: list[asyncio.Task[None]] = []

    async def connect_tcp(self, host: str, port: int, ssl: bool = True) -> None:
        """Connect to TCP server."""
        import ssl as ssl_mod

        context = ssl_mod.create_default_context() if ssl else None
        self._reader, self._writer = await asyncio.open_connection(
            host, port, ssl=context
        )
        self._read_task = asyncio.create_task(self._read_loop())

    def close(self) -> None:
        """Close the connection."""
        self._close_event.set()
        for t in self._interval_tasks:
            t.cancel()
        self._interval_tasks.clear()
        if self._writer is not None:
            self._writer.close()

    async def _read_loop(self) -> None:
        """Background task that reads packets from the connection."""
        try:
            while not self._close_event.is_set():
                header = await self._reader.readexactly(10)
                _, cmd, _, opcode, packed_len = struct.unpack("!BHBHI", header)
                payload_len = packed_len & 0xFFFFFF

                body = await self._reader.readexactly(payload_len)
                packet_data = header + body

                try:
                    pkt = unpack_packet(packet_data)
                except Exception as exc:
                    if self.verbose_log:
                        print(f"unpack error: {exc}")
                    continue

                if self.verbose_log:
                    print(f"<<< opcode={pkt.opcode} cmd={pkt.cmd} seq={pkt.seq}")

                self._dispatch(pkt)
        except asyncio.IncompleteReadError:
            pass
        except Exception as exc:
            if self.verbose_log:
                print(f"read loop error: {exc}")
        finally:
            self._cancel_all_pending(ConnectionError("Connection closed"))

    def _dispatch(self, pkt: Packet) -> None:
        """Dispatch packet to pending future AND handlers."""
        future = self._pending.pop(pkt.seq, None)
        if future is not None and pkt.opcode not in self._notification_opcodes:
            if not future.done():
                future.set_result(pkt)

        for handler in self._handlers.get(pkt.opcode, []):
            asyncio.create_task(handler(pkt))

    def _cancel_all_pending(self, exc: Exception) -> None:
        """Cancel all pending requests with an exception."""
        for future in list(self._pending.values()):
            if not future.done():
                future.set_exception(exc)
        self._pending.clear()

    async def send_raw(self, opcode: int, payload: Any) -> Packet:
        """Send a raw packet and wait for response."""
        async with self._write_lock:
            seq = self._seq
            self._seq = (self._seq + 1) & 0xFF

            if seq in self._pending:
                raise RuntimeError("seq overflow: too many concurrent requests")

            future: asyncio.Future[Packet] = asyncio.get_event_loop().create_future()
            self._pending[seq] = future

            try:
                data = pack_packet(PROTOCOL_VERSION, 0, seq, opcode, payload)

                if self.verbose_log:
                    print(f">>> opcode={opcode} seq={seq}")

                self._writer.write(data)
                await self._writer.drain()
            except Exception:
                self._pending.pop(seq, None)
                raise

        try:
            resp = await asyncio.wait_for(future, timeout=30.0)
        except asyncio.TimeoutError:
            self._pending.pop(seq, None)
            raise TimeoutError(f"request timeout (opcode={opcode} seq={seq})")

        # Error detection: if payload looks like an API error
        if isinstance(resp.payload, dict):
            err = resp.payload.get("error", "")
            msg = resp.payload.get("message", "")
            if err and msg:
                raise ApiError(
                    error=err,
                    message=msg,
                    title=resp.payload.get("title", ""),
                    localized_message=resp.payload.get("localizedMessage", ""),
                )

        if resp.opcode != opcode:
            raise ValueError(
                f"opcode mismatch: expected {opcode}, got {resp.opcode}"
            )

        return resp

    def on(self, opcode: int) -> Callable[[Callable[[Packet], Any]], Callable[[Packet], Any]]:
        """Decorator to register a handler for packets with the given opcode.

        Usage::

            @client.on(42)
            async def handle_foo(pkt: Packet) -> None:
                print(pkt.payload)
        """
        def decorator(fn: Callable[[Packet], Any]) -> Callable[[Packet], Any]:
            self._handlers.setdefault(opcode, []).append(fn)
            return fn
        return decorator

    @overload
    def every(self, interval: float, callback: Callable[..., Any]) -> asyncio.Task[None]: ...

    @overload
    def every(self, interval: float) -> Callable[[Callable[..., Any]], asyncio.Task[None]]: ...

    def every(self, interval: float, callback: Callable[..., Any] | None = None) -> asyncio.Task[None] | Callable[[Callable[..., Any]], asyncio.Task[None]]:
        """Run callback every `interval` seconds. Stops when client closes.

        Supports both sync and async callbacks. Can be used as a method call or a decorator::

            client.every(30.0, my_callback)

            @client.every(30.0)
            async def heartbeat() -> None:
                ...
        """
        if callback is not None:
            return self._every_task(interval, callback)

        def decorator(fn: Callable[..., Any]) -> asyncio.Task[None]:
            return self._every_task(interval, fn)
        return decorator

    def _every_task(self, interval: float, callback: Callable[..., Any]) -> asyncio.Task[None]:
        async def _loop() -> None:
            while not self._close_event.is_set():
                await asyncio.sleep(interval)
                if self._close_event.is_set():
                    break
                try:
                    result = callback()
                    if asyncio.iscoroutine(result):
                        await result
                except asyncio.CancelledError:
                    break
                except Exception:
                    if self.verbose_log:
                        print(f"every callback error")

        task = asyncio.create_task(_loop())
        self._interval_tasks.append(task)
        return task
