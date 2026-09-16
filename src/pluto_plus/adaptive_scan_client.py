"""Strict iiOD transport for feature-103 adaptive scan sessions."""

from __future__ import annotations

import socket
from collections.abc import Callable, Iterator
from dataclasses import dataclass
from typing import Protocol

from .adaptive_scan import (
    ACK_BYTES,
    CAPS_BYTES,
    FEEDBACK_BYTES,
    TERMINAL_BYTES,
    VISIT_BYTES,
    FeedbackResult,
    ScanAck,
    ScanCapabilities,
    ScanFeedback,
    ScanSetup,
    ScanTerminal,
    ScanVisit,
)


class AdaptiveScanTransportError(RuntimeError):
    """The scan server violated the negotiated stream or rejected a command."""


class SocketLike(Protocol):
    def sendall(self, data: bytes) -> None: ...

    def recv(self, size: int) -> bytes: ...

    def close(self) -> None: ...


Connector = Callable[[str, int, float], SocketLike]


def _connect(host: str, port: int, timeout: float) -> SocketLike:
    return socket.create_connection((host, port), timeout=timeout)


def _line(connection: SocketLike) -> bytes:
    result = bytearray()
    while True:
        byte = connection.recv(1)
        if not byte:
            raise AdaptiveScanTransportError("iiOD closed before the response line")
        if byte == b"\n":
            return bytes(result)
        if len(result) >= 31 or byte not in b"-0123456789":
            raise AdaptiveScanTransportError("iiOD returned a malformed integer line")
        result.extend(byte)


def _integer(connection: SocketLike) -> int:
    try:
        return int(_line(connection))
    except ValueError as error:
        raise AdaptiveScanTransportError("iiOD returned an empty integer line") from error


def _exact(connection: SocketLike, size: int) -> bytes:
    result = bytearray()
    while len(result) < size:
        chunk = connection.recv(size - len(result))
        if not chunk:
            raise AdaptiveScanTransportError("iiOD closed inside a binary record")
        result.extend(chunk)
    return bytes(result)


def _require_success(value: int, command: str) -> int:
    if value < 0:
        raise AdaptiveScanTransportError(f"{command} failed with errno {-value}")
    return value


@dataclass(frozen=True, slots=True)
class AdaptiveScanVisit:
    record: ScanVisit
    iq: bytes


class AdaptiveScanClient:
    """One exact iiOD endpoint; radio identity is attested by the caller."""

    def __init__(
        self,
        host: str,
        *,
        port: int = 30431,
        timeout_s: float = 10.0,
        connector: Connector = _connect,
    ) -> None:
        if not host or not 1 <= port <= 65535 or timeout_s <= 0:
            raise ValueError("adaptive scan endpoint is invalid")
        self.host = host
        self.port = port
        self.timeout_s = timeout_s
        self._connector = connector

    def _connection(self) -> SocketLike:
        return self._connector(self.host, self.port, self.timeout_s)

    def capabilities(self) -> ScanCapabilities:
        connection = self._connection()
        try:
            connection.sendall(f"SCANCAPS {CAPS_BYTES}\n".encode())
            size = _require_success(_integer(connection), "SCANCAPS")
            if size != CAPS_BYTES:
                raise AdaptiveScanTransportError("SCANCAPS returned the wrong record size")
            return ScanCapabilities.unpack(_exact(connection, size))
        finally:
            connection.close()

    def start(
        self,
        setup: ScanSetup,
        *,
        device: str = "cf-ad9361-lpc",
        samples_per_block: int = 1_000_000,
        scan_mask: str = "00000003",
    ) -> AdaptiveScanSession:
        if samples_per_block <= 0 or samples_per_block % 2:
            raise ValueError("samples_per_block must be positive and even")
        if scan_mask != "00000003":
            raise ValueError("feature-103 supports RX0 CI16 only")
        request = setup.pack()
        connection = self._connection()
        try:
            connection.sendall(
                f"OPENM {device} {samples_per_block} {scan_mask} {len(request)}\n".encode()
                + request
            )
            _require_success(_integer(connection), "OPENM")
            connection.sendall(f"READSCAN {device}\n".encode())
        except BaseException:
            connection.close()
            raise
        return AdaptiveScanSession(self, connection, device, setup)

    def submit_feedback(self, device: str, feedback: ScanFeedback) -> FeedbackResult:
        wire = feedback.pack()
        connection = self._connection()
        try:
            connection.sendall(f"SCANFEEDBACK {device} {FEEDBACK_BYTES}\n".encode() + wire)
            value = _require_success(_integer(connection), "SCANFEEDBACK")
            try:
                return FeedbackResult(value)
            except ValueError as error:
                raise AdaptiveScanTransportError("unknown feedback receipt") from error
        finally:
            connection.close()

    def take_ack(self, device: str) -> ScanAck:
        connection = self._connection()
        try:
            connection.sendall(f"SCANACK {device} {ACK_BYTES}\n".encode())
            size = _require_success(_integer(connection), "SCANACK")
            if size != ACK_BYTES:
                raise AdaptiveScanTransportError("SCANACK returned the wrong record size")
            return ScanAck.unpack(_exact(connection, size))
        finally:
            connection.close()


class AdaptiveScanSession:
    def __init__(
        self,
        owner: AdaptiveScanClient,
        connection: SocketLike,
        device: str,
        setup: ScanSetup,
    ) -> None:
        self._owner = owner
        self._connection = connection
        self.device = device
        self.setup = setup
        self.terminal: ScanTerminal | None = None
        self._iterated = False
        self._closed = False

    def visits(self) -> Iterator[AdaptiveScanVisit]:
        if self._iterated or self._closed:
            raise AdaptiveScanTransportError("adaptive scan stream is single-use")
        self._iterated = True
        try:
            while True:
                record_size = _require_success(_integer(self._connection), "READSCAN")
                if record_size == VISIT_BYTES:
                    record = ScanVisit.unpack(_exact(self._connection, record_size))
                    iq_size = _require_success(_integer(self._connection), "READSCAN IQ")
                    if iq_size != record.iq_bytes:
                        raise AdaptiveScanTransportError("visit IQ length disagrees with record")
                    yield AdaptiveScanVisit(record, _exact(self._connection, iq_size))
                    continue
                if record_size == TERMINAL_BYTES:
                    terminal = ScanTerminal.unpack(_exact(self._connection, record_size))
                    if _require_success(_integer(self._connection), "READSCAN terminal IQ"):
                        raise AdaptiveScanTransportError("terminal record unexpectedly has IQ")
                    if (
                        terminal.session != self.setup.session
                        or terminal.generation != self.setup.generation
                    ):
                        raise AdaptiveScanTransportError("terminal identity changed")
                    self.terminal = terminal
                    return
                raise AdaptiveScanTransportError("READSCAN returned an unknown record size")
        finally:
            if self.terminal is None:
                self._connection.close()
                self._closed = True

    def submit_feedback(self, feedback: ScanFeedback) -> FeedbackResult:
        if self._closed or self.terminal is not None:
            raise AdaptiveScanTransportError("adaptive scan session is no longer active")
        return self._owner.submit_feedback(self.device, feedback)

    def take_ack(self) -> ScanAck:
        return self._owner.take_ack(self.device)

    def close(self) -> None:
        if self._closed:
            return
        try:
            if self.terminal is not None:
                self._connection.sendall(f"CLOSE {self.device}\n".encode())
                _require_success(_integer(self._connection), "CLOSE")
        finally:
            self._connection.close()
            self._closed = True

    def __enter__(self) -> AdaptiveScanSession:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()
