"""Additive v5 ordered, continuous scan records and independent control path.

Old adaptive codecs retain their exact accepted versions and bounded meanings.
Only this negotiated mode admits duration zero and exactly eight ordered targets.
"""

from __future__ import annotations

import dataclasses
import enum
import struct
from collections.abc import Iterator
from contextlib import suppress
from typing import Any

from . import adaptive_scan as wire
from .adaptive_scan_client import (
    AdaptiveScanClient,
    AdaptiveScanSession,
    AdaptiveScanTransportError,
    AdaptiveScanVisit,
    SocketLike,
    _exact,
    _integer,
    _require_success,
)

VERSION = 5
CONTROL_BYTES = 48
STATUS_BYTES = 128


def build_continuous_setup(
    *,
    session: int,
    generation: int,
    seed: int,
    frequencies_hz: tuple[int, ...],
    analysis_digest: bytes,
    rx_mask: int = 3,
    transition_budget_ms: int = 20,
) -> ContinuousSetup:
    setup = ContinuousSetup(
        session=session,
        generation=generation,
        seed=seed,
        source_rate_hz=2_500_000,
        analog_bandwidth_hz=2_000_000,
        duration_ms=0,
        dwell_ms=20,
        transition_budget_ms=transition_budget_ms,
        maximum_revisit_ms=3000,
        feedback_age_ms=1000,
        application_delay_ms=1000,
        decay_ms=5000,
        maximum_boost=1,
        maximum_queue_bytes=12_800_000,
        maximum_queue_age_ms=5000,
        maximum_queue_visits=32,
        analysis_digest=analysis_digest,
        targets=tuple(
            wire.ScanTarget(index, index, frequency, 1, 0)
            for index, frequency in enumerate(frequencies_hz)
        ),
        rx_mask=rx_mask,
    )
    setup.validate()
    return setup


def _fields(
    value: wire.ScanSetup | wire.ScanCapabilities | wire.ScanVisit | wire.ScanTerminal,
) -> dict[str, Any]:
    return {field.name: getattr(value, field.name) for field in dataclasses.fields(value)}


def _version(
    packet: bytes, version: int, *, duration: int | None = None, result_kind: int | None = None
) -> bytes:
    result = bytearray(packet)
    struct.pack_into("<H", result, 4, version)
    if duration is not None:
        struct.pack_into("<I", result, 48, duration)
    if result_kind is not None:
        struct.pack_into("<I", result, 120, result_kind)
    return wire._finish(result)


@dataclasses.dataclass(frozen=True, slots=True)
class ContinuousSetup(wire.ScanSetup):
    protocol_version: int = VERSION

    def validate(self) -> None:
        if (
            self.protocol_version != VERSION
            or self.duration_ms != 0
            or self.source_rate_hz != 2_500_000
            or self.dwell_ms != 20
            or len(self.targets) != 8
            or self.maximum_boost != 1
            or any(target.baseline_weight != 1 for target in self.targets)
            or tuple(target.profile for target in self.targets) != tuple(range(8))
        ):
            raise wire.AdaptiveScanProtocolError(
                "continuous v5 requires ordered eight-target 20 ms setup"
            )
        # Reuse unchanged numerical/radio bounds, with a temporary finite
        # validation object. The old public codec never sees or accepts v5.
        wire.ScanSetup.validate(dataclasses.replace(self, protocol_version=1, duration_ms=120))

    @classmethod
    def unpack(cls, raw: bytes | bytearray | memoryview) -> ContinuousSetup:
        packet = wire._check(raw, b"SPSQ", wire.SETUP_BYTES, 1, versions=(VERSION,))
        if struct.unpack_from("<I", packet, 48)[0] != 0:
            raise wire.AdaptiveScanProtocolError("continuous duration must be zero")
        legacy = wire.ScanSetup.unpack(_version(packet, 1, duration=120))
        result = cls(**(_fields(legacy) | {"protocol_version": VERSION, "duration_ms": 0}))
        if result.pack() != packet:
            raise wire.AdaptiveScanProtocolError("continuous setup is not canonical")
        return result


@dataclasses.dataclass(frozen=True, slots=True)
class ContinuousCapabilities(wire.ScanCapabilities):
    protocol_version: int = VERSION
    rate_mask: int = 0x10
    rx_mask: int = 3
    minimum_dwell_ms: int = 20
    maximum_dwell_ms: int = 20
    maximum_duration_ms: int = 0

    def validate(self) -> None:
        if self != ContinuousCapabilities():
            raise wire.AdaptiveScanProtocolError(
                "continuous capabilities are not the exact negotiated v5 ABI"
            )

    @classmethod
    def unpack(cls, raw: bytes | bytearray | memoryview) -> ContinuousCapabilities:
        packet = wire._check(raw, b"SPCP", wire.CAPS_BYTES, 0, versions=(VERSION,))
        result = cls()
        if result.pack() != packet:
            raise wire.AdaptiveScanProtocolError("continuous capabilities are not canonical")
        return result


@dataclasses.dataclass(frozen=True, slots=True)
class ContinuousVisit(wire.ScanVisit):
    protocol_version: int = VERSION

    def pack(self) -> bytes:
        if self.protocol_version != VERSION or self.source_rate_hz != 2_500_000:
            raise wire.AdaptiveScanProtocolError("continuous visit rate/version changed")
        count = self.valid_end - self.valid_start
        if count > 50_000:
            raise wire.AdaptiveScanProtocolError("continuous visit support exceeds 20 ms")
        if self.result is wire.VisitResult.COMPLETE and count != 50_000:
            raise wire.AdaptiveScanProtocolError(
                "continuous COMPLETE visit must contain 50000 samples"
            )
        validation_result = wire.VisitResult.COMPLETE if self.iq_bytes else self.result
        normalized = dataclasses.replace(self, protocol_version=1, result=validation_result)
        return _version(wire.ScanVisit.pack(normalized), VERSION, result_kind=int(self.result))

    @classmethod
    def unpack(cls, raw: bytes | bytearray | memoryview) -> ContinuousVisit:
        flags = struct.unpack_from("<I", raw, 12)[0] if len(raw) == wire.VISIT_BYTES else 0
        packet = wire._check(raw, b"SPVR", wire.VISIT_BYTES, flags, versions=(VERSION,))
        try:
            result_kind = wire.VisitResult(struct.unpack_from("<I", packet, 120)[0])
        except ValueError as error:
            raise wire.AdaptiveScanProtocolError("continuous visit result unknown") from error
        iq_bytes = struct.unpack_from("<Q", packet, 88)[0]
        legacy = wire.ScanVisit.unpack(
            _version(
                packet,
                1,
                result_kind=int(wire.VisitResult.COMPLETE) if iq_bytes else int(result_kind),
            )
        )
        result = cls(**(_fields(legacy) | {"protocol_version": VERSION, "result": result_kind}))
        if result.pack() != packet:
            raise wire.AdaptiveScanProtocolError("continuous visit is not canonical")
        return result

    @property
    def sweep(self) -> int:
        return self.visit // 8


@dataclasses.dataclass(frozen=True, slots=True)
class ContinuousTerminal(wire.ScanTerminal):
    def pack(self) -> bytes:
        return wire.ScanTerminal.pack(self)

    @classmethod
    def unpack(cls, raw: bytes | bytearray | memoryview) -> ContinuousTerminal:
        packet = bytes(raw)
        legacy = wire.ScanTerminal.unpack(packet)
        result = cls(**_fields(legacy))
        if result.pack() != packet:
            raise wire.AdaptiveScanProtocolError("continuous terminal is not canonical")
        return result


class ContinuousState(enum.IntEnum):
    RUNNING = 1
    STOPPING = 2
    STOPPED = 3
    FAILED = 4


@dataclasses.dataclass(frozen=True, slots=True)
class ContinuousControl:
    request: int
    session: int
    generation: int
    forced: bool = False

    def pack(self) -> bytes:
        if any(
            type(value) is not int or not 0 < value < 1 << 64
            for value in (self.request, self.session, self.generation)
        ):
            raise wire.AdaptiveScanProtocolError("continuous control identity is invalid")
        packet = bytearray(CONTROL_BYTES)
        wire._header(packet, b"SPCQ", 2 if self.forced else 1, VERSION)
        struct.pack_into("<QQQ", packet, 16, self.request, self.session, self.generation)
        return wire._finish(packet)

    @classmethod
    def unpack(cls, raw: bytes) -> ContinuousControl:
        if len(raw) != CONTROL_BYTES:
            raise wire.AdaptiveScanProtocolError("continuous control length changed")
        flags = struct.unpack_from("<I", raw, 12)[0]
        if flags not in (1, 2):
            raise wire.AdaptiveScanProtocolError("continuous control flags unknown")
        packet = wire._check(raw, b"SPCQ", CONTROL_BYTES, flags, versions=(VERSION,))
        wire._require_zero(packet, 40, 44)
        request, session, generation = struct.unpack_from("<QQQ", packet, 16)
        result = cls(request, session, generation, forced=flags == 2)
        if result.pack() != packet:
            raise wire.AdaptiveScanProtocolError("continuous control is not canonical")
        return result


@dataclasses.dataclass(frozen=True, slots=True)
class ContinuousStatus:
    request: int
    session: int
    generation: int
    planned: int
    delivered: int
    counter: int
    valid_start: int
    valid_end: int
    sweep: int
    state: ContinuousState
    target: int
    queued_visits: int
    error: int
    terminal_state: int
    reason: int
    restore_after: int
    restored_flags: int

    def pack(self) -> bytes:
        if (
            not self.request
            or not self.session
            or not self.generation
            or self.delivered > self.planned
            or self.valid_end < self.valid_start
            or self.target not in (*range(8), 0xFFFFFFFF)
            or not 0 <= self.queued_visits <= 66
            or self.restored_flags & ~1
            or self.terminal_state not in (0, 1, 2, 3)
        ):
            raise wire.AdaptiveScanProtocolError("continuous status geometry/identity changed")
        if self.state is ContinuousState.STOPPED and not self.restored_flags:
            raise wire.AdaptiveScanProtocolError("stopped status lacks device owner restoration")
        packet = bytearray(STATUS_BYTES)
        wire._header(packet, b"SPCS", 1, VERSION)
        struct.pack_into(
            "<QQQQQQQQQ",
            packet,
            16,
            self.request,
            self.session,
            self.generation,
            self.planned,
            self.delivered,
            self.counter,
            self.valid_start,
            self.valid_end,
            self.sweep,
        )
        struct.pack_into(
            "<IIIiIIQI",
            packet,
            88,
            int(self.state),
            self.target,
            self.queued_visits,
            self.error,
            self.terminal_state,
            self.reason,
            self.restore_after,
            self.restored_flags,
        )
        return wire._finish(packet)

    @classmethod
    def unpack(cls, raw: bytes) -> ContinuousStatus:
        packet = wire._check(raw, b"SPCS", STATUS_BYTES, 1, versions=(VERSION,))
        values = struct.unpack_from("<QQQQQQQQQIIIiIIQI", packet, 16)
        try:
            state = ContinuousState(values[9])
        except ValueError as error:
            raise wire.AdaptiveScanProtocolError("continuous state unknown") from error
        result = cls(
            request=values[0],
            session=values[1],
            generation=values[2],
            planned=values[3],
            delivered=values[4],
            counter=values[5],
            valid_start=values[6],
            valid_end=values[7],
            sweep=values[8],
            state=state,
            target=values[10],
            queued_visits=values[11],
            error=values[12],
            terminal_state=values[13],
            reason=values[14],
            restore_after=values[15],
            restored_flags=values[16],
        )
        if result.pack() != packet:
            raise wire.AdaptiveScanProtocolError("continuous status is not canonical")
        return result


class ContinuousControlError(AdaptiveScanTransportError):
    """A rejected v5 control command, with a typed positive device errno."""

    def __init__(self, command: str, errno: int) -> None:
        super().__init__(f"{command} failed with errno {errno}")
        self.errno = errno


class ContinuousClient(AdaptiveScanClient):
    def capabilities(self) -> ContinuousCapabilities:
        connection = self._connection()
        try:
            connection.sendall(b"SCANCAPS5 96\n")
            size = _require_success(_integer(connection), "SCANCAPS5")
            if size != wire.CAPS_BYTES:
                raise AdaptiveScanTransportError("continuous capability size changed")
            return ContinuousCapabilities.unpack(_exact(connection, size))
        finally:
            connection.close()

    def control(
        self, device: str, request: ContinuousControl, *, stop: bool = False
    ) -> ContinuousStatus:
        if request.forced and not stop:
            raise ValueError("forced flag is valid only for STOP")
        connection = self._connection()
        command = "SCANSTOP" if stop else "SCANSTATUS"
        try:
            connection.sendall(f"{command} {device} 48\n".encode() + request.pack())
            size = _integer(connection)
            if size < 0:
                raise ContinuousControlError(command, -size)
            if size != STATUS_BYTES:
                raise AdaptiveScanTransportError("continuous status size changed")
            result = ContinuousStatus.unpack(_exact(connection, size))
            if (result.request, result.session, result.generation) != (
                request.request,
                request.session,
                request.generation,
            ):
                raise AdaptiveScanTransportError("continuous control returned stale identity")
            return result
        finally:
            connection.close()

    def start(
        self,
        setup: wire.ScanSetup,
        *,
        device: str = "cf-ad9361-lpc",
        samples_per_block: int = 1_000_000,
        scan_mask: str | None = None,
    ) -> ContinuousSession:
        if not isinstance(setup, ContinuousSetup):
            raise ValueError("continuous client requires its separate v5 setup")
        setup.validate()
        session = super().start(
            setup, device=device, samples_per_block=samples_per_block, scan_mask=scan_mask
        )
        return ContinuousSession(self, session._connection, session.device, setup)


class ContinuousSession(AdaptiveScanSession):
    _owner: ContinuousClient
    setup: ContinuousSetup

    def __init__(
        self, owner: ContinuousClient, connection: SocketLike, device: str, setup: ContinuousSetup
    ) -> None:
        super().__init__(owner, connection, device, setup)

    def _validate_visit(self, record: wire.ScanVisit) -> None:
        count = record.valid_end - record.valid_start
        receiver_count = self.setup.rx_mask.bit_count()
        if record.iq_bytes != count * receiver_count * 4:
            raise AdaptiveScanTransportError(
                "continuous IQ geometry disagrees with counter interval"
            )
        if record.result is wire.VisitResult.COMPLETE and record.valid_start < (
            max(record.selection_counter, record.transition_after)
            + self.setup.transition_budget_ms * 2500
        ):
            raise AdaptiveScanTransportError(
                "complete continuous IQ lacks minimum post-recall guard"
            )
        if record.target != record.visit % 8:
            raise AdaptiveScanTransportError(
                "device visit order differs from ordered eight-target policy"
            )
        if record.result is wire.VisitResult.COMPLETE and (
            record.valid_end - record.valid_start != 50_000 or record.missing_samples_before
        ):
            raise AdaptiveScanTransportError(
                "complete continuous window is not exact intact 20 ms support"
            )
        super()._validate_visit(record)

    def abort_read(self) -> None:
        """Interrupt data receipt after a bounded STOP drain failure."""
        shutdown = getattr(self._connection, "shutdown", None)
        if shutdown is not None:
            with suppress(OSError):
                shutdown(2)  # socket.SHUT_RDWR, including a blocked recv in another thread.
        self._connection.close()
        self._closed = True

    def visits(self) -> Iterator[AdaptiveScanVisit]:
        if self._iterated or self._closed:
            raise AdaptiveScanTransportError("continuous stream is single-use")
        self._iterated = True
        try:
            while True:
                size = _require_success(_integer(self._connection), "READSCAN")
                if size == wire.VISIT_BYTES:
                    record = ContinuousVisit.unpack(_exact(self._connection, size))
                    self._validate_visit(record)
                    iq_size = _require_success(_integer(self._connection), "READSCAN IQ")
                    if iq_size != record.iq_bytes:
                        raise AdaptiveScanTransportError("continuous IQ length changed")
                    yield AdaptiveScanVisit(record, _exact(self._connection, iq_size))
                elif size == wire.TERMINAL_BYTES:
                    terminal = ContinuousTerminal.unpack(_exact(self._connection, size))
                    if _require_success(_integer(self._connection), "terminal IQ"):
                        raise AdaptiveScanTransportError("continuous terminal contains IQ")
                    if (terminal.session, terminal.generation) != (
                        self.setup.session,
                        self.setup.generation,
                    ):
                        raise AdaptiveScanTransportError("continuous terminal identity changed")
                    self._validate_terminal(terminal)
                    self.terminal = terminal
                    if terminal.error:
                        self._capture_failure_diagnostics()
                    return
                else:
                    raise AdaptiveScanTransportError("continuous READSCAN record size changed")
        finally:
            if self.terminal is None:
                self._capture_failure_diagnostics()
                self._connection.close()
                self._closed = True

    def request_stop(self, request: int, *, forced: bool = False) -> ContinuousStatus:
        return self._owner.control(
            self.device,
            ContinuousControl(request, self.setup.session, self.setup.generation, forced),
            stop=True,
        )
