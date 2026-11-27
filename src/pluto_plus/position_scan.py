"""Negotiated v6 24-target scan; v5 codecs and recordings remain unchanged."""

from __future__ import annotations

import dataclasses
import struct
import zlib
from collections.abc import Iterator
from contextlib import suppress

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
from .continuous_scan import (
    ContinuousControl,
    ContinuousControlError,
    ContinuousSetup,
    ContinuousStatus,
    _fields,
)

VERSION = 6
SETUP_BYTES = 1120
VISIT_BYTES = 224
TARGETS = 24
SLOTS = 8


def _reheader(raw: bytes, version: int) -> bytes:
    result = bytearray(raw)
    struct.pack_into("<H", result, 4, version)
    return wire._finish(result)


@dataclasses.dataclass(frozen=True, slots=True)
class PositionCapabilities(wire.ScanCapabilities):
    """Separate logical capacity from the fixed eight physical slots."""

    maximum_targets: int = TARGETS
    maximum_fastlock_profiles: int = SLOTS
    rate_mask: int = 1
    rx_mask: int = 3
    minimum_dwell_ms: int = 20
    maximum_dwell_ms: int = 20
    maximum_duration_ms: int = 0
    protocol_version: int = VERSION

    def validate(self) -> None:
        if self != PositionCapabilities():
            raise wire.AdaptiveScanProtocolError("unsupported v6 capabilities")

    def pack(self) -> bytes:
        self.validate()
        from .continuous_scan import ContinuousCapabilities

        packet = bytearray(ContinuousCapabilities(rate_mask=1 | 0x10).pack())
        struct.pack_into("<H", packet, 4, VERSION)
        struct.pack_into("<I", packet, 16, self.rate_mask)
        struct.pack_into("<I", packet, 28, self.maximum_targets)
        return wire._finish(packet)

    @classmethod
    def unpack(cls, raw: bytes | bytearray | memoryview) -> PositionCapabilities:
        packet = wire._check(raw, b"SPCP", wire.CAPS_BYTES, 0, versions=(VERSION,))
        result = cls()
        if result.pack() != packet:
            raise wire.AdaptiveScanProtocolError("v6 capabilities are not canonical")
        return result


@dataclasses.dataclass(frozen=True, slots=True)
class PositionTarget(wire.ScanTarget):
    profile_image: bytes = b""

    def validate(self) -> None:
        if not 0 <= self.channel < TARGETS or self.profile != self.channel % SLOTS:
            raise wire.AdaptiveScanProtocolError("v6 logical target/physical slot changed")
        wire.ScanTarget.validate(dataclasses.replace(self, channel=self.channel % SLOTS))
        if self.profile_image and (
            len(self.profile_image) != 16
            or zlib.crc32(self.profile_image) & 0xFFFF_FFFF != self.profile_crc32
        ):
            raise wire.AdaptiveScanProtocolError("v6 profile image CRC mismatch")


@dataclasses.dataclass(frozen=True, slots=True)
class PositionSetup(wire.ScanSetup):
    targets: tuple[PositionTarget, ...]
    protocol_version: int = VERSION

    def validate(self) -> None:
        if (
            self.protocol_version != VERSION
            or len(self.targets) != TARGETS
            or self.source_rate_hz != 10_000_000
            or self.analog_bandwidth_hz != 8_000_000
            or self.rx_mask != 3
            or self.transition_budget_ms != 20
            or tuple(t.channel for t in self.targets) != tuple(range(TARGETS))
        ):
            raise wire.AdaptiveScanProtocolError("v6 requires ordered 24-target dual RX 10 MS/s")
        for target in self.targets:
            target.validate()
        values = _fields(self)
        values.update(protocol_version=5, targets=self.targets[:SLOTS])
        ContinuousSetup(**values).validate()
        if (self.dwell_ms + self.transition_budget_ms) * TARGETS > self.maximum_revisit_ms:
            raise wire.AdaptiveScanProtocolError("v6 maximum revisit cannot cover plan")

    def pack(self) -> bytes:
        self.validate()
        if any(len(t.profile_image) != 16 or not t.profile_crc32 for t in self.targets):
            raise wire.AdaptiveScanProtocolError("v6 needs all 24 prepared profile images")
        values = _fields(self)
        values.update(protocol_version=5, targets=self.targets[:SLOTS])
        prefix = ContinuousSetup(**values).pack()[:144]
        packet = bytearray(SETUP_BYTES)
        packet[:144] = prefix
        wire._header(packet, b"SPSQ", 1, VERSION)
        struct.pack_into("<I", packet, 96, TARGETS)
        for index, target in enumerate(self.targets):
            struct.pack_into(
                "<IIQII16s",
                packet,
                144 + index * 40,
                target.channel,
                target.profile,
                target.frequency_hz,
                target.baseline_weight,
                target.profile_crc32,
                target.profile_image,
            )
        return wire._finish(packet)

    @classmethod
    def unpack(cls, raw: bytes | bytearray | memoryview) -> PositionSetup:
        packet = wire._check(raw, b"SPSQ", SETUP_BYTES, 1, versions=(VERSION,))
        wire._require_zero(packet, 1104, 1116)
        if struct.unpack_from("<I", packet, 96)[0] != TARGETS:
            raise wire.AdaptiveScanProtocolError("v6 target count changed")
        targets = tuple(
            PositionTarget(*struct.unpack_from("<IIQII16s", packet, 144 + i * 40))
            for i in range(TARGETS)
        )
        legacy = bytearray(wire.SETUP_BYTES)
        legacy[:144] = packet[:144]
        wire._header(legacy, b"SPSQ", 1, 5)
        struct.pack_into("<I", legacy, 96, SLOTS)
        for index, target in enumerate(targets[:SLOTS]):
            struct.pack_into(
                "<IIQII",
                legacy,
                144 + index * 24,
                target.channel,
                target.profile,
                target.frequency_hz,
                target.baseline_weight,
                target.profile_crc32,
            )
        base = ContinuousSetup.unpack(wire._finish(legacy))
        result = cls(**(_fields(base) | {"targets": targets, "protocol_version": VERSION}))
        if result.pack() != packet:
            raise wire.AdaptiveScanProtocolError("v6 setup is not canonical")
        return result


def build_position_setup(
    *,
    session: int,
    generation: int,
    seed: int,
    frequencies_hz: tuple[int, ...],
    analysis_digest: bytes,
) -> PositionSetup:
    from .continuous_scan import build_continuous_setup

    if len(frequencies_hz) != TARGETS:
        raise ValueError("24 IFs required")
    base = build_continuous_setup(
        session=session,
        generation=generation,
        seed=seed,
        frequencies_hz=frequencies_hz[:SLOTS],
        analysis_digest=analysis_digest,
        source_rate_hz=10_000_000,
        analog_bandwidth_hz=8_000_000,
    )
    result = PositionSetup(
        **(
            _fields(base)
            | {
                "protocol_version": VERSION,
                "targets": tuple(
                    PositionTarget(i, i % SLOTS, hz, 1, 0) for i, hz in enumerate(frequencies_hz)
                ),
            }
        )
    )
    result.validate()
    return result


@dataclasses.dataclass(frozen=True, slots=True)
class PositionVisit(wire.ScanVisit):
    protocol_version: int = VERSION
    load_after: int = 0
    recall_before: int = 0
    sweep: int = 0
    slot_generation: int = 0
    verified_frequency_hz: int = 0
    original_profile_crc32: int = 0
    rx_mask: int = 3
    plan_digest: bytes = bytes(32)

    def pack(self) -> bytes:
        from .continuous_scan import ContinuousVisit

        if (
            self.protocol_version != VERSION
            or not 0 <= self.target < TARGETS
            or self.target != self.visit % TARGETS
            or self.profile != self.target % SLOTS
            or self.sweep != self.visit // TARGETS
            or not self.transition_before
            <= self.load_after
            <= self.recall_before
            <= self.transition_after
            <= self.valid_start
            or self.rx_mask != 3
            or self.source_rate_hz != 10_000_000
            or self.analog_bandwidth_hz != 8_000_000
            or len(self.plan_digest) != 32
            or not any(self.plan_digest)
        ):
            raise wire.AdaptiveScanProtocolError("v6 visit identity or timing changed")
        if self.result is wire.VisitResult.COMPLETE and (
            not self.slot_generation
            or not self.original_profile_crc32
            or not self.profile_crc32
            or abs(self.verified_frequency_hz - self.frequency_hz) > 2
        ):
            raise wire.AdaptiveScanProtocolError("v6 complete visit lacks verified tuning")
        names = {field.name for field in dataclasses.fields(wire.ScanVisit)}
        values = {key: value for key, value in _fields(self).items() if key in names}
        values.update(protocol_version=5, target=self.target % SLOTS, eligible_mask=255)
        legacy = ContinuousVisit(**values).pack()
        packet = bytearray(VISIT_BYTES)
        packet[:140] = legacy[:140]
        wire._header(packet, b"SPVR", self.flags, VERSION)
        struct.pack_into("<I", packet, 112, self.target)
        struct.pack_into("<I", packet, 124, self.eligible_mask)
        struct.pack_into(
            "<QQQQQII32s",
            packet,
            140,
            self.load_after,
            self.recall_before,
            self.sweep,
            self.slot_generation,
            self.verified_frequency_hz,
            self.original_profile_crc32,
            self.rx_mask,
            self.plan_digest,
        )
        return wire._finish(packet)

    @classmethod
    def unpack(cls, raw: bytes | bytearray | memoryview) -> PositionVisit:
        if len(raw) != VISIT_BYTES:
            raise wire.AdaptiveScanProtocolError("v6 visit size changed")
        flags = struct.unpack_from("<I", raw, 12)[0]
        packet = wire._check(raw, b"SPVR", VISIT_BYTES, flags, versions=(VERSION,))
        target = struct.unpack_from("<I", packet, 112)[0]
        eligible = struct.unpack_from("<I", packet, 124)[0]
        if eligible & ~0xFF_FFFF:
            raise wire.AdaptiveScanProtocolError("v6 eligibility outside plan")
        legacy = bytearray(wire.VISIT_BYTES)
        legacy[:140] = packet[:140]
        wire._header(legacy, b"SPVR", flags, 5)
        struct.pack_into("<I", legacy, 112, target % SLOTS)
        struct.pack_into("<I", legacy, 124, 255)
        from .continuous_scan import ContinuousVisit

        base = ContinuousVisit.unpack(wire._finish(legacy))
        extension = struct.unpack_from("<QQQQQII32s", packet, 140)
        result = cls(
            **(
                _fields(base)
                | {
                    "protocol_version": VERSION,
                    "target": target,
                    "eligible_mask": eligible,
                    **dict(
                        zip(
                            (
                                "load_after",
                                "recall_before",
                                "sweep",
                                "slot_generation",
                                "verified_frequency_hz",
                                "original_profile_crc32",
                                "rx_mask",
                                "plan_digest",
                            ),
                            extension,
                            strict=True,
                        )
                    ),
                }
            )
        )
        if result.pack() != packet:
            raise wire.AdaptiveScanProtocolError("v6 visit is not canonical")
        return result


@dataclasses.dataclass(frozen=True, slots=True)
class PositionControl(ContinuousControl):
    def pack(self) -> bytes:
        return _reheader(ContinuousControl.pack(self), VERSION)

    @classmethod
    def unpack(cls, raw: bytes) -> PositionControl:
        flags = struct.unpack_from("<I", raw, 12)[0] if len(raw) == 48 else 0
        wire._check(raw, b"SPCQ", 48, flags, versions=(VERSION,))
        base = ContinuousControl.unpack(_reheader(raw, 5))
        return cls(base.request, base.session, base.generation, base.forced)


@dataclasses.dataclass(frozen=True, slots=True)
class PositionStatus(ContinuousStatus):
    def pack(self) -> bytes:
        if self.target not in (*range(TARGETS), 0xFFFF_FFFF):
            raise wire.AdaptiveScanProtocolError("v6 status target outside plan")
        legacy = dataclasses.replace(self, target=self.target % SLOTS)
        raw = bytearray(ContinuousStatus.pack(legacy))
        struct.pack_into("<H", raw, 4, VERSION)
        struct.pack_into("<I", raw, 92, self.target)
        return wire._finish(raw)

    @classmethod
    def unpack(cls, raw: bytes) -> PositionStatus:
        wire._check(raw, b"SPCS", 128, 1, versions=(VERSION,))
        target = struct.unpack_from("<I", raw, 92)[0]
        legacy = bytearray(raw)
        struct.pack_into("<H", legacy, 4, 5)
        struct.pack_into("<I", legacy, 92, target % SLOTS)
        base = ContinuousStatus.unpack(wire._finish(legacy))
        result = cls(
            **(
                {field.name: getattr(base, field.name) for field in dataclasses.fields(base)}
                | {"target": target}
            )
        )
        if result.pack() != raw:
            raise wire.AdaptiveScanProtocolError("v6 status is not canonical")
        return result


@dataclasses.dataclass(frozen=True, slots=True)
class PositionTerminal(wire.ScanTerminal):
    def pack(self) -> bytes:
        return _reheader(wire.ScanTerminal.pack(self), VERSION)

    @classmethod
    def unpack(cls, raw: bytes | bytearray | memoryview) -> PositionTerminal:
        raw = bytes(raw)
        wire._check(raw, b"SPFT", wire.TERMINAL_BYTES, wire.TERMINAL_FLAGS, versions=(VERSION,))
        base = wire.ScanTerminal.unpack(_reheader(raw, 1))
        result = cls(**_fields(base))
        if result.pack() != raw:
            raise wire.AdaptiveScanProtocolError("v6 terminal is not canonical")
        return result


class PositionClient(AdaptiveScanClient):
    def capabilities(self) -> PositionCapabilities:
        connection = self._connection()
        try:
            connection.sendall(b"SCANCAPS6 96\n")
            size = _require_success(_integer(connection), "SCANCAPS6")
            if size != wire.CAPS_BYTES:
                raise AdaptiveScanTransportError("v6 capability size changed")
            return PositionCapabilities.unpack(_exact(connection, size))
        finally:
            connection.close()

    def start(
        self,
        setup: wire.ScanSetup,
        *,
        device: str = "cf-ad9361-lpc",
        samples_per_block: int = 100_000,
        scan_mask: str | None = None,
    ) -> PositionSession:
        if not isinstance(setup, PositionSetup):
            raise ValueError("v6 client requires separate position setup")
        session = AdaptiveScanClient.start(
            self, setup, device=device, samples_per_block=samples_per_block, scan_mask=scan_mask
        )
        return PositionSession(self, session._connection, session.device, setup)

    def control(
        self, device: str, request: PositionControl, *, stop: bool = False
    ) -> PositionStatus:
        connection = self._connection()
        command = "SCANSTOP6" if stop else "SCANSTATUS6"
        try:
            connection.sendall(f"{command} {device} 48\n".encode() + request.pack())
            size = _integer(connection)
            if size < 0:
                raise ContinuousControlError(command, -size)
            if size != 128:
                raise AdaptiveScanTransportError("v6 status size changed")
            result = PositionStatus.unpack(_exact(connection, size))
            if (result.request, result.session, result.generation) != (
                request.request,
                request.session,
                request.generation,
            ):
                raise AdaptiveScanTransportError("stale v6 status identity")
            return result
        finally:
            connection.close()


class PositionSession(AdaptiveScanSession):
    _owner: PositionClient
    setup: PositionSetup

    def __init__(
        self, owner: PositionClient, connection: SocketLike, device: str, setup: PositionSetup
    ) -> None:
        super().__init__(owner, connection, device, setup)
        self._slot_generations = [1] * SLOTS

    def _validate_visit(self, record: wire.ScanVisit) -> None:
        if not isinstance(record, PositionVisit):
            raise AdaptiveScanTransportError("v6 visit type changed")
        record.pack()
        if record.target != record.visit % TARGETS or record.sweep != record.visit // TARGETS:
            raise AdaptiveScanTransportError("v6 target order changed")
        target = self.setup.targets[record.target]
        if record.plan_digest != self.setup.analysis_digest:
            raise AdaptiveScanTransportError("v6 visit plan digest changed")
        if record.result is wire.VisitResult.COMPLETE:
            if record.original_profile_crc32 != target.profile_crc32:
                raise AdaptiveScanTransportError("v6 immutable profile CRC changed")
            if abs(record.verified_frequency_hz - target.frequency_hz) > 2:
                raise AdaptiveScanTransportError("v6 verified IF changed")
            previous = self._slot_generations[record.profile]
            if record.slot_generation != previous + int(record.visit >= SLOTS):
                raise AdaptiveScanTransportError("v6 slot generation regressed")
            if (
                record.valid_start
                < max(record.selection_counter, record.transition_after) + 200_000
            ):
                raise AdaptiveScanTransportError("v6 post-recall guard too short")
        if record.slot_generation:
            self._slot_generations[record.profile] = record.slot_generation
        AdaptiveScanSession._validate_visit(self, record)
        # An empty cancelled guard keeps its planned future valid interval in
        # the immutable receipt. Only acquired IQ and observed transition
        # counters constrain subsequent visits and the terminal source counter.
        self._last_valid_end = max(
            record.selection_counter,
            record.transition_after,
            record.valid_end if record.iq_bytes else record.transition_before,
        )

    def visits(self) -> Iterator[AdaptiveScanVisit]:
        if self._iterated or self._closed:
            raise AdaptiveScanTransportError("v6 stream is single-use")
        self._iterated = True
        try:
            while True:
                size = _require_success(_integer(self._connection), "READSCAN")
                if size == VISIT_BYTES:
                    record = PositionVisit.unpack(_exact(self._connection, size))
                    self._validate_visit(record)
                    count = _require_success(_integer(self._connection), "READSCAN IQ")
                    if count != record.iq_bytes:
                        raise AdaptiveScanTransportError("v6 IQ length changed")
                    yield AdaptiveScanVisit(record, _exact(self._connection, count))
                elif size == wire.TERMINAL_BYTES:
                    terminal = PositionTerminal.unpack(_exact(self._connection, size))
                    if _require_success(_integer(self._connection), "terminal IQ"):
                        raise AdaptiveScanTransportError("v6 terminal has IQ")
                    if (terminal.session, terminal.generation) != (
                        self.setup.session,
                        self.setup.generation,
                    ):
                        raise AdaptiveScanTransportError("v6 terminal identity changed")
                    self._validate_terminal(terminal)
                    self.terminal = terminal
                    return
                else:
                    raise AdaptiveScanTransportError("v6 READSCAN size changed")
        finally:
            if self.terminal is None:
                self._connection.close()
                self._closed = True

    def request_stop(self, request: int, *, forced: bool = False) -> PositionStatus:
        return self._owner.control(
            self.device,
            PositionControl(request, self.setup.session, self.setup.generation, forced),
            stop=True,
        )

    def abort_read(self) -> None:
        shutdown = getattr(self._connection, "shutdown", None)
        if shutdown is not None:
            with suppress(OSError):
                shutdown(2)
        self._connection.close()
        self._closed = True
