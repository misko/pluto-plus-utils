"""Feature-103 fixed-rate adaptive scan wire records.

The records are explicitly little-endian and CRC protected.  No Python object
layout is placed on the wire, and every decoder rejects unknown feature bits,
nonzero reserved bytes, and semantically inconsistent source intervals.
"""

from __future__ import annotations

import dataclasses
import enum
import struct
import zlib
from collections.abc import Sequence
from typing import Final

VERSION: Final = 1
FEATURES: Final = 0xFF
SETUP_FLAGS: Final = 1
VISIT_FLAGS: Final = 1
VISIT_DEADLINE_FORCED: Final = 2
VISIT_FLAG_MASK: Final = VISIT_FLAGS | VISIT_DEADLINE_FORCED
TERMINAL_FLAGS: Final = 1
FORMAT_CI16: Final = 1
CAPS_BYTES: Final = 96
SETUP_BYTES: Final = 352
VISIT_BYTES: Final = 160
FEEDBACK_BYTES: Final = 112
ACK_BYTES: Final = 96
TERMINAL_BYTES: Final = 128
# 2.5 MS/s is admitted only after the endpoint capability negotiation in the
# campaign runner.  Older v0.52 endpoints advertise mask 0x0f and are refused.
SUPPORTED_RATES: Final = frozenset((2_500_000, 10_000_000, 15_000_000, 20_000_000, 30_000_000))
RUNTIME_VERSION: Final = 2
MINIMUM_RUNTIME_RATE: Final = 520_833
MAXIMUM_RUNTIME_RATE: Final = 61_440_000


def _rate_valid(rate: int, version: int) -> bool:
    return type(rate) is int and (
        (version == VERSION and rate in SUPPORTED_RATES)
        or (version == RUNTIME_VERSION and MINIMUM_RUNTIME_RATE <= rate <= MAXIMUM_RUNTIME_RATE)
    )


class AdaptiveScanProtocolError(ValueError):
    """The record is not an exact feature-103 protocol value."""


class ScanOutcome(enum.IntEnum):
    UNKNOWN = 0
    ACTIVE = 1
    QUIET = 2


class VisitResult(enum.IntEnum):
    ADMITTED = 0
    COMPLETE = 1
    SKIP_CAPACITY = 2
    SKIP_AGE = 3
    INVALID_GAP = 4
    CANCELLED = 5


class FeedbackResult(enum.IntEnum):
    ACCEPTED = 0
    DUPLICATE = 1
    EXPIRED = 2
    WRONG_SESSION = 3
    REJECTED = 4
    SUPERSEDED = 5
    MAILBOX_FULL = 6
    APPLIED = 7
    CANCELLED = 8


class TerminalState(enum.IntEnum):
    COMPLETED = 1
    CANCELLED = 2
    FAILED = 3


@dataclasses.dataclass(frozen=True, slots=True)
class ScanCapabilities:
    rate_mask: int = 0x0F
    rx_mask: int = 1
    formats: int = FORMAT_CI16
    maximum_targets: int = 8
    maximum_fastlock_profiles: int = 8
    minimum_dwell_ms: int = 20
    maximum_dwell_ms: int = 240
    maximum_duration_ms: int = 300_000
    maximum_queue_bytes: int = 200_000_000
    maximum_queue_age_ms: int = 10_000
    feedback_capacity: int = 64
    maximum_feedback_age_ms: int = 10_000
    maximum_application_delay_ms: int = 10_000
    maximum_analog_bandwidth_hz: int = 56_000_000
    source_counter_bits: int = 64
    protocol_version: int = VERSION
    rate_mode: int = 0
    minimum_rate_hz: int = 0
    maximum_rate_hz: int = 0

    def validate(self) -> None:
        """Accept a feature-103 endpoint that is a strict capability superset.

        The fixed v0.52 client consumes RX0 CI16 at 10/15/20/30 MS/s.  A
        later firmware may additionally advertise other rates or receivers;
        those additions do not change this client's wire contract.  All
        non-negotiated feature-103 limits stay exact, so this is not a broad
        forward-compatibility escape hatch.
        """

        required = ScanCapabilities()
        legacy = (self.protocol_version, self.rate_mode,
                  self.minimum_rate_hz, self.maximum_rate_hz) == (VERSION, 0, 0, 0)
        runtime = (
            self.protocol_version == RUNTIME_VERSION and self.rate_mode == 1
            and MINIMUM_RUNTIME_RATE <= self.minimum_rate_hz
            <= self.maximum_rate_hz <= MAXIMUM_RUNTIME_RATE
        )
        if not (legacy or runtime):
            raise AdaptiveScanProtocolError("unsupported runtime rate capability")
        if (
            self.rate_mask & required.rate_mask != required.rate_mask
            or self.rx_mask & required.rx_mask != required.rx_mask
            or self.formats != required.formats
            or self.maximum_targets != required.maximum_targets
            or self.maximum_fastlock_profiles != required.maximum_fastlock_profiles
            or self.minimum_dwell_ms != required.minimum_dwell_ms
            or self.maximum_dwell_ms != required.maximum_dwell_ms
            or self.maximum_duration_ms != required.maximum_duration_ms
            or self.maximum_queue_bytes != required.maximum_queue_bytes
            or self.maximum_queue_age_ms != required.maximum_queue_age_ms
            or self.feedback_capacity != required.feedback_capacity
            or self.maximum_feedback_age_ms != required.maximum_feedback_age_ms
            or self.maximum_application_delay_ms != required.maximum_application_delay_ms
            or self.maximum_analog_bandwidth_hz != required.maximum_analog_bandwidth_hz
            or self.source_counter_bits != required.source_counter_bits
        ):
            raise AdaptiveScanProtocolError("capabilities are incompatible with feature-103 v1")

    def pack(self) -> bytes:
        self.validate()
        packet = bytearray(CAPS_BYTES)
        _header(packet, b"SPCP", 0, self.protocol_version)
        struct.pack_into(
            "<IIIIIIIIQIIIIII",
            packet,
            16,
            self.rate_mask,
            self.rx_mask,
            self.formats,
            self.maximum_targets,
            self.maximum_fastlock_profiles,
            self.minimum_dwell_ms,
            self.maximum_dwell_ms,
            self.maximum_duration_ms,
            self.maximum_queue_bytes,
            self.maximum_queue_age_ms,
            self.feedback_capacity,
            self.maximum_feedback_age_ms,
            self.maximum_application_delay_ms,
            self.maximum_analog_bandwidth_hz,
            self.source_counter_bits,
        )
        struct.pack_into(
            "<III", packet, 80, self.rate_mode, self.minimum_rate_hz, self.maximum_rate_hz
        )
        return _finish(packet)

    @classmethod
    def unpack(cls, raw: bytes | bytearray | memoryview) -> ScanCapabilities:
        packet = _check(raw, b"SPCP", CAPS_BYTES, 0, versions=(VERSION, RUNTIME_VERSION))
        values = struct.unpack_from("<IIIIIIIIQIIIIII", packet, 16)
        result = cls(
            protocol_version=struct.unpack_from("<H", packet, 4)[0],
            rate_mode=struct.unpack_from("<I", packet, 80)[0],
            minimum_rate_hz=struct.unpack_from("<I", packet, 84)[0],
            maximum_rate_hz=struct.unpack_from("<I", packet, 88)[0],
            rate_mask=values[0],
            rx_mask=values[1],
            formats=values[2],
            maximum_targets=values[3],
            maximum_fastlock_profiles=values[4],
            minimum_dwell_ms=values[5],
            maximum_dwell_ms=values[6],
            maximum_duration_ms=values[7],
            maximum_queue_bytes=values[8],
            maximum_queue_age_ms=values[9],
            feedback_capacity=values[10],
            maximum_feedback_age_ms=values[11],
            maximum_application_delay_ms=values[12],
            maximum_analog_bandwidth_hz=values[13],
            source_counter_bits=values[14],
        )
        result.validate()
        return result


def _crc(record: bytes | bytearray) -> int:
    return zlib.crc32(record) & 0xFFFF_FFFF


def _header(packet: bytearray, magic: bytes, flags: int, version: int = VERSION) -> None:
    struct.pack_into("<4sHHII", packet, 0, magic, version, len(packet), FEATURES, flags)


def _finish(packet: bytearray) -> bytes:
    struct.pack_into("<I", packet, len(packet) - 4, _crc(packet[:-4]))
    return bytes(packet)


def _check(raw: bytes | bytearray | memoryview, magic: bytes, size: int, flags: int,
           *, versions: tuple[int, ...] = (VERSION,)) -> bytes:
    packet = bytes(raw)
    if len(packet) != size:
        raise AdaptiveScanProtocolError(f"record size must be exactly {size} bytes")
    actual_magic, version, encoded_size, features, actual_flags = struct.unpack_from(
        "<4sHHII", packet
    )
    if actual_magic != magic or version not in versions or encoded_size != size:
        raise AdaptiveScanProtocolError("unknown record magic, version, or encoded size")
    if features != FEATURES or actual_flags != flags:
        raise AdaptiveScanProtocolError("feature or flag mask is not exact")
    if struct.unpack_from("<I", packet, size - 4)[0] != _crc(packet[:-4]):
        raise AdaptiveScanProtocolError("record CRC mismatch")
    return packet


def _require_zero(raw: bytes, start: int, end: int) -> None:
    if any(raw[start:end]):
        raise AdaptiveScanProtocolError("reserved bytes must be zero")


def _digest(value: bytes) -> bytes:
    result = bytes(value)
    if len(result) != 32 or not any(result):
        raise AdaptiveScanProtocolError("analysis digest must contain 32 nonzero-bound bytes")
    return result


@dataclasses.dataclass(frozen=True, slots=True)
class ScanTarget:
    channel: int
    profile: int
    frequency_hz: int
    baseline_weight: int
    profile_crc32: int

    def validate(self) -> None:
        if not 0 <= self.channel <= 0xFFFF_FFFF:
            raise AdaptiveScanProtocolError("channel is outside uint32")
        if not 0 <= self.profile < 8:
            raise AdaptiveScanProtocolError("fastlock profile is outside 0..7")
        if not 70_000_000 <= self.frequency_hz <= 6_000_000_000:
            raise AdaptiveScanProtocolError("frequency is outside AD9361 range")
        if not 1 <= self.baseline_weight <= 1024:
            raise AdaptiveScanProtocolError("baseline weight is outside 1..1024")
        if not 0 <= self.profile_crc32 <= 0xFFFF_FFFF:
            raise AdaptiveScanProtocolError("profile CRC is outside uint32")


@dataclasses.dataclass(frozen=True, slots=True)
class ScanSetup:
    session: int
    generation: int
    seed: int
    source_rate_hz: int
    analog_bandwidth_hz: int
    duration_ms: int
    dwell_ms: int
    transition_budget_ms: int
    maximum_revisit_ms: int
    feedback_age_ms: int
    application_delay_ms: int
    decay_ms: int
    maximum_boost: int
    maximum_queue_bytes: int
    maximum_queue_age_ms: int
    maximum_queue_visits: int
    analysis_digest: bytes
    targets: tuple[ScanTarget, ...]
    rx_mask: int = 1
    format: int = FORMAT_CI16
    flags: int = SETUP_FLAGS
    protocol_version: int = VERSION

    def validate(self) -> None:
        if not self.session or not self.generation or not self.seed:
            raise AdaptiveScanProtocolError("session, generation, and seed must be nonzero")
        if not _rate_valid(self.source_rate_hz, self.protocol_version):
            raise AdaptiveScanProtocolError(
                "rate must be fixed 2.5 or 10/15/20/30 MS/s for v1, "
                "or an integer in 520833..61440000 S/s for runtime v2"
            )
        if not 200_000 <= self.analog_bandwidth_hz <= 56_000_000:
            raise AdaptiveScanProtocolError("analog bandwidth is outside the admitted range")
        if not 1 <= self.duration_ms <= 300_000:
            raise AdaptiveScanProtocolError("duration is outside 1..300000 ms")
        if not 20 <= self.dwell_ms <= 240:
            raise AdaptiveScanProtocolError("dwell is outside 20..240 ms")
        if not 1 <= self.transition_budget_ms <= 100:
            raise AdaptiveScanProtocolError("transition budget is outside 1..100 ms")
        if not 1 <= self.maximum_revisit_ms <= 10_000:
            raise AdaptiveScanProtocolError("maximum revisit is outside range")
        if not 1 <= self.feedback_age_ms <= 10_000:
            raise AdaptiveScanProtocolError("feedback age is outside range")
        if not 1 <= self.application_delay_ms <= 10_000:
            raise AdaptiveScanProtocolError("application delay is outside range")
        if not 1 <= self.decay_ms <= 60_000 or not 1 <= self.maximum_boost <= 16:
            raise AdaptiveScanProtocolError("decay or maximum boost is outside range")
        if not 1 <= self.maximum_queue_bytes <= 200_000_000:
            raise AdaptiveScanProtocolError("queue byte limit is outside range")
        if not 1 <= self.maximum_queue_age_ms <= 10_000:
            raise AdaptiveScanProtocolError("queue age is outside range")
        if not 1 <= self.maximum_queue_visits <= 64:
            raise AdaptiveScanProtocolError("queue visit limit is outside range")
        if self.rx_mask not in (1, 3) or self.format != FORMAT_CI16 or self.flags != SETUP_FLAGS:
            raise AdaptiveScanProtocolError("RX, format, or setup flags are not exact")
        _digest(self.analysis_digest)
        if not 1 <= len(self.targets) <= 8:
            raise AdaptiveScanProtocolError("target count is outside 1..8")
        for target in self.targets:
            target.validate()
        if len({target.channel for target in self.targets}) != len(self.targets):
            raise AdaptiveScanProtocolError("channel identifiers must be unique")
        if len({target.profile for target in self.targets}) != len(self.targets):
            raise AdaptiveScanProtocolError("fastlock profiles must be unique")
        slot = self.dwell_ms + self.transition_budget_ms
        if slot * len(self.targets) > self.maximum_revisit_ms:
            raise AdaptiveScanProtocolError("maximum revisit cannot cover every target")
        if slot > self.application_delay_ms or slot > self.duration_ms:
            raise AdaptiveScanProtocolError("application or session window is unschedulable")

    def pack(self) -> bytes:
        self.validate()
        packet = bytearray(SETUP_BYTES)
        _header(packet, b"SPSQ", self.flags, self.protocol_version)
        struct.pack_into(
            "<QQQIIIIIIIIIIQIIII",
            packet,
            16,
            self.session,
            self.generation,
            self.seed,
            self.source_rate_hz,
            self.analog_bandwidth_hz,
            self.duration_ms,
            self.dwell_ms,
            self.transition_budget_ms,
            self.maximum_revisit_ms,
            self.feedback_age_ms,
            self.application_delay_ms,
            self.decay_ms,
            self.maximum_boost,
            self.maximum_queue_bytes,
            self.maximum_queue_age_ms,
            self.maximum_queue_visits,
            len(self.targets),
            self.rx_mask,
        )
        struct.pack_into("<I", packet, 104, self.format)
        packet[112:144] = _digest(self.analysis_digest)
        for index, target in enumerate(self.targets):
            struct.pack_into(
                "<IIQII",
                packet,
                144 + index * 24,
                target.channel,
                target.profile,
                target.frequency_hz,
                target.baseline_weight,
                target.profile_crc32,
            )
        return _finish(packet)

    @classmethod
    def unpack(cls, raw: bytes | bytearray | memoryview) -> ScanSetup:
        packet = _check(raw, b"SPSQ", SETUP_BYTES, SETUP_FLAGS, versions=(VERSION, RUNTIME_VERSION))
        _require_zero(packet, 108, 112)
        _require_zero(packet, 336, 348)
        values = struct.unpack_from("<QQQIIIIIIIIIIQIIII", packet, 16)
        target_count = values[16]
        if not 1 <= target_count <= 8:
            raise AdaptiveScanProtocolError("target count is outside 1..8")
        targets = tuple(
            ScanTarget(*struct.unpack_from("<IIQII", packet, 144 + index * 24))
            for index in range(target_count)
        )
        _require_zero(packet, 144 + target_count * 24, 336)
        result = cls(
            protocol_version=struct.unpack_from("<H", packet, 4)[0],
            session=values[0],
            generation=values[1],
            seed=values[2],
            source_rate_hz=values[3],
            analog_bandwidth_hz=values[4],
            duration_ms=values[5],
            dwell_ms=values[6],
            transition_budget_ms=values[7],
            maximum_revisit_ms=values[8],
            feedback_age_ms=values[9],
            application_delay_ms=values[10],
            decay_ms=values[11],
            maximum_boost=values[12],
            maximum_queue_bytes=values[13],
            maximum_queue_age_ms=values[14],
            maximum_queue_visits=values[15],
            targets=targets,
            rx_mask=values[17],
            format=struct.unpack_from("<I", packet, 104)[0],
            flags=SETUP_FLAGS,
            analysis_digest=packet[112:144],
        )
        result.validate()
        return result


@dataclasses.dataclass(frozen=True, slots=True)
class ScanFeedback:
    session: int
    generation: int
    sequence: int
    visit: int
    valid_start: int
    valid_end: int
    target: int
    outcome: ScanOutcome
    analysis_digest: bytes

    def pack(self) -> bytes:
        if (
            not self.session
            or not self.generation
            or not self.sequence
            or self.valid_start >= self.valid_end
            or not 0 <= self.target < 8
        ):
            raise AdaptiveScanProtocolError("feedback identity or interval is invalid")
        packet = bytearray(FEEDBACK_BYTES)
        _header(packet, b"SPFB", 0)
        struct.pack_into(
            "<QQQQQQII",
            packet,
            16,
            self.session,
            self.generation,
            self.sequence,
            self.visit,
            self.valid_start,
            self.valid_end,
            self.target,
            int(self.outcome),
        )
        packet[72:104] = _digest(self.analysis_digest)
        return _finish(packet)

    @classmethod
    def unpack(cls, raw: bytes | bytearray | memoryview) -> ScanFeedback:
        packet = _check(raw, b"SPFB", FEEDBACK_BYTES, 0)
        _require_zero(packet, 104, 108)
        values = struct.unpack_from("<QQQQQQII", packet, 16)
        try:
            outcome = ScanOutcome(values[7])
        except ValueError as error:
            raise AdaptiveScanProtocolError("feedback outcome is unknown") from error
        result = cls(
            session=values[0],
            generation=values[1],
            sequence=values[2],
            visit=values[3],
            valid_start=values[4],
            valid_end=values[5],
            target=values[6],
            outcome=outcome,
            analysis_digest=packet[72:104],
        )
        if result.pack() != packet:
            raise AdaptiveScanProtocolError("feedback is not canonical")
        return result


@dataclasses.dataclass(frozen=True, slots=True)
class ScanVisit:
    session: int
    generation: int
    visit: int
    selection_counter: int
    transition_before: int
    transition_after: int
    valid_start: int
    valid_end: int
    frequency_hz: int
    iq_bytes: int
    missing_samples_before: int
    analog_bandwidth_hz: int
    source_rate_hz: int
    target: int
    profile: int
    result: VisitResult
    eligible_mask: int
    effective_weight: int
    profile_crc32: int
    flags: int = VISIT_FLAGS
    protocol_version: int = VERSION

    def pack(self) -> bytes:
        samples = self.valid_end - self.valid_start
        if (
            not self.session
            or not self.generation
            or not self.transition_before <= self.transition_after <= self.valid_start
            or samples < 0
            or not 70_000_000 <= self.frequency_hz <= 6_000_000_000
            or not _rate_valid(self.source_rate_hz, self.protocol_version)
            or not 200_000 <= self.analog_bandwidth_hz <= 56_000_000
            or not 0 <= self.target < 8
            or not 0 <= self.profile < 8
            or self.eligible_mask & ~0xFF
            or not self.flags & VISIT_FLAGS
            or self.flags & ~VISIT_FLAG_MASK
            or (self.result is VisitResult.COMPLETE) != bool(self.iq_bytes)
            or (
                self.result is VisitResult.COMPLETE
                and self.iq_bytes not in (samples * 4, samples * 8)
            )
        ):
            raise AdaptiveScanProtocolError("visit record is inconsistent")
        packet = bytearray(VISIT_BYTES)
        _header(packet, b"SPVR", self.flags, self.protocol_version)
        struct.pack_into(
            "<QQQQQQQQQQQIIIIIIIII",
            packet,
            16,
            self.session,
            self.generation,
            self.visit,
            self.selection_counter,
            self.transition_before,
            self.transition_after,
            self.valid_start,
            self.valid_end,
            self.frequency_hz,
            self.iq_bytes,
            self.missing_samples_before,
            self.analog_bandwidth_hz,
            self.source_rate_hz,
            self.target,
            self.profile,
            int(self.result),
            self.eligible_mask,
            self.effective_weight,
            self.profile_crc32,
            self.flags,
        )
        return _finish(packet)

    @classmethod
    def unpack(cls, raw: bytes | bytearray | memoryview) -> ScanVisit:
        packet = bytes(raw)
        if len(packet) != VISIT_BYTES:
            raise AdaptiveScanProtocolError("visit size is not exact")
        flags = struct.unpack_from("<I", packet, 12)[0]
        packet = _check(packet, b"SPVR", VISIT_BYTES, flags, versions=(VERSION, RUNTIME_VERSION))
        _require_zero(packet, 140, 156)
        values = struct.unpack_from("<QQQQQQQQQQQIIIIIIIII", packet, 16)
        try:
            result_kind = VisitResult(values[15])
        except ValueError as error:
            raise AdaptiveScanProtocolError("visit result is unknown") from error
        result = cls(
            protocol_version=struct.unpack_from("<H", packet, 4)[0],
            session=values[0],
            generation=values[1],
            visit=values[2],
            selection_counter=values[3],
            transition_before=values[4],
            transition_after=values[5],
            valid_start=values[6],
            valid_end=values[7],
            frequency_hz=values[8],
            iq_bytes=values[9],
            missing_samples_before=values[10],
            analog_bandwidth_hz=values[11],
            source_rate_hz=values[12],
            target=values[13],
            profile=values[14],
            result=result_kind,
            eligible_mask=values[16],
            effective_weight=values[17],
            profile_crc32=values[18],
            flags=values[19],
        )
        if result.pack() != packet:
            raise AdaptiveScanProtocolError("visit is not canonical")
        return result


@dataclasses.dataclass(frozen=True, slots=True)
class ScanAck:
    sequence: int
    source_visit: int
    first_visit: int
    received_counter: int
    application_counter: int
    target: int
    result: FeedbackResult
    old_boost: int
    new_boost: int

    def pack(self) -> bytes:
        if (
            not self.sequence
            or not 0 <= self.target < 8
            or (self.result is FeedbackResult.APPLIED)
            != (self.first_visit != 0xFFFF_FFFF_FFFF_FFFF)
        ):
            raise AdaptiveScanProtocolError("feedback acknowledgement is inconsistent")
        packet = bytearray(ACK_BYTES)
        _header(packet, b"SPFA", 0)
        struct.pack_into(
            "<QQQQQIIII",
            packet,
            16,
            self.sequence,
            self.source_visit,
            self.first_visit,
            self.received_counter,
            self.application_counter,
            self.target,
            int(self.result),
            self.old_boost,
            self.new_boost,
        )
        return _finish(packet)

    @classmethod
    def unpack(cls, raw: bytes | bytearray | memoryview) -> ScanAck:
        packet = _check(raw, b"SPFA", ACK_BYTES, 0)
        _require_zero(packet, 72, 92)
        values = struct.unpack_from("<QQQQQIIII", packet, 16)
        try:
            result_kind = FeedbackResult(values[6])
        except ValueError as error:
            raise AdaptiveScanProtocolError("feedback result is unknown") from error
        result = cls(
            sequence=values[0],
            source_visit=values[1],
            first_visit=values[2],
            received_counter=values[3],
            application_counter=values[4],
            target=values[5],
            result=result_kind,
            old_boost=values[7],
            new_boost=values[8],
        )
        if result.pack() != packet:
            raise AdaptiveScanProtocolError("acknowledgement is not canonical")
        return result


@dataclasses.dataclass(frozen=True, slots=True)
class ScanTerminal:
    session: int
    generation: int
    final_counter: int
    restore_before: int
    restore_after: int
    planned: int
    delivered: int
    skipped: int
    invalid: int
    cancelled: int
    iq_bytes: int
    state: TerminalState
    reason: int
    error: int
    flags: int = TERMINAL_FLAGS

    def pack(self) -> bytes:
        if (
            not self.session
            or not self.generation
            or self.restore_before > self.restore_after
            or self.delivered + self.skipped + self.invalid + self.cancelled != self.planned
            or (self.state is TerminalState.COMPLETED and self.error)
            or (self.state is TerminalState.COMPLETED and self.restore_before < self.final_counter)
            or (self.state is TerminalState.FAILED and self.error >= 0)
            or self.flags != TERMINAL_FLAGS
            or not -(1 << 31) <= self.error < (1 << 31)
        ):
            raise AdaptiveScanProtocolError("terminal record is inconsistent")
        packet = bytearray(TERMINAL_BYTES)
        _header(packet, b"SPFT", self.flags)
        struct.pack_into(
            "<QQQQQQQQQQQIIiI",
            packet,
            16,
            self.session,
            self.generation,
            self.final_counter,
            self.restore_before,
            self.restore_after,
            self.planned,
            self.delivered,
            self.skipped,
            self.invalid,
            self.cancelled,
            self.iq_bytes,
            int(self.state),
            self.reason,
            self.error,
            self.flags,
        )
        return _finish(packet)

    @classmethod
    def unpack(cls, raw: bytes | bytearray | memoryview) -> ScanTerminal:
        packet = bytes(raw)
        if len(packet) != TERMINAL_BYTES:
            raise AdaptiveScanProtocolError("terminal size is not exact")
        flags = struct.unpack_from("<I", packet, 12)[0]
        packet = _check(packet, b"SPFT", TERMINAL_BYTES, flags)
        _require_zero(packet, 120, 124)
        values = struct.unpack_from("<QQQQQQQQQQQIIiI", packet, 16)
        try:
            state = TerminalState(values[11])
        except ValueError as error:
            raise AdaptiveScanProtocolError("terminal state is unknown") from error
        result = cls(
            session=values[0],
            generation=values[1],
            final_counter=values[2],
            restore_before=values[3],
            restore_after=values[4],
            planned=values[5],
            delivered=values[6],
            skipped=values[7],
            invalid=values[8],
            cancelled=values[9],
            iq_bytes=values[10],
            state=state,
            reason=values[12],
            error=values[13],
            flags=values[14],
        )
        if result.pack() != packet:
            raise AdaptiveScanProtocolError("terminal is not canonical")
        return result


def corruptions(record: bytes) -> Sequence[bytes]:
    """Return one single-bit corruption at every byte for protocol tests."""

    output: list[bytes] = []
    for index in range(len(record)):
        changed = bytearray(record)
        changed[index] ^= 0x80
        output.append(bytes(changed))
    return output
