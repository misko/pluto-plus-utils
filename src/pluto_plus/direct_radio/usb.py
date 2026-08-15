"""Pluto+ direct-USB protocol v3 primitives.

Wire values and validation rules are derived from ``spf.direct_radio.usb_protocol``
(reviewed 2026-08-15).  This module is intentionally standalone and performs no
USB I/O: transports pass byte records into these strict parsers.
"""

from __future__ import annotations

import dataclasses
import enum
import struct
import zlib
from typing import Final


class ProtocolError(ValueError):
    """A record violates the negotiated direct-radio wire protocol."""


MAGIC: Final = 0x314D4753  # b"SGM1"
VERSION_V3: Final = 3
CAPABILITIES_MAGIC: Final = 0x50434753  # b"SGCP"
HARDWARE_IDENTITY_MAGIC: Final = 0x31464853  # b"SHF1"
RUNTIME_STATUS_MAGIC: Final = 0x31545353  # b"SST1"
TIME_ANCHOR_QUERY_MAGIC: Final = 0x31515453  # b"STQ1"
TIME_ANCHOR_MAGIC: Final = 0x31415453  # b"STA1"
START_REQUEST_MAGIC_V3: Final = 0x33534753  # b"SGS3"
GAIN_INDEX_INVALID: Final = 0xFF
GAIN_DB_INVALID: Final = -128
RSSI_QDB_INVALID: Final = 0xFFFF
FIRST_CHANGE_UNAVAILABLE: Final = 0xFFFFFFFF
MAX_FINITE_FRAMES: Final = 16
MAX_SAMPLES_PER_CHANNEL: Final = 0xFFFFFFFF // 8
MAX_GAIN_OBSERVATIONS: Final = 256
MAX_GAIN_EVENTS: Final = 256


class SampleFormat(enum.IntEnum):
    CS16_LE_TIME_INTERLEAVED = 1


class MetadataFeatures(enum.IntFlag):
    GAIN_ENDPOINT_SNAPSHOTS = 1 << 0
    HEADER_CRC32 = 1 << 1
    SAMPLE_SEQUENCE = 1 << 2
    FPGA_GAIN_EVENTS = 1 << 3
    GAIN_DB_ENDPOINTS = 1 << 4
    RSSI_ENDPOINT_SNAPSHOTS = 1 << 5
    GAIN_OBSERVATION_SERIES = 1 << 6
    HARDWARE_SAMPLE_COUNTER = 1 << 7


KNOWN_FEATURES = MetadataFeatures(0xFF)


class MetadataFlags(enum.IntFlag):
    START_VALID = 1 << 0
    END_VALID = 1 << 1
    RX1_ENDPOINT_CHANGED = 1 << 2
    RX2_ENDPOINT_CHANGED = 1 << 3
    SAMPLE_SEQUENCE_VALID = 1 << 4
    FPGA_EVENTS_VALID = 1 << 5
    RX1_CHANGED_IN_BUFFER = 1 << 6
    RX2_CHANGED_IN_BUFFER = 1 << 7
    RX1_LOCKED_AT_END = 1 << 8
    RX2_LOCKED_AT_END = 1 << 9
    GAIN_FULL_TABLE_MODE = 1 << 10
    DEVICE_IIO_OVERFLOW = 1 << 11
    GAIN_READ_FAILED = 1 << 12
    FPGA_EVENT_OVERFLOW = 1 << 13
    DUMMY_GAINS = 1 << 14
    RSSI_START_VALID = 1 << 15
    RSSI_END_VALID = 1 << 16
    RSSI_READ_FAILED = 1 << 17
    GAIN_DB_VALUES = 1 << 18
    GAIN_OBSERVATIONS_VALID = 1 << 19
    GAIN_OBSERVATION_OVERFLOW = 1 << 20
    HARDWARE_SAMPLE_COUNTER_VALID = 1 << 21


KNOWN_FLAGS = MetadataFlags((1 << 22) - 1)


class GainObservationFlags(enum.IntFlag):
    VALID = 1 << 0
    SAMPLE_INTERVAL_VALID = 1 << 1


class GainEventFlags(enum.IntFlag):
    RX1_CHANGED = 1 << 0
    RX2_CHANGED = 1 << 1
    RX1_LOCKED = 1 << 2
    RX2_LOCKED = 1 << 3


class CapabilityFlags(enum.IntFlag):
    FINITE_RX = 1 << 0
    DUMMY_GAINS = 1 << 1
    HARDWARE_IDENTITY = 1 << 2
    STATUS = 1 << 3
    TIME_ANCHOR = 1 << 4


class HardwareIdentityFlags(enum.IntFlag):
    FPGA_DEVICE_DNA_VALID = 1 << 0
    GADGET_BUILD_ID_VALID = 1 << 1


class RuntimeStatusFlags(enum.IntFlag):
    BOOT_ID_VALID = 1 << 0
    PROCESS_NONCE_VALID = 1 << 1
    RX_WORKER_ACTIVE = 1 << 2


class RuntimeState(enum.IntEnum):
    IDLE = 0
    STARTING = 1
    STREAMING = 2
    COMPLETE = 3
    STOPPING = 4
    FAILED = 5


class ErrorSubsystem(enum.IntEnum):
    NONE = 0
    CONTROL = 1
    RX_INIT = 2
    IIO_REFILL = 3
    USB_SUBMIT = 4
    USB_COMPLETION = 5
    BUFFER_STARVATION = 6
    GAIN_READ = 7
    RSSI_READ = 8
    STOP_TIMEOUT = 9


class TimeAnchorFlags(enum.IntFlag):
    COUNTER_INTERVAL_VALID = 1 << 0
    MONOTONIC_INTERVAL_VALID = 1 << 1
    COUNTER_LOW32 = 1 << 2
    COUNTER_ADVANCED = 1 << 3


_CAPABILITIES = struct.Struct("<IHHHHIIIII")
_IDENTITY = struct.Struct("<IHHIIQ40s")
_STATUS = struct.Struct("<IHHHHiII16s16sQQ14I")
_TIME_QUERY = struct.Struct("<IHHQII")
_TIME_ANCHOR = struct.Struct("<IHHIIQQQQQII")
_START = struct.Struct("<IHHIIIIII")
_V3_PREFIX = struct.Struct("<IHHIIQQQIIIHBbbbbBIIIIHHHHII")
_V3_EXTENSION = struct.Struct("<IHHHHHHIIII")
_OBSERVATION = struct.Struct("<QQIHBBbbHI")
_EVENT = struct.Struct("<QHHI")

CAPABILITIES_BYTES: Final = _CAPABILITIES.size
HARDWARE_IDENTITY_BYTES: Final = _IDENTITY.size
RUNTIME_STATUS_BYTES: Final = _STATUS.size
TIME_ANCHOR_QUERY_BYTES: Final = _TIME_QUERY.size
TIME_ANCHOR_BYTES: Final = _TIME_ANCHOR.size
START_REQUEST_BYTES: Final = _START.size
HEADER_PREFIX_BYTES_V3: Final = _V3_PREFIX.size + _V3_EXTENSION.size
GAIN_OBSERVATION_BYTES: Final = _OBSERVATION.size
GAIN_EVENT_BYTES: Final = _EVENT.size


def _uint(name: str, value: int, bits: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 1 << bits:
        raise ProtocolError(f"{name} is outside uint{bits}: {value!r}")


@dataclasses.dataclass(frozen=True, slots=True)
class GadgetCapabilitiesV1:
    protocol_min: int
    protocol_max: int
    supported_features: MetadataFeatures
    max_samples_per_channel: int
    max_finite_frames: int
    capability_flags: CapabilityFlags

    @classmethod
    def unpack(cls, payload: bytes | bytearray | memoryview) -> GadgetCapabilitiesV1:
        if len(payload) != CAPABILITIES_BYTES:
            raise ProtocolError("capability response size mismatch")
        magic, size, minimum, maximum, r0, features, samples, frames, flags, r1 = (
            _CAPABILITIES.unpack(payload)
        )
        if magic != CAPABILITIES_MAGIC or size != CAPABILITIES_BYTES:
            raise ProtocolError("bad capability identity or size")
        if r0 or r1:
            raise ProtocolError("capability reserved fields must be zero")
        if not 0 < minimum <= maximum:
            raise ProtocolError("invalid gadget protocol range")
        if features & ~int(KNOWN_FEATURES) or flags & ~int(CapabilityFlags(0x1F)):
            raise ProtocolError("unknown capability bits")
        parsed_flags = CapabilityFlags(flags)
        if not parsed_flags & CapabilityFlags.FINITE_RX or not samples or not frames:
            raise ProtocolError("gadget reports unusable finite RX")
        return cls(minimum, maximum, MetadataFeatures(features), samples, frames, parsed_flags)


@dataclasses.dataclass(frozen=True, slots=True)
class HardwareIdentityV1:
    flags: HardwareIdentityFlags
    fpga_device_dna: int
    gadget_build_id: str

    @classmethod
    def unpack(cls, payload: bytes | bytearray | memoryview) -> HardwareIdentityV1:
        if len(payload) != HARDWARE_IDENTITY_BYTES:
            raise ProtocolError("hardware identity response size mismatch")
        magic, size, version, flags, reserved, dna, raw_sha = _IDENTITY.unpack(payload)
        if (magic, size, version) != (HARDWARE_IDENTITY_MAGIC, HARDWARE_IDENTITY_BYTES, 1):
            raise ProtocolError("bad hardware identity identity, size, or version")
        if reserved or flags & ~0x03:
            raise ProtocolError("hardware identity reserved/flag fields are invalid")
        parsed = HardwareIdentityFlags(flags)
        if bool(parsed & HardwareIdentityFlags.FPGA_DEVICE_DNA_VALID) != bool(dna):
            raise ProtocolError("FPGA Device DNA validity disagrees with value")
        if dna >> 57:
            raise ProtocolError("FPGA Device DNA is outside the 57-bit range")
        try:
            sha = raw_sha.rstrip(b"\0").decode("ascii")
        except UnicodeDecodeError as exc:
            raise ProtocolError("gadget build ID is not ASCII") from exc
        valid_sha = bool(parsed & HardwareIdentityFlags.GADGET_BUILD_ID_VALID)
        if valid_sha != bool(sha):
            raise ProtocolError("gadget build ID validity disagrees with value")
        if sha and (len(sha) != 40 or any(char not in "0123456789abcdef" for char in sha)):
            raise ProtocolError("gadget build ID must be a lowercase 40-character SHA")
        return cls(parsed, dna, sha)


@dataclasses.dataclass(frozen=True, slots=True)
class RuntimeStatusV1:
    lifecycle_state: RuntimeState
    last_error_subsystem: ErrorSubsystem
    last_errno: int
    flags: RuntimeStatusFlags
    boot_id: bytes
    process_nonce: bytes
    current_stream_id: int
    last_completed_sequence: int
    start_count: int
    stop_count: int
    completed_frame_count: int
    dropped_frame_count: int
    iio_refill_error_count: int
    usb_submit_error_count: int
    short_write_count: int
    buffer_starvation_count: int
    gain_read_failure_count: int
    rssi_read_failure_count: int
    control_error_count: int
    stop_timeout_count: int
    worker_heartbeat_age_ms: int

    @classmethod
    def unpack(cls, payload: bytes | bytearray | memoryview) -> RuntimeStatusV1:
        if len(payload) != RUNTIME_STATUS_BYTES:
            raise ProtocolError("runtime status response size mismatch")
        values = _STATUS.unpack(payload)
        magic, size, version, state, subsystem, errno, flags, r0 = values[:8]
        boot_id, nonce, stream_id, sequence = values[8:12]
        counters = values[12:]
        if (magic, size, version) != (RUNTIME_STATUS_MAGIC, RUNTIME_STATUS_BYTES, 1):
            raise ProtocolError("bad runtime status identity, size, or version")
        if r0 or counters[-1] or flags & ~0x07:
            raise ProtocolError("runtime status reserved/flag fields are invalid")
        try:
            parsed_state = RuntimeState(state)
            parsed_subsystem = ErrorSubsystem(subsystem)
        except ValueError as exc:
            raise ProtocolError("unknown runtime status state or subsystem") from exc
        parsed_flags = RuntimeStatusFlags(flags)
        if not parsed_flags & RuntimeStatusFlags.BOOT_ID_VALID and any(boot_id):
            raise ProtocolError("invalid runtime boot ID must be zero")
        if not parsed_flags & RuntimeStatusFlags.PROCESS_NONCE_VALID and any(nonce):
            raise ProtocolError("invalid runtime process nonce must be zero")
        if not parsed_flags & RuntimeStatusFlags.RX_WORKER_ACTIVE and counters[-2]:
            raise ProtocolError("inactive worker heartbeat age must be zero")
        return cls(
            parsed_state,
            parsed_subsystem,
            errno,
            parsed_flags,
            boot_id,
            nonce,
            stream_id,
            sequence,
            *counters[:-1],
        )


def pack_time_anchor_query(*, request_id: int) -> bytes:
    _uint("request_id", request_id, 64)
    if request_id == 0:
        raise ProtocolError("time-anchor request ID must be non-zero")
    record = _TIME_QUERY.pack(TIME_ANCHOR_QUERY_MAGIC, TIME_ANCHOR_QUERY_BYTES, 1, request_id, 0, 0)
    crc = zlib.crc32(record) & 0xFFFFFFFF
    return record[:-4] + struct.pack("<I", crc)


@dataclasses.dataclass(frozen=True, slots=True)
class TimeAnchorV1:
    flags: TimeAnchorFlags
    request_id: int
    radio_monotonic_before_ns: int
    sample_counter_before: int
    sample_counter_after: int
    radio_monotonic_after_ns: int

    @property
    def counter_delta(self) -> int:
        return (self.sample_counter_after - self.sample_counter_before) & 0xFFFFFFFF

    def _validate(self) -> None:
        required = TimeAnchorFlags(0x07)
        if self.flags & ~TimeAnchorFlags(0x0F) or self.flags & required != required:
            raise ProtocolError("time anchor lacks required validity flags")
        for name, value in dataclasses.asdict(self).items():
            if name != "flags":
                _uint(name, value, 64)
        if (
            not self.request_id
            or self.sample_counter_before >> 32
            or self.sample_counter_after >> 32
        ):
            raise ProtocolError("time anchor request/counter fields are invalid")
        if self.radio_monotonic_after_ns < self.radio_monotonic_before_ns:
            raise ProtocolError("time-anchor radio monotonic interval regressed")
        if self.counter_delta >= 0x80000000:
            raise ProtocolError("time-anchor counter interval is ambiguous")
        if bool(self.flags & TimeAnchorFlags.COUNTER_ADVANCED) != bool(self.counter_delta):
            raise ProtocolError("time-anchor advanced flag disagrees with counter")

    def pack(self) -> bytes:
        self._validate()
        values = (
            TIME_ANCHOR_MAGIC,
            TIME_ANCHOR_BYTES,
            1,
            int(self.flags),
            0,
            self.request_id,
            self.radio_monotonic_before_ns,
            self.sample_counter_before,
            self.sample_counter_after,
            self.radio_monotonic_after_ns,
            0,
            0,
        )
        record = _TIME_ANCHOR.pack(*values)
        return record[:-4] + struct.pack("<I", zlib.crc32(record) & 0xFFFFFFFF)

    @classmethod
    def unpack(cls, payload: bytes | bytearray | memoryview) -> TimeAnchorV1:
        if len(payload) != TIME_ANCHOR_BYTES:
            raise ProtocolError("time-anchor response size mismatch")
        values = _TIME_ANCHOR.unpack(payload)
        if values[:3] != (TIME_ANCHOR_MAGIC, TIME_ANCHOR_BYTES, 1) or values[4] or values[10]:
            raise ProtocolError("bad time-anchor identity, size, version, or reserved field")
        scratch = bytearray(payload)
        received = values[-1]
        scratch[-4:] = bytes(4)
        if received != zlib.crc32(scratch) & 0xFFFFFFFF:
            raise ProtocolError("time-anchor CRC mismatch")
        result = cls(TimeAnchorFlags(values[3]), *values[5:10])
        result._validate()
        return result


def pack_start_request_v3(
    *,
    requested_features: MetadataFeatures,
    enabled_scan_mask: int,
    samples_per_channel: int,
    frame_count: int,
    gain_observation_interval_samples: int,
    gain_observation_capacity: int,
    gain_event_capacity: int = 0,
) -> bytes:
    required = (
        MetadataFeatures.GAIN_ENDPOINT_SNAPSHOTS
        | MetadataFeatures.HEADER_CRC32
        | MetadataFeatures.SAMPLE_SEQUENCE
        | MetadataFeatures.GAIN_DB_ENDPOINTS
        | MetadataFeatures.RSSI_ENDPOINT_SNAPSHOTS
        | MetadataFeatures.GAIN_OBSERVATION_SERIES
        | MetadataFeatures.HARDWARE_SAMPLE_COUNTER
    )
    if requested_features != required or enabled_scan_mask != 0x0F:
        raise ProtocolError("protocol v3 feature mask or scan mask is invalid")
    if not 1 <= samples_per_channel <= MAX_SAMPLES_PER_CHANNEL:
        raise ProtocolError("samples_per_channel is outside the v3 limit")
    if not 1 <= frame_count <= MAX_FINITE_FRAMES:
        raise ProtocolError("frame_count is outside the v3 finite limit")
    if not 1 <= gain_observation_interval_samples <= samples_per_channel:
        raise ProtocolError("gain observation interval is outside the frame")
    if not 1 <= gain_observation_capacity <= MAX_GAIN_OBSERVATIONS:
        raise ProtocolError("gain observation capacity is outside the v3 limit")
    if not 0 <= gain_event_capacity <= MAX_GAIN_EVENTS:
        raise ProtocolError("gain event capacity is outside the v3 limit")
    capacities = gain_observation_capacity | gain_event_capacity << 16
    return _START.pack(
        START_REQUEST_MAGIC_V3,
        3,
        START_REQUEST_BYTES,
        int(requested_features),
        enabled_scan_mask,
        samples_per_channel,
        frame_count,
        gain_observation_interval_samples,
        capacities,
    )


@dataclasses.dataclass(frozen=True, slots=True)
class GainObservationV3:
    sample_sequence_before: int
    sample_sequence_after: int
    read_duration_ns: int
    flags: GainObservationFlags
    rx1_gain_index: int = GAIN_INDEX_INVALID
    rx2_gain_index: int = GAIN_INDEX_INVALID
    rx1_gain_db: int = GAIN_DB_INVALID
    rx2_gain_db: int = GAIN_DB_INVALID

    def _validate(self) -> None:
        for name, value, bits in (
            ("sample_sequence_before", self.sample_sequence_before, 64),
            ("sample_sequence_after", self.sample_sequence_after, 64),
            ("read_duration_ns", self.read_duration_ns, 32),
            ("rx1_gain_index", self.rx1_gain_index, 8),
            ("rx2_gain_index", self.rx2_gain_index, 8),
        ):
            _uint(name, value, bits)
        if self.flags & ~GainObservationFlags(0x03):
            raise ProtocolError("unknown gain-observation flags")
        interval = bool(self.flags & GainObservationFlags.SAMPLE_INTERVAL_VALID)
        if interval and self.sample_sequence_after < self.sample_sequence_before:
            raise ProtocolError("gain observation sample interval runs backwards")
        if not interval and (self.sample_sequence_before or self.sample_sequence_after):
            raise ProtocolError("invalid gain observation interval must be zero")
        gains_valid = bool(self.flags & GainObservationFlags.VALID)
        sentinels_absent = (
            self.rx1_gain_index != GAIN_INDEX_INVALID
            and self.rx2_gain_index != GAIN_INDEX_INVALID
            and self.rx1_gain_db != GAIN_DB_INVALID
            and self.rx2_gain_db != GAIN_DB_INVALID
        )
        if gains_valid != sentinels_absent or gains_valid and not interval:
            raise ProtocolError("gain observation validity disagrees with values")
        if any(not -128 <= value <= 127 for value in (self.rx1_gain_db, self.rx2_gain_db)):
            raise ProtocolError("gain observation dB is outside int8")

    def pack(self) -> bytes:
        self._validate()
        return _OBSERVATION.pack(
            self.sample_sequence_before,
            self.sample_sequence_after,
            self.read_duration_ns,
            int(self.flags),
            self.rx1_gain_index,
            self.rx2_gain_index,
            self.rx1_gain_db,
            self.rx2_gain_db,
            0,
            0,
        )

    @classmethod
    def unpack(cls, payload: bytes | bytearray | memoryview) -> GainObservationV3:
        if len(payload) != GAIN_OBSERVATION_BYTES:
            raise ProtocolError("gain observation record has the wrong size")
        values = _OBSERVATION.unpack(payload)
        if values[-2] or values[-1]:
            raise ProtocolError("gain observation reserved fields must be zero")
        result = cls(
            sample_sequence_before=values[0],
            sample_sequence_after=values[1],
            read_duration_ns=values[2],
            flags=GainObservationFlags(values[3]),
            rx1_gain_index=values[4],
            rx2_gain_index=values[5],
            rx1_gain_db=values[6],
            rx2_gain_db=values[7],
        )
        result._validate()
        return result


@dataclasses.dataclass(frozen=True, slots=True)
class GainEventV3:
    sample_sequence: int
    flags: GainEventFlags

    def pack(self) -> bytes:
        _uint("event sample_sequence", self.sample_sequence, 64)
        if self.flags & ~GainEventFlags(0x0F) or not self.flags & GainEventFlags(0x03):
            raise ProtocolError("gain event flags are invalid")
        return _EVENT.pack(self.sample_sequence, int(self.flags), 0, 0)

    @classmethod
    def unpack(cls, payload: bytes | bytearray | memoryview) -> GainEventV3:
        if len(payload) != GAIN_EVENT_BYTES:
            raise ProtocolError("gain event record has the wrong size")
        sequence, flags, r0, r1 = _EVENT.unpack(payload)
        if r0 or r1:
            raise ProtocolError("gain event reserved fields must be zero")
        result = cls(sequence, GainEventFlags(flags))
        result.pack()
        return result


@dataclasses.dataclass(frozen=True, slots=True)
class RadioMetadataV3:
    features: MetadataFeatures
    flags: MetadataFlags
    stream_id: int
    buffer_sequence: int
    first_sample_sequence: int
    samples_per_channel: int
    iq_payload_bytes: int
    enabled_scan_mask: int
    sample_format: SampleFormat
    channel_count: int
    rx1_gain_db_start: int = GAIN_DB_INVALID
    rx2_gain_db_start: int = GAIN_DB_INVALID
    rx1_gain_db_end: int = GAIN_DB_INVALID
    rx2_gain_db_end: int = GAIN_DB_INVALID
    gain_start_read_duration_ns: int = 0
    gain_end_read_duration_ns: int = 0
    rx1_first_change_sample: int = FIRST_CHANGE_UNAVAILABLE
    rx2_first_change_sample: int = FIRST_CHANGE_UNAVAILABLE
    rx1_rssi_start_qdb: int = RSSI_QDB_INVALID
    rx2_rssi_start_qdb: int = RSSI_QDB_INVALID
    rx1_rssi_end_qdb: int = RSSI_QDB_INVALID
    rx2_rssi_end_qdb: int = RSSI_QDB_INVALID
    rssi_start_read_duration_ns: int = 0
    rssi_end_read_duration_ns: int = 0
    gain_observation_interval_samples: int = 0
    gain_observation_capacity: int = 0
    gain_event_capacity: int = 0
    gain_observation_overflow_count: int = 0
    gain_event_overflow_count: int = 0
    gain_observations: tuple[GainObservationV3, ...] = ()
    gain_events: tuple[GainEventV3, ...] = ()

    @property
    def header_bytes(self) -> int:
        return (
            HEADER_PREFIX_BYTES_V3
            + self.gain_observation_capacity * 32
            + self.gain_event_capacity * 16
            + 4
        )

    def _validate(self) -> None:
        if int(self.features) & ~int(KNOWN_FEATURES) or int(self.flags) & ~int(KNOWN_FLAGS):
            raise ProtocolError("unknown metadata feature or flag bits")
        required_features = MetadataFeatures(0xF7)
        if self.features & required_features != required_features:
            raise ProtocolError("protocol v3 is missing required features")
        required_flags = (
            MetadataFlags.SAMPLE_SEQUENCE_VALID
            | MetadataFlags.GAIN_OBSERVATIONS_VALID
            | MetadataFlags.HARDWARE_SAMPLE_COUNTER_VALID
        )
        if self.flags & required_flags != required_flags:
            raise ProtocolError("protocol v3 sample/gain/counter metadata is not valid")
        if not self.stream_id or not self.samples_per_channel:
            raise ProtocolError("stream and sample counts must be non-zero")
        if (
            self.enabled_scan_mask != 0x0F
            or self.channel_count != 2
            or self.sample_format != SampleFormat.CS16_LE_TIME_INTERLEAVED
        ):
            raise ProtocolError("protocol v3 requires dual-RX CI16 scan layout")
        if self.iq_payload_bytes != self.samples_per_channel * 8:
            raise ProtocolError("payload size does not match dual-RX CI16 layout")
        if not 1 <= self.gain_observation_interval_samples <= self.samples_per_channel:
            raise ProtocolError("protocol v3 observation interval is outside the frame")
        if not 1 <= self.gain_observation_capacity <= MAX_GAIN_OBSERVATIONS:
            raise ProtocolError("protocol v3 observation capacity is invalid")
        if not 0 <= self.gain_event_capacity <= MAX_GAIN_EVENTS:
            raise ProtocolError("protocol v3 event capacity is invalid")
        if (
            not self.gain_observations
            or len(self.gain_observations) > self.gain_observation_capacity
        ):
            raise ProtocolError("protocol v3 observation count is invalid")
        if len(self.gain_events) > self.gain_event_capacity:
            raise ProtocolError("protocol v3 event count is invalid")
        if bool(self.flags & MetadataFlags.GAIN_OBSERVATION_OVERFLOW) != bool(
            self.gain_observation_overflow_count
        ):
            raise ProtocolError("gain observation overflow flag/count disagree")
        if bool(self.flags & MetadataFlags.FPGA_EVENT_OVERFLOW) != bool(
            self.gain_event_overflow_count
        ):
            raise ProtocolError("gain event overflow flag/count disagree")
        if bool(self.features & MetadataFeatures.FPGA_GAIN_EVENTS) != bool(
            self.gain_event_capacity or self.gain_events
        ):
            raise ProtocolError("gain event capacity disagrees with FPGA feature")
        frame_end = self.first_sample_sequence + self.samples_per_channel
        prior = -1
        for observation in self.gain_observations:
            observation._validate()
            if observation.sample_sequence_before < prior:
                raise ProtocolError("gain observations are not ordered")
            prior = observation.sample_sequence_before
            if observation.flags & GainObservationFlags.SAMPLE_INTERVAL_VALID and not (
                observation.sample_sequence_after >= self.first_sample_sequence
                and observation.sample_sequence_before < frame_end
            ):
                raise ProtocolError("gain observation does not overlap its IQ frame")
        prior = -1
        for event in self.gain_events:
            event.pack()
            if (
                not self.first_sample_sequence <= event.sample_sequence < frame_end
                or event.sample_sequence < prior
            ):
                raise ProtocolError("gain events are unordered or outside their IQ frame")
            prior = event.sample_sequence

    def pack(self) -> bytes:
        self._validate()
        prefix = _V3_PREFIX.pack(
            MAGIC,
            VERSION_V3,
            self.header_bytes,
            int(self.features),
            int(self.flags),
            self.stream_id,
            self.buffer_sequence,
            self.first_sample_sequence,
            self.samples_per_channel,
            self.iq_payload_bytes,
            self.enabled_scan_mask,
            int(self.sample_format),
            self.channel_count,
            self.rx1_gain_db_start,
            self.rx2_gain_db_start,
            self.rx1_gain_db_end,
            self.rx2_gain_db_end,
            0,
            self.gain_start_read_duration_ns,
            self.gain_end_read_duration_ns,
            self.rx1_first_change_sample,
            self.rx2_first_change_sample,
            self.rx1_rssi_start_qdb,
            self.rx2_rssi_start_qdb,
            self.rx1_rssi_end_qdb,
            self.rx2_rssi_end_qdb,
            self.rssi_start_read_duration_ns,
            self.rssi_end_read_duration_ns,
        )
        extension = _V3_EXTENSION.pack(
            self.gain_observation_interval_samples,
            len(self.gain_observations),
            self.gain_observation_capacity,
            32,
            len(self.gain_events),
            self.gain_event_capacity,
            16,
            self.gain_observation_overflow_count,
            self.gain_event_overflow_count,
            0,
            0,
        )
        observations = b"".join(item.pack() for item in self.gain_observations)
        observations += bytes((self.gain_observation_capacity - len(self.gain_observations)) * 32)
        events = b"".join(item.pack() for item in self.gain_events)
        events += bytes((self.gain_event_capacity - len(self.gain_events)) * 16)
        header = prefix + extension + observations + events + bytes(4)
        return header[:-4] + struct.pack("<I", zlib.crc32(header) & 0xFFFFFFFF)

    @classmethod
    def unpack(cls, header: bytes | bytearray | memoryview) -> RadioMetadataV3:
        if len(header) < HEADER_PREFIX_BYTES_V3 + 4:
            raise ProtocolError("short protocol v3 metadata header")
        prefix = _V3_PREFIX.unpack_from(header)
        if prefix[:2] != (MAGIC, VERSION_V3) or prefix[17]:
            raise ProtocolError("bad protocol v3 identity or reserved field")
        header_bytes = prefix[2]
        if len(header) != header_bytes:
            raise ProtocolError("protocol v3 metadata length mismatch")
        extension = _V3_EXTENSION.unpack_from(header, _V3_PREFIX.size)
        (
            interval,
            obs_count,
            obs_capacity,
            obs_size,
            event_count,
            event_capacity,
            event_size,
            obs_overflow,
            event_overflow,
            r1,
            r2,
        ) = extension
        if r1 or r2 or obs_size != 32 or event_size != 16:
            raise ProtocolError("protocol v3 extension record/reserved fields are invalid")
        expected = HEADER_PREFIX_BYTES_V3 + obs_capacity * 32 + event_capacity * 16 + 4
        if header_bytes != expected or obs_count > obs_capacity or event_count > event_capacity:
            raise ProtocolError("protocol v3 header size or record count mismatch")
        scratch = bytearray(header)
        received = struct.unpack_from("<I", scratch, header_bytes - 4)[0]
        scratch[-4:] = bytes(4)
        if received != zlib.crc32(scratch) & 0xFFFFFFFF:
            raise ProtocolError("protocol v3 metadata CRC mismatch")
        offset = HEADER_PREFIX_BYTES_V3
        observations = tuple(
            GainObservationV3.unpack(header[offset + i * 32 : offset + (i + 1) * 32])
            for i in range(obs_count)
        )
        offset += obs_capacity * 32
        if any(header[HEADER_PREFIX_BYTES_V3 + obs_count * 32 : offset]):
            raise ProtocolError("unused gain observation records must be zero")
        events = tuple(
            GainEventV3.unpack(header[offset + i * 16 : offset + (i + 1) * 16])
            for i in range(event_count)
        )
        if any(header[offset + event_count * 16 : offset + event_capacity * 16]):
            raise ProtocolError("unused gain event records must be zero")
        result = cls(
            features=MetadataFeatures(prefix[3]),
            flags=MetadataFlags(prefix[4]),
            stream_id=prefix[5],
            buffer_sequence=prefix[6],
            first_sample_sequence=prefix[7],
            samples_per_channel=prefix[8],
            iq_payload_bytes=prefix[9],
            enabled_scan_mask=prefix[10],
            sample_format=SampleFormat(prefix[11]),
            channel_count=prefix[12],
            rx1_gain_db_start=prefix[13],
            rx2_gain_db_start=prefix[14],
            rx1_gain_db_end=prefix[15],
            rx2_gain_db_end=prefix[16],
            gain_start_read_duration_ns=prefix[18],
            gain_end_read_duration_ns=prefix[19],
            rx1_first_change_sample=prefix[20],
            rx2_first_change_sample=prefix[21],
            rx1_rssi_start_qdb=prefix[22],
            rx2_rssi_start_qdb=prefix[23],
            rx1_rssi_end_qdb=prefix[24],
            rx2_rssi_end_qdb=prefix[25],
            rssi_start_read_duration_ns=prefix[26],
            rssi_end_read_duration_ns=prefix[27],
            gain_observation_interval_samples=interval,
            gain_observation_capacity=obs_capacity,
            gain_event_capacity=event_capacity,
            gain_observation_overflow_count=obs_overflow,
            gain_event_overflow_count=event_overflow,
            gain_observations=observations,
            gain_events=events,
        )
        result._validate()
        return result


@dataclasses.dataclass(frozen=True, slots=True)
class DirectRxFrame:
    metadata: RadioMetadataV3
    iq_payload: bytes


class RxFrameParser:
    """Incremental fail-closed parser for a single ordered protocol-v3 stream."""

    def __init__(self, *, allow_sequence_gaps: bool = False) -> None:
        self.allow_sequence_gaps = allow_sequence_gaps
        self.dropped_frame_count = 0
        self._buffer = bytearray()
        self._stream_id: int | None = None
        self._buffer_sequence: int | None = None
        self._sample_sequence: int | None = None

    def reset(self) -> None:
        self._buffer.clear()
        self._stream_id = self._buffer_sequence = self._sample_sequence = None

    def feed(self, chunk: bytes | bytearray | memoryview) -> list[DirectRxFrame]:
        self._buffer.extend(chunk)
        frames: list[DirectRxFrame] = []
        try:
            while len(self._buffer) >= HEADER_PREFIX_BYTES_V3 + 4:
                magic, version, header_bytes = struct.unpack_from("<IHH", self._buffer)
                if (magic, version) != (
                    MAGIC,
                    VERSION_V3,
                ) or not HEADER_PREFIX_BYTES_V3 + 4 <= header_bytes <= 0xFFFF:
                    raise ProtocolError("bad protocol v3 frame identity or header size")
                if len(self._buffer) < header_bytes:
                    break
                metadata = RadioMetadataV3.unpack(self._buffer[:header_bytes])
                total = header_bytes + metadata.iq_payload_bytes
                if len(self._buffer) < total:
                    break
                self._validate_sequence(metadata)
                frames.append(DirectRxFrame(metadata, bytes(self._buffer[header_bytes:total])))
                del self._buffer[:total]
        except (ProtocolError, ValueError) as exc:
            self.reset()
            if isinstance(exc, ProtocolError):
                raise
            raise ProtocolError(str(exc)) from exc
        return frames

    def parse_complete_frame(self, frame: bytes | bytearray | memoryview) -> DirectRxFrame:
        if self._buffer:
            raise ProtocolError("cannot parse a complete frame with staged bytes")
        view = memoryview(frame)
        try:
            if len(view) < HEADER_PREFIX_BYTES_V3 + 4:
                raise ProtocolError("complete frame is shorter than its header")
            header_bytes = struct.unpack_from("<H", view, 6)[0]
            if len(view) < header_bytes:
                raise ProtocolError("complete frame is shorter than its header")
            metadata = RadioMetadataV3.unpack(view[:header_bytes])
            if len(view) != header_bytes + metadata.iq_payload_bytes:
                raise ProtocolError("complete frame length mismatch")
            self._validate_sequence(metadata)
            return DirectRxFrame(metadata, bytes(view[header_bytes:]))
        except (ProtocolError, ValueError) as exc:
            self.reset()
            if isinstance(exc, ProtocolError):
                raise
            raise ProtocolError(str(exc)) from exc

    def finish(self) -> None:
        if self._buffer:
            count = len(self._buffer)
            self.reset()
            raise ProtocolError(f"stream ended with {count} unframed bytes")

    def _validate_sequence(self, metadata: RadioMetadataV3) -> None:
        if self._stream_id is None:
            if metadata.buffer_sequence:
                raise ProtocolError("new stream must begin at buffer sequence 0")
            self._stream_id = metadata.stream_id
        elif metadata.stream_id != self._stream_id:
            raise ProtocolError("stream ID changed without reset")
        if self._buffer_sequence is not None and metadata.buffer_sequence != self._buffer_sequence:
            skipped = (metadata.buffer_sequence - self._buffer_sequence) & 0xFFFFFFFFFFFFFFFF
            if not self.allow_sequence_gaps or skipped > MAX_FINITE_FRAMES:
                raise ProtocolError("buffer sequence discontinuity")
            self.dropped_frame_count += skipped
        if (
            self._sample_sequence is not None
            and metadata.first_sample_sequence != self._sample_sequence
        ):
            advance = (metadata.first_sample_sequence - self._sample_sequence) & 0xFFFFFFFFFFFFFFFF
            if not self.allow_sequence_gaps or advance % metadata.samples_per_channel:
                raise ProtocolError("sample sequence discontinuity")
        self._buffer_sequence = (metadata.buffer_sequence + 1) & 0xFFFFFFFFFFFFFFFF
        self._sample_sequence = (
            metadata.first_sample_sequence + metadata.samples_per_channel
        ) & 0xFFFFFFFFFFFFFFFF
