"""Tandem-AGC request and metadata-v5 protocol primitives.

The layouts mirror the reviewed firmware UAPI and the metadata ABI emitted by
the qualified v6 tandem development profile.  Parsing is deliberately strict:
unknown bits, torn gain pairs, sequence holes, and bad CRCs fail the session.
"""

from __future__ import annotations

import dataclasses
import enum
import struct
import zlib
from typing import Final

from pluto_plus.direct_radio.usb import (
    FIRST_CHANGE_UNAVAILABLE,
    GAIN_DB_INVALID,
    GAIN_EVENT_BYTES,
    GAIN_INDEX_INVALID,
    GAIN_OBSERVATION_BYTES,
    HEADER_PREFIX_BYTES_V3,
    MAX_GAIN_EVENTS,
    MAX_GAIN_OBSERVATIONS,
    RSSI_QDB_INVALID,
    VERSION_V3,
    GainObservationFlags,
    GainObservationV3,
    MetadataFeatures,
    MetadataFlags,
    ProtocolError,
    RadioMetadataV3,
    SampleFormat,
)

TANDEM_REQUEST_MAGIC: Final = 0x54465053
TANDEM_ABI_VERSION: Final = 1
TANDEM_REQUIRED_FEATURES: Final = 0x7
VERSION_V5: Final = 5
VERSION_V6: Final = 6
VERSION_V7: Final = 7
TANDEM_METADATA_FEATURE: Final = 1 << 8
AD9361_TEMPERATURE_FEATURE: Final = 1 << 9
TANDEM_METADATA_VALID_FLAG: Final = 1 << 22
CANONICAL_RX_LAYOUT_FEATURE: Final = 1 << 10
EXACT_GAP_ACCOUNTING_FEATURE: Final = 1 << 11
SAMPLE_GAP_BEFORE_FLAG: Final = 1 << 23
FPGA_GAIN_TIMELINE_FEATURE: Final = 1 << 12
FPGA_GAIN_TIMELINE_VALID_FLAG: Final = 1 << 24
FPGA_GAIN_TIMELINE_COMPLETE: Final = 1 << 0
TANDEM_EVENT_RETENTION_FRAMES: Final = 2
MAX_TANDEM_EVENT_RETENTION_FRAMES: Final = 65
HEADER_EXTENSION_BYTES_V5: Final = 56
HEADER_PREFIX_BYTES_V5: Final = HEADER_PREFIX_BYTES_V3 + HEADER_EXTENSION_BYTES_V5
HEADER_EXTENSION_BYTES_V7: Final = 56
HEADER_PREFIX_BYTES_V7: Final = HEADER_PREFIX_BYTES_V3 + HEADER_EXTENSION_BYTES_V7
TEMPERATURE_INVALID: Final = -(1 << 31)

METADATA_PROVIDER_REQUEST_MAGIC: Final = 0x31524D53
METADATA_PROVIDER_REQUEST_VERSION: Final = 1
METADATA_PROVIDER_REQUEST_BYTES: Final = 32
METADATA_PROVIDER_REQUIRED_FEATURES: Final = 0x0F
METADATA_PROVIDER_RECORD_VERSION: Final = VERSION_V7

_REQUEST = struct.Struct("<IHHIIIIiiiIIIIII4BII8I")
_PROVIDER_REQUEST = struct.Struct("<IHHIHHHHIII")
_IDENTITY = struct.Struct("<IHHII")
_V7_PREFIX = struct.Struct("<IHHIIQQQIIIHBbbbbBIIIIHHHHII")
_V3_EXTENSION = struct.Struct("<IHHHHHHIIII")
_V5_EXTENSION = struct.Struct("<IIIIIIiiiBBBBi3I")
_V7_EXTENSION = struct.Struct("<IIIIIIiiiBBBBiIBBHI")
_EVENT = struct.Struct("<QIHBB")
_LEGACY_EVENT = struct.Struct("<QHHI")

if _REQUEST.size != 104:  # pragma: no cover - frozen wire invariant
    raise RuntimeError("tandem request wire size changed")
if _PROVIDER_REQUEST.size != METADATA_PROVIDER_REQUEST_BYTES:  # pragma: no cover
    raise RuntimeError("metadata provider request wire size changed")
if _V7_PREFIX.size + _V3_EXTENSION.size != HEADER_PREFIX_BYTES_V3:  # pragma: no cover
    raise RuntimeError("metadata v7 base prefix wire size changed")
if _V7_EXTENSION.size != HEADER_EXTENSION_BYTES_V7:  # pragma: no cover
    raise RuntimeError("metadata v7 extension wire size changed")


class TandemMode(enum.IntEnum):
    HOLD = 0
    AUTO = 1


class TandemState(enum.IntEnum):
    IDLE = 0
    VALIDATING = 1
    ARMED_HOLD = 2
    ARMED_AUTO = 3
    FAULTED = 4
    RESTORING = 5


class TandemGainTable(enum.IntEnum):
    MHZ_200_1300 = 1
    MHZ_1300_4000 = 2
    MHZ_4000_6000 = 3


class TandemEventDirection(enum.IntEnum):
    INCREASE = 1
    DECREASE = 2


class MetadataTransportKind(enum.IntEnum):
    ORDINARY = 0
    DDR_BURST = 1
    DDR_RING = 2

    @property
    def trailer_bytes(self) -> int:
        return {
            MetadataTransportKind.ORDINARY: 0,
            MetadataTransportKind.DDR_BURST: 32,
            MetadataTransportKind.DDR_RING: 48,
        }[self]


@dataclasses.dataclass(frozen=True, slots=True)
class TandemSessionRequestV1:
    mode: TandemMode
    observation_capacity: int = 64
    event_capacity: int = 64
    minimum_gain_db: int = 0
    maximum_gain_db: int = 62
    initial_gain_db: int = 30
    power_measurement_samples: int = 1024
    low_power_dwell_periods: int = 3
    cooldown_periods: int = 16
    pulse_high_cycles: int = 4
    pulse_low_cycles: int = 4
    detector_blanking_cycles: int = 8
    low_power_threshold: int = 20
    large_lmt_overload_threshold: int = 58
    large_adc_overload_threshold: int = 49
    small_adc_overload_threshold: int = 48

    @classmethod
    def auto_for_sample_count(
        cls,
        samples_per_channel: int,
        *,
        retention_frames: int = TANDEM_EVENT_RETENTION_FRAMES,
    ) -> TandemSessionRequestV1:
        """Build AUTO settings that cover a refill plus its arm-safety window."""

        if samples_per_channel <= 0:
            raise ValueError("samples_per_channel must be positive")
        _validate_retention_frames(retention_frames)
        request = cls(mode=TandemMode.AUTO)
        events_denominator = request.event_capacity * request.power_measurement_samples
        retention_samples = samples_per_channel * retention_frames
        minimum_periods = (retention_samples + events_denominator - 1) // events_denominator
        return dataclasses.replace(
            request,
            cooldown_periods=max(request.cooldown_periods, minimum_periods - 1),
        )

    def pack(
        self,
        samples_per_channel: int,
        *,
        retention_frames: int = TANDEM_EVENT_RETENTION_FRAMES,
    ) -> bytes:
        if not 0 <= self.minimum_gain_db <= self.initial_gain_db <= self.maximum_gain_db <= 62:
            raise ValueError("tandem gains must be ordered within 0..62 dB")
        if not 1 <= self.observation_capacity <= 64 or not 1 <= self.event_capacity <= 64:
            raise ValueError("tandem capacities must be within 1..64")
        if samples_per_channel <= 0:
            raise ValueError("samples_per_channel must be positive")
        _validate_retention_frames(retention_frames)
        minimum_transition_samples = self.power_measurement_samples * (self.cooldown_periods + 1)
        retention_samples = samples_per_channel * retention_frames
        maximum_retained_events = (
            0
            if self.mode is TandemMode.HOLD
            else 1 + (retention_samples - 1) // minimum_transition_samples
        )
        if maximum_retained_events > self.event_capacity:
            raise ValueError("event capacity cannot cover the worst-case AUTO arm window")
        byte_values = (
            self.low_power_threshold,
            self.large_lmt_overload_threshold,
            self.large_adc_overload_threshold,
            self.small_adc_overload_threshold,
        )
        if any(not 0 <= value <= 0xFF for value in byte_values):
            raise ValueError("detector thresholds must fit uint8")
        return _REQUEST.pack(
            TANDEM_REQUEST_MAGIC,
            TANDEM_ABI_VERSION,
            _REQUEST.size,
            TANDEM_REQUIRED_FEATURES,
            int(self.mode),
            self.observation_capacity,
            self.event_capacity,
            self.minimum_gain_db,
            self.maximum_gain_db,
            self.initial_gain_db,
            self.power_measurement_samples,
            self.low_power_dwell_periods,
            self.cooldown_periods,
            self.pulse_high_cycles,
            self.pulse_low_cycles,
            self.detector_blanking_cycles,
            *byte_values,
            0,
            0,
            *([0] * 8),
        )


def pack_metadata_provider_request_v1(
    tandem_request: TandemSessionRequestV1,
    samples_per_channel: int,
    *,
    transport_kind: MetadataTransportKind,
    retention_frames: int,
) -> bytes:
    """Wrap one tandem request in the exact ABI-4 provider envelope.

    The native libiio provider appends the selected transport trailer after
    this envelope and its embedded tandem request. The header therefore
    declares, but does not contain, those trailer bytes.
    """

    if not isinstance(transport_kind, MetadataTransportKind):
        raise TypeError("metadata transport kind must be a MetadataTransportKind")
    tandem = tandem_request.pack(
        samples_per_channel,
        retention_frames=retention_frames,
    )
    if len(tandem) != _REQUEST.size:  # pragma: no cover - pack() is fixed-size
        raise ProtocolError("tandem request has the wrong provider-envelope size")
    header = _PROVIDER_REQUEST.pack(
        METADATA_PROVIDER_REQUEST_MAGIC,
        METADATA_PROVIDER_REQUEST_VERSION,
        METADATA_PROVIDER_REQUEST_BYTES,
        METADATA_PROVIDER_REQUIRED_FEATURES,
        METADATA_PROVIDER_RECORD_VERSION,
        int(transport_kind),
        len(tandem),
        transport_kind.trailer_bytes,
        0,
        0,
        0,
    )
    return header + tandem


def _validate_retention_frames(retention_frames: int) -> None:
    if (
        isinstance(retention_frames, bool)
        or not isinstance(retention_frames, int)
        or not 1 <= retention_frames <= MAX_TANDEM_EVENT_RETENTION_FRAMES
    ):
        raise ValueError(
            "tandem event retention frames must be an integer between 1 and "
            f"{MAX_TANDEM_EVENT_RETENTION_FRAMES}"
        )


@dataclasses.dataclass(frozen=True, slots=True)
class TandemGainEventV1:
    sample_sequence: int
    event_sequence: int
    flags: int
    rx1_gain_index: int
    rx2_gain_index: int

    @property
    def direction(self) -> TandemEventDirection:
        return TandemEventDirection((self.flags >> 4) & 0x3)

    @classmethod
    def unpack(cls, payload: bytes) -> TandemGainEventV1:
        if len(payload) != _EVENT.size:
            raise ProtocolError("tandem event record has the wrong size")
        event = cls(*_EVENT.unpack(payload))
        if event.flags & 0xFFC0:
            raise ProtocolError("tandem event has unknown flag bits")
        try:
            _ = event.direction
        except ValueError as error:
            raise ProtocolError("tandem event direction is invalid") from error
        if event.rx1_gain_index != event.rx2_gain_index or event.rx1_gain_index > 0x7F:
            raise ProtocolError("tandem event gain pair is invalid")
        return event


@dataclasses.dataclass(frozen=True, slots=True)
class RadioMetadataV5:
    base: RadioMetadataV3
    header_bytes: int
    ownership_epoch: int
    tandem_state: TandemState
    tandem_fault_flags: int
    tandem_transition_count: int
    gain_table_id: TandemGainTable
    threshold_provenance: int
    minimum_gain_db: int
    maximum_gain_db: int
    initial_gain_db: int
    minimum_gain_index: int
    maximum_gain_index: int
    rx1_gain_index: int
    rx2_gain_index: int
    ad9361_temperature_mdeg_c: int | None
    gain_events: tuple[TandemGainEventV1, ...]

    @classmethod
    def unpack(cls, header: bytes | bytearray | memoryview) -> RadioMetadataV5:
        raw = bytes(header)
        if len(raw) < HEADER_PREFIX_BYTES_V5 + 4:
            raise ProtocolError("short protocol v5 metadata header")
        magic, version, header_bytes, features, flags = _IDENTITY.unpack_from(raw)
        if (magic, version) != (0x314D4753, VERSION_V5) or len(raw) != header_bytes:
            raise ProtocolError("bad protocol v5 identity or length")
        if not features & TANDEM_METADATA_FEATURE or not features & int(
            MetadataFeatures.FPGA_GAIN_EVENTS
        ):
            raise ProtocolError("protocol v5 lacks tandem event features")
        if not features & AD9361_TEMPERATURE_FEATURE:
            raise ProtocolError("protocol v5 lacks AD9361 temperature support")
        if not flags & TANDEM_METADATA_VALID_FLAG:
            raise ProtocolError("protocol v5 tandem metadata is invalid")
        scratch = bytearray(raw)
        received_crc = struct.unpack_from("<I", scratch, header_bytes - 4)[0]
        scratch[-4:] = bytes(4)
        if received_crc != zlib.crc32(scratch) & 0xFFFFFFFF:
            raise ProtocolError("protocol v5 metadata CRC mismatch")

        v3_extension = _V3_EXTENSION.unpack_from(raw, 92)
        observation_count = v3_extension[1]
        observation_capacity = v3_extension[2]
        observation_bytes = v3_extension[3]
        event_count = v3_extension[4]
        event_capacity = v3_extension[5]
        event_bytes = v3_extension[6]
        expected = (
            HEADER_PREFIX_BYTES_V5
            + observation_capacity * observation_bytes
            + event_capacity * event_bytes
            + 4
        )
        if header_bytes != expected or observation_count > observation_capacity:
            raise ProtocolError("protocol v5 capacities disagree with its header")
        if event_count > event_capacity or observation_bytes != GAIN_OBSERVATION_BYTES:
            raise ProtocolError("protocol v5 record capacity is invalid")
        if event_bytes != GAIN_EVENT_BYTES:
            raise ProtocolError("protocol v5 event size is unsupported")

        extension = _V5_EXTENSION.unpack_from(raw, HEADER_PREFIX_BYTES_V3)
        if any(extension[-3:]):
            raise ProtocolError("protocol v5 reserved fields are nonzero")
        (
            ownership_epoch,
            tandem_state,
            fault_flags,
            transition_count,
            gain_table,
            threshold_provenance,
            minimum_gain_db,
            maximum_gain_db,
            initial_gain_db,
            minimum_gain_index,
            maximum_gain_index,
            rx1_gain_index,
            rx2_gain_index,
            temperature_mdeg_c,
            *_reserved,
        ) = extension
        try:
            state = TandemState(tandem_state)
            parsed_gain_table = TandemGainTable(gain_table)
        except ValueError as error:
            raise ProtocolError("unknown tandem state or gain table") from error
        if (
            not ownership_epoch
            or fault_flags
            or state
            not in {
                TandemState.ARMED_HOLD,
                TandemState.ARMED_AUTO,
            }
        ):
            raise ProtocolError("tandem lease is not valid and armed")
        if rx1_gain_index != rx2_gain_index:
            raise ProtocolError("tandem endpoint gains are not paired")

        arrays = raw[HEADER_PREFIX_BYTES_V5:header_bytes]
        event_offset = observation_capacity * observation_bytes
        events: list[TandemGainEventV1] = []
        for index in range(event_count):
            offset = event_offset + index * event_bytes
            event = TandemGainEventV1.unpack(arrays[offset : offset + event_bytes])
            if events and event.event_sequence != (events[-1].event_sequence + 1) & 0xFFFFFFFF:
                raise ProtocolError("tandem event sequence has a hole")
            if events and event.sample_sequence < events[-1].sample_sequence:
                raise ProtocolError("tandem events are not sample ordered")
            events.append(event)
        if any(
            arrays[
                event_offset + event_count * event_bytes : event_offset
                + event_capacity * event_bytes
            ]
        ):
            raise ProtocolError("unused tandem event records are nonzero")

        synthetic = bytearray(raw[:HEADER_PREFIX_BYTES_V3])
        struct.pack_into("<H", synthetic, 4, VERSION_V3)
        struct.pack_into("<H", synthetic, 6, header_bytes - HEADER_EXTENSION_BYTES_V5)
        struct.pack_into(
            "<I",
            synthetic,
            8,
            features & ~(TANDEM_METADATA_FEATURE | AD9361_TEMPERATURE_FEATURE),
        )
        struct.pack_into("<I", synthetic, 12, flags & ~TANDEM_METADATA_VALID_FLAG)
        synthetic.extend(arrays)
        synthetic_event_offset = HEADER_PREFIX_BYTES_V3 + event_offset
        for index, event in enumerate(events):
            _LEGACY_EVENT.pack_into(
                synthetic,
                synthetic_event_offset + index * GAIN_EVENT_BYTES,
                event.sample_sequence,
                3,
                0,
                0,
            )
        synthetic[-4:] = bytes(4)
        struct.pack_into("<I", synthetic, len(synthetic) - 4, zlib.crc32(synthetic))
        base = RadioMetadataV3.unpack(synthetic)
        frame_end = base.first_sample_sequence + base.samples_per_channel
        if any(
            not base.first_sample_sequence <= event.sample_sequence < frame_end for event in events
        ):
            raise ProtocolError("tandem event lies outside its IQ frame")
        return cls(
            base,
            header_bytes,
            ownership_epoch,
            state,
            fault_flags,
            transition_count,
            parsed_gain_table,
            threshold_provenance,
            minimum_gain_db,
            maximum_gain_db,
            initial_gain_db,
            minimum_gain_index,
            maximum_gain_index,
            rx1_gain_index,
            rx2_gain_index,
            None if temperature_mdeg_c == TEMPERATURE_INVALID else temperature_mdeg_c,
            tuple(events),
        )


@dataclasses.dataclass(frozen=True, slots=True)
class RadioMetadataV6:
    """ABI3 tandem metadata with canonical variable RX layout and exact gaps."""

    base: RadioMetadataV3
    tandem: RadioMetadataV5
    header_bytes: int
    missing_samples_before: int

    @classmethod
    def unpack(cls, header: bytes | bytearray | memoryview) -> RadioMetadataV6:
        raw = bytes(header)
        if len(raw) < HEADER_PREFIX_BYTES_V5 + 4:
            raise ProtocolError("short protocol v6 metadata header")
        magic, version, header_bytes, features, flags = _IDENTITY.unpack_from(raw)
        if (magic, version) != (0x314D4753, VERSION_V6) or len(raw) != header_bytes:
            raise ProtocolError("bad protocol v6 identity or length")
        required_features = (
            0xFF
            | TANDEM_METADATA_FEATURE
            | AD9361_TEMPERATURE_FEATURE
            | CANONICAL_RX_LAYOUT_FEATURE
            | EXACT_GAP_ACCOUNTING_FEATURE
        )
        if features != required_features:
            raise ProtocolError("protocol v6 feature set is not canonical")
        if flags & ~((1 << 24) - 1) or not flags & TANDEM_METADATA_VALID_FLAG:
            raise ProtocolError("protocol v6 flags are invalid")

        scratch = bytearray(raw)
        received_crc = struct.unpack_from("<I", scratch, header_bytes - 4)[0]
        scratch[-4:] = bytes(4)
        if received_crc != zlib.crc32(scratch) & 0xFFFFFFFF:
            raise ProtocolError("protocol v6 metadata CRC mismatch")

        samples_per_channel = struct.unpack_from("<I", raw, 40)[0]
        iq_payload_bytes = struct.unpack_from("<I", raw, 44)[0]
        enabled_scan_mask = struct.unpack_from("<I", raw, 48)[0]
        channel_count = raw[54]
        if enabled_scan_mask in {0x03, 0x0C}:
            expected_channels = 1
            bytes_per_sample = 4
            if samples_per_channel & 1:
                raise ProtocolError("protocol v6 single-RX sample count must be even")
        elif enabled_scan_mask == 0x0F:
            expected_channels = 2
            bytes_per_sample = 8
        else:
            raise ProtocolError("protocol v6 scan mask is not canonical")
        if (
            channel_count != expected_channels
            or not samples_per_channel
            or iq_payload_bytes != samples_per_channel * bytes_per_sample
        ):
            raise ProtocolError("protocol v6 RX geometry is inconsistent")

        v3_extension = _V3_EXTENSION.unpack_from(raw, 92)
        missing_samples_before = v3_extension[-2] | (v3_extension[-1] << 32)
        if bool(flags & SAMPLE_GAP_BEFORE_FLAG) != bool(missing_samples_before):
            raise ProtocolError("protocol v6 gap flag and exact count disagree")

        synthetic = bytearray(raw)
        struct.pack_into("<H", synthetic, 4, VERSION_V5)
        struct.pack_into(
            "<I",
            synthetic,
            8,
            features & ~(CANONICAL_RX_LAYOUT_FEATURE | EXACT_GAP_ACCOUNTING_FEATURE),
        )
        struct.pack_into("<I", synthetic, 12, flags & ~SAMPLE_GAP_BEFORE_FLAG)
        struct.pack_into("<II", synthetic, 116, 0, 0)
        if channel_count == 1:
            struct.pack_into("<I", synthetic, 44, samples_per_channel * 8)
            struct.pack_into("<I", synthetic, 48, 0x0F)
            synthetic[54] = 2
        synthetic[-4:] = bytes(4)
        struct.pack_into("<I", synthetic, len(synthetic) - 4, zlib.crc32(synthetic))
        tandem = RadioMetadataV5.unpack(synthetic)
        base = dataclasses.replace(
            tandem.base,
            features=MetadataFeatures(
                features & ~(TANDEM_METADATA_FEATURE | AD9361_TEMPERATURE_FEATURE)
            ),
            flags=MetadataFlags(flags & ~TANDEM_METADATA_VALID_FLAG),
            iq_payload_bytes=iq_payload_bytes,
            enabled_scan_mask=enabled_scan_mask,
            channel_count=channel_count,
        )
        return cls(base, tandem, header_bytes, missing_samples_before)


@dataclasses.dataclass(frozen=True, slots=True)
class RadioMetadataV7:
    """ABI-4 metadata with an FPGA-authoritative per-frame gain timeline.

    This is intentionally a standalone parser. In particular, it never
    weakens or routes through the SPI-observation requirements of protocol
    v3/v5/v6.
    """

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
    rx1_gain_db_start: int
    rx2_gain_db_start: int
    rx1_gain_db_end: int
    rx2_gain_db_end: int
    gain_start_read_duration_ns: int
    gain_end_read_duration_ns: int
    rx1_first_change_sample: int
    rx2_first_change_sample: int
    rx1_rssi_start_qdb: int
    rx2_rssi_start_qdb: int
    rx1_rssi_end_qdb: int
    rx2_rssi_end_qdb: int
    rssi_start_read_duration_ns: int
    rssi_end_read_duration_ns: int
    gain_observation_interval_samples: int
    gain_observation_capacity: int
    gain_event_capacity: int
    gain_observation_overflow_count: int
    gain_event_overflow_count: int
    gain_observations: tuple[GainObservationV3, ...]
    gain_events: tuple[TandemGainEventV1, ...]
    header_bytes: int
    missing_samples_before: int
    ownership_epoch: int
    tandem_state: TandemState
    tandem_fault_flags: int
    tandem_transition_count_start: int
    tandem_transition_count: int
    gain_table_id: TandemGainTable
    threshold_provenance: int
    minimum_gain_db: int
    maximum_gain_db: int
    initial_gain_db: int
    minimum_gain_index: int
    maximum_gain_index: int
    rx1_gain_index_start: int
    rx2_gain_index_start: int
    rx1_gain_index: int
    rx2_gain_index: int
    ad9361_temperature_mdeg_c: int | None
    timeline_flags: int
    event_sequence_start: int

    @property
    def base(self) -> RadioMetadataV7:
        """Expose the frame fields through the established tandem interface."""

        return self

    @classmethod
    def unpack(cls, header: bytes | bytearray | memoryview) -> RadioMetadataV7:
        raw = bytes(header)
        if len(raw) < HEADER_PREFIX_BYTES_V7 + 4:
            raise ProtocolError("short protocol v7 metadata header")
        prefix = _V7_PREFIX.unpack_from(raw)
        magic, version, header_bytes, features_value, flags_value = prefix[:5]
        if (
            (magic, version) != (0x314D4753, VERSION_V7)
            or len(raw) != header_bytes
            or prefix[17]
        ):
            raise ProtocolError("bad protocol v7 identity or length")
        required_features = (
            0xFF
            | TANDEM_METADATA_FEATURE
            | AD9361_TEMPERATURE_FEATURE
            | CANONICAL_RX_LAYOUT_FEATURE
            | EXACT_GAP_ACCOUNTING_FEATURE
            | FPGA_GAIN_TIMELINE_FEATURE
        )
        if features_value != required_features:
            raise ProtocolError("protocol v7 feature set is not canonical")
        if flags_value & ~((1 << 25) - 1):
            raise ProtocolError("protocol v7 has unknown flag bits")
        flags = MetadataFlags(flags_value)
        required_flags = (
            MetadataFlags.START_VALID
            | MetadataFlags.END_VALID
            | MetadataFlags.SAMPLE_SEQUENCE_VALID
            | MetadataFlags.GAIN_FULL_TABLE_MODE
            | MetadataFlags.GAIN_DB_VALUES
            | MetadataFlags.HARDWARE_SAMPLE_COUNTER_VALID
            | MetadataFlags(TANDEM_METADATA_VALID_FLAG)
            | MetadataFlags(FPGA_GAIN_TIMELINE_VALID_FLAG)
        )
        if flags & required_flags != required_flags:
            raise ProtocolError("protocol v7 lacks required frame/timeline validity flags")
        if flags & MetadataFlags.DUMMY_GAINS:
            raise ProtocolError("protocol v7 cannot use dummy gains")
        if flags & (MetadataFlags.RX1_LOCKED_AT_END | MetadataFlags.RX2_LOCKED_AT_END):
            raise ProtocolError("protocol v7 cannot claim legacy endpoint lock flags")

        scratch = bytearray(raw)
        received_crc = struct.unpack_from("<I", scratch, header_bytes - 4)[0]
        scratch[-4:] = bytes(4)
        if received_crc != zlib.crc32(scratch) & 0xFFFFFFFF:
            raise ProtocolError("protocol v7 metadata CRC mismatch")

        stream_id = prefix[5]
        samples_per_channel = prefix[8]
        iq_payload_bytes = prefix[9]
        enabled_scan_mask = prefix[10]
        try:
            sample_format = SampleFormat(prefix[11])
        except ValueError as error:
            raise ProtocolError("protocol v7 sample format is unknown") from error
        channel_count = prefix[12]
        if not stream_id or not samples_per_channel:
            raise ProtocolError("protocol v7 stream and sample counts must be non-zero")
        if sample_format is not SampleFormat.CS16_LE_TIME_INTERLEAVED:
            raise ProtocolError("protocol v7 sample format is not canonical CI16")
        if enabled_scan_mask in {0x03, 0x0C}:
            expected_channels = 1
            bytes_per_sample = 4
            if samples_per_channel & 1:
                raise ProtocolError("protocol v7 single-RX sample count must be even")
        elif enabled_scan_mask == 0x0F:
            expected_channels = 2
            bytes_per_sample = 8
        else:
            raise ProtocolError("protocol v7 scan mask is not canonical")
        if (
            channel_count != expected_channels
            or iq_payload_bytes != samples_per_channel * bytes_per_sample
        ):
            raise ProtocolError("protocol v7 RX geometry is inconsistent")

        extension = _V3_EXTENSION.unpack_from(raw, _V7_PREFIX.size)
        (
            observation_interval,
            observation_count,
            observation_capacity,
            observation_bytes,
            event_count,
            event_capacity,
            event_bytes,
            observation_overflow_count,
            event_overflow_count,
            missing_low,
            missing_high,
        ) = extension
        if (
            not 1 <= observation_interval <= samples_per_channel
            or not 1 <= observation_capacity <= MAX_GAIN_OBSERVATIONS
            or observation_count > observation_capacity
            or observation_bytes != GAIN_OBSERVATION_BYTES
            or not 1 <= event_capacity <= MAX_GAIN_EVENTS
            or event_count > event_capacity
            or event_bytes != GAIN_EVENT_BYTES
        ):
            raise ProtocolError("protocol v7 variable-record geometry is invalid")
        expected_header_bytes = (
            HEADER_PREFIX_BYTES_V7
            + observation_capacity * observation_bytes
            + event_capacity * event_bytes
            + 4
        )
        if header_bytes != expected_header_bytes:
            raise ProtocolError("protocol v7 capacities disagree with its header")
        missing_samples_before = missing_low | (missing_high << 32)
        if bool(flags & MetadataFlags.SAMPLE_GAP_BEFORE) != bool(missing_samples_before):
            raise ProtocolError("protocol v7 gap flag and exact count disagree")
        if bool(flags & MetadataFlags.DEVICE_IIO_OVERFLOW) != bool(missing_samples_before):
            raise ProtocolError("protocol v7 overflow flag and exact gap count disagree")
        if bool(flags & MetadataFlags.GAIN_OBSERVATION_OVERFLOW) != bool(
            observation_overflow_count
        ):
            raise ProtocolError("protocol v7 observation overflow flag/count disagree")
        if event_overflow_count or flags & MetadataFlags.FPGA_EVENT_OVERFLOW:
            raise ProtocolError("protocol v7 FPGA gain-event FIFO overflowed")
        if bool(flags & MetadataFlags.FPGA_EVENTS_VALID) != bool(event_count):
            raise ProtocolError("protocol v7 FPGA-event validity disagrees with its records")

        v7 = _V7_EXTENSION.unpack_from(raw, HEADER_PREFIX_BYTES_V3)
        (
            ownership_epoch,
            tandem_state_value,
            tandem_fault_flags,
            transition_count_end,
            gain_table_value,
            threshold_provenance,
            minimum_gain_db,
            maximum_gain_db,
            initial_gain_db,
            minimum_gain_index,
            maximum_gain_index,
            end_rx1_gain_index,
            end_rx2_gain_index,
            temperature_mdeg_c,
            transition_count_start,
            start_rx1_gain_index,
            start_rx2_gain_index,
            timeline_flags,
            event_sequence_start,
        ) = v7
        try:
            tandem_state = TandemState(tandem_state_value)
            gain_table = TandemGainTable(gain_table_value)
        except ValueError as error:
            raise ProtocolError("protocol v7 tandem state or gain table is unknown") from error
        if (
            not ownership_epoch
            or tandem_fault_flags
            or tandem_state not in {TandemState.ARMED_HOLD, TandemState.ARMED_AUTO}
        ):
            raise ProtocolError("protocol v7 tandem lease is not valid and armed")
        if timeline_flags != FPGA_GAIN_TIMELINE_COMPLETE:
            raise ProtocolError("protocol v7 gain timeline is incomplete or has unknown flags")
        if not 0 <= minimum_gain_db <= initial_gain_db <= maximum_gain_db <= 62:
            raise ProtocolError("protocol v7 gain limits are invalid")
        indices = (
            start_rx1_gain_index,
            start_rx2_gain_index,
            end_rx1_gain_index,
            end_rx2_gain_index,
        )
        if (
            start_rx1_gain_index != start_rx2_gain_index
            or end_rx1_gain_index != end_rx2_gain_index
            or any(value == GAIN_INDEX_INVALID for value in indices)
            or not 0 <= minimum_gain_index <= maximum_gain_index <= 0x7F
            or any(not minimum_gain_index <= value <= maximum_gain_index for value in indices)
        ):
            raise ProtocolError("protocol v7 authoritative gain endpoints are invalid")
        gain_db_endpoints = prefix[13:17]
        if (
            gain_db_endpoints[0] != gain_db_endpoints[1]
            or gain_db_endpoints[2] != gain_db_endpoints[3]
            or any(value == GAIN_DB_INVALID for value in gain_db_endpoints)
            or any(not minimum_gain_db <= value <= maximum_gain_db for value in gain_db_endpoints)
        ):
            raise ProtocolError("protocol v7 gain-dB endpoints are invalid")

        records = raw[HEADER_PREFIX_BYTES_V7 : header_bytes - 4]
        observation_region_bytes = observation_capacity * observation_bytes
        observations = tuple(
            GainObservationV3.unpack(
                records[index * observation_bytes : (index + 1) * observation_bytes]
            )
            for index in range(observation_count)
        )
        if any(records[observation_count * observation_bytes : observation_region_bytes]):
            raise ProtocolError("unused protocol v7 observation records are nonzero")
        observations_valid = bool(flags & MetadataFlags.GAIN_OBSERVATIONS_VALID)
        gain_read_failed = bool(flags & MetadataFlags.GAIN_READ_FAILED)
        if bool(observations) != observations_valid or gain_read_failed == observations_valid:
            raise ProtocolError("protocol v7 SPI-observation availability flags disagree")
        if not observations_valid and (prefix[18] or prefix[19]):
            raise ProtocolError("protocol v7 unavailable SPI observations have read durations")
        frame_end = prefix[7] + samples_per_channel
        previous_observation_before = -1
        previous_observation_after = -1
        for observation in observations:
            required_observation_flags = (
                GainObservationFlags.VALID
                | GainObservationFlags.SAMPLE_INTERVAL_VALID
            )
            if observation.flags != required_observation_flags:
                raise ProtocolError("protocol v7 valid SPI observation is incomplete")
            if (
                observation.sample_sequence_before < previous_observation_before
                or observation.sample_sequence_after < previous_observation_after
            ):
                raise ProtocolError("protocol v7 SPI observations are not ordered")
            previous_observation_before = observation.sample_sequence_before
            previous_observation_after = observation.sample_sequence_after
            if not (
                observation.sample_sequence_after >= prefix[7]
                and observation.sample_sequence_before < frame_end
            ):
                raise ProtocolError("protocol v7 SPI observation does not overlap its frame")

        event_region = records[observation_region_bytes:]
        events = tuple(
            TandemGainEventV1.unpack(
                event_region[index * event_bytes : (index + 1) * event_bytes]
            )
            for index in range(event_count)
        )
        if any(event_region[event_count * event_bytes : event_capacity * event_bytes]):
            raise ProtocolError("unused protocol v7 gain-event records are nonzero")
        expected_transition_end = (transition_count_start + event_count) & 0xFFFFFFFF
        if transition_count_end != expected_transition_end:
            raise ProtocolError("protocol v7 transition-count delta disagrees with events")
        frame_start_event_count = 0
        for event in events:
            if event.sample_sequence != prefix[7]:
                break
            frame_start_event_count += 1
        if frame_start_event_count and (
            events[frame_start_event_count - 1].rx1_gain_index != start_rx1_gain_index
        ):
            raise ProtocolError(
                "protocol v7 frame-start event result disagrees with start endpoint"
            )
        current_gain = start_rx1_gain_index
        prior_sample = -1
        for index, event in enumerate(events):
            if event.event_sequence != (event_sequence_start + index) & 0xFFFFFFFF:
                raise ProtocolError("protocol v7 gain-event sequence has a hole")
            if (
                not prefix[7] <= event.sample_sequence < frame_end
                or event.sample_sequence < prior_sample
            ):
                raise ProtocolError("protocol v7 gain events are unordered or outside the frame")
            if (event.flags & 0x0F) > 6:
                raise ProtocolError("protocol v7 gain-event reason is invalid")
            if not minimum_gain_index <= event.rx1_gain_index <= maximum_gain_index:
                raise ProtocolError("protocol v7 gain-event result is outside gain limits")
            if index >= frame_start_event_count:
                if event.direction is TandemEventDirection.INCREASE:
                    direction_matches = event.rx1_gain_index > current_gain
                else:
                    direction_matches = event.rx1_gain_index < current_gain
                if not direction_matches:
                    raise ProtocolError(
                        "protocol v7 gain-event result contradicts its direction"
                    )
                current_gain = event.rx1_gain_index
            prior_sample = event.sample_sequence
        if current_gain != end_rx1_gain_index:
            raise ProtocolError("protocol v7 final event result disagrees with endpoint gain")
        if tandem_state is TandemState.ARMED_HOLD and events:
            raise ProtocolError("protocol v7 HOLD timeline contains a gain transition")
        first_change = (
            FIRST_CHANGE_UNAVAILABLE
            if not events
            else events[0].sample_sequence - prefix[7]
        )
        if prefix[20] != first_change or prefix[21] != first_change:
            raise ProtocolError("protocol v7 first-change offsets disagree with its timeline")
        endpoint_changed = start_rx1_gain_index != end_rx1_gain_index
        for flag in (MetadataFlags.RX1_ENDPOINT_CHANGED, MetadataFlags.RX2_ENDPOINT_CHANGED):
            if bool(flags & flag) != endpoint_changed:
                raise ProtocolError("protocol v7 endpoint-change flags disagree with its timeline")
        for flag in (MetadataFlags.RX1_CHANGED_IN_BUFFER, MetadataFlags.RX2_CHANGED_IN_BUFFER):
            if bool(flags & flag) != bool(events):
                raise ProtocolError("protocol v7 in-buffer-change flags disagree with its timeline")

        rssi_start_valid = bool(flags & MetadataFlags.RSSI_START_VALID)
        rssi_end_valid = bool(flags & MetadataFlags.RSSI_END_VALID)
        start_rssi = prefix[22:24]
        end_rssi = prefix[24:26]
        if (
            rssi_start_valid and any(value == RSSI_QDB_INVALID for value in start_rssi)
        ) or (
            not rssi_start_valid and any(value != RSSI_QDB_INVALID for value in start_rssi)
        ):
            raise ProtocolError("protocol v7 start-RSSI validity disagrees with its values")
        if (
            rssi_end_valid and any(value == RSSI_QDB_INVALID for value in end_rssi)
        ) or (
            not rssi_end_valid and any(value != RSSI_QDB_INVALID for value in end_rssi)
        ):
            raise ProtocolError("protocol v7 end-RSSI validity disagrees with its values")
        if bool(flags & MetadataFlags.RSSI_READ_FAILED) != (
            not (rssi_start_valid and rssi_end_valid)
        ):
            raise ProtocolError("protocol v7 RSSI availability flags disagree")
        if (not rssi_start_valid and prefix[26]) or (not rssi_end_valid and prefix[27]):
            raise ProtocolError("protocol v7 unavailable RSSI has a read duration")

        return cls(
            features=MetadataFeatures(features_value),
            flags=flags,
            stream_id=stream_id,
            buffer_sequence=prefix[6],
            first_sample_sequence=prefix[7],
            samples_per_channel=samples_per_channel,
            iq_payload_bytes=iq_payload_bytes,
            enabled_scan_mask=enabled_scan_mask,
            sample_format=sample_format,
            channel_count=channel_count,
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
            gain_observation_interval_samples=observation_interval,
            gain_observation_capacity=observation_capacity,
            gain_event_capacity=event_capacity,
            gain_observation_overflow_count=observation_overflow_count,
            gain_event_overflow_count=event_overflow_count,
            gain_observations=observations,
            gain_events=events,
            header_bytes=header_bytes,
            missing_samples_before=missing_samples_before,
            ownership_epoch=ownership_epoch,
            tandem_state=tandem_state,
            tandem_fault_flags=tandem_fault_flags,
            tandem_transition_count_start=transition_count_start,
            tandem_transition_count=transition_count_end,
            gain_table_id=gain_table,
            threshold_provenance=threshold_provenance,
            minimum_gain_db=minimum_gain_db,
            maximum_gain_db=maximum_gain_db,
            initial_gain_db=initial_gain_db,
            minimum_gain_index=minimum_gain_index,
            maximum_gain_index=maximum_gain_index,
            rx1_gain_index_start=start_rx1_gain_index,
            rx2_gain_index_start=start_rx2_gain_index,
            rx1_gain_index=end_rx1_gain_index,
            rx2_gain_index=end_rx2_gain_index,
            ad9361_temperature_mdeg_c=(
                None if temperature_mdeg_c == TEMPERATURE_INVALID else temperature_mdeg_c
            ),
            timeline_flags=timeline_flags,
            event_sequence_start=event_sequence_start,
        )
