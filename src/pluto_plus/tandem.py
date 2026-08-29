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
    GAIN_EVENT_BYTES,
    GAIN_OBSERVATION_BYTES,
    HEADER_PREFIX_BYTES_V3,
    VERSION_V3,
    MetadataFeatures,
    MetadataFlags,
    ProtocolError,
    RadioMetadataV3,
)

TANDEM_REQUEST_MAGIC: Final = 0x54465053
TANDEM_ABI_VERSION: Final = 1
TANDEM_REQUIRED_FEATURES: Final = 0x7
VERSION_V5: Final = 5
VERSION_V6: Final = 6
TANDEM_METADATA_FEATURE: Final = 1 << 8
AD9361_TEMPERATURE_FEATURE: Final = 1 << 9
TANDEM_METADATA_VALID_FLAG: Final = 1 << 22
CANONICAL_RX_LAYOUT_FEATURE: Final = 1 << 10
EXACT_GAP_ACCOUNTING_FEATURE: Final = 1 << 11
SAMPLE_GAP_BEFORE_FLAG: Final = 1 << 23
TANDEM_EVENT_RETENTION_FRAMES: Final = 2
HEADER_EXTENSION_BYTES_V5: Final = 56
HEADER_PREFIX_BYTES_V5: Final = HEADER_PREFIX_BYTES_V3 + HEADER_EXTENSION_BYTES_V5
TEMPERATURE_INVALID: Final = -(1 << 31)

_REQUEST = struct.Struct("<IHHIIIIiiiIIIIII4BII8I")
_IDENTITY = struct.Struct("<IHHII")
_V3_EXTENSION = struct.Struct("<IHHHHHHIIII")
_V5_EXTENSION = struct.Struct("<IIIIIIiiiBBBBi3I")
_EVENT = struct.Struct("<QIHBB")
_LEGACY_EVENT = struct.Struct("<QHHI")


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
    def auto_for_sample_count(cls, samples_per_channel: int) -> TandemSessionRequestV1:
        """Build AUTO settings that cover a refill plus its arm-safety window."""

        if samples_per_channel <= 0:
            raise ValueError("samples_per_channel must be positive")
        request = cls(mode=TandemMode.AUTO)
        events_denominator = request.event_capacity * request.power_measurement_samples
        retention_samples = samples_per_channel * TANDEM_EVENT_RETENTION_FRAMES
        minimum_periods = (retention_samples + events_denominator - 1) // events_denominator
        return dataclasses.replace(
            request,
            cooldown_periods=max(request.cooldown_periods, minimum_periods - 1),
        )

    def pack(self, samples_per_channel: int) -> bytes:
        if not 0 <= self.minimum_gain_db <= self.initial_gain_db <= self.maximum_gain_db <= 62:
            raise ValueError("tandem gains must be ordered within 0..62 dB")
        if not 1 <= self.observation_capacity <= 64 or not 1 <= self.event_capacity <= 64:
            raise ValueError("tandem capacities must be within 1..64")
        if samples_per_channel <= 0:
            raise ValueError("samples_per_channel must be positive")
        minimum_transition_samples = self.power_measurement_samples * (self.cooldown_periods + 1)
        retention_samples = samples_per_channel * TANDEM_EVENT_RETENTION_FRAMES
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
