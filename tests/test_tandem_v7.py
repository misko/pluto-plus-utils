from __future__ import annotations

import hashlib
import struct
import zlib

import pytest

from pluto_plus.direct_radio.usb import (
    FIRST_CHANGE_UNAVAILABLE,
    MetadataFeatures,
    MetadataFlags,
    ProtocolError,
)
from pluto_plus.tandem import (
    AD9361_TEMPERATURE_FEATURE,
    CANONICAL_RX_LAYOUT_FEATURE,
    EXACT_GAP_ACCOUNTING_FEATURE,
    FPGA_GAIN_TIMELINE_COMPLETE,
    FPGA_GAIN_TIMELINE_FEATURE,
    FPGA_GAIN_TIMELINE_VALID_FLAG,
    HEADER_PREFIX_BYTES_V7,
    METADATA_PROVIDER_RECORD_VERSION,
    METADATA_PROVIDER_REQUEST_BYTES,
    METADATA_PROVIDER_REQUEST_MAGIC,
    METADATA_PROVIDER_REQUEST_VERSION,
    METADATA_PROVIDER_REQUIRED_FEATURES,
    TANDEM_METADATA_FEATURE,
    TANDEM_METADATA_VALID_FLAG,
    MetadataTransportKind,
    RadioMetadataV7,
    TandemMode,
    TandemSessionRequestV1,
    TandemState,
    pack_metadata_provider_request_v1,
)

_PREFIX = struct.Struct("<IHHIIQQQIIIHBbbbbBIIIIHHHHII")
_V3_EXTENSION = struct.Struct("<IHHHHHHIIII")
_V7_EXTENSION = struct.Struct("<IIIIIIiiiBBBBiIBBHI")
_OBSERVATION = struct.Struct("<QQIHBBbbHI")
_EVENT = struct.Struct("<QIHBB")
_PROVIDER = struct.Struct("<IHHIHHHHIII")


def _metadata_v7(
    *,
    with_event: bool = False,
    event_at_start: bool = False,
    with_observation: bool = False,
) -> bytes:
    frame_start = 1_000
    samples = 4
    event_count = int(with_event)
    start_index = 20
    end_index = 21 if with_event else start_index
    serialized_start_index = end_index if event_at_start else start_index
    first_change = 0 if event_at_start else 2 if with_event else FIRST_CHANGE_UNAVAILABLE
    flags = (
        MetadataFlags.START_VALID
        | MetadataFlags.END_VALID
        | MetadataFlags.SAMPLE_SEQUENCE_VALID
        | MetadataFlags.GAIN_FULL_TABLE_MODE
        | MetadataFlags.RSSI_READ_FAILED
        | MetadataFlags.GAIN_DB_VALUES
        | MetadataFlags.HARDWARE_SAMPLE_COUNTER_VALID
        | MetadataFlags(TANDEM_METADATA_VALID_FLAG)
        | MetadataFlags(FPGA_GAIN_TIMELINE_VALID_FLAG)
    )
    flags |= (
        MetadataFlags.GAIN_OBSERVATIONS_VALID
        if with_observation
        else MetadataFlags.GAIN_READ_FAILED
    )
    if with_event:
        flags |= (
            MetadataFlags.FPGA_EVENTS_VALID
            | MetadataFlags.RX1_CHANGED_IN_BUFFER
            | MetadataFlags.RX2_CHANGED_IN_BUFFER
        )
        if not event_at_start:
            flags |= (
                MetadataFlags.RX1_ENDPOINT_CHANGED
                | MetadataFlags.RX2_ENDPOINT_CHANGED
            )
    features = (
        MetadataFeatures(0xFF)
        | MetadataFeatures(TANDEM_METADATA_FEATURE)
        | MetadataFeatures(AD9361_TEMPERATURE_FEATURE)
        | MetadataFeatures(CANONICAL_RX_LAYOUT_FEATURE)
        | MetadataFeatures(EXACT_GAP_ACCOUNTING_FEATURE)
        | MetadataFeatures(FPGA_GAIN_TIMELINE_FEATURE)
    )
    observation_capacity = 1
    event_capacity = 1
    header_bytes = HEADER_PREFIX_BYTES_V7 + 32 * observation_capacity + 16 + 4
    prefix = _PREFIX.pack(
        0x314D4753,
        7,
        header_bytes,
        int(features),
        int(flags),
        0x1234,
        0,
        frame_start,
        samples,
        samples * 8,
        0x0F,
        1,
        2,
        21 if event_at_start else 20,
        21 if event_at_start else 20,
        21 if with_event else 20,
        21 if with_event else 20,
        0,
        0,
        0,
        first_change,
        first_change,
        0xFFFF,
        0xFFFF,
        0xFFFF,
        0xFFFF,
        0,
        0,
    )
    base_extension = _V3_EXTENSION.pack(
        samples,
        int(with_observation),
        observation_capacity,
        32,
        event_count,
        event_capacity,
        16,
        0,
        0,
        0,
        0,
    )
    timeline_extension = _V7_EXTENSION.pack(
        9,
        int(TandemState.ARMED_AUTO if with_event else TandemState.ARMED_HOLD),
        0,
        8 if with_event else 7,
        2,
        0x30313A14,
        0,
        62,
        20,
        0,
        76,
        end_index,
        end_index,
        43_000,
        7,
        serialized_start_index,
        serialized_start_index,
        FPGA_GAIN_TIMELINE_COMPLETE,
        55,
    )
    event = _EVENT.pack(
        frame_start if event_at_start else frame_start + 2,
        55,
        0x13,
        end_index,
        end_index,
    )
    observation = _OBSERVATION.pack(
        frame_start,
        frame_start + 1,
        100,
        3,
        serialized_start_index,
        serialized_start_index,
        21 if event_at_start else 20,
        21 if event_at_start else 20,
        0,
        0,
    )
    records = (observation if with_observation else bytes(32)) + (
        event if with_event else bytes(16)
    )
    raw = bytearray(prefix + base_extension + timeline_extension + records + bytes(4))
    raw[-4:] = struct.pack("<I", zlib.crc32(raw))
    return bytes(raw)


def _recrc(raw: bytearray) -> bytes:
    raw[-4:] = bytes(4)
    raw[-4:] = struct.pack("<I", zlib.crc32(raw))
    return bytes(raw)


@pytest.mark.parametrize(
    ("kind", "transport_bytes"),
    (
        (MetadataTransportKind.ORDINARY, 0),
        (MetadataTransportKind.DDR_BURST, 32),
        (MetadataTransportKind.DDR_RING, 48),
    ),
)
def test_abi4_provider_request_envelope_is_exact(
    kind: MetadataTransportKind,
    transport_bytes: int,
) -> None:
    tandem = TandemSessionRequestV1(mode=TandemMode.HOLD)
    request = pack_metadata_provider_request_v1(
        tandem,
        262_144,
        transport_kind=kind,
        retention_frames=5,
    )

    assert len(request) == METADATA_PROVIDER_REQUEST_BYTES + 104
    assert _PROVIDER.unpack_from(request) == (
        METADATA_PROVIDER_REQUEST_MAGIC,
        METADATA_PROVIDER_REQUEST_VERSION,
        METADATA_PROVIDER_REQUEST_BYTES,
        METADATA_PROVIDER_REQUIRED_FEATURES,
        METADATA_PROVIDER_RECORD_VERSION,
        int(kind),
        104,
        transport_bytes,
        0,
        0,
        0,
    )
    assert request[METADATA_PROVIDER_REQUEST_BYTES:] == tandem.pack(262_144)


def test_abi4_provider_request_rejects_an_untyped_transport_kind() -> None:
    with pytest.raises(TypeError, match="MetadataTransportKind"):
        pack_metadata_provider_request_v1(
            TandemSessionRequestV1(mode=TandemMode.HOLD),
            262_144,
            transport_kind=0,  # type: ignore[arg-type]
            retention_frames=5,
        )


@pytest.mark.parametrize("retention_frames", (0, 66, True))
def test_tandem_request_rejects_an_invalid_retention_window(
    retention_frames: object,
) -> None:
    with pytest.raises(ValueError, match="retention frames"):
        TandemSessionRequestV1.auto_for_sample_count(
            262_144,
            retention_frames=retention_frames,  # type: ignore[arg-type]
        )


def test_v7_zero_spi_and_rssi_telemetry_is_a_valid_complete_hold_timeline() -> None:
    raw = _metadata_v7()
    parsed = RadioMetadataV7.unpack(raw)

    assert hashlib.sha256(raw).hexdigest() == (
        "ef36947762179d82cc16c642cdf98495cbc32496749f3565939a2402a6734fe9"
    )
    assert parsed.base is parsed
    assert parsed.gain_observations == ()
    assert parsed.gain_events == ()
    assert parsed.flags & MetadataFlags.GAIN_READ_FAILED
    assert parsed.flags & MetadataFlags.RSSI_READ_FAILED
    assert parsed.tandem_state is TandemState.ARMED_HOLD
    assert parsed.tandem_transition_count_start == parsed.tandem_transition_count == 7
    assert parsed.rx1_gain_index_start == parsed.rx1_gain_index == 20


def test_v7_auto_timeline_binds_exact_event_sequence_and_endpoint() -> None:
    parsed = RadioMetadataV7.unpack(_metadata_v7(with_event=True))

    assert parsed.tandem_state is TandemState.ARMED_AUTO
    assert parsed.tandem_transition_count_start == 7
    assert parsed.tandem_transition_count == 8
    assert parsed.event_sequence_start == 55
    assert len(parsed.gain_events) == 1
    assert parsed.gain_events[0].sample_sequence == 1_002
    assert parsed.gain_events[0].event_sequence == 55
    assert parsed.rx1_first_change_sample == parsed.rx2_first_change_sample == 2
    assert parsed.rx1_gain_index_start == 20
    assert parsed.rx1_gain_index == 21


def test_v7_available_spi_observation_must_be_fully_valid() -> None:
    parsed = RadioMetadataV7.unpack(_metadata_v7(with_observation=True))
    assert len(parsed.gain_observations) == 1

    incomplete = bytearray(_metadata_v7(with_observation=True))
    struct.pack_into("<H", incomplete, HEADER_PREFIX_BYTES_V7 + 20, 2)
    with pytest.raises(ProtocolError, match="observation.*valid"):
        RadioMetadataV7.unpack(_recrc(incomplete))


def test_v7_spi_observation_endpoints_must_both_be_non_regressing() -> None:
    raw = bytearray(_metadata_v7(with_observation=True))
    first = _OBSERVATION.pack(1_000, 1_003, 100, 3, 20, 20, 20, 20, 0, 0)
    second = _OBSERVATION.pack(1_001, 1_002, 101, 3, 20, 20, 20, 20, 0, 0)
    raw[HEADER_PREFIX_BYTES_V7 : HEADER_PREFIX_BYTES_V7 + 32] = first
    raw[HEADER_PREFIX_BYTES_V7 + 32 : HEADER_PREFIX_BYTES_V7 + 32] = second
    struct.pack_into("<H", raw, 6, len(raw))
    struct.pack_into("<HH", raw, 96, 2, 2)

    with pytest.raises(ProtocolError, match="observations are not ordered"):
        RadioMetadataV7.unpack(_recrc(raw))


def test_v7_unavailable_spi_observation_has_zero_endpoint_read_durations() -> None:
    raw = bytearray(_metadata_v7())
    struct.pack_into("<I", raw, 60, 1)
    with pytest.raises(ProtocolError, match="unavailable SPI observations"):
        RadioMetadataV7.unpack(_recrc(raw))


def test_v7_optional_rssi_telemetry_is_strict_when_present() -> None:
    raw = bytearray(_metadata_v7())
    flags = struct.unpack_from("<I", raw, 12)[0]
    flags &= ~int(MetadataFlags.RSSI_READ_FAILED)
    flags |= int(MetadataFlags.RSSI_START_VALID | MetadataFlags.RSSI_END_VALID)
    struct.pack_into("<I", raw, 12, flags)
    struct.pack_into("<HHHHII", raw, 76, 400, 401, 402, 403, 100, 101)
    parsed = RadioMetadataV7.unpack(_recrc(raw))

    assert parsed.rx1_rssi_start_qdb == 400
    assert parsed.rx2_rssi_end_qdb == 403

    partial = bytearray(raw)
    struct.pack_into("<H", partial, 78, 0xFFFF)
    with pytest.raises(ProtocolError, match="start-RSSI validity"):
        RadioMetadataV7.unpack(_recrc(partial))


def test_v7_frame_start_event_result_defines_the_start_endpoint() -> None:
    parsed = RadioMetadataV7.unpack(_metadata_v7(with_event=True, event_at_start=True))

    assert parsed.gain_events[0].sample_sequence == parsed.first_sample_sequence
    assert parsed.rx1_gain_index_start == parsed.gain_events[0].rx1_gain_index == 21
    assert parsed.rx1_first_change_sample == parsed.rx2_first_change_sample == 0


def test_v7_hold_timeline_rejects_any_transition() -> None:
    raw = bytearray(_metadata_v7(with_event=True))
    struct.pack_into("<I", raw, 128, int(TandemState.ARMED_HOLD))
    with pytest.raises(ProtocolError, match="HOLD timeline"):
        RadioMetadataV7.unpack(_recrc(raw))


def test_v7_event_reason_is_bounded() -> None:
    raw = bytearray(_metadata_v7(with_event=True))
    struct.pack_into("<H", raw, 224, 0x17)
    with pytest.raises(ProtocolError, match="reason is invalid"):
        RadioMetadataV7.unpack(_recrc(raw))


def test_v7_event_and_transition_sequences_wrap_modulo_u32() -> None:
    raw = bytearray(_metadata_v7(with_event=True))
    struct.pack_into("<I", raw, 136, 0)
    struct.pack_into("<I", raw, 168, 0xFFFFFFFF)
    struct.pack_into("<I", raw, 176, 0xFFFFFFFF)
    struct.pack_into("<I", raw, 220, 0xFFFFFFFF)
    parsed = RadioMetadataV7.unpack(_recrc(raw))

    assert parsed.tandem_transition_count_start == 0xFFFFFFFF
    assert parsed.tandem_transition_count == 0
    assert parsed.gain_events[0].event_sequence == 0xFFFFFFFF


def test_v7_zero_event_hold_requires_event_flag_clear_and_identical_endpoints() -> None:
    flagged = bytearray(_metadata_v7())
    flags = struct.unpack_from("<I", flagged, 12)[0]
    struct.pack_into("<I", flagged, 12, flags | int(MetadataFlags.FPGA_EVENTS_VALID))
    with pytest.raises(ProtocolError, match="FPGA-event validity"):
        RadioMetadataV7.unpack(_recrc(flagged))

    changed = bytearray(_metadata_v7())
    struct.pack_into("<BB", changed, 162, 21, 21)
    with pytest.raises(ProtocolError, match="final event result"):
        RadioMetadataV7.unpack(_recrc(changed))


def test_v7_rejects_event_at_frame_end_and_wrong_first_change_offset() -> None:
    at_end = bytearray(_metadata_v7(with_event=True))
    struct.pack_into("<Q", at_end, 212, 1_004)
    with pytest.raises(ProtocolError, match="outside the frame"):
        RadioMetadataV7.unpack(_recrc(at_end))

    wrong_offset = bytearray(_metadata_v7(with_event=True))
    struct.pack_into("<I", wrong_offset, 68, 1)
    with pytest.raises(ProtocolError, match="first-change offsets"):
        RadioMetadataV7.unpack(_recrc(wrong_offset))


@pytest.mark.parametrize(
    ("offset", "encoding", "value", "message"),
    (
        (8, "<I", 0x0FFF, "feature set"),
        (12, "<I", 0, "validity flags"),
        (59, "<B", 1, "identity or length"),
        (
            12,
            "<I",
            int(
                MetadataFlags.START_VALID
                | MetadataFlags.END_VALID
                | MetadataFlags.SAMPLE_SEQUENCE_VALID
                | MetadataFlags.GAIN_DB_VALUES
                | MetadataFlags.HARDWARE_SAMPLE_COUNTER_VALID
                | MetadataFlags.GAIN_READ_FAILED
                | MetadataFlags.RSSI_READ_FAILED
                | MetadataFlags(TANDEM_METADATA_VALID_FLAG)
                | MetadataFlags(FPGA_GAIN_TIMELINE_VALID_FLAG)
            ),
            "validity flags",
        ),
        (
            12,
            "<I",
            int(
                MetadataFlags.START_VALID
                | MetadataFlags.END_VALID
                | MetadataFlags.SAMPLE_SEQUENCE_VALID
                | MetadataFlags.GAIN_FULL_TABLE_MODE
                | MetadataFlags.GAIN_DB_VALUES
                | MetadataFlags.HARDWARE_SAMPLE_COUNTER_VALID
                | MetadataFlags.GAIN_READ_FAILED
                | MetadataFlags.RSSI_READ_FAILED
                | MetadataFlags.RX1_LOCKED_AT_END
                | MetadataFlags(TANDEM_METADATA_VALID_FLAG)
                | MetadataFlags(FPGA_GAIN_TIMELINE_VALID_FLAG)
            ),
            "endpoint lock flags",
        ),
        (132, "<I", 1, "lease"),
        (136, "<I", 9, "transition-count"),
        (173, "<B", 19, "gain endpoints"),
        (174, "<H", 3, "timeline is incomplete"),
        (112, "<I", 1, "FIFO overflowed"),
        (220, "<I", 57, "sequence has a hole"),
    ),
)
def test_v7_fault_mutations_fail_closed(
    offset: int,
    encoding: str,
    value: int,
    message: str,
) -> None:
    raw = bytearray(_metadata_v7(with_event=True))
    struct.pack_into(encoding, raw, offset, value)

    with pytest.raises(ProtocolError, match=message):
        RadioMetadataV7.unpack(_recrc(raw))


@pytest.mark.parametrize(
    ("missing_samples", "extra_flag", "message"),
    (
        (1, MetadataFlags.SAMPLE_GAP_BEFORE, "overflow flag"),
        (0, MetadataFlags.DEVICE_IIO_OVERFLOW, "overflow flag"),
    ),
)
def test_v7_gap_requires_both_canonical_gap_flags(
    missing_samples: int,
    extra_flag: MetadataFlags,
    message: str,
) -> None:
    raw = bytearray(_metadata_v7())
    flags = struct.unpack_from("<I", raw, 12)[0]
    struct.pack_into("<I", raw, 12, flags | int(extra_flag))
    struct.pack_into("<I", raw, 116, missing_samples)

    with pytest.raises(ProtocolError, match=message):
        RadioMetadataV7.unpack(_recrc(raw))


def test_v7_exact_gap_with_both_canonical_flags_is_valid() -> None:
    raw = bytearray(_metadata_v7())
    flags = struct.unpack_from("<I", raw, 12)[0]
    flags |= int(MetadataFlags.SAMPLE_GAP_BEFORE | MetadataFlags.DEVICE_IIO_OVERFLOW)
    struct.pack_into("<I", raw, 12, flags)
    struct.pack_into("<I", raw, 116, 1)

    assert RadioMetadataV7.unpack(_recrc(raw)).missing_samples_before == 1


def test_v7_parser_does_not_relax_legacy_v6_identity() -> None:
    raw = bytearray(_metadata_v7())
    struct.pack_into("<H", raw, 4, 6)

    with pytest.raises(ProtocolError, match="identity"):
        RadioMetadataV7.unpack(_recrc(raw))
