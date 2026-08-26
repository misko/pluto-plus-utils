from __future__ import annotations

import dataclasses
import struct
import zlib

import numpy as np
import pytest

from pluto_plus.direct_radio.samples import ci16_dual_rx
from pluto_plus.direct_radio.usb import (
    CAPABILITIES_BYTES,
    CAPABILITIES_MAGIC,
    HARDWARE_IDENTITY_BYTES,
    HARDWARE_IDENTITY_MAGIC,
    HEADER_PREFIX_BYTES_V3,
    RUNTIME_STATUS_BYTES,
    RUNTIME_STATUS_MAGIC,
    CapabilityFlags,
    DirectRxFrame,
    GadgetCapabilitiesV1,
    GainEventFlags,
    GainEventV3,
    GainObservationFlags,
    GainObservationV3,
    HardwareIdentityFlags,
    HardwareIdentityV1,
    MetadataFeatures,
    MetadataFlags,
    ProtocolError,
    RadioMetadataV3,
    RuntimeState,
    RuntimeStatusFlags,
    RuntimeStatusV1,
    RxFrameParser,
    SampleFormat,
    TimeAnchorFlags,
    TimeAnchorV1,
    pack_start_request_v3,
    pack_time_anchor_query,
)
from pluto_plus.tandem import (
    AD9361_TEMPERATURE_FEATURE,
    HEADER_PREFIX_BYTES_V5,
    TANDEM_METADATA_FEATURE,
    TANDEM_METADATA_VALID_FLAG,
    TEMPERATURE_INVALID,
    RadioMetadataV5,
    TandemGainTable,
    TandemState,
)

FEATURES = MetadataFeatures(0xF7)


def metadata(*, buffer_sequence: int = 0, first_sample_sequence: int = 1_000) -> RadioMetadataV3:
    observation = GainObservationV3(
        first_sample_sequence - 10,
        first_sample_sequence + 3,
        500,
        GainObservationFlags.VALID | GainObservationFlags.SAMPLE_INTERVAL_VALID,
        42,
        43,
        20,
        21,
    )
    return RadioMetadataV3(
        features=FEATURES,
        flags=(
            MetadataFlags.START_VALID
            | MetadataFlags.END_VALID
            | MetadataFlags.SAMPLE_SEQUENCE_VALID
            | MetadataFlags.GAIN_FULL_TABLE_MODE
            | MetadataFlags.GAIN_DB_VALUES
            | MetadataFlags.RSSI_START_VALID
            | MetadataFlags.RSSI_END_VALID
            | MetadataFlags.GAIN_OBSERVATIONS_VALID
            | MetadataFlags.HARDWARE_SAMPLE_COUNTER_VALID
        ),
        stream_id=0x1234,
        buffer_sequence=buffer_sequence,
        first_sample_sequence=first_sample_sequence,
        samples_per_channel=4,
        iq_payload_bytes=32,
        enabled_scan_mask=0x0F,
        sample_format=SampleFormat.CS16_LE_TIME_INTERLEAVED,
        channel_count=2,
        rx1_gain_db_start=20,
        rx2_gain_db_start=21,
        rx1_gain_db_end=20,
        rx2_gain_db_end=21,
        rx1_rssi_start_qdb=400,
        rx2_rssi_start_qdb=401,
        rx1_rssi_end_qdb=402,
        rx2_rssi_end_qdb=403,
        gain_observation_interval_samples=4,
        gain_observation_capacity=2,
        gain_observations=(observation,),
    )


def frame(meta: RadioMetadataV3) -> bytes:
    payload = np.arange(meta.samples_per_channel * 4, dtype="<i2").tobytes()
    return meta.pack() + payload


def test_usb_v3_metadata_reference_layout_round_trip_and_crc() -> None:
    meta = metadata()
    packed = meta.pack()
    assert len(packed) == 192  # 124 prefix + 2*32 observations + CRC.
    assert packed[:8].hex() == "53474d310300c000"
    assert RadioMetadataV3.unpack(packed) == meta

    corrupt = bytearray(packed)
    corrupt[40] ^= 1
    with pytest.raises(ProtocolError, match="CRC"):
        RadioMetadataV3.unpack(corrupt)
    with pytest.raises(ProtocolError, match="length"):
        RadioMetadataV3.unpack(packed + b"\0")


def _tandem_v5_frame(temperature_mdeg_c: int) -> bytes:
    base = dataclasses.replace(
        metadata(),
        features=FEATURES | MetadataFeatures.FPGA_GAIN_EVENTS,
        flags=metadata().flags | MetadataFlags.FPGA_EVENTS_VALID,
        gain_event_capacity=1,
        gain_events=(
            GainEventV3(
                sample_sequence=1_001,
                flags=GainEventFlags.RX1_CHANGED | GainEventFlags.RX2_CHANGED,
            ),
        ),
    )
    v3 = bytearray(base.pack())
    prefix = v3[:HEADER_PREFIX_BYTES_V3]
    struct.pack_into("<H", prefix, 4, 5)
    struct.pack_into("<H", prefix, 6, len(v3) + 56)
    struct.pack_into(
        "<I",
        prefix,
        8,
        struct.unpack_from("<I", prefix, 8)[0]
        | TANDEM_METADATA_FEATURE
        | AD9361_TEMPERATURE_FEATURE,
    )
    struct.pack_into(
        "<I",
        prefix,
        12,
        struct.unpack_from("<I", prefix, 12)[0] | TANDEM_METADATA_VALID_FLAG,
    )
    extension = struct.pack(
        "<IIIIIIiiiBBBBi3I",
        9,
        int(TandemState.ARMED_AUTO),
        0,
        1,
        int(TandemGainTable.MHZ_1300_4000),
        0x30313A14,
        0,
        62,
        20,
        0,
        76,
        21,
        21,
        temperature_mdeg_c,
        0,
        0,
        0,
    )
    arrays = bytearray(v3[HEADER_PREFIX_BYTES_V3:-4])
    struct.pack_into("<QIHBB", arrays, 64, 1_001, 7, 0x13, 21, 21)
    output = prefix + extension + arrays + bytes(4)
    output[-4:] = struct.pack("<I", zlib.crc32(output))
    assert len(prefix) + len(extension) == HEADER_PREFIX_BYTES_V5
    return bytes(output)


def test_tandem_v5_temperature_decodes_without_growing_extension() -> None:
    valid = RadioMetadataV5.unpack(_tandem_v5_frame(43_860))
    invalid = RadioMetadataV5.unpack(_tandem_v5_frame(TEMPERATURE_INVALID))

    assert valid.ad9361_temperature_mdeg_c == 43_860
    assert invalid.ad9361_temperature_mdeg_c is None


def test_usb_frame_parser_handles_bulk_boundaries_and_fails_closed() -> None:
    first = frame(metadata())
    second = frame(metadata(buffer_sequence=1, first_sample_sequence=1_004))
    parser = RxFrameParser()
    parsed: list[DirectRxFrame] = []
    wire = first + second
    for boundary in (1, 23, 191, len(wire)):
        chunk, wire = wire[:boundary], wire[boundary:]
        parsed.extend(parser.feed(chunk))
    parsed.extend(parser.feed(wire))
    assert [item.metadata.buffer_sequence for item in parsed] == [0, 1]
    parser.finish()

    bad = metadata(buffer_sequence=3, first_sample_sequence=1_004)
    with pytest.raises(ProtocolError, match="sequence"):
        parser.parse_complete_frame(frame(bad))


def test_capability_identity_status_and_time_anchor_strict_records() -> None:
    caps = struct.pack(
        "<IHHHHIIIII",
        CAPABILITIES_MAGIC,
        CAPABILITIES_BYTES,
        1,
        3,
        0,
        int(FEATURES),
        524_288,
        16,
        int(CapabilityFlags.FINITE_RX | CapabilityFlags.HARDWARE_IDENTITY),
        0,
    )
    assert GadgetCapabilitiesV1.unpack(caps).protocol_max == 3

    sha = b"0123456789abcdef0123456789abcdef01234567"
    identity = struct.pack(
        "<IHHIIQ40s",
        HARDWARE_IDENTITY_MAGIC,
        HARDWARE_IDENTITY_BYTES,
        1,
        int(
            HardwareIdentityFlags.FPGA_DEVICE_DNA_VALID
            | HardwareIdentityFlags.GADGET_BUILD_ID_VALID
        ),
        0,
        0x123456789ABCD,
        sha,
    )
    assert HardwareIdentityV1.unpack(identity).gadget_build_id == sha.decode()

    status = struct.pack(
        "<IHHHHiII16s16sQQ14I",
        RUNTIME_STATUS_MAGIC,
        RUNTIME_STATUS_BYTES,
        1,
        int(RuntimeState.STREAMING),
        0,
        0,
        int(
            RuntimeStatusFlags.BOOT_ID_VALID
            | RuntimeStatusFlags.PROCESS_NONCE_VALID
            | RuntimeStatusFlags.RX_WORKER_ACTIVE
        ),
        0,
        b"b" * 16,
        b"n" * 16,
        7,
        9,
        *([0] * 12),
        3,
        0,
    )
    assert RuntimeStatusV1.unpack(status).worker_heartbeat_age_ms == 3

    anchor = TimeAnchorV1(TimeAnchorFlags(0x0F), 99, 1_000, 0xFFFF_FFFE, 1, 2_000)
    assert TimeAnchorV1.unpack(anchor.pack()) == anchor
    query = pack_time_anchor_query(request_id=0x0102030405060708)
    assert query[:16].hex() == "53545131180001000807060504030201"
    damaged = bytearray(anchor.pack())
    damaged[-1] ^= 1
    with pytest.raises(ProtocolError, match="CRC"):
        TimeAnchorV1.unpack(damaged)


def test_v3_start_request_golden_prefix_and_ci16_layout() -> None:
    request = pack_start_request_v3(
        requested_features=FEATURES,
        enabled_scan_mask=0x0F,
        samples_per_channel=4,
        frame_count=2,
        gain_observation_interval_samples=4,
        gain_observation_capacity=2,
    )
    assert request.hex() == ("5347533303002000f70000000f00000004000000020000000400000002000000")
    payload = struct.pack("<8h", 1, -2, 3, -4, 5, -6, 7, -8)
    samples = ci16_dual_rx(payload)
    np.testing.assert_array_equal(samples, [[1 - 2j, 5 - 6j], [3 - 4j, 7 - 8j]])
    assert samples.shape == (2, 2)
    with pytest.raises(ProtocolError):
        ci16_dual_rx(payload[:-1])
