from __future__ import annotations

import dataclasses
import errno
import struct
import zlib
from collections import deque
from types import SimpleNamespace

import numpy as np
import pytest

import pluto_plus.hardware.iio as iio_adapter
from pluto_plus.direct_radio.usb import (
    HEADER_PREFIX_BYTES_V3,
    GainEventFlags,
    GainEventV3,
    GainObservationFlags,
    GainObservationV3,
    MetadataFeatures,
    MetadataFlags,
    ProtocolError,
    RadioMetadataV3,
    SampleFormat,
)
from pluto_plus.errors import RadioConfigurationError
from pluto_plus.hardware.iio import IioRadioDevice
from pluto_plus.hardware.iio_metadata import (
    ABI3_METADATA_LAYOUTS_TEXT,
    IIO_CONTEXT_TIMEOUT_FRAME_MULTIPLIER,
    IIO_CONTEXT_TIMEOUT_MAX_MS,
    IIO_CONTEXT_TIMEOUT_MS,
    IIO_DDR_BURST_TIMEOUT_MAX_MS,
    metadata_iio_context_timeout_ms,
)
from pluto_plus.tandem import (
    AD9361_TEMPERATURE_FEATURE,
    CANONICAL_RX_LAYOUT_FEATURE,
    EXACT_GAP_ACCOUNTING_FEATURE,
    SAMPLE_GAP_BEFORE_FLAG,
    TANDEM_METADATA_FEATURE,
    TANDEM_METADATA_VALID_FLAG,
    RadioMetadataV6,
    TandemGainTable,
    TandemState,
)

SAMPLE_COUNT = 4
STREAM = 0x1234
REQUIRED_FEATURES = MetadataFeatures(0xF7)


def _metadata_v3(
    *,
    stream_id: int = STREAM,
    buffer_sequence: int = 0,
    first_sample_sequence: int = 1_000,
    counter_valid: bool = True,
) -> RadioMetadataV3:
    flags = (
        MetadataFlags.START_VALID
        | MetadataFlags.END_VALID
        | MetadataFlags.SAMPLE_SEQUENCE_VALID
        | MetadataFlags.GAIN_FULL_TABLE_MODE
        | MetadataFlags.GAIN_DB_VALUES
        | MetadataFlags.RSSI_START_VALID
        | MetadataFlags.RSSI_END_VALID
        | MetadataFlags.GAIN_OBSERVATIONS_VALID
    )
    if counter_valid:
        flags |= MetadataFlags.HARDWARE_SAMPLE_COUNTER_VALID
    observation = GainObservationV3(
        first_sample_sequence,
        first_sample_sequence + 1,
        100,
        GainObservationFlags.VALID | GainObservationFlags.SAMPLE_INTERVAL_VALID,
        42,
        42,
        20,
        20,
    )
    return RadioMetadataV3(
        features=REQUIRED_FEATURES,
        flags=flags,
        stream_id=stream_id,
        buffer_sequence=buffer_sequence,
        first_sample_sequence=first_sample_sequence,
        samples_per_channel=SAMPLE_COUNT,
        iq_payload_bytes=SAMPLE_COUNT * 8,
        enabled_scan_mask=0x0F,
        sample_format=SampleFormat.CS16_LE_TIME_INTERLEAVED,
        channel_count=2,
        rx1_gain_db_start=20,
        rx2_gain_db_start=20,
        rx1_gain_db_end=20,
        rx2_gain_db_end=20,
        rx1_rssi_start_qdb=400,
        rx2_rssi_start_qdb=401,
        rx1_rssi_end_qdb=402,
        rx2_rssi_end_qdb=403,
        gain_observation_interval_samples=SAMPLE_COUNT,
        gain_observation_capacity=1,
        gain_observations=(observation,),
    )


def _metadata_v5(**kwargs: int | bool) -> bytes:
    base = _metadata_v3(**kwargs)
    event = GainEventV3(
        sample_sequence=base.first_sample_sequence,
        flags=GainEventFlags.RX1_CHANGED | GainEventFlags.RX2_CHANGED,
    )
    base = dataclasses.replace(
        base,
        features=base.features | MetadataFeatures.FPGA_GAIN_EVENTS,
        flags=base.flags | MetadataFlags.FPGA_EVENTS_VALID,
        gain_event_capacity=1,
        gain_events=(event,),
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
        20,
        20,
        43_000,
        0,
        0,
        0,
    )
    arrays = bytearray(v3[HEADER_PREFIX_BYTES_V3:-4])
    event_offset = base.gain_observation_capacity * 32
    struct.pack_into(
        "<QIHBB",
        arrays,
        event_offset,
        base.first_sample_sequence,
        1,
        0x13,
        20,
        20,
    )
    output = prefix + extension + arrays + bytes(4)
    output[-4:] = struct.pack("<I", zlib.crc32(output))
    return bytes(output)


def _metadata_v6(
    *,
    channels: tuple[int, ...] = (0, 1),
    missing_samples_before: int = 0,
    **kwargs: int | bool,
) -> bytes:
    raw = bytearray(_metadata_v5(**kwargs))
    struct.pack_into("<H", raw, 4, 6)
    struct.pack_into(
        "<I",
        raw,
        8,
        struct.unpack_from("<I", raw, 8)[0]
        | CANONICAL_RX_LAYOUT_FEATURE
        | EXACT_GAP_ACCOUNTING_FEATURE,
    )
    flags = struct.unpack_from("<I", raw, 12)[0]
    if missing_samples_before:
        flags |= SAMPLE_GAP_BEFORE_FLAG
    struct.pack_into("<I", raw, 12, flags)
    mask, receivers, iq_bytes = {
        (0,): (0x03, 1, SAMPLE_COUNT * 4),
        (1,): (0x0C, 1, SAMPLE_COUNT * 4),
        (0, 1): (0x0F, 2, SAMPLE_COUNT * 8),
    }[channels]
    struct.pack_into("<II", raw, 44, iq_bytes, mask)
    raw[54] = receivers
    struct.pack_into(
        "<II",
        raw,
        116,
        missing_samples_before & 0xFFFFFFFF,
        missing_samples_before >> 32,
    )
    raw[-4:] = bytes(4)
    raw[-4:] = struct.pack("<I", zlib.crc32(raw))
    return bytes(raw)


class FakeRxAdc:
    def __init__(self, headers: list[bytes], *, preserve_readback: bool = True) -> None:
        self.headers = deque(headers)
        self.kernel_buffers_count = 4
        self.preserve_readback = preserve_readback

    def set_kernel_buffers_count(self, count: int) -> int:
        if self.preserve_readback:
            self.kernel_buffers_count = count
        return 0

    def reg_read(self, _address: int) -> int:
        return 1_004


class FakeMetadataBuffer:
    def __init__(
        self,
        rxadc: FakeRxAdc,
        signature: tuple[object, ...],
        keywords: dict[str, object],
    ) -> None:
        self._rxadc = rxadc
        self.signature = signature
        self.keywords = keywords
        self.closed = False
        self.cancelled = False

    @property
    def metadata(self) -> bytes | None:
        return self._rxadc.headers.popleft() if self._rxadc.headers else None

    def close(self) -> None:
        self.closed = True

    def cancel(self) -> None:
        self.cancelled = True


class FakeMetadataBufferFactory:
    def __init__(self) -> None:
        self.instances: list[FakeMetadataBuffer] = []

    def __call__(
        self, rxadc: FakeRxAdc, *signature: object, **keywords: object
    ) -> FakeMetadataBuffer:
        result = FakeMetadataBuffer(rxadc, signature, keywords)
        self.instances.append(result)
        return result


class FakeAd9361:
    def __init__(
        self,
        uri: str,
        headers: list[bytes],
        *,
        metadata_abi: int | None,
        metadata_layouts: str | None,
        ddr_burst: bool = False,
        preserve_readback: bool = True,
    ) -> None:
        self.uri = uri
        self.events: list[str] = []
        self.timeout_calls: list[int] = []
        self.rx_failure: OSError | None = None
        self.context_close_count = 0
        attrs = {
            "hw_serial": "SERIAL_A",
            "hw_model": "Pluto+ Test",
            "fw_version": "v-test",
            "ad9361-phy,model": "ad9361",
        }
        if metadata_abi is not None:
            attrs["iio,buffer-metadata"] = str(metadata_abi)
        if metadata_layouts is not None:
            attrs["iio,buffer-metadata-layouts"] = metadata_layouts
        if ddr_burst:
            attrs.update(
                {
                    "iio,buffer-ddr-burst": "1",
                    "iio,buffer-ddr-burst-max-iq-bytes": "200000000",
                    "iio,buffer-ddr-burst-reserve-bytes": "134217728",
                }
            )
        channels = tuple(
            SimpleNamespace(id=f"voltage{index}", scan_element=True) for index in range(4)
        )
        self.ctx = SimpleNamespace(
            attrs=attrs,
            find_device=lambda name: (
                SimpleNamespace(channels=channels)
                if name == "cf-ad9361-lpc"
                else SimpleNamespace(channels=())
                if name == "tandem-agc" and metadata_abi in {2, 3}
                else None
            ),
            set_timeout=self._set_timeout,
            close=self._close_context,
        )
        self.sample_rate = 2_500_000
        self.rx_rf_bandwidth = 2_500_000
        self.rx_lo = 1_000_000_000
        self.rx_buffer_size = SAMPLE_COUNT
        self.rx_enabled_channels = [0, 1]
        self.tx_enabled_channels = [0, 1]
        self.gain_control_mode_chan0 = "manual"
        self.gain_control_mode_chan1 = "manual"
        self.rx_hardwaregain_chan0 = 30.0
        self.rx_hardwaregain_chan1 = 30.0
        self.tx_hardwaregain_chan0 = -10.0
        self.tx_hardwaregain_chan1 = -10.0
        self.dds_scales = [0.5] * 8
        self.dds_enabled = [1] * 8
        self._rxadc = FakeRxAdc(headers, preserve_readback=preserve_readback)
        self._rxbuf: object | None = None
        self.destroy_count = 0

    def rx_destroy_buffer(self) -> None:
        self.destroy_count += 1
        self._rxbuf = None

    def tx_destroy_buffer(self) -> None:
        pass

    def disable_dds(self) -> None:
        self.dds_enabled = [0] * 8

    def _set_timeout(self, timeout_ms: int) -> None:
        self.timeout_calls.append(timeout_ms)
        self.events.append(f"timeout:{timeout_ms}")

    def _close_context(self) -> None:
        self.context_close_count += 1

    def rx(self) -> np.ndarray:
        self.events.append("read")
        if self.rx_failure is not None:
            raise self.rx_failure
        axis = np.arange(self.rx_buffer_size, dtype=np.float32)
        receivers = (
            axis + 1j * axis,
            2 * axis + 3j * axis,
        )
        selected = tuple(receivers[channel] for channel in self.rx_enabled_channels)
        if len(selected) == 1:
            return np.asarray(selected[0], dtype=np.complex64)
        return np.stack(selected).astype(np.complex64)


class FakeAdi:
    def __init__(
        self,
        headers: list[bytes],
        *,
        metadata_abi: int | None = 1,
        metadata_layouts: str | None = None,
        preserve_readback: bool = True,
        ddr_burst: bool = False,
    ) -> None:
        self.headers = headers
        self.metadata_abi = metadata_abi
        self.metadata_layouts = (
            ABI3_METADATA_LAYOUTS_TEXT
            if metadata_abi == 3 and metadata_layouts is None
            else metadata_layouts
        )
        self.preserve_readback = preserve_readback
        self.ddr_burst = ddr_burst
        self.device: FakeAd9361 | None = None

    def ad9361(self, uri: str) -> FakeAd9361:
        self.device = FakeAd9361(
            uri,
            self.headers,
            metadata_abi=self.metadata_abi,
            metadata_layouts=self.metadata_layouts,
            preserve_readback=self.preserve_readback,
            ddr_burst=self.ddr_burst,
        )
        return self.device


def _open_radio(
    headers: list[bytes],
    *,
    metadata_abi: int | None = 1,
    metadata_layouts: str | None = None,
    channels: tuple[int, ...] = (0, 1),
    include_metadata_buffer: bool = True,
    preserve_readback: bool = True,
    ddr_burst: bool = False,
) -> tuple[IioRadioDevice, FakeAdi, FakeMetadataBufferFactory]:
    adi = FakeAdi(
        headers,
        metadata_abi=metadata_abi,
        metadata_layouts=metadata_layouts,
        preserve_readback=preserve_readback,
        ddr_burst=ddr_burst,
    )
    factory = FakeMetadataBufferFactory()
    iio = SimpleNamespace(MetadataBuffer=factory) if include_metadata_buffer else SimpleNamespace()
    radio = IioRadioDevice(
        "ip:192.0.2.1",
        serial="SERIAL_A",
        adi_module=adi,
        iio_module=iio,
    )
    radio.open()
    assert adi.device is not None
    adi.device.rx_enabled_channels = list(channels)
    return radio, adi, factory


def test_abi1_capture_reports_contiguous_counter_time_and_exact_constructor() -> None:
    headers = [
        _metadata_v3(buffer_sequence=0, first_sample_sequence=1_000).pack(),
        _metadata_v3(buffer_sequence=1, first_sample_sequence=1_004).pack(),
    ]
    radio, _adi, factory = _open_radio(headers)
    try:
        with radio.begin_metadata_capture(SAMPLE_COUNT, kernel_buffers=8) as capture:
            first = capture.read_block()
            second = capture.read_block()
            assert capture.kernel_buffers == 8
        assert first.metadata_abi == 1
        assert first.stream_generation == STREAM
        assert first.buffer_sequence == 0
        assert first.first_sample_sequence == 1_000
        assert first.last_sample_sequence_exclusive == 1_004
        assert first.missing_samples_before == 0
        assert first.sample_time_realtime_start_ns is not None
        assert first.sample_time_uncertainty_ns is not None
        assert second.missing_samples_before == 0
        assert factory.instances[0].signature == (SAMPLE_COUNT, 64 * 1024)
        assert factory.instances[0].closed
        capture.close()
        with pytest.raises(RuntimeError, match="not open"):
            capture.read_block()
    finally:
        radio.close()


def test_context_timeout_precedes_reads_and_read_timeout_allows_cleanup() -> None:
    radio, adi, factory = _open_radio([])
    assert adi.device is not None
    device = adi.device
    assert device.timeout_calls == [IIO_CONTEXT_TIMEOUT_MS]
    assert device.events == [f"timeout:{IIO_CONTEXT_TIMEOUT_MS}"]

    capture = radio.begin_metadata_capture(SAMPLE_COUNT, kernel_buffers=8)
    assert device.events[:3] == [
        f"timeout:{IIO_CONTEXT_TIMEOUT_MS}",
        f"timeout:{IIO_CONTEXT_TIMEOUT_MS}",
        "read",
    ]
    device.rx_failure = TimeoutError(errno.ETIMEDOUT, "IIO context timed out")

    with pytest.raises(TimeoutError, match="IIO context timed out") as caught:
        capture.read_block()

    assert caught.value.errno == errno.ETIMEDOUT
    assert not capture.is_open
    assert factory.instances[0].closed
    radio.close()
    assert device.context_close_count == 1


@pytest.mark.parametrize(
    ("sample_rate_hz", "samples_per_channel", "expected_timeout_ms"),
    (
        (2_500_000, 262_144, 5_000),
        (2_500_000, 4_194_304, 13_424),
        (3_000_000, 4_194_304, 11_192),
        (5_000_000, 4_194_304, 6_712),
        (1, 4_194_304, 30_000),
    ),
)
def test_metadata_context_timeout_scales_with_native_refill_duration(
    sample_rate_hz: int,
    samples_per_channel: int,
    expected_timeout_ms: int,
) -> None:
    assert IIO_CONTEXT_TIMEOUT_FRAME_MULTIPLIER == 8
    assert IIO_CONTEXT_TIMEOUT_MAX_MS == 30_000
    assert (
        metadata_iio_context_timeout_ms(sample_rate_hz, samples_per_channel) == expected_timeout_ms
    )


def test_metadata_context_timeout_covers_complete_ddr_burst() -> None:
    assert IIO_DDR_BURST_TIMEOUT_MAX_MS == 300_000
    assert (
        metadata_iio_context_timeout_ms(
            25_000_000,
            1_000_000,
            ddr_burst_frames=50,
        )
        == 9_000
    )


@pytest.mark.parametrize(
    ("sample_rate_hz", "samples_per_channel"),
    ((0, 1), (1, 0), (True, 1), (1, False)),
)
def test_metadata_context_timeout_rejects_invalid_geometry(
    sample_rate_hz: int,
    samples_per_channel: int,
) -> None:
    with pytest.raises(ValueError, match="positive integer"):
        metadata_iio_context_timeout_ms(sample_rate_hz, samples_per_channel)


def test_metadata_capture_applies_rate_resolved_timeout_before_priming() -> None:
    radio, adi, _factory = _open_radio([])
    assert adi.device is not None
    device = adi.device
    device.sample_rate = 1

    capture = radio.begin_metadata_capture(SAMPLE_COUNT, kernel_buffers=8)
    try:
        assert device.timeout_calls == [IIO_CONTEXT_TIMEOUT_MS, 30_000]
        assert device.events[:3] == [
            f"timeout:{IIO_CONTEXT_TIMEOUT_MS}",
            "timeout:30000",
            "read",
        ]
    finally:
        capture.close()
        radio.close()


def test_abi1_capture_surfaces_a_whole_refill_gap() -> None:
    headers = [
        _metadata_v3(buffer_sequence=0, first_sample_sequence=1_000).pack(),
        _metadata_v3(buffer_sequence=2, first_sample_sequence=1_008).pack(),
    ]
    radio, _adi, _factory = _open_radio(headers)
    try:
        capture = radio.begin_metadata_capture(SAMPLE_COUNT, kernel_buffers=8)
        capture.read_block()
        assert capture.read_block().missing_samples_before == SAMPLE_COUNT
    finally:
        radio.close()


def test_sequence_disagreement_and_stream_change_fail_closed() -> None:
    bad_sequence = [
        _metadata_v3(buffer_sequence=0, first_sample_sequence=1_000).pack(),
        _metadata_v3(buffer_sequence=2, first_sample_sequence=1_004).pack(),
    ]
    radio, _adi, _factory = _open_radio(bad_sequence)
    try:
        capture = radio.begin_metadata_capture(SAMPLE_COUNT, kernel_buffers=8)
        capture.read_block()
        with pytest.raises(RuntimeError, match="sequences disagree"):
            capture.read_block()
        assert not capture.is_open
    finally:
        radio.close()

    hidden_counter_gap = [
        _metadata_v3(buffer_sequence=0, first_sample_sequence=1_000).pack(),
        _metadata_v3(buffer_sequence=1, first_sample_sequence=1_008).pack(),
    ]
    radio, _adi, _factory = _open_radio(hidden_counter_gap)
    try:
        capture = radio.begin_metadata_capture(SAMPLE_COUNT, kernel_buffers=8)
        capture.read_block()
        with pytest.raises(RuntimeError, match="sequences disagree"):
            capture.read_block()
        assert not capture.is_open
    finally:
        radio.close()

    changed_stream = [
        _metadata_v3(stream_id=1, buffer_sequence=0).pack(),
        _metadata_v3(stream_id=2, buffer_sequence=1, first_sample_sequence=1_004).pack(),
    ]
    radio, _adi, _factory = _open_radio(changed_stream)
    try:
        capture = radio.begin_metadata_capture(SAMPLE_COUNT, kernel_buffers=8)
        capture.read_block()
        with pytest.raises(RuntimeError, match="stream changed"):
            capture.read_block()
    finally:
        radio.close()


def test_reset_allows_a_new_stream_and_tune_closes_the_old_session() -> None:
    headers = [
        _metadata_v3(stream_id=1, buffer_sequence=0).pack(),
        _metadata_v3(stream_id=2, buffer_sequence=0, first_sample_sequence=2_000).pack(),
    ]
    radio, _adi, _factory = _open_radio(headers)
    try:
        first = radio.begin_metadata_capture(SAMPLE_COUNT, kernel_buffers=8)
        assert first.read_block().stream_id == 1
        assert radio.tune_center_frequency(1_200_000_000) == 1_200_000_000
        with pytest.raises(RuntimeError, match="not open"):
            first.read_block()
        second = radio.begin_metadata_capture(SAMPLE_COUNT, kernel_buffers=8)
        assert second.read_block().stream_id == 2
        radio.reset_receive_buffer()
        radio.reset_receive_buffer()
    finally:
        radio.close()


def test_capability_binding_header_and_counter_fail_closed() -> None:
    radio, _adi, _factory = _open_radio([], metadata_abi=None)
    try:
        with pytest.raises(RadioConfigurationError, match="capability"):
            radio.begin_metadata_capture(SAMPLE_COUNT, kernel_buffers=8)
    finally:
        radio.close()

    radio, _adi, _factory = _open_radio([], include_metadata_buffer=False)
    try:
        with pytest.raises(RadioConfigurationError, match="MetadataBuffer"):
            radio.begin_metadata_capture(SAMPLE_COUNT, kernel_buffers=8)
    finally:
        radio.close()

    corrupt = bytearray(_metadata_v3().pack())
    corrupt[-1] ^= 1
    radio, _adi, _factory = _open_radio([bytes(corrupt)])
    try:
        capture = radio.begin_metadata_capture(SAMPLE_COUNT, kernel_buffers=8)
        with pytest.raises(ProtocolError, match="CRC"):
            capture.read_block()
    finally:
        radio.close()

    no_counter = bytearray(_metadata_v3().pack())
    flags = struct.unpack_from("<I", no_counter, 12)[0]
    flags &= ~int(MetadataFlags.HARDWARE_SAMPLE_COUNTER_VALID)
    struct.pack_into("<I", no_counter, 12, flags)
    no_counter[-4:] = bytes(4)
    no_counter[-4:] = struct.pack("<I", zlib.crc32(no_counter))
    radio, _adi, _factory = _open_radio([bytes(no_counter)])
    try:
        capture = radio.begin_metadata_capture(SAMPLE_COUNT, kernel_buffers=8)
        with pytest.raises(ProtocolError, match="counter metadata"):
            capture.read_block()
    finally:
        radio.close()


def test_abi2_uses_request_constructor_and_persists_overflow_flag() -> None:
    raw = bytearray(_metadata_v5())
    flags = struct.unpack_from("<I", raw, 12)[0] | int(MetadataFlags.DEVICE_IIO_OVERFLOW)
    struct.pack_into("<I", raw, 12, flags)
    raw[-4:] = bytes(4)
    raw[-4:] = struct.pack("<I", zlib.crc32(raw))
    radio, _adi, factory = _open_radio([bytes(raw)], metadata_abi=2)
    try:
        capture = radio.begin_metadata_capture(SAMPLE_COUNT, kernel_buffers=8)
        block = capture.read_block()
        assert block.metadata_abi == 2
        assert block.overflow_observed
        assert len(factory.instances[0].signature) == 3
        assert factory.instances[0].signature[0] == SAMPLE_COUNT
        assert isinstance(factory.instances[0].signature[1], bytes)
        assert factory.instances[0].signature[2] == 64 * 1024
    finally:
        radio.close()


def test_default_metadata_request_scales_auto_cooldown_to_refill_size() -> None:
    session = iio_adapter.IioMetadataCaptureSession(
        SimpleNamespace(rx_enabled_channels=(0, 1)),
        FakeMetadataBufferFactory(),
        sample_rate_hz=2_500_000,
        samples_per_channel=4_194_304,
        kernel_buffers=4,
        metadata_abi=3,
    )

    assert session._tandem_request.cooldown_periods == 127  # noqa: SLF001
    assert len(session._tandem_request.pack(4_194_304)) == 104  # noqa: SLF001


@pytest.mark.parametrize(
    ("channels", "mask", "receivers", "iq_payload_bytes"),
    (
        ((0,), 0x03, 1, SAMPLE_COUNT * 4),
        ((1,), 0x0C, 1, SAMPLE_COUNT * 4),
        ((0, 1), 0x0F, 2, SAMPLE_COUNT * 8),
    ),
)
def test_v6_parser_accepts_only_canonical_rx_layouts(
    channels: tuple[int, ...],
    mask: int,
    receivers: int,
    iq_payload_bytes: int,
) -> None:
    declared_gap = (1 << 32) + 7
    parsed = RadioMetadataV6.unpack(
        _metadata_v6(channels=channels, missing_samples_before=declared_gap)
    )
    assert parsed.base.enabled_scan_mask == mask
    assert parsed.base.channel_count == receivers
    assert parsed.base.iq_payload_bytes == iq_payload_bytes
    assert parsed.missing_samples_before == declared_gap

    malformed = bytearray(_metadata_v6(channels=channels))
    struct.pack_into("<I", malformed, 48, 0x01)
    malformed[-4:] = bytes(4)
    malformed[-4:] = struct.pack("<I", zlib.crc32(malformed))
    with pytest.raises(ProtocolError, match="scan mask"):
        RadioMetadataV6.unpack(malformed)


def test_v6_parser_rejects_odd_single_rx_and_gap_flag_disagreement() -> None:
    odd = bytearray(_metadata_v6(channels=(0,)))
    struct.pack_into("<II", odd, 40, 3, 12)
    odd[-4:] = bytes(4)
    odd[-4:] = struct.pack("<I", zlib.crc32(odd))
    with pytest.raises(ProtocolError, match="must be even"):
        RadioMetadataV6.unpack(odd)

    missing_flag = bytearray(_metadata_v6(channels=(0,)))
    struct.pack_into("<II", missing_flag, 116, 1, 0)
    missing_flag[-4:] = bytes(4)
    missing_flag[-4:] = struct.pack("<I", zlib.crc32(missing_flag))
    with pytest.raises(ProtocolError, match="gap flag"):
        RadioMetadataV6.unpack(missing_flag)


def test_abi3_single_rx_capture_preserves_exact_sub_refill_gap() -> None:
    headers = [
        _metadata_v6(channels=(0,), buffer_sequence=0, first_sample_sequence=1_000),
        _metadata_v6(
            channels=(0,),
            buffer_sequence=1,
            first_sample_sequence=1_005,
            missing_samples_before=1,
        ),
    ]
    radio, _adi, factory = _open_radio(headers, metadata_abi=3, channels=(0,))
    try:
        capture = radio.begin_metadata_capture(SAMPLE_COUNT, kernel_buffers=8)
        first = capture.read_block()
        second = capture.read_block()
        assert first.samples.shape == (1, SAMPLE_COUNT)
        assert first.metadata_abi == 3
        assert second.missing_samples_before == 1
        assert second.buffer_sequence == 1
        assert len(factory.instances[0].signature) == 3
        assert factory.instances[0].signature[0] == SAMPLE_COUNT
    finally:
        radio.close()


def test_abi3_single_rx_ddr_burst_is_per_buffer_and_reports_admission() -> None:
    headers = [
        _metadata_v6(
            channels=(0,),
            buffer_sequence=sequence,
            first_sample_sequence=1_000 + sequence * SAMPLE_COUNT,
        )
        for sequence in range(3)
    ]
    radio, _adi, factory = _open_radio(
        headers,
        metadata_abi=3,
        channels=(0,),
        ddr_burst=True,
    )
    requested_bytes = SAMPLE_COUNT * 4 * 3 + 1
    try:
        capture = radio.begin_metadata_capture(
            SAMPLE_COUNT,
            kernel_buffers=4,
            ddr_burst_bytes=requested_bytes,
        )
        assert capture.ddr_burst_enabled
        assert capture.ddr_burst_requested_bytes == requested_bytes
        assert capture.ddr_burst_admitted_bytes == SAMPLE_COUNT * 4 * 3
        assert capture.ddr_burst_frames == 3
        assert factory.instances[0].keywords == {
            "batch_frames": 1,
            "ddr_burst_bytes": requested_bytes,
        }
        assert [capture.read_block().buffer_sequence for _ in range(3)] == [0, 1, 2]
        capture.close()
        assert factory.instances[0].closed
    finally:
        radio.close()


def test_ddr_burst_cancel_reaches_underlying_iio_buffer() -> None:
    radio, _adi, factory = _open_radio(
        [],
        metadata_abi=3,
        channels=(0,),
        ddr_burst=True,
    )
    try:
        capture = radio.begin_metadata_capture(
            SAMPLE_COUNT,
            kernel_buffers=4,
            ddr_burst_bytes=SAMPLE_COUNT * 4,
        )
        capture.cancel()
        assert factory.instances[0].cancelled
        assert factory.instances[0].closed
        assert not capture.is_open
    finally:
        radio.close()


def test_ddr_burst_requires_capability_single_rx_and_valid_byte_budget() -> None:
    radio, _adi, _factory = _open_radio([], metadata_abi=3, channels=(0,))
    try:
        with pytest.raises(RadioConfigurationError, match="does not advertise"):
            radio.begin_metadata_capture(
                SAMPLE_COUNT,
                kernel_buffers=4,
                ddr_burst_bytes=SAMPLE_COUNT * 4,
            )
    finally:
        radio.close()

    radio, _adi, _factory = _open_radio(
        [], metadata_abi=3, channels=(0, 1), ddr_burst=True
    )
    try:
        with pytest.raises(RadioConfigurationError, match="exactly one receiver"):
            radio.begin_metadata_capture(
                SAMPLE_COUNT,
                kernel_buffers=4,
                ddr_burst_bytes=SAMPLE_COUNT * 8,
            )
    finally:
        radio.close()

    radio, _adi, _factory = _open_radio(
        [], metadata_abi=3, channels=(0,), ddr_burst=True
    )
    try:
        with pytest.raises(RadioConfigurationError, match="one complete IIO frame"):
            radio.begin_metadata_capture(
                SAMPLE_COUNT,
                kernel_buffers=4,
                ddr_burst_bytes=SAMPLE_COUNT * 4 - 1,
            )
        with pytest.raises(RadioConfigurationError, match="advertised limit"):
            radio.begin_metadata_capture(
                SAMPLE_COUNT,
                kernel_buffers=4,
                ddr_burst_bytes=200_000_001,
            )
    finally:
        radio.close()


def test_abi3_rx1_and_dual_rx_captures_bind_to_the_requested_layout() -> None:
    for channels in ((1,), (0, 1)):
        radio, _adi, _factory = _open_radio(
            [_metadata_v6(channels=channels)],
            metadata_abi=3,
            channels=channels,
        )
        try:
            capture = radio.begin_metadata_capture(SAMPLE_COUNT, kernel_buffers=8)
            assert capture.read_block().samples.shape == (len(channels), SAMPLE_COUNT)
        finally:
            radio.close()


def test_abi3_capability_sample_multiple_and_exact_gap_fail_closed() -> None:
    with pytest.raises(RadioConfigurationError, match="canonical RX layouts"):
        _open_radio(
            [],
            metadata_abi=3,
            metadata_layouts="00000003:1:4:1",
        )


def test_abi3_odd_single_rx_and_counter_gap_disagreement_fail_closed() -> None:
    radio, _adi, _factory = _open_radio([], metadata_abi=3, channels=(0,))
    try:
        with pytest.raises(RadioConfigurationError, match="sample count"):
            radio.begin_metadata_capture(3, kernel_buffers=8)
    finally:
        radio.close()

    headers = [
        _metadata_v6(channels=(0,), buffer_sequence=0, first_sample_sequence=1_000),
        _metadata_v6(
            channels=(0,),
            buffer_sequence=1,
            first_sample_sequence=1_005,
            missing_samples_before=2,
        ),
    ]
    radio, _adi, _factory = _open_radio(headers, metadata_abi=3, channels=(0,))
    try:
        capture = radio.begin_metadata_capture(SAMPLE_COUNT, kernel_buffers=8)
        capture.read_block()
        with pytest.raises(RuntimeError, match="exact gap count"):
            capture.read_block()
        assert not capture.is_open
    finally:
        radio.close()


def test_kernel_buffer_readback_is_mandatory() -> None:
    radio, _adi, _factory = _open_radio([], preserve_readback=False)
    try:
        with pytest.raises(RadioConfigurationError, match="read-back"):
            radio.configure_kernel_buffers(8)
    finally:
        radio.close()


def test_open_preloads_expected_runtime_before_importing_pyadi(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    events: list[str] = []
    adi = FakeAdi([], metadata_abi=1)
    iio = SimpleNamespace(MetadataBuffer=FakeMetadataBufferFactory())

    def verify(expected_abi: int) -> SimpleNamespace:
        events.append(f"verify:{expected_abi}")
        return SimpleNamespace(metadata_abi=expected_abi)

    def import_module(name: str) -> object:
        events.append(f"import:{name}")
        return iio if name == "iio" else adi

    monkeypatch.setattr(iio_adapter, "verify_metadata_runtime", verify)
    monkeypatch.setattr(iio_adapter.importlib, "import_module", import_module)
    radio = IioRadioDevice(
        "ip:192.0.2.1",
        serial="SERIAL_A",
        expected_metadata_abi=1,
    )
    radio.open()
    try:
        assert events[:3] == ["verify:1", "import:iio", "import:adi"]
        assert radio.capabilities.supports_device_sample_counter
        assert radio.capabilities.supports_continuity_sequence
    finally:
        radio.close()
    assert not radio.capabilities.supports_device_sample_counter
    assert not radio.capabilities.supports_continuity_sequence
    radio.open()
    try:
        assert events.count("verify:1") == 2
        assert radio.capabilities.supports_device_sample_counter
        assert radio.capabilities.supports_continuity_sequence
    finally:
        radio.close()


def test_expected_runtime_must_match_radio_capability(monkeypatch: pytest.MonkeyPatch) -> None:
    adi = FakeAdi([], metadata_abi=1)
    iio = SimpleNamespace(MetadataBuffer=FakeMetadataBufferFactory())
    monkeypatch.setattr(
        iio_adapter,
        "verify_metadata_runtime",
        lambda expected_abi: SimpleNamespace(metadata_abi=expected_abi),
    )
    monkeypatch.setattr(
        iio_adapter.importlib,
        "import_module",
        lambda name: iio if name == "iio" else adi,
    )
    radio = IioRadioDevice(
        "ip:192.0.2.1",
        serial="SERIAL_A",
        expected_metadata_abi=2,
    )
    with pytest.raises(RadioConfigurationError, match="does not match"):
        radio.open()


def test_real_context_without_predeclared_runtime_cannot_claim_continuity() -> None:
    adi = FakeAdi([], metadata_abi=1)
    radio = IioRadioDevice("ip:192.0.2.1", serial="SERIAL_A", adi_module=adi)
    radio.open()
    try:
        assert not radio.capabilities.supports_device_sample_counter
        assert not radio.capabilities.supports_continuity_sequence
        with pytest.raises(RadioConfigurationError, match="matched continuity-observable"):
            radio.begin_metadata_capture(SAMPLE_COUNT, kernel_buffers=8)
    finally:
        radio.close()
