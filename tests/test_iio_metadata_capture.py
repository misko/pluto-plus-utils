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
from pluto_plus.hardware.preflight import V7_FIRMWARE_VERSION
from pluto_plus.tandem import (
    TANDEM_METADATA_FEATURE,
    TANDEM_METADATA_VALID_FLAG,
    TandemGainTable,
    TandemMode,
    TandemSessionRequestV1,
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
    gain_db: int = 20,
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
        gain_db,
        gain_db,
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
        rx1_gain_db_start=gain_db,
        rx2_gain_db_start=gain_db,
        rx1_gain_db_end=gain_db,
        rx2_gain_db_end=gain_db,
        rx1_rssi_start_qdb=400,
        rx2_rssi_start_qdb=401,
        rx1_rssi_end_qdb=402,
        rx2_rssi_end_qdb=403,
        gain_observation_interval_samples=SAMPLE_COUNT,
        gain_observation_capacity=1,
        gain_observations=(observation,),
    )


def _metadata_v4(
    *,
    tandem_state: TandemState = TandemState.ARMED_AUTO,
    tandem_transition_count: int = 1,
    tandem_initial_gain_db: int = 20,
    include_gain_event: bool = True,
    **kwargs: int | bool,
) -> bytes:
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
        gain_events=((event,) if include_gain_event else ()),
    )
    v3 = bytearray(base.pack())
    prefix = v3[:HEADER_PREFIX_BYTES_V3]
    struct.pack_into("<H", prefix, 4, 4)
    struct.pack_into("<H", prefix, 6, len(v3) + 56)
    struct.pack_into(
        "<I",
        prefix,
        8,
        struct.unpack_from("<I", prefix, 8)[0] | TANDEM_METADATA_FEATURE,
    )
    struct.pack_into(
        "<I",
        prefix,
        12,
        struct.unpack_from("<I", prefix, 12)[0] | TANDEM_METADATA_VALID_FLAG,
    )
    extension = struct.pack(
        "<IIIIIIiiiBBBB4I",
        9,
        int(tandem_state),
        0,
        tandem_transition_count,
        int(TandemGainTable.MHZ_1300_4000),
        0x30313A14,
        0,
        62,
        tandem_initial_gain_db,
        0,
        76,
        20,
        20,
        0,
        0,
        0,
        0,
    )
    arrays = bytearray(v3[HEADER_PREFIX_BYTES_V3:-4])
    event_offset = base.gain_observation_capacity * 32
    if include_gain_event:
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


class FakeRxAdc:
    def __init__(self, headers: list[bytes], *, preserve_readback: bool = True) -> None:
        self.headers = deque(headers)
        self.kernel_buffers_count = 4
        self.preserve_readback = preserve_readback
        self.metadata_active = False

    def set_kernel_buffers_count(self, count: int) -> int:
        if self.preserve_readback:
            self.kernel_buffers_count = count
        return 0

    def reg_read(self, _address: int) -> int:
        return 1_004


class FakeMetadataBuffer:
    def __init__(self, rxadc: FakeRxAdc, signature: tuple[object, ...]) -> None:
        self._rxadc = rxadc
        self.signature = signature
        self.closed = False
        self._rxadc.metadata_active = True

    @property
    def metadata(self) -> bytes | None:
        return self._rxadc.headers.popleft() if self._rxadc.headers else None

    def close(self) -> None:
        self.closed = True
        self._rxadc.metadata_active = False


class FakeMetadataBufferFactory:
    def __init__(self) -> None:
        self.instances: list[FakeMetadataBuffer] = []

    def __call__(self, rxadc: FakeRxAdc, *signature: object) -> FakeMetadataBuffer:
        result = FakeMetadataBuffer(rxadc, signature)
        self.instances.append(result)
        return result


class FakeAd9361:
    def __init__(
        self,
        uri: str,
        headers: list[bytes],
        *,
        metadata_abi: int | None,
        preserve_readback: bool = True,
        metadata_startup_eagain: int = 0,
    ) -> None:
        self.uri = uri
        attrs = {
            "hw_serial": "SERIAL_A",
            "hw_model": "Pluto+ Test",
            "fw_version": (
                V7_FIRMWARE_VERSION if metadata_abi == 2 else "v-test"
            ),
            "ad9361-phy,model": "ad9361",
        }
        if metadata_abi is not None:
            attrs["iio,buffer-metadata"] = str(metadata_abi)
        channels = tuple(
            SimpleNamespace(id=f"voltage{index}", scan_element=True) for index in range(4)
        )
        self.ctx = SimpleNamespace(
            attrs=attrs,
            find_device=lambda name: (
                SimpleNamespace(channels=channels)
                if name == "cf-ad9361-lpc"
                else SimpleNamespace(channels=())
                if name == "tandem-agc" and metadata_abi == 2
                else None
            ),
            close=lambda: None,
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
        self.metadata_startup_eagain = metadata_startup_eagain
        self.ordinary_metadata_fallbacks = 0

    def rx_destroy_buffer(self) -> None:
        self.destroy_count += 1
        self._rxbuf = None

    def tx_destroy_buffer(self) -> None:
        pass

    def disable_dds(self) -> None:
        self.dds_enabled = [0] * 8

    def rx(self) -> np.ndarray:
        if self._rxadc.metadata_active and self._rxbuf is None:
            self.ordinary_metadata_fallbacks += 1
            self._rxbuf = object()
        if self._rxadc.metadata_active and self.metadata_startup_eagain:
            self.metadata_startup_eagain -= 1
            self._rxbuf = None
            raise OSError(errno.EAGAIN, "metadata generation is not ready")
        axis = np.arange(self.rx_buffer_size, dtype=np.float32)
        return np.stack((axis + 1j * axis, 2 * axis + 3j * axis)).astype(np.complex64)


class FakeAdi:
    def __init__(
        self,
        headers: list[bytes],
        *,
        metadata_abi: int | None = 1,
        preserve_readback: bool = True,
        metadata_startup_eagain: int = 0,
    ) -> None:
        self.headers = headers
        self.metadata_abi = metadata_abi
        self.preserve_readback = preserve_readback
        self.metadata_startup_eagain = metadata_startup_eagain
        self.device: FakeAd9361 | None = None

    def ad9361(self, uri: str) -> FakeAd9361:
        self.device = FakeAd9361(
            uri,
            self.headers,
            metadata_abi=self.metadata_abi,
            preserve_readback=self.preserve_readback,
            metadata_startup_eagain=self.metadata_startup_eagain,
        )
        return self.device


def _open_radio(
    headers: list[bytes],
    *,
    metadata_abi: int | None = 1,
    include_metadata_buffer: bool = True,
    preserve_readback: bool = True,
    metadata_startup_eagain: int = 0,
) -> tuple[IioRadioDevice, FakeAdi, FakeMetadataBufferFactory]:
    adi = FakeAdi(
        headers,
        metadata_abi=metadata_abi,
        preserve_readback=preserve_readback,
        metadata_startup_eagain=metadata_startup_eagain,
    )
    factory = FakeMetadataBufferFactory()
    iio = SimpleNamespace(MetadataBuffer=factory) if include_metadata_buffer else SimpleNamespace()
    radio = IioRadioDevice(
        "ip:192.0.2.1",
        serial="SERIAL_A",
        adi_module=adi,
        iio_module=iio,
        expected_metadata_abi=metadata_abi,
        expected_firmware_version=(
            V7_FIRMWARE_VERSION if metadata_abi == 2 else None
        ),
        _allow_test_runtime_injection=metadata_abi is not None,
    )
    radio.open()
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
    raw = bytearray(_metadata_v4())
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


def test_v9_startup_eagain_restores_the_metadata_buffer_before_retry() -> None:
    raw = _metadata_v4(
        tandem_state=TandemState.ARMED_HOLD,
        tandem_transition_count=0,
        tandem_initial_gain_db=30,
        include_gain_event=False,
        gain_db=30,
    )
    radio, adi, factory = _open_radio(
        [raw],
        metadata_abi=2,
        metadata_startup_eagain=1,
    )
    try:
        capture = radio.begin_metadata_capture(
            SAMPLE_COUNT,
            kernel_buffers=8,
            tandem_request=TandemSessionRequestV1(
                mode=TandemMode.HOLD,
                initial_gain_db=30,
            ),
        )
        block = capture.read_block()
        assert block.buffer_sequence == 0
        assert len(factory.instances) == 1
        assert adi.device is not None
        assert adi.device.ordinary_metadata_fallbacks == 0
    finally:
        radio.close()


def test_hold_metadata_gain_must_match_the_requested_gain() -> None:
    raw = _metadata_v4(
        tandem_state=TandemState.ARMED_HOLD,
        tandem_transition_count=0,
        tandem_initial_gain_db=30,
        include_gain_event=False,
        gain_db=30,
    )
    radio, _adi, _factory = _open_radio([raw], metadata_abi=2)
    try:
        capture = radio.begin_metadata_capture(
            SAMPLE_COUNT,
            kernel_buffers=8,
            tandem_request=TandemSessionRequestV1(
                mode=TandemMode.HOLD,
                initial_gain_db=60,
            ),
        )
        with pytest.raises(RuntimeError, match="HOLD gain"):
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

    def verify(
        expected_abi: int, *, expected_firmware_version: str | None
    ) -> SimpleNamespace:
        events.append(f"verify:{expected_abi}")
        return SimpleNamespace(
            metadata_abi=expected_abi,
            firmware_version=expected_firmware_version,
        )

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
        lambda expected_abi, *, expected_firmware_version: SimpleNamespace(
            metadata_abi=expected_abi,
            firmware_version=expected_firmware_version,
        ),
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
        expected_firmware_version=V7_FIRMWARE_VERSION,
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
