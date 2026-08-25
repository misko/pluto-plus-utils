from __future__ import annotations

from dataclasses import replace
from types import SimpleNamespace

import numpy as np
import pytest

import pluto_plus.hardware.stimulus as stimulus
from pluto_plus.direct_radio.usb import MetadataFlags
from pluto_plus.hardware import (
    SafeDdsTonePlan,
    capture_continuous_safe_dds_tone,
    capture_safe_dds_tone,
)
from pluto_plus.hardware.base import SampleBlockV2
from pluto_plus.hardware.preflight import V7_FIRMWARE_VERSION


class FakeRxAdc:
    def __init__(self) -> None:
        self.kernel_buffers_count = 4

    def set_kernel_buffers_count(self, count: int) -> int:
        self.kernel_buffers_count = count
        return 0


class FakeToneRadio:
    def __init__(self, uri: str, *, fail_capture: bool = False) -> None:
        self.uri = uri
        self.fail_capture = fail_capture
        self.context_closed = False
        self.ctx = SimpleNamespace(
            attrs={
                "hw_serial": "SERIAL_A",
                "hw_model": "Pluto+ Test",
                "fw_version": V7_FIRMWARE_VERSION,
                "ad9361-phy,model": "ad9361",
                "iio,buffer-metadata": "2",
            },
            find_device=self._find_device,
            close=self._close_context,
        )
        self.sample_rate = 2_500_000
        self.rx_rf_bandwidth = 2_500_000
        self.tx_rf_bandwidth = 2_500_000
        self.rx_lo = 915_000_000
        self.tx_lo = 915_000_000
        self.rx_buffer_size = 1024
        self.rx_enabled_channels = [0, 1]
        self.tx_enabled_channels = [0, 1]
        self.gain_control_mode_chan0 = "manual"
        self.gain_control_mode_chan1 = "manual"
        self.rx_hardwaregain_chan0 = 40.0
        self.rx_hardwaregain_chan1 = 40.0
        self.tx_hardwaregain_chan0 = -10.0
        self.tx_hardwaregain_chan1 = -10.0
        self.dds_scales = [0.5] * 8
        self.dds_enabled = [1] * 8
        self.dds_frequencies = [0] * 8
        self.selected_tone: tuple[int, float, int] | None = None
        self._rxadc = FakeRxAdc()
        self._rxbuf: object | None = None
        self.destroy_count = 0

    @staticmethod
    def _find_device(name: str) -> object | None:
        if name == "cf-ad9361-lpc":
            channels = tuple(
                SimpleNamespace(id=f"voltage{index}", scan_element=True)
                for index in range(4)
            )
            return SimpleNamespace(channels=channels)
        if name == "tandem-agc":
            return SimpleNamespace(channels=())
        return None

    def _close_context(self) -> None:
        self.context_closed = True

    def rx_destroy_buffer(self) -> None:
        self.destroy_count += 1
        self._rxbuf = None

    def tx_destroy_buffer(self) -> None:
        pass

    def disable_dds(self) -> None:
        self.dds_enabled = [0] * 8

    def dds_single_tone(self, frequency: int, scale: float, *, channel: int) -> None:
        self.selected_tone = (frequency, scale, channel)
        self.dds_scales = [0.0] * 8
        self.dds_frequencies = [0] * 8
        for index in (channel * 4, channel * 4 + 2):
            self.dds_scales[index] = scale
            self.dds_frequencies[index] = frequency
        self.dds_enabled = [1] * 8

    def rx(self) -> np.ndarray:
        if self.fail_capture:
            raise OSError("capture failed")
        return np.ones((2, self.rx_buffer_size), dtype=np.complex64)


class FakeAdi:
    def __init__(self, *, fail_capture: bool = False) -> None:
        self.fail_capture = fail_capture
        self.device: FakeToneRadio | None = None

    def ad9361(self, uri: str) -> FakeToneRadio:
        self.device = FakeToneRadio(uri, fail_capture=self.fail_capture)
        return self.device


class FakeMetadataSession:
    instances: list[FakeMetadataSession] = []

    def __init__(
        self,
        device: FakeToneRadio,
        _metadata_buffer_type: object,
        *,
        sample_rate_hz: int,
        samples_per_channel: int,
        kernel_buffers: int,
        metadata_abi: int,
        tandem_request: object,
    ) -> None:
        self.device = device
        self.sample_rate_hz = sample_rate_hz
        self.samples_per_channel = samples_per_channel
        self.kernel_buffers = kernel_buffers
        self.metadata_abi = metadata_abi
        self.tandem_request = tandem_request
        self.is_open = False
        self.sequence = 0
        self.closed = False
        self.instances.append(self)

    def open(self) -> None:
        self.is_open = True

    def read_block(self) -> SampleBlockV2:
        sequence = self.sequence
        self.sequence += 1
        first_sample = 10_000 + sequence * self.samples_per_channel
        timestamp = 1_000_000_000 + sequence * 100_000_000
        return SampleBlockV2(
            utc_ns=timestamp,
            samples=np.ones((2, self.samples_per_channel), dtype=np.complex64),
            stream_id=77,
            buffer_sequence=sequence,
            first_sample_sequence=first_sample,
            metadata_flags=int(
                MetadataFlags.SAMPLE_SEQUENCE_VALID
                | MetadataFlags.HARDWARE_SAMPLE_COUNTER_VALID
            ),
            metadata_abi=self.metadata_abi,
            sample_time_realtime_start_ns=timestamp,
            sample_time_realtime_end_ns=timestamp + 100_000_000,
            sample_time_monotonic_start_ns=timestamp + 1_000,
            sample_time_monotonic_end_ns=timestamp + 100_001_000,
            sample_time_uncertainty_ns=10,
        )

    def close(self) -> None:
        self.is_open = False
        self.closed = True


def safe_plan() -> SafeDdsTonePlan:
    return SafeDdsTonePlan(
        uri="usb:1.2.3",
        serial="SERIAL_A",
        center_frequency_hz=2_400_000_000,
        sample_rate_hz=3_000_000,
        bandwidth_hz=1_500_000,
        tone_frequency_hz=100_000,
        tx_channel=0,
        tx_hardware_gain_db=-40.0,
        dds_scale=0.25,
        receiver_gain_db=40.0,
        source_peak_output_bound_dbm=7.0,
        load_input_limit_dbm=0.0,
        path_attenuation_before_load_db=0.0,
        required_margin_db=10.0,
        settle_ms=0,
    )


def test_plan_rejects_tone_above_load_safety_margin() -> None:
    with pytest.raises(ValueError, match="unsafe tone plan"):
        SafeDdsTonePlan(
            uri="usb:1",
            serial="SERIAL_A",
            center_frequency_hz=2_400_000_000,
            sample_rate_hz=3_000_000,
            bandwidth_hz=1_500_000,
            tone_frequency_hz=100_000,
            tx_channel=0,
            tx_hardware_gain_db=0.0,
            dds_scale=1.0,
            receiver_gain_db=40.0,
            source_peak_output_bound_dbm=7.0,
            load_input_limit_dbm=0.0,
            path_attenuation_before_load_db=0.0,
        )


def test_capture_is_serial_bound_and_always_finishes_muted() -> None:
    module = FakeAdi()

    capture = capture_safe_dds_tone(
        safe_plan(),
        sample_count=4096,
        adi_module=module,
        iio_contexts={"usb:1.2.3": "Pluto serial=SERIAL_A"},
    )

    assert capture.identity.serial == "SERIAL_A"
    assert capture.block.samples.shape == (2, 4096)
    assert capture.tx_gain_readback_db == -40.0
    assert any(capture.dds_enabled_readback)
    assert max(capture.dds_scale_readback) == 0.25
    assert capture.plan.worst_case_load_input_dbm == pytest.approx(-45.0412)
    assert module.device is not None
    assert module.device.selected_tone == (100_000, 0.25, 0)
    assert module.device.tx_hardwaregain_chan0 == -80.0
    assert module.device.tx_hardwaregain_chan1 == -80.0
    assert module.device.tx_enabled_channels == []
    assert module.device.dds_scales == [0.0] * 8
    assert module.device.dds_enabled == [0] * 8
    assert module.device.context_closed


def test_capture_failure_still_finishes_muted() -> None:
    module = FakeAdi(fail_capture=True)

    with pytest.raises(OSError, match="capture failed"):
        capture_safe_dds_tone(
            safe_plan(),
            sample_count=4096,
            adi_module=module,
            iio_contexts={"usb:1.2.3": "Pluto serial=SERIAL_A"},
        )

    assert module.device is not None
    assert module.device.tx_hardwaregain_chan0 == -80.0
    assert module.device.tx_hardwaregain_chan1 == -80.0
    assert module.device.dds_scales == [0.0] * 8
    assert module.device.context_closed


def test_continuous_capture_uses_fixed_gap_free_frames_and_finishes_muted(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    module = FakeAdi()
    consumed: list[SampleBlockV2] = []
    FakeMetadataSession.instances.clear()
    monkeypatch.setattr(stimulus, "IioMetadataCaptureSession", FakeMetadataSession)
    monkeypatch.setattr(stimulus, "verify_metadata_runtime", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        stimulus.importlib,
        "import_module",
        lambda name: SimpleNamespace(MetadataBuffer=object) if name == "iio" else module,
    )

    capture = capture_continuous_safe_dds_tone(
        safe_plan(),
        samples_per_frame=100,
        frame_count=4,
        kernel_buffers=8,
        block_consumer=consumed.append,
        iio_contexts={"usb:1.2.3": "Pluto serial=SERIAL_A"},
    )

    assert capture.sample_count == 400
    assert capture.duration_s == pytest.approx(400 / 3_000_000)
    assert capture.kernel_buffers == 8
    assert [frame.buffer_sequence for frame in capture.frames] == [0, 1, 2, 3]
    assert [frame.first_sample_sequence for frame in capture.frames] == [
        10_000,
        10_100,
        10_200,
        10_300,
    ]
    assert len(consumed) == 4
    assert FakeMetadataSession.instances[0].closed
    assert FakeMetadataSession.instances[0].tandem_request.initial_gain_db == 40
    assert module.device is not None
    assert capture.dds_frequency_readback_hz[0] == 100_000
    assert capture.dds_frequency_readback_hz[2] == 100_000
    assert module.device.tx_hardwaregain_chan0 == -80.0
    assert module.device.tx_hardwaregain_chan1 == -80.0
    assert module.device.dds_enabled == [0] * 8
    assert module.device.context_closed


def test_continuous_capture_rejects_sequence_gap_and_still_mutes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class GappedMetadataSession(FakeMetadataSession):
        def read_block(self) -> SampleBlockV2:
            block = super().read_block()
            if block.buffer_sequence == 1:
                return SampleBlockV2(
                    utc_ns=block.utc_ns,
                    samples=block.samples,
                    stream_id=block.stream_id,
                    buffer_sequence=2,
                    first_sample_sequence=block.first_sample_sequence
                    + block.sample_count,
                    metadata_flags=block.metadata_flags,
                    metadata_abi=block.metadata_abi,
                    missing_samples_before=block.sample_count,
                    sample_time_realtime_start_ns=block.sample_time_realtime_start_ns,
                    sample_time_realtime_end_ns=block.sample_time_realtime_end_ns,
                    sample_time_monotonic_start_ns=block.sample_time_monotonic_start_ns,
                    sample_time_monotonic_end_ns=block.sample_time_monotonic_end_ns,
                    sample_time_uncertainty_ns=block.sample_time_uncertainty_ns,
                )
            return block

    module = FakeAdi()
    monkeypatch.setattr(stimulus, "IioMetadataCaptureSession", GappedMetadataSession)
    monkeypatch.setattr(stimulus, "verify_metadata_runtime", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        stimulus.importlib,
        "import_module",
        lambda name: SimpleNamespace(MetadataBuffer=object) if name == "iio" else module,
    )

    with pytest.raises(RuntimeError, match="missing FPGA samples"):
        capture_continuous_safe_dds_tone(
            safe_plan(),
            samples_per_frame=100,
            frame_count=4,
            kernel_buffers=8,
            iio_contexts={"usb:1.2.3": "Pluto serial=SERIAL_A"},
        )

    assert module.device is not None
    assert module.device.tx_hardwaregain_chan0 == -80.0
    assert module.device.tx_hardwaregain_chan1 == -80.0
    assert module.device.dds_enabled == [0] * 8
    assert module.device.context_closed


def test_continuous_capture_requires_more_than_two_kernel_buffers() -> None:
    with pytest.raises(ValueError, match="kernel_buffers must be 3..64"):
        capture_continuous_safe_dds_tone(
            safe_plan(),
            samples_per_frame=100,
            frame_count=4,
            kernel_buffers=2,
        )


def test_continuous_capture_rejects_more_than_sixty_million_samples() -> None:
    with pytest.raises(ValueError, match="sample-count bound"):
        capture_continuous_safe_dds_tone(
            safe_plan(),
            samples_per_frame=1_000_000,
            frame_count=61,
            kernel_buffers=8,
        )


def test_continuous_capture_rejects_unrepresentable_hold_gain() -> None:
    plan = safe_plan()
    invalid = replace(plan, receiver_gain_db=40.5)

    with pytest.raises(ValueError, match="integer receiver gain"):
        capture_continuous_safe_dds_tone(
            invalid,
            samples_per_frame=100,
            frame_count=4,
            kernel_buffers=8,
        )


def test_continuous_capture_mutes_before_a_metadata_close_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    class CloseFailureSession(FakeMetadataSession):
        def close(self) -> None:
            super().close()
            raise OSError("metadata close failed")

    module = FakeAdi()
    monkeypatch.setattr(stimulus, "IioMetadataCaptureSession", CloseFailureSession)
    monkeypatch.setattr(stimulus, "verify_metadata_runtime", lambda *_args, **_kwargs: None)
    monkeypatch.setattr(
        stimulus.importlib,
        "import_module",
        lambda name: SimpleNamespace(MetadataBuffer=object) if name == "iio" else module,
    )

    with pytest.raises(OSError, match="metadata close failed"):
        capture_continuous_safe_dds_tone(
            safe_plan(),
            samples_per_frame=100,
            frame_count=2,
            kernel_buffers=8,
            iio_contexts={"usb:1.2.3": "Pluto serial=SERIAL_A"},
        )

    assert module.device is not None
    assert module.device.tx_hardwaregain_chan0 == -80.0
    assert module.device.tx_hardwaregain_chan1 == -80.0
    assert module.device.dds_scales == [0.0] * 8
    assert module.device.dds_enabled == [0] * 8
    assert module.device.context_closed
