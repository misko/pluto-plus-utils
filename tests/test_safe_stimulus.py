from __future__ import annotations

from types import SimpleNamespace

import numpy as np
import pytest

from pluto_plus.hardware import SafeDdsTonePlan, capture_safe_dds_tone


class FakeToneRadio:
    def __init__(self, uri: str, *, fail_capture: bool = False) -> None:
        self.uri = uri
        self.fail_capture = fail_capture
        self.context_closed = False
        self.ctx = SimpleNamespace(
            attrs={
                "hw_serial": "SERIAL_A",
                "hw_model": "Pluto+ Test",
                "fw_version": "v-test",
            },
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
        self.selected_tone: tuple[int, float, int] | None = None

    def _close_context(self) -> None:
        self.context_closed = True

    def rx_destroy_buffer(self) -> None:
        pass

    def tx_destroy_buffer(self) -> None:
        pass

    def disable_dds(self) -> None:
        self.dds_enabled = [0] * 8

    def dds_single_tone(self, frequency: int, scale: float, *, channel: int) -> None:
        self.selected_tone = (frequency, scale, channel)
        self.dds_scales = [scale] + [0.0] * 7
        self.dds_enabled = [1] + [0] * 7

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
