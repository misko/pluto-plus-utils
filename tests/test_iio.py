from __future__ import annotations

from types import SimpleNamespace

import numpy as np
import pytest

from pluto_plus.errors import RadioConfigurationError
from pluto_plus.hardware.iio import (
    IioRadioDevice,
    context_facts,
    discover_usb_serials,
    find_usb_sysfs_path,
    resolve_iio_uri,
)
from pluto_plus.models import GainMode, RadioSettings, Transport


class FakeAd9361:
    def __init__(self, uri: str, serial: str = "SERIAL_A") -> None:
        self.uri = uri
        self.ctx = SimpleNamespace(
            attrs={
                "hw_serial": serial,
                "hw_model": "Pluto+ Test",
                "fw_version": "v-test",
            },
            close=lambda: None,
        )
        self.sample_rate = 2_500_000
        self.rx_rf_bandwidth = 2_500_000
        self.rx_lo = 915_000_000
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
        self.destroy_count = 0

    def rx_destroy_buffer(self) -> None:
        self.destroy_count += 1

    def tx_destroy_buffer(self) -> None:
        pass

    def disable_dds(self) -> None:
        self.dds_enabled = [0] * 8

    def rx(self) -> np.ndarray:
        return np.stack(
            [
                np.ones(self.rx_buffer_size, dtype=np.complex64),
                np.ones(self.rx_buffer_size, dtype=np.complex64) * 2,
            ][: len(self.rx_enabled_channels)]
        )


class FakeAdi:
    def __init__(self, serial: str = "SERIAL_A") -> None:
        self.serial = serial
        self.device: FakeAd9361 | None = None

    def ad9361(self, uri: str) -> FakeAd9361:
        self.device = FakeAd9361(uri, self.serial)
        return self.device


class UnsafeFakeAd9361(FakeAd9361):
    def disable_dds(self) -> None:
        pass


class UnsafeFakeAdi(FakeAdi):
    def ad9361(self, uri: str) -> FakeAd9361:
        self.device = UnsafeFakeAd9361(uri, self.serial)
        return self.device


def test_usb_uri_resolution_requires_one_serial_match() -> None:
    contexts = {
        "usb:1.2.3": "PlutoSDR serial=SERIAL_A",
        "ip:192.168.2.1": "PlutoSDR",
    }
    assert resolve_iio_uri("usb:", "SERIAL_A", contexts=contexts) == "usb:1.2.3"
    with pytest.raises(RadioConfigurationError, match="found 0"):
        resolve_iio_uri("usb:", "missing", contexts=contexts)


def test_iio_adapter_applies_reads_back_and_captures_paired_rx() -> None:
    module = FakeAdi()
    radio = IioRadioDevice(
        "pluto://usb:",
        serial="SERIAL_A",
        adi_module=module,
        iio_contexts={"usb:1.2.3": "Pluto serial=SERIAL_A"},
    )
    radio.open()
    try:
        assert radio.identity.serial == "SERIAL_A"
        assert radio.identity.transport is Transport.IIO_USB
        settings = RadioSettings(
            center_frequency_hz=1_000_000_000,
            sample_rate_hz=1_000_000,
            bandwidth_hz=800_000,
            gain_mode=GainMode.SLOW_ATTACK,
            gain_db=None,
            channels=(0, 1),
        )
        assert radio.apply_settings(settings) == settings
        block = radio.read_block(2048)
        assert block.samples.shape == (2, 2048)
        assert module.device is not None
        assert module.device.tx_enabled_channels == []
        assert module.device.tx_hardwaregain_chan0 == -80.0
        assert module.device.tx_hardwaregain_chan1 == -80.0
        assert module.device.dds_scales == [0.0] * 8
        assert module.device.dds_enabled == [0] * 8
    finally:
        radio.close()


def test_iio_adapter_fails_closed_on_wrong_opened_serial() -> None:
    radio = IioRadioDevice(
        "usb:",
        serial="SERIAL_A",
        adi_module=FakeAdi(serial="SERIAL_B"),
        iio_contexts={"usb:1": "serial=SERIAL_A"},
    )
    with pytest.raises(RadioConfigurationError, match="expected 'SERIAL_A'"):
        radio.open()


def test_iio_adapter_fails_closed_when_dds_mute_does_not_read_back() -> None:
    radio = IioRadioDevice(
        "usb:",
        serial="SERIAL_A",
        adi_module=UnsafeFakeAdi(),
        iio_contexts={"usb:1": "serial=SERIAL_A"},
    )
    with pytest.raises(RadioConfigurationError, match="DDS source remained enabled"):
        radio.open()


def test_sysfs_discovery_is_stable_and_filtered(tmp_path) -> None:
    pluto = tmp_path / "1-1"
    pluto.mkdir()
    (pluto / "idVendor").write_text("0456\n")
    (pluto / "idProduct").write_text("b673\n")
    (pluto / "serial").write_text("SERIAL_A\n")
    other = tmp_path / "2-1"
    other.mkdir()
    (other / "idVendor").write_text("ffff\n")
    (other / "idProduct").write_text("b673\n")
    (other / "serial").write_text("OTHER\n")

    assert discover_usb_serials(tmp_path) == ["SERIAL_A"]
    assert find_usb_sysfs_path("SERIAL_A", tmp_path) == str(pluto)
    assert find_usb_sysfs_path("missing", tmp_path) is None


def test_context_facts_include_live_model_metadata_and_dual_rx_scan() -> None:
    channels = [
        SimpleNamespace(id=f"voltage{index}", scan_element=True) for index in range(4)
    ]
    context = SimpleNamespace(
        attrs={
            "hw_serial": "SERIAL_A",
            "fw_version": "v-test",
            "ad9361-phy,model": "ad9361",
            "iio,buffer-metadata": "1",
        },
        find_device=lambda name: (
            SimpleNamespace(channels=channels) if name == "cf-ad9361-lpc" else None
        ),
    )

    facts = context_facts(context)
    assert facts["phy_model"] == "ad9361"
    assert facts["buffer_metadata"] is True
    assert facts["rx_scan_channels"] == (
        "voltage0",
        "voltage1",
        "voltage2",
        "voltage3",
    )
