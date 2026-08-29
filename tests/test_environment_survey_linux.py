from __future__ import annotations

from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest

from pluto_plus.environment_survey import EnvironmentSurveyError, EnvironmentSurveyTarget
from pluto_plus.environment_survey_linux import LinuxEnvironmentSurveyBackend
from pluto_plus.errors import RadioConfigurationError
from pluto_plus.hardware.iio import IioReceiverSettingsReadback
from pluto_plus.inventory import LocalUsbPluto
from pluto_plus.models import GainMode, RadioSettings

SERIAL = "winbond-db6968136727402c"
USB_PATH = Path("/sys/bus/usb/devices/3-7")


class FakeAttr:
    def __init__(self, value: str | float | int) -> None:
        self.value = str(value)


class FakeChannel:
    def __init__(
        self,
        identifier: str,
        *,
        output: bool,
        attrs: dict[str, FakeAttr] | None = None,
        enabled: bool = False,
    ) -> None:
        self.id = identifier
        self.output = output
        self.attrs = attrs or {}
        self.enabled = enabled
        self.scan_element = True


class FakeDevice:
    def __init__(
        self,
        channels: list[FakeChannel] | None = None,
        *,
        attrs: dict[str, FakeAttr] | None = None,
    ) -> None:
        self.channels = channels or []
        self.attrs = attrs or {}
        self.registers = {0x0418 + index * 0x40: 0 for index in range(4)}
        self.registers.update({0x0414 + index * 0x40: 1 for index in range(4)})

    def find_channel(self, identifier: str, output: bool) -> FakeChannel | None:
        return next(
            (
                channel
                for channel in self.channels
                if channel.id == identifier and channel.output == output
            ),
            None,
        )

    def reg_read(self, address: int) -> int:
        return self.registers.get(address, 0)

    def reg_write(self, address: int, value: int) -> None:
        self.registers[address] = value


class FakeRawContext:
    def __init__(self) -> None:
        self.attrs = {
            "hw_serial": SERIAL,
            "hw_model": "Analog Devices PlutoSDR Rev.C (Z7010-AD9361)",
            "fw_version": "v-survey-test",
            "iio,buffer-metadata": "2",
        }
        self.timeout_calls: list[int] = []
        self.closed = False
        self.phy = FakeDevice(
            [
                *[
                    FakeChannel(
                        f"voltage{index}",
                        output=True,
                        attrs={"hardwaregain": FakeAttr(-10 - index)},
                    )
                    for index in range(2)
                ],
                *[
                    FakeChannel(
                        f"voltage{index}",
                        output=False,
                        attrs={
                            "sampling_frequency": FakeAttr(2_500_000),
                            "rf_bandwidth": FakeAttr(2_500_000),
                        },
                    )
                    for index in range(2)
                ],
                FakeChannel("temp0", output=False, attrs={"input": FakeAttr(44_125)}),
            ]
        )
        self.dds = FakeDevice(
            [
                *[
                    FakeChannel(f"voltage{index}", output=True, enabled=index == 0)
                    for index in range(4)
                ],
                *[
                    FakeChannel(
                        f"altvoltage{index}",
                        output=True,
                        attrs={
                            "raw": FakeAttr(1 if index == 0 else 0),
                            "scale": FakeAttr(0.5 if index == 0 else 0),
                        },
                    )
                    for index in range(8)
                ],
            ],
            attrs={
                "buffer_enable": FakeAttr(1),
                "data_available": FakeAttr(0),
            },
        )
        self.tandem = FakeDevice(
            attrs={
                "state": FakeAttr(0),
                "fifo_level": FakeAttr(0),
                "fault_flags": FakeAttr(0),
                "overflow_count": FakeAttr(0),
            }
        )
        self.rx = FakeDevice([FakeChannel(f"voltage{index}", output=False) for index in range(4)])

    def set_timeout(self, value: int) -> None:
        self.timeout_calls.append(value)

    def find_device(self, name: str) -> FakeDevice | None:
        return {
            "ad9361-phy": self.phy,
            "cf-ad9361-lpc": self.rx,
            "cf-ad9361-dds-core-lpc": self.dds,
            "tandem-agc": self.tandem,
        }.get(name)

    def close(self) -> None:
        self.closed = True


class FakeAdiDevice:
    def __init__(self, uri: str, raw: FakeRawContext) -> None:
        self.uri = uri
        self.raw = raw
        self.ctx = SimpleNamespace(
            attrs={
                "hw_serial": SERIAL,
                "hw_model": "Analog Devices PlutoSDR Rev.C (Z7010-AD9361)",
                "fw_version": "v-survey-test",
                "usb,path": str(USB_PATH),
                "ad9361-phy,model": "ad9361",
            },
            set_timeout=lambda _value: None,
            find_device=lambda name: (
                SimpleNamespace(
                    channels=tuple(
                        SimpleNamespace(id=f"voltage{index}", scan_element=True)
                        for index in range(4)
                    )
                )
                if name == "cf-ad9361-lpc"
                else None
            ),
            close=lambda: None,
        )
        self._sample_rate = 2_500_000
        self._rx_rf_bandwidth = 2_500_000
        self.rx_lo = 915_000_000
        self.rx_enabled_channels = [0, 1]
        self.rx_buffer_size = 1_024
        self.gain_control_mode_chan0 = "manual"
        self.gain_control_mode_chan1 = "manual"
        self.rx_hardwaregain_chan0 = 40.0
        self.rx_hardwaregain_chan1 = 40.0
        self.tx_hardwaregain_chan0 = -80.0
        self.tx_hardwaregain_chan1 = -80.0
        self.tx_enabled_channels = []
        self.dds_scales = [0.0] * 8
        self.dds_enabled = [0] * 8

    @property
    def sample_rate(self) -> int:
        return self._sample_rate

    @sample_rate.setter
    def sample_rate(self, value: int) -> None:
        self._sample_rate = value
        for index in (0, 1):
            self.raw.phy.find_channel(f"voltage{index}", False).attrs[
                "sampling_frequency"
            ].value = str(value)

    @property
    def rx_rf_bandwidth(self) -> int:
        return self._rx_rf_bandwidth

    @rx_rf_bandwidth.setter
    def rx_rf_bandwidth(self, value: int) -> None:
        self._rx_rf_bandwidth = value
        for index in (0, 1):
            self.raw.phy.find_channel(f"voltage{index}", False).attrs["rf_bandwidth"].value = str(
                value
            )

    def rx_destroy_buffer(self) -> None:
        pass

    def tx_destroy_buffer(self) -> None:
        pass

    def disable_dds(self) -> None:
        self.dds_enabled = [0] * 8

    def rx(self) -> np.ndarray:
        return np.zeros((2, self.rx_buffer_size), dtype=np.complex64)


class FakeAdiModule:
    def __init__(self, raw: FakeRawContext) -> None:
        self.raw = raw
        self.opened: list[str] = []
        self.device: FakeAdiDevice | None = None

    def ad9361(self, uri: str) -> FakeAdiDevice:
        assert all(
            float(self.raw.phy.find_channel(f"voltage{index}", True).attrs["hardwaregain"].value)
            <= -80
            for index in range(2)
        )
        assert all(
            float(self.raw.dds.find_channel(f"altvoltage{index}", True).attrs["raw"].value) == 0
            for index in range(8)
        )
        assert all(self.raw.dds.reg_read(0x0418 + index * 0x40) & 0xF == 3 for index in range(4))
        self.opened.append(uri)
        self.device = FakeAdiDevice(uri, self.raw)
        return self.device


class FakeIioModule:
    def __init__(self, context: FakeRawContext) -> None:
        self.context = context
        self.opened: list[str] = []

    def Context(self, uri: str) -> FakeRawContext:  # noqa: N802
        self.opened.append(uri)
        return self.context


def _local(*, device_number: int = 29) -> LocalUsbPluto:
    return LocalUsbPluto(
        usb_path=str(USB_PATH),
        bus_number=3,
        device_number=device_number,
        product="PlutoSDR+",
        serial=SERIAL,
        speed_mbps=480.0,
        interface_count=7,
    )


def _target() -> EnvironmentSurveyTarget:
    return EnvironmentSurveyTarget(
        serial=SERIAL,
        topology="3-7",
        usb_path=USB_PATH,
        bus_number=3,
        device_number=29,
        usb_uri="usb:3.29.5",
    )


def test_raw_complete_state_is_observed_and_muted_before_pyadi_open(tmp_path: Path) -> None:
    raw = FakeRawContext()
    iio = FakeIioModule(raw)
    adi = FakeAdiModule(raw)
    backend = LinuxEnvironmentSurveyBackend(
        scanner=lambda: (_local(),),
        iio_module=iio,
        adi_module=adi,
        lock_root=(tmp_path / "locks").absolute(),
    )

    with backend.locked_session(_target()) as session:
        before = session.observe_tx_state()
        assert not before.safe
        assert adi.opened == []
        muted = session.ensure_tx_safe()
        assert muted.safe
        assert adi.opened == []
        post_open = session.open_rx()
        assert post_open.safe
        assert adi.opened == ["usb:3.29.5"]
        assert post_open.tx_buffer_enabled is False
        assert post_open.tx_scan_enabled == (False, False, False, False)
        assert post_open.dds_raw == (0,) * 8
        assert post_open.dds_scale == (0.0,) * 8
        assert post_open.dac_selectors == (3, 3, 3, 3)
        assert post_open.overflow_count == 0
        requested = RadioSettings(
            center_frequency_hz=2_445_000_000,
            sample_rate_hz=2_500_000,
            bandwidth_hz=1_500_000,
            gain_mode=GainMode.MANUAL,
            gain_db=40.0,
            channels=(0, 1),
        )
        configured = session.apply_rx_settings(requested)
        assert configured.center_frequency_hz == 2_445_000_000
        assert configured.receiver_gain_modes == (GainMode.MANUAL, GainMode.MANUAL)
        assert configured.receiver_gain_db == (40.0, 40.0)
        assert configured.sample_rate_source_channels == (0, 1)
        assert configured.sample_rate_source_values_hz == (2_500_000.0, 2_500_000.0)
        assert configured.rf_bandwidth_source_channels == (0, 1)
        assert configured.rf_bandwidth_source_values_hz == (1_500_000.0, 1_500_000.0)
        assert session.read_temperature().millidegrees_c == 44_125
        assert adi.device is not None
        adi.device.rx_hardwaregain_chan0 = 39.74
        adi.device.rx_hardwaregain_chan1 = 40.26
        after_block = session.read_survey_rx_settings()
        assert after_block.receiver_gain_db == (39.74, 40.26)

    assert iio.opened == ["usb:3.29.5"]
    assert raw.closed


def test_asymmetric_per_channel_gains_restore_without_collapsing(tmp_path: Path) -> None:
    raw = FakeRawContext()
    adi = FakeAdiModule(raw)
    backend = LinuxEnvironmentSurveyBackend(
        scanner=lambda: (_local(),),
        iio_module=FakeIioModule(raw),
        adi_module=adi,
        lock_root=(tmp_path / "locks").absolute(),
    )

    with backend.locked_session(_target()) as session:
        session.ensure_tx_safe()
        session.open_rx()
        assert adi.device is not None
        adi.device.rx_hardwaregain_chan0 = 39.9
        adi.device.rx_hardwaregain_chan1 = 40.1
        snapshot = session.read_rx_settings()
        session.apply_rx_settings(
            RadioSettings(
                center_frequency_hz=2_445_000_000,
                sample_rate_hz=2_500_000,
                bandwidth_hz=1_500_000,
                gain_mode=GainMode.MANUAL,
                gain_db=40.0,
                channels=(0, 1),
            )
        )
        restored = session.restore_rx_settings(snapshot)

        assert snapshot.receiver_gain_db == (39.9, 40.1)
        assert restored.receiver_gain_db == (39.9, 40.1)
        assert adi.device.rx_hardwaregain_chan0 == 39.9
        assert adi.device.rx_hardwaregain_chan1 == 40.1


@pytest.mark.parametrize("channels", [[0], [1]])
def test_single_channel_original_state_is_snapshotted_and_restored(
    tmp_path: Path, channels: list[int]
) -> None:
    raw = FakeRawContext()
    adi = FakeAdiModule(raw)
    backend = LinuxEnvironmentSurveyBackend(
        scanner=lambda: (_local(),),
        iio_module=FakeIioModule(raw),
        adi_module=adi,
        lock_root=(tmp_path / "locks").absolute(),
    )

    with backend.locked_session(_target()) as session:
        session.ensure_tx_safe()
        session.open_rx()
        assert adi.device is not None
        adi.device.rx_enabled_channels = channels.copy()
        setattr(adi.device, f"rx_hardwaregain_chan{channels[0]}", 39.9)
        snapshot = session.read_rx_settings()
        session.apply_rx_settings(
            RadioSettings(
                center_frequency_hz=2_445_000_000,
                sample_rate_hz=2_500_000,
                bandwidth_hz=1_500_000,
                gain_mode=GainMode.MANUAL,
                gain_db=40.0,
                channels=(0, 1),
            )
        )
        restored = session.restore_rx_settings(snapshot)

        assert snapshot.receiver_channels == tuple(channels)
        assert restored == snapshot
        assert adi.device.rx_enabled_channels == channels


@pytest.mark.parametrize("field", ["lo", "gain"])
def test_restore_rejects_nearby_but_not_exact_manual_readback(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, field: str
) -> None:
    raw = FakeRawContext()
    adi = FakeAdiModule(raw)
    backend = LinuxEnvironmentSurveyBackend(
        scanner=lambda: (_local(),),
        iio_module=FakeIioModule(raw),
        adi_module=adi,
        lock_root=(tmp_path / "locks").absolute(),
    )

    with backend.locked_session(_target()) as session:
        session.ensure_tx_safe()
        session.open_rx()
        radio = session._require_radio()
        snapshot = radio.read_receiver_settings_readback()
        replacement = (
            replace(snapshot, center_frequency_hz=snapshot.center_frequency_hz + 1)
            if field == "lo"
            else replace(snapshot, gain_db=(snapshot.gain_db[0] + 0.25, snapshot.gain_db[1]))
        )
        monkeypatch.setattr(radio, "read_receiver_settings_readback", lambda: replacement)

        with pytest.raises(RadioConfigurationError, match="read back exactly"):
            radio.restore_receiver_settings_readback(snapshot)


def test_exact_restore_reuses_proven_sixteen_hz_request_search(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = FakeRawContext()
    adi = FakeAdiModule(raw)
    backend = LinuxEnvironmentSurveyBackend(
        scanner=lambda: (_local(),),
        iio_module=FakeIioModule(raw),
        adi_module=adi,
        lock_root=(tmp_path / "locks").absolute(),
    )

    with backend.locked_session(_target()) as session:
        session.ensure_tx_safe()
        session.open_rx()
        assert adi.device is not None
        radio = session._require_radio()
        snapshot = radio.read_receiver_settings_readback()

        def non_idempotent_lo_readback() -> IioReceiverSettingsReadback:
            if adi.device is not None and adi.device.rx_lo == snapshot.center_frequency_hz + 16:
                return snapshot
            return replace(snapshot, center_frequency_hz=snapshot.center_frequency_hz + 1)

        monkeypatch.setattr(radio, "read_receiver_settings_readback", non_idempotent_lo_readback)

        assert radio.restore_receiver_settings_readback(snapshot) == snapshot


def test_mixed_agc_restore_ignores_dynamic_agc_gain_only(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    raw = FakeRawContext()
    adi = FakeAdiModule(raw)
    backend = LinuxEnvironmentSurveyBackend(
        scanner=lambda: (_local(),),
        iio_module=FakeIioModule(raw),
        adi_module=adi,
        lock_root=(tmp_path / "locks").absolute(),
    )

    with backend.locked_session(_target()) as session:
        session.ensure_tx_safe()
        session.open_rx()
        assert adi.device is not None
        adi.device.gain_control_mode_chan0 = GainMode.SLOW_ATTACK.value
        adi.device.rx_hardwaregain_chan0 = 12.0
        adi.device.rx_hardwaregain_chan1 = 39.9
        snapshot = session.read_rx_settings()
        session.apply_rx_settings(
            RadioSettings(
                center_frequency_hz=2_445_000_000,
                sample_rate_hz=2_500_000,
                bandwidth_hz=1_500_000,
                gain_mode=GainMode.MANUAL,
                gain_db=40.0,
                channels=(0, 1),
            )
        )
        radio = session._require_radio()
        read = radio.read_receiver_settings_readback

        def drifting_agc_readback() -> IioReceiverSettingsReadback:
            value = read()
            if value.gain_modes[0] is GainMode.SLOW_ATTACK:
                return replace(value, gain_db=(27.0, value.gain_db[1]))
            return value

        monkeypatch.setattr(radio, "read_receiver_settings_readback", drifting_agc_readback)
        restored = session.restore_rx_settings(snapshot)

        assert restored.receiver_gain_modes == (GainMode.SLOW_ATTACK, GainMode.MANUAL)
        assert restored.receiver_gain_db == (27.0, 39.9)


def test_required_tx_state_unknown_fails_closed(tmp_path: Path) -> None:
    raw = FakeRawContext()
    del raw.dds.attrs["buffer_enable"]
    backend = LinuxEnvironmentSurveyBackend(
        scanner=lambda: (_local(),),
        iio_module=FakeIioModule(raw),
        adi_module=FakeAdiModule(raw),
        lock_root=(tmp_path / "locks").absolute(),
    )

    with backend.locked_session(_target()) as session:
        with pytest.raises(EnvironmentSurveyError, match="required TX attribute aliases"):
            session.observe_tx_state()
        with pytest.raises(EnvironmentSurveyError, match="TX buffer"):
            session.ensure_tx_safe()


def test_temperature_and_every_exposed_shared_phy_value_are_required(tmp_path: Path) -> None:
    raw = FakeRawContext()
    adi = FakeAdiModule(raw)
    backend = LinuxEnvironmentSurveyBackend(
        scanner=lambda: (_local(),),
        iio_module=FakeIioModule(raw),
        adi_module=adi,
        lock_root=(tmp_path / "locks").absolute(),
    )

    with backend.locked_session(_target()) as session:
        session.ensure_tx_safe()
        session.open_rx()
        del raw.phy.find_channel("temp0", False).attrs["input"]
        with pytest.raises(EnvironmentSurveyError, match="unavailable"):
            session.read_temperature()
        raw.phy.find_channel("voltage1", False).attrs["sampling_frequency"].value = "2499999"
        with pytest.raises(EnvironmentSurveyError, match="differs across exposed"):
            session.read_survey_rx_settings()


def test_changed_usb_address_fails_before_context_open(tmp_path: Path) -> None:
    raw = FakeRawContext()
    iio = FakeIioModule(raw)
    backend = LinuxEnvironmentSurveyBackend(
        scanner=lambda: (_local(device_number=30),),
        iio_module=iio,
        adi_module=FakeAdiModule(raw),
        lock_root=(tmp_path / "locks").absolute(),
    )

    with (
        pytest.raises(EnvironmentSurveyError, match="changed"),
        backend.locked_session(_target()),
    ):
        pytest.fail("changed target unexpectedly opened")

    assert iio.opened == []
