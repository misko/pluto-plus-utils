from __future__ import annotations

from pathlib import Path
from types import SimpleNamespace

import numpy as np
import pytest

from pluto_plus.catalog import Catalog
from pluto_plus.controller import RadioController
from pluto_plus.errors import RadioConfigurationError, RadioSetupRequiredError
from pluto_plus.hardware.iio import (
    IioRadioDevice,
    context_facts,
    discover_usb_serials,
    find_usb_sysfs_path,
    resolve_iio_uri,
)
from pluto_plus.hardware.iio_metadata import IIO_CONTEXT_TIMEOUT_MS
from pluto_plus.models import GainMode, RadioSettings, RadioState, Transport
from pluto_plus.setup_profiles import SetupTarget, setup_target_profile


class FakeRxAdc:
    def __init__(self) -> None:
        self.kernel_buffers_count = 4
        self.counter = 123

    def set_kernel_buffers_count(self, count: int) -> int:
        self.kernel_buffers_count = count
        return 0

    def reg_read(self, address: int) -> int:
        assert address == 0x800000B8
        self.counter += 1
        return self.counter


class FakeAd9361:
    def __init__(self, uri: str, serial: str = "SERIAL_A") -> None:
        self.uri = uri
        self.timeout_calls: list[int] = []
        self.ctx = SimpleNamespace(
            attrs={
                "hw_serial": serial,
                "hw_model": "Pluto+ Test",
                "fw_version": "v-test",
            },
            set_timeout=self.timeout_calls.append,
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
        self._rxadc = FakeRxAdc()

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


def test_opt_in_raw_decoder_returns_owned_complex64_and_resets_on_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    adi = FakeAdi()
    radio = IioRadioDevice(
        "ip:192.0.2.1", serial="SERIAL_A", adi_module=adi, iq_decoder="raw-complex64"
    )
    expected = np.ones((2, 1024), dtype=np.complex64)
    calls: list[tuple[int, tuple[int, ...]]] = []

    def decode(
        device: object, *, samples_per_channel: int, channels: tuple[int, ...]
    ) -> np.ndarray:
        assert device is adi.device
        calls.append((samples_per_channel, channels))
        return expected

    monkeypatch.setattr("pluto_plus.hardware.iio.read_interleaved_complex64", decode)
    radio.open()
    try:
        block = radio.read_block(1024)
        assert block.samples is expected
        assert calls == [(1024, (0, 1))]
        assert adi.device is not None
        destroyed = adi.device.destroy_count

        def fail_decode(*_args: object, **_kwargs: object) -> np.ndarray:
            raise RuntimeError("unproven scan layout")

        monkeypatch.setattr("pluto_plus.hardware.iio.read_interleaved_complex64", fail_decode)
        with pytest.raises(RuntimeError, match="unproven scan layout"):
            radio.read_block(1024)
        assert adi.device.destroy_count == destroyed + 1
    finally:
        radio.close()


class UnsafeFakeAd9361(FakeAd9361):
    def disable_dds(self) -> None:
        pass


class UnsafeFakeAdi(FakeAdi):
    def ad9361(self, uri: str) -> FakeAd9361:
        self.device = UnsafeFakeAd9361(uri, self.serial)
        return self.device


class OneRxFakeAd9361(FakeAd9361):
    def __init__(self, uri: str, serial: str = "SERIAL_A") -> None:
        self._missing_chan1 = False
        super().__init__(uri, serial)
        self._missing_chan1 = True
        self.ctx = SimpleNamespace(
            attrs={
                "hw_serial": serial,
                "hw_model": "Pluto+ 1R1T",
                "fw_version": "v-test",
                "ad9361-phy,model": "ad9363a",
            },
            find_device=lambda name: (
                SimpleNamespace(
                    channels=(
                        SimpleNamespace(id="voltage0", scan_element=True),
                        SimpleNamespace(id="voltage1", scan_element=True),
                    )
                )
                if name == "cf-ad9361-lpc"
                else None
            ),
            set_timeout=self.timeout_calls.append,
            close=lambda: None,
        )
        self.tx_enabled_channels = [0]

    @property
    def tx_hardwaregain_chan1(self) -> float:
        if not self._missing_chan1:
            return self._initial_chan1_gain
        raise Exception("No channel found with name: voltage1")

    @tx_hardwaregain_chan1.setter
    def tx_hardwaregain_chan1(self, value: float) -> None:
        if not self._missing_chan1:
            self._initial_chan1_gain = value
            return
        raise Exception("No channel found with name: voltage1")


class OneRxFakeAdi(FakeAdi):
    def ad9361(self, uri: str) -> FakeAd9361:
        self.device = OneRxFakeAd9361(uri, self.serial)
        return self.device


class IgnoredRxSelectionFakeAd9361(OneRxFakeAd9361):
    def __init__(self, uri: str, serial: str = "SERIAL_A") -> None:
        self._ignore_rx_selection = False
        self._selected_rx_channels: list[int] = []
        super().__init__(uri, serial)
        self._ignore_rx_selection = True

    @property
    def rx_enabled_channels(self) -> list[int]:
        return list(self._selected_rx_channels)

    @rx_enabled_channels.setter
    def rx_enabled_channels(self, value: list[int]) -> None:
        if not self._ignore_rx_selection:
            self._selected_rx_channels = list(value)


class IgnoredRxSelectionFakeAdi(FakeAdi):
    def ad9361(self, uri: str) -> FakeAd9361:
        self.device = IgnoredRxSelectionFakeAd9361(uri, self.serial)
        return self.device


class BrokenProbeFakeAd9361(OneRxFakeAd9361):
    @property
    def tx_hardwaregain_chan1(self) -> float:
        if not self._missing_chan1:
            return self._initial_chan1_gain
        raise OSError("IIO transport disconnected")

    @tx_hardwaregain_chan1.setter
    def tx_hardwaregain_chan1(self, value: float) -> None:
        if not self._missing_chan1:
            self._initial_chan1_gain = value
            return
        raise OSError("IIO transport disconnected")


class BrokenProbeFakeAdi(FakeAdi):
    def ad9361(self, uri: str) -> FakeAd9361:
        self.device = BrokenProbeFakeAd9361(uri, self.serial)
        return self.device


class ResetFailureFakeAd9361(FakeAd9361):
    def __init__(self, uri: str, serial: str = "SERIAL_A") -> None:
        super().__init__(uri, serial)
        self.context_closed = False
        self.ctx.close = lambda: setattr(self, "context_closed", True)

    def rx_destroy_buffer(self) -> None:
        self.destroy_count += 1
        if self.destroy_count == 2:
            raise OSError("injected reset failure")


class ResetFailureFakeAdi(FakeAdi):
    def ad9361(self, uri: str) -> FakeAd9361:
        self.device = ResetFailureFakeAd9361(uri, self.serial)
        return self.device


def test_usb_uri_resolution_requires_one_serial_match() -> None:
    contexts = {
        "usb:1.2.3": "PlutoSDR serial=SERIAL_A",
        "ip:192.168.2.1": "PlutoSDR",
    }
    assert resolve_iio_uri("usb:", "SERIAL_A", contexts=contexts) == "usb:1.2.3"
    assert resolve_iio_uri("usb:3.49.5", "SERIAL_A", contexts={}) == "usb:3.49.5"
    with pytest.raises(RadioConfigurationError, match="found 0"):
        resolve_iio_uri("usb:", "missing", contexts=contexts)


def test_sysfs_pinned_iio_uri_is_refreshed_on_every_open(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    path = Path("/sys/bus/usb/devices/5-2")
    returned_uris = iter(("usb:5.13.5", "usb:5.14.5", "usb:5.15.5"))
    resolutions: list[tuple[Path, str]] = []

    def resolve(selected_path: Path, serial: str) -> str:
        resolutions.append((selected_path, serial))
        return next(returned_uris)

    monkeypatch.setattr("pluto_plus.hardware.iio.exact_usb_iio_uri", resolve)
    monkeypatch.setattr(
        "pluto_plus.hardware.iio.find_usb_sysfs_path",
        lambda serial: str(path),
    )
    module = FakeAdi()
    radio = IioRadioDevice(
        "usb:",
        serial="SERIAL_A",
        usb_sysfs_path=path,
        adi_module=module,
    )

    assert radio.identity.uri == "usb:5.13.5"
    radio.open()
    assert radio.identity.uri == "usb:5.14.5"
    radio.close()
    radio.open()
    assert radio.identity.uri == "usb:5.15.5"
    radio.close()
    assert resolutions == [(path, "SERIAL_A")] * 3


def test_iio_adapter_exposes_bufferless_fastlock_and_counter_control() -> None:
    module = FakeAdi()
    radio = IioRadioDevice("usb:3.49.5", serial="SERIAL_A", adi_module=module)
    radio.open()
    try:
        assert module.device is not None
        device = module.device
        profiles: dict[int, tuple[int, tuple[int, ...]]] = {}
        active_profile: list[int | None] = [None]
        save_profile: list[int] = [0]

        class Attribute:
            def __init__(self, reader, writer) -> None:
                self.reader = reader
                self.writer = writer

            @property
            def value(self) -> str:
                return str(self.reader())

            @value.setter
            def value(self, value: str) -> None:
                self.writer(value)

        def store(value: str) -> None:
            profile = int(value)
            frequency = round(device.rx_lo)
            values = tuple((frequency // (index + 1) + profile) & 0xFF for index in range(16))
            profiles[profile] = (frequency, values)

        def recall(value: str) -> None:
            profile = int(value)
            device.rx_lo = profiles[profile][0]
            active_profile[0] = profile

        def active() -> int:
            value = active_profile[0]
            if value is None:
                raise OSError(22, "Fast Lock is inactive")
            return value

        def save(value: str) -> None:
            save_profile[0] = int(value)

        def saved_values() -> str:
            profile = save_profile[0]
            values = ",".join(str(value) for value in profiles[profile][1])
            return f"{profile} {values}"

        channel = SimpleNamespace(
            attrs={
                "fastlock_store": Attribute(lambda: "", store),
                "fastlock_recall": Attribute(active, recall),
                "fastlock_save": Attribute(saved_values, save),
            }
        )
        phy = SimpleNamespace(
            find_channel=lambda name, output: (
                channel if name == "altvoltage0" and output is True else None
            )
        )
        device.ctx.find_device = lambda name: phy if name == "ad9361-phy" else None

        assert radio.read_active_rx_fastlock_profile() is None
        radio.write_center_frequency(959_687_500)
        lower = radio.store_rx_fastlock_profile(6)
        radio.write_center_frequency(1_190_312_500)
        upper = radio.store_rx_fastlock_profile(7)
        radio.recall_rx_fastlock_profile(6)

        assert lower != upper
        assert radio.read_active_rx_fastlock_profile() == 6
        assert radio.read_center_frequency() == 959_687_500
        assert radio.read_device_sample_counter_low32() == 124
        device._rxbuf = object()
        with pytest.raises(RadioConfigurationError, match="requires no ordinary"):
            radio.recall_rx_fastlock_profile(7)
    finally:
        module.device._rxbuf = None  # type: ignore[union-attr]
        radio.close()


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
        assert module.device is not None
        assert module.device.timeout_calls == [IIO_CONTEXT_TIMEOUT_MS]
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
        assert module.device.tx_enabled_channels == []
        assert module.device.tx_hardwaregain_chan0 == -80.0
        assert module.device.tx_hardwaregain_chan1 == -80.0
        assert module.device.dds_scales == [0.0] * 8
        assert module.device.dds_enabled == [0] * 8
        radio.configure_kernel_buffers(8)
        assert module.device._rxadc.kernel_buffers_count == 8
    finally:
        radio.close()
    assert radio.diagnostic_facts() == {}


def test_iio_adapter_records_setter_basis_when_kernel_buffer_readback_is_absent() -> None:
    module = FakeAdi()
    radio = IioRadioDevice(
        "pluto://usb:",
        serial="SERIAL_A",
        adi_module=module,
        iio_contexts={"usb:1.2.3": "Pluto serial=SERIAL_A"},
    )
    radio.open()
    try:
        assert module.device is not None
        module.device._rxadc = SimpleNamespace(set_kernel_buffers_count=lambda _count: 0)

        assert radio.configure_kernel_buffers(8) == 8
        assert radio.kernel_buffer_configuration_basis == "setter_accepted"
    finally:
        radio.close()


def test_iio_adapter_refuses_single_buffer_above_half_cma() -> None:
    module = FakeAdi()
    radio = IioRadioDevice(
        "usb:",
        serial="SERIAL_A",
        adi_module=module,
        iio_contexts={"usb:1": "serial=SERIAL_A"},
    )
    radio.open()
    try:
        with pytest.raises(RadioConfigurationError, match="safety ceiling"):
            radio.read_block(4_194_305)
        with pytest.raises(RadioConfigurationError, match="safety ceiling"):
            radio.begin_metadata_capture(4_194_305, kernel_buffers=1)
    finally:
        radio.close()


def test_iio_adapter_fails_closed_on_wrong_opened_serial() -> None:
    module = FakeAdi(serial="SERIAL_B")
    radio = IioRadioDevice(
        "usb:",
        serial="SERIAL_A",
        adi_module=module,
        iio_contexts={"usb:1": "serial=SERIAL_A"},
    )
    with pytest.raises(RadioConfigurationError, match="expected 'SERIAL_A'"):
        radio.open()

    assert module.device is not None
    assert module.device.destroy_count == 0
    assert module.device.tx_hardwaregain_chan0 == -10.0
    assert module.device.tx_hardwaregain_chan1 == -10.0
    assert module.device.tx_enabled_channels == [0, 1]
    assert module.device.dds_scales == [0.5] * 8
    assert module.device.dds_enabled == [1] * 8


def test_iio_adapter_runs_pre_mutation_guard_before_radio_writes() -> None:
    module = FakeAdi()

    def refuse_mutation() -> None:
        raise RadioConfigurationError("injected ownership conflict")

    radio = IioRadioDevice(
        "usb:3.49.5",
        serial="SERIAL_A",
        mutation_preflight=refuse_mutation,
        adi_module=module,
    )

    with pytest.raises(RadioConfigurationError, match="ownership conflict"):
        radio.open()

    assert module.device is not None
    assert module.device.destroy_count == 0
    assert module.device.tx_hardwaregain_chan0 == -10.0
    assert module.device.tx_enabled_channels == [0, 1]


def test_iio_adapter_requires_stable_idle_tandem_owner_before_mutation() -> None:
    module = FakeAdi()
    radio = IioRadioDevice(
        "usb:3.49.5",
        serial="SERIAL_A",
        require_idle_tandem_owner=True,
        adi_module=module,
    )

    with pytest.raises(RadioConfigurationError, match="stable idle tandem-owner"):
        radio.open()

    assert module.device is not None
    assert module.device.destroy_count == 0
    assert module.device.tx_hardwaregain_chan0 == -10.0


def test_iio_adapter_fails_closed_when_dds_mute_does_not_read_back() -> None:
    radio = IioRadioDevice(
        "usb:",
        serial="SERIAL_A",
        adi_module=UnsafeFakeAdi(),
        iio_contexts={"usb:1": "serial=SERIAL_A"},
    )
    with pytest.raises(RadioConfigurationError, match="DDS source remained enabled"):
        radio.open()


def test_iio_adapter_retains_facts_and_types_noncanonical_1r1t() -> None:
    module = OneRxFakeAdi()
    radio = IioRadioDevice(
        "usb:",
        serial="SERIAL_A",
        adi_module=module,
        iio_contexts={"usb:1": "serial=SERIAL_A"},
    )

    with pytest.raises(RadioSetupRequiredError, match="AD936x paired-RX"):
        radio.open()

    assert radio.identity.serial == "SERIAL_A"
    assert radio.identity.firmware_version == "v-test"
    assert radio.diagnostic_facts()["phy_model"] == "ad9363a"
    assert radio.diagnostic_facts()["rx_scan_channels"] == ("voltage0", "voltage1")
    assert module.device is not None
    assert module.device.tx_hardwaregain_chan0 == -80.0
    assert module.device.tx_enabled_channels == []


def test_iio_adapter_opens_exact_native_single_stream_target() -> None:
    module = OneRxFakeAdi()
    radio = IioRadioDevice(
        "usb:",
        serial="SERIAL_A",
        adi_module=module,
        iio_contexts={"usb:1": "serial=SERIAL_A"},
    )
    radio.configure_rx_layout(
        setup_target_profile(SetupTarget.AD9363A_1R1T).rx_layout_expectation
    )

    radio.open()
    try:
        assert radio.read_settings().channels == (0,)
        assert radio.capabilities.receiver_channels == (0,)
        assert radio.read_block(1024).samples.shape == (1, 1024)
        with pytest.raises(RadioConfigurationError, match="selected RX layout"):
            radio.apply_settings(
                radio.read_settings().model_copy(update={"channels": (0, 1)})
            )
    finally:
        radio.close()


def test_iio_adapter_opens_ad9361_driver_in_single_stream_mode() -> None:
    class Ad9361OneRxFakeAdi(OneRxFakeAdi):
        def ad9361(self, uri: str) -> FakeAd9361:
            device = super().ad9361(uri)
            device.ctx.attrs["ad9361-phy,model"] = "ad9361"
            return device

    radio = IioRadioDevice(
        "usb:",
        serial="SERIAL_A",
        adi_module=Ad9361OneRxFakeAdi(),
        iio_contexts={"usb:1": "serial=SERIAL_A"},
    )
    radio.configure_rx_layout(
        setup_target_profile(SetupTarget.AD9361_1R1T).rx_layout_expectation
    )

    radio.open()
    try:
        assert radio.read_settings().channels == (0,)
        assert radio.capabilities.receiver_channels == (0,)
    finally:
        radio.close()


@pytest.mark.parametrize("reported_model", [None, "ad9361"])
def test_iio_adapter_single_stream_target_requires_exact_live_driver(
    reported_model: str | None,
) -> None:
    class ModelFakeAdi(OneRxFakeAdi):
        def ad9361(self, uri: str) -> FakeAd9361:
            device = super().ad9361(uri)
            if reported_model is None:
                device.ctx.attrs.pop("ad9361-phy,model")
            else:
                device.ctx.attrs["ad9361-phy,model"] = reported_model
            return device

    radio = IioRadioDevice(
        "usb:",
        serial="SERIAL_A",
        adi_module=ModelFakeAdi(),
        iio_contexts={"usb:1": "serial=SERIAL_A"},
    )
    radio.configure_rx_layout(
        setup_target_profile(SetupTarget.AD9363A_1R1T).rx_layout_expectation
    )

    with pytest.raises(RadioSetupRequiredError, match="selected RX layout"):
        radio.open()
    assert radio.capabilities.receiver_channels == (0, 1)


def test_iio_adapter_requires_exact_single_channel_selection_readback() -> None:
    radio = IioRadioDevice(
        "usb:",
        serial="SERIAL_A",
        adi_module=IgnoredRxSelectionFakeAdi(),
        iio_contexts={"usb:1": "serial=SERIAL_A"},
    )
    radio.configure_rx_layout(
        setup_target_profile(SetupTarget.AD9363A_1R1T).rx_layout_expectation
    )

    with pytest.raises(RadioConfigurationError, match="channel selection readback"):
        radio.open()
    assert radio.capabilities.receiver_channels == (0, 1)


def test_controller_recovers_setup_required_iio_as_one_receiver(tmp_path) -> None:
    radio = IioRadioDevice(
        "usb:",
        serial="SERIAL_A",
        adi_module=OneRxFakeAdi(),
        iio_contexts={"usb:1": "serial=SERIAL_A"},
    )
    controller = RadioController(
        radio,
        tmp_path / "captures",
        Catalog(tmp_path / "catalog.sqlite3"),
    )
    try:
        assert controller.snapshot().state is RadioState.ERROR
        assert controller.setup_required

        controller.prepare_setup_mutation()
        controller.recover_after_radio_mutation(
            rx_layout=setup_target_profile(
                SetupTarget.AD9363A_1R1T
            ).rx_layout_expectation
        )

        snapshot = controller.snapshot()
        assert snapshot.state is RadioState.READY
        assert snapshot.actual_settings.channels == (0,)
        assert snapshot.capabilities.receiver_channels == (0,)
    finally:
        controller.close()


def test_iio_adapter_does_not_hide_genuine_tx_probe_io_error() -> None:
    module = BrokenProbeFakeAdi()
    radio = IioRadioDevice(
        "usb:",
        serial="SERIAL_A",
        adi_module=module,
        iio_contexts={"usb:1": "serial=SERIAL_A"},
    )

    with pytest.raises(OSError, match="transport disconnected"):
        radio.open()

    assert module.device is not None
    assert module.device.tx_hardwaregain_chan0 == -80.0


def test_iio_adapter_close_releases_context_after_buffer_reset_failure() -> None:
    module = ResetFailureFakeAdi()
    radio = IioRadioDevice("usb:3.49.5", serial="SERIAL_A", adi_module=module)
    radio.open()

    with pytest.raises(OSError, match="injected reset failure"):
        radio.close()

    assert module.device is not None
    assert module.device.context_closed  # type: ignore[attr-defined]
    assert module.device.destroy_count == 3
    assert module.device.tx_hardwaregain_chan0 == -80.0


def test_sysfs_discovery_is_stable_and_filtered(tmp_path) -> None:
    root_hub = tmp_path / "usb3"
    root_hub.mkdir()
    (root_hub / "idVendor").write_text("1d6b\n")
    (root_hub / "idProduct").write_text("0002\n")
    # Non-Pluto serial attributes must never be touched; some host controllers
    # can block inside the kernel while rendering these descriptors.
    (root_hub / "serial").write_bytes(b"\xff")
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
    channels = [SimpleNamespace(id=f"voltage{index}", scan_element=True) for index in range(4)]
    context = SimpleNamespace(
        attrs={
            "hw_serial": "SERIAL_A",
            "fw_version": "v-test",
            "ad9361-phy,model": "ad9361",
            "iio,buffer-metadata": "2",
        },
        find_device=lambda name: (
            SimpleNamespace(channels=channels)
            if name == "cf-ad9361-lpc"
            else SimpleNamespace(
                channels=(),
                attrs={
                    "state": SimpleNamespace(value="0"),
                    "ownership_epoch": SimpleNamespace(value="0"),
                    "fault_flags": SimpleNamespace(value="0"),
                },
            )
            if name == "tandem-agc"
            else None
        ),
    )

    facts = context_facts(context)
    assert facts["phy_model"] == "ad9361"
    assert facts["buffer_metadata"] is True
    assert facts["buffer_metadata_abi"] == 2
    assert facts["buffer_metadata_raw"] == "2"
    assert facts["tandem_agc"] is True
    assert facts["tandem_agc_state"] == 0
    assert facts["tandem_agc_ownership_epoch"] == 0
    assert facts["tandem_agc_fault_flags"] == 0
    assert facts["rx_scan_channels"] == (
        "voltage0",
        "voltage1",
        "voltage2",
        "voltage3",
    )


@pytest.mark.parametrize(
    (
        "abi_versions",
        "status_versions",
        "abi_state",
        "status_state",
        "effective_abi",
        "effective_status",
    ),
    (
        ("1,2,3,4", "1,2", "available", "available", 4, 2),
        ("1,2,4", "1,2", "inconsistent", "available", None, 2),
        ("1,2,3,03,4", "1,2", "malformed", "available", None, 2),
        ("1,2,3,4", "2", "available", "inconsistent", 4, None),
        ("1,2,3,4", "1,02", "available", "malformed", 4, None),
    ),
)
def test_context_facts_resolve_explicit_metadata_version_sets_fail_closed(
    abi_versions: str,
    status_versions: str,
    abi_state: str,
    status_state: str,
    effective_abi: int | None,
    effective_status: int | None,
) -> None:
    context = SimpleNamespace(
        attrs={
            "iio,buffer-metadata": "3",
            "iio,buffer-metadata-abi-versions": abi_versions,
            "iio,buffer-metadata-status": "1",
            "iio,buffer-metadata-status-versions": status_versions,
        },
        find_device=lambda _name: None,
    )

    facts = context_facts(context)

    assert facts["buffer_metadata_legacy_abi"] == 3
    assert facts["buffer_metadata_abi_versions_raw"] == abi_versions
    assert facts["buffer_metadata_abi_versions_state"] == abi_state
    assert facts["buffer_metadata_abi"] == effective_abi
    assert facts["buffer_metadata_status_legacy_version"] == 1
    assert facts["buffer_metadata_status_versions_raw"] == status_versions
    assert facts["buffer_metadata_status_versions_state"] == status_state
    assert facts["buffer_metadata_status_max_version"] == effective_status
