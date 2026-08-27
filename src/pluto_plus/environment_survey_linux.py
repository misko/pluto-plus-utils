"""Exact local USB-IIO backend for RX-only environment surveys."""

from __future__ import annotations

import importlib
import math
from collections.abc import Callable, Iterator, Mapping, Sequence
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from types import ModuleType
from typing import Any, Literal

from pluto_plus.environment_survey import (
    EnvironmentSurveyError,
    EnvironmentSurveyTarget,
    SurveyRuntimeIdentity,
    SurveyRxSettingsReadback,
    SurveySession,
    SurveyTemperatureReadback,
    TxStateObservation,
    make_tx_state_observation,
)
from pluto_plus.hardware.base import SampleBlock
from pluto_plus.hardware.iio import IioRadioDevice, IioReceiverSettingsReadback
from pluto_plus.hardware.iio_metadata import configure_iio_context_timeout
from pluto_plus.inventory import LocalUsbPluto, scan_local_usb_plutos
from pluto_plus.models import RadioSettings
from pluto_plus.radio_lock import acquire_radio_lock, shared_radio_lock_root


class LinuxEnvironmentSurveyBackend:
    """Open only one exact serial/topology USB-IIO context under the shared lock."""

    def __init__(
        self,
        *,
        scanner: Callable[[], Sequence[LocalUsbPluto]] = scan_local_usb_plutos,
        iio_module: ModuleType | Any | None = None,
        adi_module: ModuleType | Any | None = None,
        lock_root: Path | None = None,
    ) -> None:
        self.scanner = scanner
        self.iio_module = iio_module
        self.adi_module = adi_module
        self.lock_root = lock_root or shared_radio_lock_root()

    @contextmanager
    def locked_session(self, target: EnvironmentSurveyTarget) -> Iterator[SurveySession]:
        with acquire_radio_lock(target.serial, root=self.lock_root):
            self._revalidate_target(target)
            module = self.iio_module
            if module is None:
                try:
                    module = importlib.import_module("iio")
                except (ImportError, OSError) as error:
                    raise EnvironmentSurveyError(
                        "pylibiio is required for a local environment survey"
                    ) from error
            context: Any = None
            session: LinuxEnvironmentSurveySession | None = None
            try:
                context = module.Context(target.usb_uri)
                configure_iio_context_timeout(context)
                session = LinuxEnvironmentSurveySession(
                    target,
                    context,
                    iio_module=module,
                    adi_module=self.adi_module,
                )
                yield session
            finally:
                if session is not None:
                    session.close()
                elif context is not None:
                    close = getattr(context, "close", None)
                    if callable(close):
                        close()

    def _revalidate_target(self, target: EnvironmentSurveyTarget) -> None:
        matches = tuple(device for device in self.scanner() if device.serial == target.serial)
        if len(matches) != 1:
            raise EnvironmentSurveyError(
                f"survey target serial must still match one runtime device, found {len(matches)}"
            )
        current = matches[0]
        if (
            not current.confirmed_plus
            or Path(current.usb_path) != target.usb_path
            or current.bus_number != target.bus_number
            or current.device_number != target.device_number
            or current.interface_count is None
            or current.interface_count < 7
        ):
            raise EnvironmentSurveyError(
                "survey target topology, USB address, or canonical interface set changed"
            )


class LinuxEnvironmentSurveySession:
    """A passive raw context which lazily promotes to an RX-only pyadi adapter."""

    def __init__(
        self,
        target: EnvironmentSurveyTarget,
        context: Any,
        *,
        iio_module: ModuleType | Any,
        adi_module: ModuleType | Any | None,
    ) -> None:
        self.target = target
        self.context = context
        self.iio_module = iio_module
        self.adi_module = adi_module
        self._radio: IioRadioDevice | None = None
        attrs = {str(key): str(value) for key, value in context.attrs.items()}
        serial = attrs.get("hw_serial", attrs.get("usb,serial", attrs.get("serial", "")))
        model = attrs.get("hw_model", "").strip()
        firmware = attrs.get("fw_version", "").strip()
        if serial != target.serial or not model or not firmware:
            raise EnvironmentSurveyError(
                "exact USB-IIO context serial, model, or firmware identity is invalid"
            )
        required = ("ad9361-phy", "cf-ad9361-lpc", "cf-ad9361-dds-core-lpc", "tandem-agc")
        missing = tuple(name for name in required if context.find_device(name) is None)
        if missing:
            raise EnvironmentSurveyError(f"survey runtime lacks required IIO devices: {missing}")
        metadata = attrs.get("iio,buffer-metadata")
        self._runtime = SurveyRuntimeIdentity(
            serial=serial,
            usb_uri=target.usb_uri,
            usb_path=target.usb_path,
            hardware_model=model,
            firmware_version=firmware,
            metadata_abi=(
                None
                if not metadata
                else metadata
                if metadata.startswith("frame-metadata-v")
                else f"frame-metadata-v{metadata}"
            ),
        )

    @property
    def runtime(self) -> SurveyRuntimeIdentity:
        return self._runtime

    def observe_tx_state(self) -> TxStateObservation:
        phy = _required_device(self.context, "ad9361-phy")
        dds = _required_device(self.context, "cf-ad9361-dds-core-lpc")
        tandem = _required_device(self.context, "tandem-agc")
        gains = tuple(
            _read_number(_required_channel(phy, f"voltage{index}", True), "hardwaregain")
            for index in (0, 1)
        )
        raw = tuple(
            round(_read_number(_required_channel(dds, f"altvoltage{index}", True), "raw"))
            for index in range(8)
        )
        scales = tuple(
            _read_number(_required_channel(dds, f"altvoltage{index}", True), "scale")
            for index in range(8)
        )
        selectors = tuple(int(dds.reg_read(0x0418 + index * 0x40)) & 0xF for index in range(4))
        scan = _read_scan_enable(dds)
        buffer_enabled = _read_required_bool_attr(
            dds, ("buffer_enable", "buffer_enabled", "buffer/enable")
        )
        data_available = _read_required_int_attr(
            dds, ("data_available", "buffer_data_available", "buffer/data_available")
        )
        values: dict[str, object] = {
            "observed_at": datetime.now(UTC),
            "tx_gain_db": (float(gains[0]), float(gains[1])),
            "tx_buffer_enabled": buffer_enabled,
            "tx_data_available": data_available,
            "tx_scan_enabled": scan,
            "dds_raw": tuple(int(value) for value in raw),
            "dds_scale": tuple(float(value) for value in scales),
            "dac_selectors": tuple(int(value) for value in selectors),
            "tandem_state": round(_read_number(tandem, "state")),
            "fifo_level": round(_read_number(tandem, "fifo_level")),
            "fault_flags": round(_read_number(tandem, "fault_flags")),
            "overflow_count": round(_read_number(tandem, "overflow_count")),
        }
        return make_tx_state_observation(**values)

    def ensure_tx_safe(self) -> TxStateObservation:
        self._ensure_raw_tx_safe()
        if self._radio is not None:
            self._radio.ensure_transmit_muted()
            self._ensure_raw_tx_safe()
        observed = self.observe_tx_state()
        if not observed.safe:
            raise EnvironmentSurveyError(
                f"complete local TX mute readback remained unsafe: {observed}"
            )
        return observed

    def open_rx(self) -> TxStateObservation:
        if self._radio is not None:
            raise EnvironmentSurveyError("survey RX adapter is already open")
        radio = IioRadioDevice(
            self.target.usb_uri,
            serial=self.target.serial,
            radio_id=self.target.serial,
            adi_module=self.adi_module,
            iio_module=self.iio_module,
            iio_contexts={self.target.usb_uri: f"serial={self.target.serial}"},
        )
        try:
            radio.open()
            if (
                radio.identity.serial != self.target.serial
                or radio.identity.uri != self.target.usb_uri
            ):
                raise EnvironmentSurveyError("survey RX adapter opened a different radio")
            self._radio = radio
            return self.ensure_tx_safe()
        except BaseException:
            try:
                radio.close()
            finally:
                self._radio = None
            raise

    def read_rx_settings(self) -> SurveyRxSettingsReadback:
        return self._read_rx_settings()

    def apply_rx_settings(self, settings: RadioSettings) -> SurveyRxSettingsReadback:
        self._require_radio().apply_settings(settings)
        return self.read_survey_rx_settings()

    def read_survey_rx_settings(self) -> SurveyRxSettingsReadback:
        settings = self._read_rx_settings()
        if settings.receiver_channels != (0, 1):
            raise EnvironmentSurveyError("survey RX settings lost the paired RX0/RX1 layout")
        return settings

    def _read_rx_settings(self) -> SurveyRxSettingsReadback:
        radio = self._require_radio()
        settings = radio.read_receiver_settings_readback()
        if (
            not settings.channels
            or tuple(sorted(set(settings.channels))) != settings.channels
            or any(channel not in (0, 1) for channel in settings.channels)
            or len(settings.gain_modes) != len(settings.channels)
            or len(settings.gain_db) != len(settings.channels)
        ):
            raise EnvironmentSurveyError("RX settings readback has an invalid channel layout")
        phy = _required_device(self.context, "ad9361-phy")
        sample_channels, sample_values = _read_exposed_rx_attribute(phy, "sampling_frequency")
        bandwidth_channels, bandwidth_values = _read_exposed_rx_attribute(phy, "rf_bandwidth")
        return SurveyRxSettingsReadback(
            center_frequency_hz=settings.center_frequency_hz,
            sample_rate_hz=settings.sample_rate_hz,
            rf_bandwidth_hz=settings.bandwidth_hz,
            receiver_channels=settings.channels,
            receiver_gain_modes=settings.gain_modes,
            receiver_gain_db=settings.gain_db,
            sample_rate_source_channels=sample_channels,
            sample_rate_source_values_hz=sample_values,
            rf_bandwidth_source_channels=bandwidth_channels,
            rf_bandwidth_source_values_hz=bandwidth_values,
        )

    def read_temperature(self) -> SurveyTemperatureReadback:
        phy = _required_device(self.context, "ad9361-phy")
        temperature = _read_number(_required_channel(phy, "temp0", False), "input")
        if not temperature.is_integer():
            raise EnvironmentSurveyError("AD9361 shared temperature is not integer millidegrees C")
        return SurveyTemperatureReadback(millidegrees_c=int(temperature))

    def read_rx_block(self, sample_count: int) -> SampleBlock:
        return self._require_radio().read_block(sample_count)

    def reset_rx_buffer(self) -> None:
        self._require_radio().reset_receive_buffer()

    def restore_rx_settings(self, settings: SurveyRxSettingsReadback) -> SurveyRxSettingsReadback:
        radio = self._require_radio()
        radio.restore_receiver_settings_readback(
            IioReceiverSettingsReadback(
                center_frequency_hz=settings.center_frequency_hz,
                sample_rate_hz=settings.sample_rate_hz,
                bandwidth_hz=settings.rf_bandwidth_hz,
                channels=settings.receiver_channels,
                gain_modes=settings.receiver_gain_modes,
                gain_db=settings.receiver_gain_db,
            )
        )
        return self.read_rx_settings()

    def close(self) -> None:
        radio, self._radio = self._radio, None
        try:
            if radio is not None:
                radio.close()
        finally:
            close = getattr(self.context, "close", None)
            if callable(close):
                close()

    def _ensure_raw_tx_safe(self) -> None:
        phy = _required_device(self.context, "ad9361-phy")
        dds = _required_device(self.context, "cf-ad9361-dds-core-lpc")
        failures: list[str] = []
        for index in (0, 1):
            try:
                _write_number(
                    _required_channel(phy, f"voltage{index}", True),
                    "hardwaregain",
                    -80.0,
                    tolerance=0.26,
                )
            except BaseException as error:
                failures.append(f"TX{index + 1} gain: {error}")
        try:
            _write_required_zero_attr(dds, ("buffer_enable", "buffer_enabled", "buffer/enable"))
        except BaseException as error:
            failures.append(f"TX buffer: {error}")
        for index in range(4):
            try:
                channel = _required_channel(dds, f"voltage{index}", True)
                if not hasattr(channel, "enabled"):
                    raise EnvironmentSurveyError("TX scan channel lacks enabled read/write state")
                channel.enabled = False
                if bool(channel.enabled):
                    raise EnvironmentSurveyError("TX scan channel did not disable")
            except BaseException as error:
                failures.append(f"TX scan channel {index}: {error}")
        for index in range(8):
            try:
                channel = _required_channel(dds, f"altvoltage{index}", True)
                _write_number(channel, "raw", 0.0, tolerance=1e-9)
                _write_number(channel, "scale", 0.0, tolerance=1e-9)
            except BaseException as error:
                failures.append(f"DDS{index}: {error}")
        for index in range(4):
            try:
                legacy = 0x0414 + index * 0x40
                selector = 0x0418 + index * 0x40
                dds.reg_write(legacy, int(dds.reg_read(legacy)) & ~1)
                dds.reg_write(selector, 3)
                if int(dds.reg_read(selector)) & 0xF != 3:
                    raise EnvironmentSurveyError("selector did not read back ZERO")
            except BaseException as error:
                failures.append(f"DAC selector {index}: {error}")
        if failures:
            raise EnvironmentSurveyError("; ".join(failures))

    def _require_radio(self) -> IioRadioDevice:
        if self._radio is None:
            raise EnvironmentSurveyError("survey RX adapter has not been opened")
        return self._radio


def _required_device(context: Any, name: str) -> Any:
    device = context.find_device(name)
    if device is None:
        raise EnvironmentSurveyError(f"survey runtime lacks IIO device {name!r}")
    return device


def _required_channel(device: Any, identifier: str, output: bool) -> Any:
    finder = getattr(device, "find_channel", None)
    channel = finder(identifier, output) if callable(finder) else None
    if channel is None:
        for candidate in getattr(device, "channels", ()):
            if (
                str(getattr(candidate, "id", "")) == identifier
                and bool(getattr(candidate, "output", output)) == output
            ):
                channel = candidate
                break
    if channel is None:
        direction = "output" if output else "input"
        raise EnvironmentSurveyError(f"IIO device lacks {direction} channel {identifier!r}")
    return channel


def _read_number(owner: Any, name: str) -> float:
    try:
        text = str(owner.attrs[name].value)
    except (AttributeError, KeyError, TypeError) as error:
        raise EnvironmentSurveyError(f"IIO attribute {name!r} is unavailable") from error
    token = text.strip().split(maxsplit=1)[0]
    try:
        value = float(token)
    except ValueError as error:
        raise EnvironmentSurveyError(f"IIO attribute {name!r} is not numeric") from error
    if not math.isfinite(value):
        raise EnvironmentSurveyError(f"IIO attribute {name!r} is non-finite")
    return value


def _write_number(owner: Any, name: str, value: float, *, tolerance: float) -> None:
    try:
        owner.attrs[name].value = str(value)
    except (AttributeError, KeyError, TypeError) as error:
        raise EnvironmentSurveyError(f"IIO attribute {name!r} is not writable") from error
    observed = _read_number(owner, name)
    if abs(observed - value) > tolerance:
        raise EnvironmentSurveyError(
            f"IIO attribute {name!r} read back {observed}, expected {value}"
        )


def _attribute_mapping(owner: Any) -> Mapping[str, Any]:
    attrs = getattr(owner, "attrs", None)
    return attrs if isinstance(attrs, Mapping) else {}


def _read_required_bool_attr(owner: Any, names: Sequence[str]) -> bool:
    attrs = _attribute_mapping(owner)
    for name in names:
        if name not in attrs:
            continue
        value = str(attrs[name].value).strip().lower()
        if value in {"0", "false", "disabled"}:
            return False
        if value in {"1", "true", "enabled"}:
            return True
        raise EnvironmentSurveyError(f"required TX attribute {name!r} is not boolean")
    raise EnvironmentSurveyError(f"required TX attribute aliases are unavailable: {tuple(names)!r}")


def _read_required_int_attr(owner: Any, names: Sequence[str]) -> int:
    attrs = _attribute_mapping(owner)
    for name in names:
        if name not in attrs:
            continue
        value = _read_number(owner, name)
        if not value.is_integer() or value < 0:
            raise EnvironmentSurveyError(f"required TX attribute {name!r} is not uint")
        return int(value)
    raise EnvironmentSurveyError(f"required TX attribute aliases are unavailable: {tuple(names)!r}")


def _write_required_zero_attr(owner: Any, names: Sequence[str]) -> None:
    attrs = _attribute_mapping(owner)
    for name in names:
        if name not in attrs:
            continue
        attrs[name].value = "0"
        if _read_number(owner, name) != 0:
            raise EnvironmentSurveyError(f"required TX attribute {name!r} did not clear")
        return
    raise EnvironmentSurveyError(f"required TX attribute aliases are unavailable: {tuple(names)!r}")


def _read_scan_enable(device: Any) -> tuple[bool, bool, bool, bool]:
    values: list[bool] = []
    for index in range(4):
        channel = _required_channel(device, f"voltage{index}", True)
        if not hasattr(channel, "enabled"):
            raise EnvironmentSurveyError("required TX scan channel lacks enabled state")
        values.append(bool(channel.enabled))
    return (values[0], values[1], values[2], values[3])


def _read_exposed_rx_attribute(
    phy: Any, attribute: str
) -> tuple[tuple[Literal[0, 1], ...], tuple[float, ...]]:
    channels: list[Literal[0, 1]] = []
    values: list[float] = []
    for index in (0, 1):
        channel = _required_channel(phy, f"voltage{index}", False)
        if attribute in _attribute_mapping(channel):
            channels.append(index)
            values.append(_read_number(channel, attribute))
    if not channels:
        raise EnvironmentSurveyError(
            f"shared AD9361 PHY attribute {attribute!r} is not exposed by either RX channel"
        )
    if any(value != values[0] for value in values[1:]):
        raise EnvironmentSurveyError(
            f"shared AD9361 PHY attribute {attribute!r} differs across exposed RX channels"
        )
    return tuple(channels), tuple(values)
