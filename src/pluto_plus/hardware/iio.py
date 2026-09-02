"""Lazy receive-only libiio/pyadi adapter with stable serial attestation."""

from __future__ import annotations

import errno
import importlib
import re
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any, Literal

import numpy as np

from pluto_plus.diagnostic_profiles import SUPPORTED_AD936X_PHY_MODELS, parse_metadata_abi
from pluto_plus.errors import RadioConfigurationError, RadioSetupRequiredError
from pluto_plus.hardware.base import (
    DEFAULT_RESTORE_LO_SEARCH_HZ,
    SampleBlock,
)
from pluto_plus.hardware.iio_iq_decode import (
    IioIqDecoder,
    read_interleaved_complex64,
    validate_iq_decoder,
)
from pluto_plus.hardware.iio_metadata import (
    ABI3_METADATA_LAYOUTS,
    ABI4_METADATA_FEATURES_TEXT,
    ABI4_METADATA_LAYOUTS,
    ABI4_METADATA_RECORD,
    DIRECT_ASYNC_FRAME_TARGET_MAX,
    SUPPORTED_METADATA_ABIS,
    SUPPORTED_METADATA_STATUS_VERSIONS,
    IioMetadataCaptureSession,
    configure_iio_context_timeout,
    metadata_iio_context_timeout_ms,
    parse_metadata_layout_capabilities,
    parse_metadata_version_capabilities,
)
from pluto_plus.hardware.preflight import MetadataRuntimeVerification, verify_metadata_runtime
from pluto_plus.models import (
    GainMode,
    RadioCapabilities,
    RadioIdentity,
    RadioSettings,
    Transport,
)
from pluto_plus.rf_profile import RxLayoutExpectation
from pluto_plus.tandem import TandemSessionRequestV1

PLUTO_USB_VENDOR = "0456"
PLUTO_RUNTIME_PRODUCT = "b673"
PLUTO_USB_ROOT = Path("/sys/bus/usb/devices")
ADC_SAMPLE_COUNTER_LOW_REG = 0x800000B8
ADC_GP_CONTROL_REG = 0x800000BC
AD9361_FASTLOCK_PROFILE_COUNT = 8
_CONCRETE_USB_URI = re.compile(r"^usb:[0-9]+[.][0-9]+[.][0-9]+$")
_SERIAL_PATTERN = re.compile(r"^[A-Za-z0-9._:-]{1,128}$")


@dataclass(frozen=True, slots=True)
class IioReceiverSettingsReadback:
    center_frequency_hz: float
    sample_rate_hz: float
    bandwidth_hz: float
    channels: tuple[int, ...]
    gain_modes: tuple[GainMode, ...]
    gain_db: tuple[float, ...]


@dataclass(frozen=True, slots=True)
class IioCaptureRateAttestation:
    """Independent RFIC/capture readbacks for a factor-one receive stream."""

    requested_rate_hz: int
    phy_rate_hz: int
    capture_rate_hz: int
    capture_rates_available_hz: tuple[int, ...]
    fpga_decimation_factor: int
    fpga_decimation_bypass: bool
    adc_gp_control: int


@dataclass(frozen=True, slots=True)
class IioRxSignalPathAttestation:
    """Exact AD936x receive-filter and gain state bound to a rate proof."""

    receiver_channels: tuple[int, ...]
    requested_rf_bandwidth_hz: int
    rf_bandwidth_hz: tuple[int, ...]
    requested_gain_mode: GainMode
    gain_modes: tuple[GainMode, ...]
    requested_manual_gain_db: tuple[float, ...] | None
    hardware_gain_db: tuple[float, ...]
    requested_fir_enabled: bool
    fir_enabled: tuple[bool, ...]
    rx_path_rates: str
    trx_rate_governor: str


@dataclass(frozen=True, slots=True)
class IioSampleCounterSlopeAttestation:
    """Host-monotonic slope measurement of the FPGA capture sample counter."""

    expected_rate_hz: int
    observation_seconds_requested: float
    counter_start_low32: int
    counter_end_low32: int
    counter_delta: int
    host_elapsed_ns: int
    start_read_span_ns: int
    end_read_span_ns: int
    measured_rate_hz: float
    error_ppm: float
    tolerance_ppm: float
    within_tolerance: bool


@dataclass(frozen=True, slots=True)
class IioExactUsbRxOnlyRateEvidence:
    """Identity and clock proof from a direct RX-only libiio context."""

    serial: str
    usb_sysfs_path: str
    usb_uri: str
    hardware_model: str
    firmware_version: str
    phy_model: str
    rx_scan_channels: tuple[str, ...]
    access_path: Literal["direct-libiio"]
    rate: IioCaptureRateAttestation
    signal_path: IioRxSignalPathAttestation | None = None
    sample_counter_slope: IioSampleCounterSlopeAttestation | None = None


def configure_exact_usb_rx_only_source_locked_rate(
    *,
    serial: str,
    usb_sysfs_path: Path,
    expected_rx_layout: RxLayoutExpectation,
    rate_hz: int,
    expected_hardware_model: str | None = None,
    expected_firmware_version: str | None = None,
    expected_metadata_abi: int | None = None,
    rf_bandwidth_hz: int | None = None,
    gain_mode: GainMode | None = None,
    manual_gain_db: tuple[float, ...] | None = None,
    fir_enabled: bool | None = None,
    sample_counter_observation_seconds: float | None = None,
    sample_counter_tolerance_ppm: float = 10_000.0,
    iio_module: ModuleType | Any | None = None,
) -> IioExactUsbRxOnlyRateEvidence:
    """Program and attest one exact RX-only Pluto without requiring a TX facade."""

    _validate_source_locked_rate(rate_hz)
    _validate_rx_signal_path_request(
        expected_rx_layout=expected_rx_layout,
        rf_bandwidth_hz=rf_bandwidth_hz,
        gain_mode=gain_mode,
        manual_gain_db=manual_gain_db,
        fir_enabled=fir_enabled,
    )
    _validate_counter_slope_request(
        rate_hz=rate_hz,
        observation_seconds=sample_counter_observation_seconds,
        tolerance_ppm=sample_counter_tolerance_ppm,
    )
    uri = exact_usb_iio_uri(usb_sysfs_path, serial)
    module = iio_module
    if module is None:
        try:
            module = importlib.import_module("iio")
        except ImportError as error:
            raise ImportError("direct RX-only rate control requires pylibiio") from error
    context = module.Context(uri)
    try:
        configure_iio_context_timeout(context)
        facts = context_facts(context)
        observed_serial = str(facts.get("serial") or "")
        observed_model = str(facts.get("model") or "")
        observed_firmware = str(facts.get("firmware_version") or "")
        observed_usb_path = _optional_string(facts.get("usb_path"))
        if observed_serial != serial:
            raise RadioConfigurationError(
                f"opened Pluto serial {observed_serial!r}, expected {serial!r}"
            )
        if observed_usb_path is not None and observed_usb_path != str(usb_sysfs_path):
            raise RadioConfigurationError(
                f"opened Pluto USB path {observed_usb_path!r}, expected {str(usb_sysfs_path)!r}"
            )
        if expected_hardware_model is not None and observed_model != expected_hardware_model:
            raise RadioConfigurationError(
                f"opened Pluto model {observed_model!r}, expected {expected_hardware_model!r}"
            )
        if (
            expected_firmware_version is not None
            and observed_firmware != expected_firmware_version
        ):
            raise RadioConfigurationError(
                f"opened Pluto firmware {observed_firmware!r}, "
                f"expected {expected_firmware_version!r}"
            )
        _require_rx_layout(facts, expected_rx_layout)
        _select_context_metadata_abi(facts, expected=expected_metadata_abi)
        if _device_exists(context, "cf-ad9361-dds-core-lpc") or _device_exists(
            context, "tandem-agc"
        ):
            raise RadioConfigurationError(
                "direct RX-only rate control requires no DDS or tandem IIO device"
            )
        rate = _configure_context_source_locked_rx_rate(context, rate_hz)
        signal_path = None
        if rf_bandwidth_hz is not None:
            assert gain_mode is not None
            assert fir_enabled is not None
            signal_path = _configure_context_rx_signal_path(
                context,
                expected_rx_layout=expected_rx_layout,
                rf_bandwidth_hz=rf_bandwidth_hz,
                gain_mode=gain_mode,
                manual_gain_db=manual_gain_db,
                fir_enabled=fir_enabled,
            )
        sample_counter_slope = None
        if sample_counter_observation_seconds is not None:
            sample_counter_slope = _attest_context_sample_counter_slope(
                context,
                expected_rate_hz=rate_hz,
                observation_seconds=sample_counter_observation_seconds,
                tolerance_ppm=sample_counter_tolerance_ppm,
            )
        raw_scan_channels = facts.get("rx_scan_channels")
        rx_scan_channels = (
            tuple(str(item) for item in raw_scan_channels)
            if isinstance(raw_scan_channels, (tuple, list))
            else ()
        )
        return IioExactUsbRxOnlyRateEvidence(
            serial=observed_serial,
            usb_sysfs_path=str(usb_sysfs_path),
            usb_uri=uri,
            hardware_model=observed_model,
            firmware_version=observed_firmware,
            phy_model=str(facts.get("phy_model") or ""),
            rx_scan_channels=rx_scan_channels,
            access_path="direct-libiio",
            rate=rate,
            signal_path=signal_path,
            sample_counter_slope=sample_counter_slope,
        )
    finally:
        close = getattr(context, "close", None)
        if callable(close):
            close()


def _receiver_settings_restored(
    snapshot: IioReceiverSettingsReadback,
    readback: IioReceiverSettingsReadback,
) -> bool:
    """Compare exact settable state while treating AGC gain as observation only."""

    if (
        readback.center_frequency_hz != snapshot.center_frequency_hz
        or readback.sample_rate_hz != snapshot.sample_rate_hz
        or readback.bandwidth_hz != snapshot.bandwidth_hz
        or readback.channels != snapshot.channels
        or readback.gain_modes != snapshot.gain_modes
    ):
        return False
    return all(
        mode is not GainMode.MANUAL or actual == expected
        for mode, actual, expected in zip(
            snapshot.gain_modes, readback.gain_db, snapshot.gain_db, strict=True
        )
    )


class IioRadioDevice:
    """One pyadi context controlling one or both Pluto+ receive channels."""

    def __init__(
        self,
        uri: str,
        *,
        serial: str | None = None,
        expected_usb_path: str | None = None,
        usb_sysfs_path: Path | None = None,
        mutation_preflight: Callable[[], None] | None = None,
        require_idle_tandem_owner: bool = False,
        radio_id: str | None = None,
        adi_module: ModuleType | Any | None = None,
        iio_module: ModuleType | Any | None = None,
        iio_contexts: Mapping[str, str] | None = None,
        expected_metadata_abi: int | None = None,
        iq_decoder: IioIqDecoder = "pyadi",
    ) -> None:
        if expected_metadata_abi not in {None, 1, 2, 3, 4}:
            raise ValueError("expected_metadata_abi must be 1, 2, 3, 4, or None")
        validate_iq_decoder(iq_decoder)
        normalized = uri.removeprefix("pluto://")
        if usb_sysfs_path is not None:
            if serial is None or not normalized.startswith("usb:"):
                raise ValueError("exact USB sysfs IIO selection requires a serial and USB URI")
            selected_path = str(usb_sysfs_path)
            if expected_usb_path not in {None, selected_path}:
                raise ValueError("expected USB path conflicts with exact USB sysfs selection")
            normalized = exact_usb_iio_uri(usb_sysfs_path, serial)
            expected_usb_path = selected_path
        self._configured_uri = normalized
        self._requested_serial = serial
        self._expected_usb_path = expected_usb_path
        self._usb_sysfs_path = usb_sysfs_path
        self._mutation_preflight = mutation_preflight
        self._require_idle_tandem_owner = require_idle_tandem_owner
        self._radio_id = radio_id or serial or normalized
        self._adi_module = adi_module
        self._iio_module = iio_module
        self._iio_contexts = iio_contexts
        self._expected_metadata_abi = expected_metadata_abi
        self._iq_decoder = iq_decoder
        self._metadata_runtime: MetadataRuntimeVerification | None = None
        self._selected_metadata_abi: int | None = None
        self._device: Any | None = None
        self._rx_layout_expectation: RxLayoutExpectation | None = None
        self._buffer_size: int | None = None
        self._metadata_capture: IioMetadataCaptureSession | None = None
        self._kernel_buffer_configuration_basis: Literal[
            "not_configured", "setter_accepted", "readback"
        ] = "not_configured"
        self._diagnostic_facts: dict[str, object] = {}
        transport = Transport.IIO_USB if normalized.startswith("usb:") else Transport.IIO_IP
        self._identity = RadioIdentity(
            radio_id=self._radio_id,
            serial=serial or "unattested",
            uri=normalized,
            transport=transport,
        )
        self._capabilities = RadioCapabilities(
            receiver_channels=(0, 1),
            supports_live_tuning=True,
            supports_volatile_firmware=transport is Transport.IIO_USB,
            supports_persistent_firmware=transport is Transport.IIO_USB,
            minimum_sample_rate_hz=520_833,
            maximum_sample_rate_hz=30_720_000,
        )

    @property
    def identity(self) -> RadioIdentity:
        return self._identity

    @property
    def capabilities(self) -> RadioCapabilities:
        return self._capabilities

    @property
    def kernel_buffer_configuration_basis(
        self,
    ) -> Literal["not_configured", "setter_accepted", "readback"]:
        """State whether kernel-buffer configuration had an independent readback."""

        return self._kernel_buffer_configuration_basis

    def configure_rx_layout(self, expectation: RxLayoutExpectation | None) -> None:
        """Select an already-attested RX layout before the next open."""

        if self._device is not None:
            raise RuntimeError("IIO RX layout can change only while the radio is closed")
        self._rx_layout_expectation = expectation

    def open(self) -> None:
        if self._device is not None:
            raise RuntimeError("IIO radio is already open")
        self._diagnostic_facts = {}
        self._metadata_runtime = None
        self._selected_metadata_abi = None
        injected_runtime = self._adi_module is not None and self._iio_module is not None
        if self._expected_metadata_abi is not None and not injected_runtime:
            # This must happen before importing pyadi: pyadi imports pylibiio,
            # and an ambient object which has already satisfied libiio.so.0
            # cannot be replaced safely later in this process. Reverify on
            # every open so a closed/reopened adapter never loses its runtime
            # attestation while retaining the already imported module.
            self._metadata_runtime = verify_metadata_runtime(self._expected_metadata_abi)
            if self._iio_module is None:
                self._iio_module = importlib.import_module("iio")
        module = self._adi_module
        if module is None:
            try:
                module = importlib.import_module("adi")
            except (ImportError, AttributeError) as error:
                raise ImportError(
                    "IIO hardware requires the 'hardware' extra and a compatible native libiio"
                ) from error
        configured_uri = self._configured_uri
        if self._usb_sysfs_path is not None:
            if self._requested_serial is None:  # pragma: no cover - constructor invariant
                raise RuntimeError("exact USB sysfs selection lost its serial")
            configured_uri = exact_usb_iio_uri(
                self._usb_sysfs_path,
                self._requested_serial,
            )
        uri = resolve_iio_uri(
            configured_uri,
            self._requested_serial,
            contexts=self._iio_contexts,
        )
        # pyadi's ad9361/ad9363 facades enumerate all four 2R2T component
        # channels before creating a buffer. A genuine 1R1T context exposes
        # only voltage0/voltage1, so use its one-complex-channel ad9364 facade;
        # the independently attested context model still enforces the selected
        # AD9361/AD9363A driver personality below.
        facade_name = (
            "ad9364"
            if self._rx_layout_expectation is not None
            and self._rx_layout_expectation.receiver_channels == (0,)
            else "ad9361"
        )
        facade = getattr(module, facade_name, None)
        if not callable(facade):
            raise RadioConfigurationError(
                f"pyadi runtime does not provide the required {facade_name} facade"
            )
        device = facade(uri=uri)
        attested = False
        try:
            configure_iio_context_timeout(device.ctx)
            facts = context_facts(device.ctx)
            facts["pyadi_facade"] = facade_name
            detected_serial = str(facts.get("serial") or "")
            if self._requested_serial and detected_serial != self._requested_serial:
                raise RadioConfigurationError(
                    f"opened Pluto serial {detected_serial!r}, expected {self._requested_serial!r}"
                )
            if not detected_serial:
                if not self._requested_serial:
                    raise RadioConfigurationError("selected IIO context did not report a serial")
                detected_serial = self._requested_serial
            usb_path = _optional_string(facts.get("usb_path"))
            if usb_path is None:
                usb_path = find_usb_sysfs_path(detected_serial)
            if self._expected_usb_path is not None and usb_path != self._expected_usb_path:
                raise RadioConfigurationError(
                    f"opened Pluto USB path {usb_path!r}, expected {self._expected_usb_path!r}"
                )
            if self._require_idle_tandem_owner:
                first_tandem = (
                    facts.get("tandem_agc_state"),
                    facts.get("tandem_agc_ownership_epoch"),
                    facts.get("tandem_agc_fault_flags"),
                )
                second_tandem = _tandem_owner_snapshot(device.ctx)
                facts["tandem_agc_second_owner_snapshot"] = second_tandem
                if first_tandem != (0, 0, 0) or second_tandem != first_tandem:
                    raise RadioConfigurationError(
                        "Fast Lock requires two stable idle tandem-owner snapshots, got "
                        f"{first_tandem!r} then {second_tandem!r}"
                    )
            firmware_capable = usb_path is not None
            self._identity = RadioIdentity(
                radio_id=self._radio_id,
                serial=detected_serial,
                uri=uri,
                transport=(Transport.IIO_USB if uri.startswith("usb:") else Transport.IIO_IP),
                model=str(facts.get("model") or "Pluto+"),
                firmware_version=_optional_string(facts.get("firmware_version")),
                usb_path=usb_path,
            )
            self._capabilities = self._capabilities.model_copy(
                update={
                    "supports_volatile_firmware": firmware_capable,
                    "supports_persistent_firmware": firmware_capable,
                }
            )
            self._diagnostic_facts = {
                **facts,
                "usb_path": usb_path,
                "boot_provenance": None,
                "uboot": None,
            }
            if self._mutation_preflight is not None:
                self._mutation_preflight()
            # Nothing above this point may alter buffers, RF state, channels, or
            # TX state. A concrete BUS.DEVICE can be reused between inventory
            # and open; only mutate after both serial and sysfs path attest.
            attested = True
            device.rx_destroy_buffer()
            # Capture identity and passive context facts before accessing any
            # per-channel pyadi properties. A 1R1T device raises a bare Exception
            # from those getters rather than AttributeError.
            _mute_transmit(device)
            _require_rx_layout(facts, self._rx_layout_expectation)
            if self._rx_layout_expectation is not None:
                device.rx_enabled_channels = list(
                    self._rx_layout_expectation.receiver_channels
                )
                enabled_channels = tuple(int(item) for item in device.rx_enabled_channels)
                if enabled_channels != self._rx_layout_expectation.receiver_channels:
                    raise RadioConfigurationError(
                        "IIO RX channel selection readback is "
                        f"{enabled_channels}, expected "
                        f"{self._rx_layout_expectation.receiver_channels}"
                    )
            actual_metadata_abi = _select_context_metadata_abi(
                facts, expected=self._expected_metadata_abi
            )
            facts["buffer_metadata_selected_abi"] = actual_metadata_abi
            self._diagnostic_facts["buffer_metadata_selected_abi"] = actual_metadata_abi
            injected_runtime = self._adi_module is not None and self._iio_module is not None
            expected_layouts = (
                ABI3_METADATA_LAYOUTS
                if actual_metadata_abi == 3
                else ABI4_METADATA_LAYOUTS
                if actual_metadata_abi == 4
                else None
            )
            if expected_layouts is not None and facts.get("buffer_metadata_layouts") != (
                expected_layouts
            ):
                raise RadioConfigurationError(
                    f"metadata ABI {actual_metadata_abi} radio did not advertise "
                    "the canonical RX layouts"
                )
            if actual_metadata_abi == 4 and (
                facts.get("buffer_metadata_record_raw") != str(ABI4_METADATA_RECORD)
                or facts.get("buffer_metadata_features_raw") != ABI4_METADATA_FEATURES_TEXT
            ):
                raise RadioConfigurationError(
                    "metadata ABI 4 radio did not advertise the exact record/features contract"
                )
            runtime_ready = actual_metadata_abi in {1, 2, 3, 4} and (
                self._metadata_runtime is not None or injected_runtime
            )
            if runtime_ready:
                counter_reader = getattr(getattr(device, "_rxadc", None), "reg_read", None)
                if not callable(counter_reader):
                    raise RadioConfigurationError(
                        "metadata runtime lacks FPGA sample-counter register access"
                    )
                try:
                    int(counter_reader(0x800000B8)) & 0xFFFFFFFF
                except (AttributeError, OSError, TypeError, ValueError) as error:
                    raise RadioConfigurationError(
                        "FPGA sample-counter register probe failed"
                    ) from error
            self._capabilities = self._capabilities.model_copy(
                update={
                    "supports_device_sample_counter": runtime_ready,
                    "supports_continuity_sequence": runtime_ready,
                }
            )
            self._device = device
            self._selected_metadata_abi = actual_metadata_abi
            self._capabilities = self._capabilities.model_copy(
                update={
                    "receiver_channels": (
                        (0, 1)
                        if self._rx_layout_expectation is None
                        else self._rx_layout_expectation.receiver_channels
                    )
                }
            )
        except BaseException as failure:
            self._selected_metadata_abi = None
            try:
                if attested:
                    _release_device(device)
                else:
                    _close_context_only(device)
            except BaseException as cleanup_error:
                failure.add_note(f"IIO open cleanup also failed: {cleanup_error!r}")
            raise

    def close(self) -> None:
        errors: list[BaseException] = []
        try:
            self.reset_receive_buffer()
        except BaseException as error:
            errors.append(error)
        device, self._device = self._device, None
        self._buffer_size = None
        self._metadata_runtime = None
        self._selected_metadata_abi = None
        self._capabilities = self._capabilities.model_copy(
            update={
                "supports_device_sample_counter": False,
                "supports_continuity_sequence": False,
            }
        )
        self._diagnostic_facts = {}
        if device is not None:
            try:
                _release_device(device)
            except BaseException as error:
                errors.append(error)
        if errors:
            raise errors[0]

    def read_settings(self) -> RadioSettings:
        device = self._require_device()
        channels = tuple(int(item) for item in device.rx_enabled_channels)
        if not channels:
            channels = (
                (0, 1)
                if self._rx_layout_expectation is None
                else self._rx_layout_expectation.receiver_channels
            )
        modes = tuple(
            GainMode(str(getattr(device, f"gain_control_mode_chan{channel}")))
            for channel in channels
        )
        if len(set(modes)) != 1:
            raise RadioConfigurationError(f"receiver gain modes differ: {modes}")
        mode = modes[0]
        gain = None
        if mode is GainMode.MANUAL:
            gains = tuple(
                float(getattr(device, f"rx_hardwaregain_chan{channel}")) for channel in channels
            )
            if max(gains) - min(gains) > 0.25:
                raise RadioConfigurationError(f"receiver manual gains differ: {gains}")
            gain = sum(gains) / len(gains)
        return RadioSettings(
            center_frequency_hz=float(device.rx_lo),
            sample_rate_hz=float(device.sample_rate),
            bandwidth_hz=float(device.rx_rf_bandwidth),
            gain_mode=mode,
            gain_db=gain,
            channels=channels,
        )

    def apply_settings(self, settings: RadioSettings) -> RadioSettings:
        device = self._require_device()
        if any(
            channel not in self._capabilities.receiver_channels
            for channel in settings.channels
        ):
            raise RadioConfigurationError(
                "requested receiver channels are outside the selected RX layout"
            )
        self.reset_receive_buffer()
        device.sample_rate = round(settings.sample_rate_hz)
        device.rx_rf_bandwidth = round(settings.bandwidth_hz)
        device.rx_lo = round(settings.center_frequency_hz)
        device.rx_enabled_channels = list(settings.channels)
        for channel in settings.channels:
            setattr(device, f"gain_control_mode_chan{channel}", settings.gain_mode.value)
            if settings.gain_mode is GainMode.MANUAL:
                assert settings.gain_db is not None
                setattr(device, f"rx_hardwaregain_chan{channel}", settings.gain_db)
        _mute_transmit(device)
        return self.read_settings()

    def ensure_transmit_muted(self) -> None:
        """Apply and read back the adapter's ordinary fail-closed TX guard."""

        _mute_transmit(self._require_device())

    def read_receiver_gain_state(
        self, channels: tuple[int, ...] = (0, 1)
    ) -> tuple[tuple[GainMode, ...], tuple[float, ...]]:
        """Read each requested RX channel's mode and gain without changing cadence."""

        if (
            not channels
            or len(set(channels)) != len(channels)
            or any(channel not in (0, 1) for channel in channels)
        ):
            raise ValueError("receiver gain-state channels must be unique RX0/RX1 values")
        device = self._require_device()
        modes = tuple(
            GainMode(str(getattr(device, f"gain_control_mode_chan{channel}")))
            for channel in channels
        )
        gains = tuple(
            float(getattr(device, f"rx_hardwaregain_chan{channel}")) for channel in channels
        )
        if not all(np.isfinite(gain) for gain in gains):
            raise RadioConfigurationError("receiver gain readback is non-finite")
        return modes, gains

    def read_receiver_settings_readback(self) -> IioReceiverSettingsReadback:
        """Read exact paired-RX fields without collapsing per-channel gains."""

        device = self._require_device()
        channels = tuple(int(item) for item in device.rx_enabled_channels)
        modes, gains = self.read_receiver_gain_state(channels)
        numeric = (
            float(device.rx_lo),
            float(device.sample_rate),
            float(device.rx_rf_bandwidth),
        )
        if not all(np.isfinite(value) for value in numeric):
            raise RadioConfigurationError("receiver settings readback is non-finite")
        return IioReceiverSettingsReadback(
            center_frequency_hz=numeric[0],
            sample_rate_hz=numeric[1],
            bandwidth_hz=numeric[2],
            channels=channels,
            gain_modes=modes,
            gain_db=gains,
        )

    def restore_receiver_settings_readback(
        self,
        snapshot: IioReceiverSettingsReadback,
        *,
        maximum_lo_offset_hz: int = DEFAULT_RESTORE_LO_SEARCH_HZ,
    ) -> IioReceiverSettingsReadback:
        """Restore every settable RX field and require its exact hardware readback."""

        if maximum_lo_offset_hz < 0:
            raise ValueError("maximum LO restoration offset cannot be negative")
        device = self._require_device()
        self.reset_receive_buffer()
        device.sample_rate = round(snapshot.sample_rate_hz)
        device.rx_rf_bandwidth = round(snapshot.bandwidth_hz)
        device.rx_enabled_channels = list(snapshot.channels)
        for channel, mode, gain_db in zip(
            snapshot.channels, snapshot.gain_modes, snapshot.gain_db, strict=True
        ):
            setattr(device, f"gain_control_mode_chan{channel}", mode.value)
            if mode is GainMode.MANUAL:
                setattr(device, f"rx_hardwaregain_chan{channel}", gain_db)
        _mute_transmit(device)
        requested_lo = round(snapshot.center_frequency_hz)
        offsets = (
            0,
            *tuple(value for step in range(1, maximum_lo_offset_hz + 1) for value in (-step, step)),
        )
        last: IioReceiverSettingsReadback | None = None
        for offset in offsets:
            device.rx_lo = requested_lo + offset
            last = self.read_receiver_settings_readback()
            if _receiver_settings_restored(snapshot, last):
                return last
        raise RadioConfigurationError(
            "lossless per-channel RX settings restoration did not read back exactly: "
            f"snapshot={snapshot!r} last={last!r}"
        )

    def read_block(self, sample_count: int) -> SampleBlock:
        """Read legacy host-timed IQ with continuity explicitly unobservable."""

        from pluto_plus.data_plane import require_safe_iio_buffer

        device = self._require_device()
        if self._metadata_capture is not None and self._metadata_capture.is_open:
            raise RuntimeError(
                "legacy read_block cannot run during a metadata capture; "
                "use the session's read_block instead"
            )
        if sample_count <= 0:
            raise ValueError("sample_count must be positive")
        receiver_count = len(tuple(device.rx_enabled_channels))
        require_safe_iio_buffer(sample_count, receiver_count)
        if self._buffer_size != sample_count:
            device.rx_destroy_buffer()
            device.rx_buffer_size = sample_count
            self._buffer_size = sample_count
        before = time.time_ns()
        if self._iq_decoder == "raw-complex64":
            try:
                raw = read_interleaved_complex64(
                    device,
                    samples_per_channel=sample_count,
                    channels=tuple(int(item) for item in device.rx_enabled_channels),
                )
            except BaseException:
                self.reset_receive_buffer()
                raise
        else:
            raw = device.rx()
        after = time.time_ns()
        values = np.asarray(raw)
        expected_receivers = len(tuple(device.rx_enabled_channels))
        if expected_receivers == 1 and values.ndim == 1:
            values = values[np.newaxis, :]
        if values.ndim != 2 or values.shape != (expected_receivers, sample_count):
            raise RuntimeError(
                f"Pluto read returned {values.shape}, expected "
                f"({expected_receivers}, {sample_count})"
            )
        return SampleBlock(
            utc_ns=(before + after) // 2,
            samples=values.astype(np.complex64, copy=self._iq_decoder == "pyadi"),
        )

    def configure_kernel_buffers(self, count: int) -> int:
        """Set the libiio RX kernel-buffer count before creating a userspace buffer."""

        if count < 1 or count > 64:
            raise ValueError("kernel buffer count must be between 1 and 64")
        device = self._require_device()
        self.reset_receive_buffer()
        rx_device = getattr(device, "_rxadc", None)
        setter = getattr(rx_device, "set_kernel_buffers_count", None)
        if not callable(setter):
            raise RadioConfigurationError(
                "installed libiio binding cannot configure RX kernel buffers"
            )
        result = setter(count)
        if isinstance(result, int) and result < 0:
            raise RadioConfigurationError(
                f"libiio rejected RX kernel buffer count {count}: error {result}"
            )
        actual = getattr(rx_device, "kernel_buffers_count", None)
        if actual is None:
            self._kernel_buffer_configuration_basis = "setter_accepted"
            return count
        if int(actual) != count:
            raise RadioConfigurationError(
                f"RX kernel buffer read-back is {actual}, expected {count}"
            )
        self._kernel_buffer_configuration_basis = "readback"
        return int(actual)

    def read_kernel_buffers_count(self) -> int:
        """Return the live kernel-buffer count, failing if readback is unavailable."""

        rx_device = getattr(self._require_device(), "_rxadc", None)
        actual = getattr(rx_device, "kernel_buffers_count", None)
        if actual is None:
            raise RadioConfigurationError(
                "installed libiio binding cannot read back RX kernel buffers"
            )
        return int(actual)

    def reset_receive_buffer(self) -> None:
        """Synchronously destroy any ordinary or metadata RX buffer.

        This operation is idempotent and defines the reset boundary required
        before a new dwell or retuned scanner target.
        """

        capture, self._metadata_capture = self._metadata_capture, None
        if capture is not None:
            capture.close()
        device = self._device
        self._buffer_size = None
        if device is not None:
            buffer = getattr(device, "_rxbuf", None)
            device.rx_destroy_buffer()
            close = getattr(buffer, "close", None)
            if callable(close):
                close()

    def tune_center_frequency(self, center_frequency_hz: float) -> float:
        """Reset RX, tune the LO, and return the exact hardware readback."""

        self.write_center_frequency(center_frequency_hz)
        return self.read_center_frequency()

    def write_center_frequency(self, center_frequency_hz: float) -> None:
        """Issue one ordinary RX-LO write after enforcing a bufferless boundary."""

        if center_frequency_hz <= 0:
            raise ValueError("center_frequency_hz must be positive")
        device = self._require_device()
        self.reset_receive_buffer()
        device.rx_lo = round(center_frequency_hz)

    def write_center_frequency_bufferless(self, center_frequency_hz: float) -> None:
        """Issue only an RX-LO attribute write after proving no local RX buffer exists."""

        if center_frequency_hz <= 0:
            raise ValueError("center_frequency_hz must be positive")
        self._require_bufferless_device().rx_lo = round(center_frequency_hz)

    def read_center_frequency(self) -> float:
        """Return the live RX synthesizer frequency, including Fast Lock state."""

        return float(self._require_device().rx_lo)

    def mute_transmit(self) -> None:
        """Apply and verify the adapter's receive-only transmit safety state."""

        _mute_transmit(self._require_device())

    def read_device_sample_counter_low32(self) -> int:
        """Read the free-running FPGA sample counter without arming an RX buffer."""

        device = self._require_device()
        reader = getattr(getattr(device, "_rxadc", None), "reg_read", None)
        if not callable(reader):
            raise RadioConfigurationError(
                "installed libiio binding cannot read the FPGA sample-counter register"
            )
        try:
            return int(reader(ADC_SAMPLE_COUNTER_LOW_REG)) & 0xFFFFFFFF
        except (AttributeError, OSError, TypeError, ValueError) as error:
            raise RadioConfigurationError("FPGA sample-counter register read failed") from error

    def configure_source_locked_rx_rate(self, rate_hz: int) -> IioCaptureRateAttestation:
        """Program the RFIC source and prove the FPGA capture path is factor one.

        Pluto device trees can advertise a fixed /8 receive filter. In that
        configuration, writing only the capture device's sampling frequency
        selects either parent or parent/8; it does not program the AD936x
        source. Program the RFIC first, explicitly select the parent rate on
        the capture device, and require independent rate and bypass readbacks.
        """

        _validate_source_locked_rate(rate_hz)
        device = self._require_device()
        self.reset_receive_buffer()
        device.sample_rate = rate_hz
        try:
            phy_rate_hz = int(device.sample_rate)
        except (AttributeError, OSError, TypeError, ValueError) as error:
            raise RadioConfigurationError("AD936x source-rate readback failed") from error
        if phy_rate_hz != rate_hz:
            raise RadioConfigurationError(
                f"AD936x source rate read back {phy_rate_hz}, expected {rate_hz}"
            )

        capture = _capture_rate_channel(device)
        sampling_frequency = capture.attrs["sampling_frequency"]
        sampling_frequency_available = capture.attrs["sampling_frequency_available"]
        try:
            sampling_frequency.value = str(rate_hz)
            capture_rate_hz = int(sampling_frequency.value)
            capture_rates_available_hz = tuple(
                int(value)
                for value in str(sampling_frequency_available.value)
                .strip()
                .replace("[", "")
                .replace("]", "")
                .split()
            )
            adc_gp_control = int(device._rxadc.reg_read(ADC_GP_CONTROL_REG)) & 0xFFFFFFFF
        except (AttributeError, OSError, TypeError, ValueError) as error:
            raise RadioConfigurationError("FPGA capture-rate attestation failed") from error

        fpga_decimation_factor = 8 if adc_gp_control & 1 else 1
        attestation = IioCaptureRateAttestation(
            requested_rate_hz=rate_hz,
            phy_rate_hz=phy_rate_hz,
            capture_rate_hz=capture_rate_hz,
            capture_rates_available_hz=capture_rates_available_hz,
            fpga_decimation_factor=fpga_decimation_factor,
            fpga_decimation_bypass=fpga_decimation_factor == 1,
            adc_gp_control=adc_gp_control,
        )
        expected_available = (rate_hz, rate_hz // 8)
        if (
            capture_rate_hz != rate_hz
            or capture_rates_available_hz != expected_available
            or not attestation.fpga_decimation_bypass
        ):
            raise RadioConfigurationError(
                "source-locked RX rate did not produce an exact factor-one capture path: "
                f"{attestation!r}"
            )
        _mute_transmit(device)
        return attestation

    def store_rx_fastlock_profile(self, profile: int) -> tuple[int, ...]:
        """Store the current RX synthesizer state in one volatile AD9361 profile."""

        _validate_fastlock_profile(profile)
        device = self._require_bufferless_device()
        channel = _rx_fastlock_channel(device)
        channel.attrs["fastlock_store"].value = str(profile)
        return self.save_rx_fastlock_profile(profile)

    def save_rx_fastlock_profile(self, profile: int) -> tuple[int, ...]:
        """Read back one volatile RX Fast Lock profile as its sixteen register bytes."""

        _validate_fastlock_profile(profile)
        device = self._require_bufferless_device()
        attribute = _rx_fastlock_channel(device).attrs["fastlock_save"]
        attribute.value = str(profile)
        raw = str(attribute.value).strip()
        try:
            raw_profile, raw_values = raw.split(maxsplit=1)
            values = tuple(int(value) for value in raw_values.split(","))
        except (TypeError, ValueError) as error:
            raise RadioConfigurationError(
                f"malformed RX Fast Lock profile readback: {raw!r}"
            ) from error
        if (
            int(raw_profile) != profile
            or len(values) != 16
            or any(value < 0 or value > 255 for value in values)
        ):
            raise RadioConfigurationError(
                f"invalid RX Fast Lock profile {profile} readback: {raw!r}"
            )
        return values

    def recall_rx_fastlock_profile(self, profile: int) -> None:
        """Issue one RX Fast Lock recall write without arming an RX buffer."""

        _validate_fastlock_profile(profile)
        device = self._require_bufferless_device()
        _rx_fastlock_channel(device).attrs["fastlock_recall"].value = str(profile)

    def read_active_rx_fastlock_profile(self) -> int | None:
        """Read the active RX Fast Lock profile, or ``None`` when inactive."""

        device = self._require_bufferless_device()
        attribute = _rx_fastlock_channel(device).attrs["fastlock_recall"]
        try:
            active = int(attribute.value)
        except OSError as error:
            if error.errno == errno.EINVAL:
                return None
            raise
        except (TypeError, ValueError) as error:
            raise RadioConfigurationError("RX Fast Lock active-profile readback failed") from error
        _validate_fastlock_profile(active)
        return active

    def _require_bufferless_device(self) -> Any:
        device = self._require_device()
        if self._metadata_capture is not None or getattr(device, "_rxbuf", None) is not None:
            raise RadioConfigurationError(
                "RX Fast Lock control requires no ordinary or metadata RX buffer"
            )
        return device

    def begin_metadata_capture(
        self,
        sample_count: int,
        *,
        kernel_buffers: int,
        tandem_request: TandemSessionRequestV1 | None = None,
        ddr_burst_bytes: int = 0,
        ddr_ring_bytes: int = 0,
        ddr_ring_frames: int = 0,
        ddr_ring_continuous: bool = False,
        direct_async_frames: int = 0,
        drop_backlog_on_overrun: bool = True,
    ) -> IioMetadataCaptureSession:
        """Reset and arm one fail-closed FPGA-metadata capture generation."""

        from pluto_plus.data_plane import require_safe_iio_buffer

        if sample_count <= 0:
            raise ValueError("sample_count must be positive")
        if isinstance(ddr_burst_bytes, bool) or not isinstance(ddr_burst_bytes, int):
            raise TypeError("ddr_burst_bytes must be an integer")
        if ddr_burst_bytes < 0:
            raise ValueError("ddr_burst_bytes must not be negative")
        if isinstance(ddr_ring_bytes, bool) or not isinstance(ddr_ring_bytes, int):
            raise TypeError("ddr_ring_bytes must be an integer")
        if isinstance(ddr_ring_frames, bool) or not isinstance(ddr_ring_frames, int):
            raise TypeError("ddr_ring_frames must be an integer")
        if not isinstance(ddr_ring_continuous, bool):
            raise TypeError("ddr_ring_continuous must be a bool")
        if isinstance(direct_async_frames, bool) or not isinstance(
            direct_async_frames, int
        ):
            raise TypeError("direct_async_frames must be an integer")
        if not 0 <= direct_async_frames <= DIRECT_ASYNC_FRAME_TARGET_MAX:
            raise ValueError(
                f"direct_async_frames must be in [0, {DIRECT_ASYNC_FRAME_TARGET_MAX}]"
            )
        if not isinstance(drop_backlog_on_overrun, bool):
            raise TypeError("drop_backlog_on_overrun must be a bool")
        if direct_async_frames and kernel_buffers < 2:
            raise ValueError("direct async capture requires at least two kernel buffers")
        if direct_async_frames and ddr_ring_bytes and kernel_buffers < 3:
            raise ValueError(
                "direct async RAM extension requires at least three kernel buffers"
            )
        if ddr_ring_bytes < 0 or ddr_ring_frames < 0:
            raise ValueError("DDR ring values must not be negative")
        if ddr_burst_bytes and ddr_ring_bytes:
            raise ValueError("device DDR burst and DDR ring are mutually exclusive")
        if direct_async_frames and ddr_burst_bytes:
            raise ValueError("direct async capture cannot use the sealed DDR burst")
        if ddr_ring_bytes:
            if direct_async_frames and (ddr_ring_frames or ddr_ring_continuous):
                raise ValueError(
                    "direct async RAM extension owns the finite frame target"
                )
            if ddr_ring_continuous and ddr_ring_frames:
                raise ValueError("continuous DDR ring must not specify a frame target")
            if not direct_async_frames and not ddr_ring_continuous and not ddr_ring_frames:
                raise ValueError("finite DDR ring requires a positive frame target")
        elif ddr_ring_frames or ddr_ring_continuous:
            raise ValueError("DDR ring mode requires a positive byte budget")
        device = self._require_device()
        self.reset_receive_buffer()
        channels = tuple(int(item) for item in device.rx_enabled_channels)
        if channels not in {(0,), (1,), (0, 1)}:
            raise RadioConfigurationError("metadata capture receiver selection is not canonical")
        require_safe_iio_buffer(sample_count, len(channels))
        facts = context_facts(device.ctx)
        metadata_abi = _select_context_metadata_abi(
            facts, expected=self._expected_metadata_abi
        )
        if metadata_abi != self._selected_metadata_abi:
            raise RadioConfigurationError(
                "metadata ABI capability changed after the radio was opened"
            )
        if metadata_abi not in {1, 2, 3, 4}:
            raise RadioConfigurationError(
                "metadata capture requires supported context capability "
                "iio,buffer-metadata=1, 2, 3, or 4"
            )
        if metadata_abi in {1, 2} and channels != (0, 1):
            raise RadioConfigurationError("metadata ABI 1 and 2 require paired RX channels")
        if metadata_abi in {3, 4}:
            layouts = facts.get("buffer_metadata_layouts")
            expected_layouts = (
                ABI3_METADATA_LAYOUTS if metadata_abi == 3 else ABI4_METADATA_LAYOUTS
            )
            if layouts != expected_layouts:
                raise RadioConfigurationError(
                    f"metadata ABI {metadata_abi} requires the exact canonical RX "
                    "layout capability"
                )
            expected_mask = {(0,): 0x03, (1,): 0x0C, (0, 1): 0x0F}[channels]
            layout = next(item for item in layouts if item.scan_mask == expected_mask)
            if sample_count % layout.sample_count_multiple:
                raise RadioConfigurationError(
                    "metadata sample count violates the advertised RX layout multiple"
                )
        if metadata_abi == 4 and (
            facts.get("buffer_metadata_record_raw") != str(ABI4_METADATA_RECORD)
            or facts.get("buffer_metadata_features_raw") != ABI4_METADATA_FEATURES_TEXT
        ):
            raise RadioConfigurationError(
                "metadata ABI 4 requires the exact record/features capability contract"
            )
        if ddr_burst_bytes:
            if metadata_abi not in {3, 4} or len(channels) != 1:
                raise RadioConfigurationError(
                    "device DDR burst v1 requires metadata ABI 3/4 and exactly one receiver"
                )
            if facts.get("buffer_ddr_burst") is not True:
                raise RadioConfigurationError(
                    "IIO context does not advertise device DDR burst v1"
                )
            maximum_burst_bytes = facts.get("buffer_ddr_burst_max_iq_bytes")
            if not isinstance(maximum_burst_bytes, int) or maximum_burst_bytes <= 0:
                raise RadioConfigurationError("IIO DDR burst byte limit is invalid")
            frame_iq_bytes = sample_count * 4
            if ddr_burst_bytes < frame_iq_bytes:
                raise RadioConfigurationError(
                    "device DDR burst byte budget cannot hold one complete IIO frame"
                )
            if ddr_burst_bytes > maximum_burst_bytes:
                raise RadioConfigurationError(
                    "device DDR burst byte budget exceeds the advertised limit"
                )
        if ddr_ring_bytes:
            if metadata_abi not in {3, 4} or len(channels) != 1:
                raise RadioConfigurationError(
                    "device DDR ring v1 requires metadata ABI 3/4 and one receiver"
                )
            if facts.get("buffer_ddr_ring") is not True:
                raise RadioConfigurationError("IIO context does not advertise device DDR ring v1")
            if facts.get("buffer_ddr_ring_modes_raw") != "finite,continuous":
                raise RadioConfigurationError("IIO DDR ring mode capability is not canonical")
            status_versions = facts.get("buffer_metadata_status_versions")
            status_versions_state = facts.get("buffer_metadata_status_versions_state")
            if metadata_abi == 4 and (
                status_versions_state != "available"
                or not isinstance(status_versions, tuple)
                or 2 not in status_versions
            ):
                raise RadioConfigurationError(
                    "metadata ABI 4 DDR ring requires metadata status v2 in the explicit "
                    "version set"
                )
            if facts.get("buffer_metadata_status") is not True:
                raise RadioConfigurationError("IIO context cannot report DDR ring status")
            maximum_ring_bytes = facts.get("buffer_ddr_ring_max_iq_bytes")
            if not isinstance(maximum_ring_bytes, int) or maximum_ring_bytes <= 0:
                raise RadioConfigurationError("IIO DDR ring byte limit is invalid")
            frame_iq_bytes = sample_count * len(channels) * 4
            if ddr_ring_bytes < frame_iq_bytes:
                raise RadioConfigurationError(
                    "device DDR ring byte budget cannot hold one complete IIO frame"
                )
            if ddr_ring_bytes > maximum_ring_bytes:
                raise RadioConfigurationError(
                    "device DDR ring byte budget exceeds the advertised limit"
                )
        if metadata_abi in {2, 3, 4} and not facts.get("tandem_agc"):
            raise RadioConfigurationError(
                "metadata ABI 2, 3, and 4 capture requires the tandem-agc IIO device"
            )
        if direct_async_frames:
            if metadata_abi != 3 or len(channels) != 1:
                raise RadioConfigurationError(
                    "direct async capture is qualified only for metadata ABI 3 and one receiver"
                )
            if facts.get("buffer_direct_async") is not True:
                raise RadioConfigurationError(
                    "IIO context does not advertise direct async DMA-to-network capture"
                )
            if facts.get("buffer_direct_async_exact_kernel_queue") is not True:
                raise RadioConfigurationError(
                    "IIO context does not advertise exact direct-async DMA admission"
                )
            if ddr_ring_bytes and facts.get("buffer_direct_async_ring") is not True:
                raise RadioConfigurationError(
                    "IIO context does not advertise direct async RAM queue extension"
                )
            policies = facts.get("buffer_direct_async_overrun_policies")
            requested_policy = (
                "drop-backlog" if drop_backlog_on_overrun else "preserve-backlog"
            )
            if not isinstance(policies, tuple) or requested_policy not in policies:
                raise RadioConfigurationError(
                    f"IIO context does not advertise {requested_policy} direct async "
                    "overrun handling"
                )
        if not (
            self._capabilities.supports_device_sample_counter
            and self._capabilities.supports_continuity_sequence
        ):
            raise RadioConfigurationError(
                "radio was not opened with a matched continuity-observable metadata runtime"
            )
        sample_rate_hz = round(float(device.sample_rate))
        configure_iio_context_timeout(
            device.ctx,
            timeout_ms=metadata_iio_context_timeout_ms(
                sample_rate_hz,
                sample_count,
                ddr_burst_frames=(
                    0 if not ddr_burst_bytes else ddr_burst_bytes // (sample_count * 4)
                ),
            ),
        )
        module = self._iio_module
        if module is None:
            raise RadioConfigurationError(
                "metadata capture runtime was not loaded before the IIO context"
            )
        metadata_buffer_type = getattr(module, "MetadataBuffer", None)
        if metadata_buffer_type is None:
            raise RadioConfigurationError("installed pylibiio does not expose MetadataBuffer")
        actual_kernel_buffers = self.configure_kernel_buffers(kernel_buffers)
        session = IioMetadataCaptureSession(
            device,
            metadata_buffer_type,
            sample_rate_hz=sample_rate_hz,
            samples_per_channel=sample_count,
            kernel_buffers=actual_kernel_buffers,
            metadata_abi=int(metadata_abi),
            tandem_request=tandem_request,
            ddr_burst_bytes=ddr_burst_bytes,
            ddr_ring_bytes=ddr_ring_bytes,
            ddr_ring_frames=ddr_ring_frames,
            ddr_ring_continuous=ddr_ring_continuous,
            direct_async_frames=direct_async_frames,
            drop_backlog_on_overrun=drop_backlog_on_overrun,
            iq_decoder=self._iq_decoder,
        )
        try:
            session.open()
        except BaseException:
            session.close()
            self.reset_receive_buffer()
            raise
        self._metadata_capture = session
        return session

    def diagnostic_facts(self) -> Mapping[str, object]:
        """Return passive facts captured when the exact IIO context was opened."""

        return dict(self._diagnostic_facts)

    def _require_device(self) -> Any:
        if self._device is None:
            raise RuntimeError("IIO radio is not open")
        return self._device


def resolve_iio_uri(
    uri: str,
    serial: str | None,
    *,
    contexts: Mapping[str, str] | None = None,
) -> str:
    normalized = uri.removeprefix("pluto://")
    if not serial or not normalized.startswith("usb:"):
        return normalized
    if _CONCRETE_USB_URI.fullmatch(normalized):
        # The caller has already selected one physical bus/device/interface.
        # Open-time context attestation below still requires the exact serial.
        return normalized
    if contexts is None:
        try:
            iio = importlib.import_module("iio")
        except ImportError as error:
            raise ImportError("USB serial resolution requires pylibiio") from error
        contexts = iio.scan_contexts()
    matches = [
        candidate
        for candidate, description in contexts.items()
        if candidate.startswith("usb:") and f"serial={serial}" in description
    ]
    if len(matches) != 1:
        raise RadioConfigurationError(
            f"expected exactly one USB Pluto with serial {serial}, found {len(matches)}"
        )
    return matches[0]


def exact_usb_iio_uri(
    usb_sysfs_path: Path,
    serial: str,
    *,
    usb_root: Path = PLUTO_USB_ROOT,
) -> str:
    """Resolve one serial/path-bound IIO URI without probing peer radios."""

    if not usb_sysfs_path.is_absolute() or usb_sysfs_path.parent != usb_root:
        raise RadioConfigurationError(
            "USB sysfs path must name one direct device below /sys/bus/usb/devices"
        )
    try:
        resolved = usb_sysfs_path.resolve(strict=True)
        vendor = (resolved / "idVendor").read_text(encoding="ascii").strip().lower()
        product = (resolved / "idProduct").read_text(encoding="ascii").strip().lower()
        observed_serial = (resolved / "serial").read_text(encoding="utf-8").strip()
        bus = int((resolved / "busnum").read_text(encoding="ascii").strip())
        device = int((resolved / "devnum").read_text(encoding="ascii").strip())
    except (OSError, UnicodeError, ValueError) as error:
        raise RadioConfigurationError(f"cannot resolve exact USB-IIO identity: {error}") from error
    if resolved.name != usb_sysfs_path.name or ":" in usb_sysfs_path.name:
        raise RadioConfigurationError("USB sysfs path must name one direct device")
    if (
        vendor != PLUTO_USB_VENDOR
        or product != PLUTO_RUNTIME_PRODUCT
        or bus <= 0
        or device <= 0
    ):
        raise RadioConfigurationError("exact USB path is not one runtime Pluto")
    if observed_serial != serial or not _SERIAL_PATTERN.fullmatch(serial):
        raise RadioConfigurationError("exact USB path serial does not match the requested radio")

    interfaces: list[int] = []
    for candidate in usb_sysfs_path.parent.glob(f"{usb_sysfs_path.name}:*"):
        try:
            interface_class = (
                (candidate / "bInterfaceClass").read_text(encoding="ascii").strip().lower()
            )
            interface_subclass = (
                (candidate / "bInterfaceSubClass").read_text(encoding="ascii").strip().lower()
            )
            interface_protocol = (
                (candidate / "bInterfaceProtocol").read_text(encoding="ascii").strip().lower()
            )
            interface_number = int(
                (candidate / "bInterfaceNumber").read_text(encoding="ascii").strip(), 16
            )
        except (OSError, UnicodeError, ValueError):
            continue
        if (
            interface_class == "02"
            and interface_subclass == "00"
            and interface_protocol == "00"
            and interface_number >= 0
        ):
            interfaces.append(interface_number)
    if len(interfaces) != 1:
        raise RadioConfigurationError(
            f"expected one exact USB-IIO interface at {usb_sysfs_path}, found {interfaces}"
        )
    return f"usb:{bus}.{device}.{interfaces[0]}"


def discover_usb_serials(usb_root: Path = Path("/sys/bus/usb/devices")) -> list[str]:
    serials: list[str] = []
    if not usb_root.is_dir():
        return serials
    for device in usb_root.iterdir():
        try:
            vendor = (device / "idVendor").read_text().strip().lower()
            product = (device / "idProduct").read_text().strip().lower()
        except OSError:
            continue
        if vendor != PLUTO_USB_VENDOR or product != PLUTO_RUNTIME_PRODUCT:
            continue
        try:
            serial = (device / "serial").read_text().strip()
        except (OSError, UnicodeError):
            continue
        if serial:
            serials.append(serial)
    if len(serials) != len(set(serials)):
        raise RadioConfigurationError(f"duplicate Pluto USB serials: {serials}")
    return sorted(serials)


def find_usb_sysfs_path(serial: str, usb_root: Path = Path("/sys/bus/usb/devices")) -> str | None:
    """Correlate one runtime Pluto USB device by serial, failing on ambiguity."""

    matches: list[Path] = []
    if not serial or not usb_root.is_dir():
        return None
    for device in usb_root.iterdir():
        try:
            vendor = (device / "idVendor").read_text().strip().lower()
            product = (device / "idProduct").read_text().strip().lower()
        except OSError:
            continue
        if vendor != PLUTO_USB_VENDOR or product != PLUTO_RUNTIME_PRODUCT:
            continue
        try:
            candidate_serial = (device / "serial").read_text().strip()
        except (OSError, UnicodeError):
            continue
        if candidate_serial == serial:
            matches.append(device)
    if len(matches) > 1:
        raise RadioConfigurationError(
            f"expected at most one attached USB Pluto with serial {serial}, found {len(matches)}"
        )
    return str(matches[0]) if matches else None


def _resolve_version_capability(
    legacy_version: int | None,
    versions_raw: object,
    *,
    host_versions: tuple[int, ...],
) -> tuple[tuple[int, ...], str, int | None]:
    if versions_raw is None:
        selected = legacy_version if legacy_version in host_versions else None
        return (), "absent", selected
    try:
        versions = parse_metadata_version_capabilities(versions_raw)
    except ValueError:
        return (), "malformed", None
    if legacy_version is None or legacy_version not in versions:
        return versions, "inconsistent", None
    compatible = tuple(version for version in versions if version in host_versions)
    if not compatible:
        return versions, "unsupported", None
    return versions, "available", compatible[-1]


def _select_context_metadata_abi(
    facts: Mapping[str, object], *, expected: int | None
) -> int | None:
    versions_state = facts.get("buffer_metadata_abi_versions_state")
    versions = facts.get("buffer_metadata_abi_versions")
    if versions_state == "absent":
        selected = facts.get("buffer_metadata_abi")
        if selected == 4:
            raise RadioConfigurationError(
                "metadata ABI 4 requires an explicit iio,buffer-metadata-abi-versions set"
            )
    elif versions_state == "available" and isinstance(versions, tuple):
        selected = facts.get("buffer_metadata_abi") if expected is None else expected
        if selected not in SUPPORTED_METADATA_ABIS or selected not in versions:
            raise RadioConfigurationError(
                "radio metadata ABI version set does not contain the requested host ABI: "
                f"radio={versions!r}, host={expected!r}"
            )
    else:
        raise RadioConfigurationError(
            "radio metadata ABI version capability is malformed or inconsistent"
        )
    if selected is None and expected is None:
        return None
    if selected not in SUPPORTED_METADATA_ABIS:
        raise RadioConfigurationError(
            "metadata capture requires a supported radio metadata ABI"
        )
    if expected is not None and selected != expected:
        raise RadioConfigurationError(
            "radio metadata ABI does not match the release-local host runtime: "
            f"radio={selected!r}, host={expected}"
        )
    return selected


def context_facts(context: Any) -> dict[str, object]:
    attrs = dict(getattr(context, "attrs", {}) or {})
    metadata = parse_metadata_abi(attrs.get("iio,buffer-metadata"))
    metadata_abi_versions_raw = attrs.get("iio,buffer-metadata-abi-versions")
    metadata_abi_versions, metadata_abi_versions_state, effective_metadata_abi = (
        _resolve_version_capability(
            metadata.abi,
            metadata_abi_versions_raw,
            host_versions=SUPPORTED_METADATA_ABIS,
        )
    )
    layouts_raw = attrs.get("iio,buffer-metadata-layouts")
    try:
        layouts = parse_metadata_layout_capabilities(layouts_raw)
        layouts_state = "available"
    except ValueError:
        layouts = ()
        layouts_state = "absent" if layouts_raw in {None, ""} else "malformed"
    ddr_burst_raw = attrs.get("iio,buffer-ddr-burst")
    ddr_burst = ddr_burst_raw == "1"
    try:
        ddr_burst_max_iq_bytes = int(attrs["iio,buffer-ddr-burst-max-iq-bytes"])
        ddr_burst_reserve_bytes = int(attrs["iio,buffer-ddr-burst-reserve-bytes"])
    except (KeyError, TypeError, ValueError):
        ddr_burst_max_iq_bytes = None
        ddr_burst_reserve_bytes = None
    ddr_ring_raw = attrs.get("iio,buffer-ddr-ring")
    ddr_ring = ddr_ring_raw == "1"
    try:
        ddr_ring_max_iq_bytes = int(attrs["iio,buffer-ddr-ring-max-iq-bytes"])
    except (KeyError, TypeError, ValueError):
        ddr_ring_max_iq_bytes = None
    ddr_ring_modes_raw = attrs.get("iio,buffer-ddr-ring-modes")
    direct_async_raw = attrs.get("iio,buffer-direct-async")
    direct_async_exact_kernel_queue_raw = attrs.get(
        "iio,buffer-direct-async-exact-kernel-queue"
    )
    direct_async_ring_raw = attrs.get("iio,buffer-direct-async-ring")
    direct_async_overrun_policies_raw = attrs.get(
        "iio,buffer-direct-async-overrun-policies"
    )
    direct_async_overrun_policies = tuple(
        item
        for item in str(direct_async_overrun_policies_raw or "").split(",")
        if item
    )
    direct_async_default_overrun_policy = attrs.get(
        "iio,buffer-direct-async-default-overrun-policy"
    )
    metadata_status_raw = attrs.get("iio,buffer-metadata-status")
    legacy_metadata_status_version = (
        1 if metadata_status_raw == "1" else 2 if metadata_status_raw == "2" else None
    )
    metadata_status_versions_raw = attrs.get("iio,buffer-metadata-status-versions")
    (
        metadata_status_versions,
        metadata_status_versions_state,
        metadata_status_max_version,
    ) = _resolve_version_capability(
        legacy_metadata_status_version,
        metadata_status_versions_raw,
        host_versions=SUPPORTED_METADATA_STATUS_VERSIONS,
    )
    metadata_record_raw = attrs.get("iio,buffer-metadata-record")
    try:
        metadata_record = int(str(metadata_record_raw))
    except (TypeError, ValueError):
        metadata_record = None
    metadata_features_raw = attrs.get("iio,buffer-metadata-features")
    return {
        "serial": attrs.get("hw_serial") or attrs.get("usb,serial"),
        "model": attrs.get("hw_model") or attrs.get("usb,product"),
        "firmware_version": attrs.get("fw_version"),
        "kernel_version": attrs.get("local,kernel"),
        "usb_path": attrs.get("usb,path"),
        "context_uri": attrs.get("uri"),
        "phy_model": attrs.get("ad9361-phy,model"),
        "buffer_metadata": effective_metadata_abi is not None,
        "buffer_metadata_abi": effective_metadata_abi,
        "buffer_metadata_legacy_abi": metadata.abi,
        "buffer_metadata_raw": metadata.raw,
        "buffer_metadata_state": metadata.state.value,
        "buffer_metadata_abi_versions_raw": metadata_abi_versions_raw,
        "buffer_metadata_abi_versions": metadata_abi_versions,
        "buffer_metadata_abi_versions_state": metadata_abi_versions_state,
        "buffer_metadata_layouts_raw": layouts_raw,
        "buffer_metadata_layouts": layouts,
        "buffer_metadata_layouts_state": layouts_state,
        "buffer_ddr_burst": ddr_burst,
        "buffer_ddr_burst_raw": ddr_burst_raw,
        "buffer_ddr_burst_max_iq_bytes": ddr_burst_max_iq_bytes,
        "buffer_ddr_burst_reserve_bytes": ddr_burst_reserve_bytes,
        "buffer_ddr_ring": ddr_ring,
        "buffer_ddr_ring_raw": ddr_ring_raw,
        "buffer_ddr_ring_max_iq_bytes": ddr_ring_max_iq_bytes,
        "buffer_ddr_ring_modes_raw": ddr_ring_modes_raw,
        "buffer_direct_async": direct_async_raw == "1",
        "buffer_direct_async_raw": direct_async_raw,
        "buffer_direct_async_exact_kernel_queue": (
            direct_async_exact_kernel_queue_raw == "1"
        ),
        "buffer_direct_async_exact_kernel_queue_raw": (
            direct_async_exact_kernel_queue_raw
        ),
        "buffer_direct_async_ring": direct_async_ring_raw == "1",
        "buffer_direct_async_ring_raw": direct_async_ring_raw,
        "buffer_direct_async_overrun_policies_raw": (
            direct_async_overrun_policies_raw
        ),
        "buffer_direct_async_overrun_policies": direct_async_overrun_policies,
        "buffer_direct_async_default_overrun_policy": (
            direct_async_default_overrun_policy
        ),
        "buffer_metadata_status": metadata_status_max_version is not None,
        "buffer_metadata_status_raw": metadata_status_raw,
        "buffer_metadata_status_legacy_version": legacy_metadata_status_version,
        "buffer_metadata_status_versions_raw": metadata_status_versions_raw,
        "buffer_metadata_status_versions": metadata_status_versions,
        "buffer_metadata_status_versions_state": metadata_status_versions_state,
        "buffer_metadata_status_max_version": metadata_status_max_version,
        "buffer_metadata_record": metadata_record,
        "buffer_metadata_record_raw": metadata_record_raw,
        "buffer_metadata_features_raw": metadata_features_raw,
        "tandem_agc": _device_exists(context, "tandem-agc"),
        "tandem_agc_state": _optional_device_int_attribute(context, "tandem-agc", "state"),
        "tandem_agc_ownership_epoch": _optional_device_int_attribute(
            context, "tandem-agc", "ownership_epoch"
        ),
        "tandem_agc_fault_flags": _optional_device_int_attribute(
            context, "tandem-agc", "fault_flags"
        ),
        "rx_scan_channels": _scan_channel_ids(context, "cf-ad9361-lpc"),
    }


def _scan_channel_ids(context: Any, device_name: str) -> tuple[str, ...]:
    find_device = getattr(context, "find_device", None)
    if not callable(find_device):
        return ()
    device = find_device(device_name)
    if device is None:
        return ()
    channels = getattr(device, "channels", ())
    return tuple(
        str(identifier)
        for channel in channels
        if (identifier := getattr(channel, "id", None)) is not None
        and bool(getattr(channel, "scan_element", True))
    )


def _device_exists(context: Any, device_name: str) -> bool:
    find_device = getattr(context, "find_device", None)
    return bool(callable(find_device) and find_device(device_name) is not None)


def _optional_device_int_attribute(
    context: Any, device_name: str, attribute_name: str
) -> int | None:
    find_device = getattr(context, "find_device", None)
    device = find_device(device_name) if callable(find_device) else None
    attributes = getattr(device, "attrs", {}) if device is not None else {}
    attribute = attributes.get(attribute_name) if hasattr(attributes, "get") else None
    if attribute is None:
        return None
    try:
        return int(attribute.value)
    except (AttributeError, OSError, TypeError, ValueError):
        return None


def _tandem_owner_snapshot(context: Any) -> tuple[int | None, int | None, int | None]:
    """Read a second owner snapshot in reverse attribute order to reject torn state."""

    faults = _optional_device_int_attribute(context, "tandem-agc", "fault_flags")
    epoch = _optional_device_int_attribute(context, "tandem-agc", "ownership_epoch")
    state = _optional_device_int_attribute(context, "tandem-agc", "state")
    return state, epoch, faults


def _validate_fastlock_profile(profile: int) -> None:
    if not isinstance(profile, int) or isinstance(profile, bool):
        raise ValueError("Fast Lock profile must be an integer")
    if not 0 <= profile < AD9361_FASTLOCK_PROFILE_COUNT:
        raise ValueError(
            f"Fast Lock profile must be between 0 and {AD9361_FASTLOCK_PROFILE_COUNT - 1}"
        )


def _rx_fastlock_channel(device: Any) -> Any:
    context = getattr(device, "ctx", None)
    find_device = getattr(context, "find_device", None)
    phy = find_device("ad9361-phy") if callable(find_device) else None
    find_channel = getattr(phy, "find_channel", None)
    channel = find_channel("altvoltage0", True) if callable(find_channel) else None
    required = {"fastlock_store", "fastlock_recall", "fastlock_save"}
    attributes = getattr(channel, "attrs", {}) if channel is not None else {}
    if channel is None or not required.issubset(attributes):
        raise RadioConfigurationError(
            "AD9361 RX LO channel does not expose the required Fast Lock attributes"
        )
    return channel


def _capture_rate_channel(device: Any) -> Any:
    capture = getattr(device, "_rxadc", None)
    find_channel = getattr(capture, "find_channel", None)
    channel = find_channel("voltage0", False) if callable(find_channel) else None
    required = {"sampling_frequency", "sampling_frequency_available"}
    attributes = getattr(channel, "attrs", {}) if channel is not None else {}
    if channel is None or not required.issubset(attributes):
        raise RadioConfigurationError(
            "FPGA capture channel does not expose sampling-frequency controls"
        )
    if not callable(getattr(capture, "reg_read", None)):
        raise RadioConfigurationError("FPGA capture device does not expose register readback")
    return channel


def _validate_source_locked_rate(rate_hz: int) -> None:
    if not isinstance(rate_hz, int) or isinstance(rate_hz, bool) or rate_hz <= 0:
        raise ValueError("source-locked RX rate must be a positive integer")


def _validate_rx_signal_path_request(
    *,
    expected_rx_layout: RxLayoutExpectation,
    rf_bandwidth_hz: int | None,
    gain_mode: GainMode | None,
    manual_gain_db: tuple[float, ...] | None,
    fir_enabled: bool | None,
) -> None:
    requested = (rf_bandwidth_hz is not None, gain_mode is not None, fir_enabled is not None)
    if any(requested) and not all(requested):
        raise ValueError(
            "RF bandwidth, gain mode, and FIR state must be requested together"
        )
    if not any(requested):
        if manual_gain_db is not None:
            raise ValueError("manual RX gain requires a complete signal-path request")
        return
    if (
        not isinstance(rf_bandwidth_hz, int)
        or isinstance(rf_bandwidth_hz, bool)
        or rf_bandwidth_hz <= 0
    ):
        raise ValueError("RX RF bandwidth must be a positive integer")
    if not isinstance(gain_mode, GainMode):
        raise ValueError("RX gain mode must be a GainMode")
    if not isinstance(fir_enabled, bool):
        raise ValueError("RX FIR state must be boolean")
    if gain_mode is GainMode.MANUAL:
        if manual_gain_db is None or len(manual_gain_db) != len(
            expected_rx_layout.receiver_channels
        ):
            raise ValueError("manual RX gain must provide one value per receiver channel")
        if any(
            not isinstance(value, (int, float)) or isinstance(value, bool)
            for value in manual_gain_db
        ):
            raise ValueError("manual RX gain values must be numeric")
    elif manual_gain_db is not None:
        raise ValueError("automatic RX gain modes do not accept manual gain values")


def _validate_counter_slope_request(
    *, rate_hz: int, observation_seconds: float | None, tolerance_ppm: float
) -> None:
    if observation_seconds is None:
        return
    if (
        not isinstance(observation_seconds, (int, float))
        or isinstance(observation_seconds, bool)
        or not 0.01 <= observation_seconds <= 30.0
    ):
        raise ValueError("sample-counter observation must be between 0.01 and 30 seconds")
    if rate_hz * observation_seconds >= 2**32:
        raise ValueError("sample-counter observation may span at most one low-word wrap")
    if (
        not isinstance(tolerance_ppm, (int, float))
        or isinstance(tolerance_ppm, bool)
        or not 0 < tolerance_ppm <= 100_000
    ):
        raise ValueError("sample-counter tolerance must be in (0, 100000] ppm")


def _required_iio_attribute(container: Any, name: str, *, label: str) -> Any:
    attributes = getattr(container, "attrs", {})
    attribute = attributes.get(name) if hasattr(attributes, "get") else None
    if attribute is None:
        raise RadioConfigurationError(f"{label} does not expose {name}")
    return attribute


def _parse_iio_float(value: object, *, label: str) -> float:
    try:
        return float(str(value).strip().split()[0])
    except (IndexError, TypeError, ValueError) as error:
        raise RadioConfigurationError(f"malformed {label} readback: {value!r}") from error


def _configure_context_rx_signal_path(
    context: Any,
    *,
    expected_rx_layout: RxLayoutExpectation,
    rf_bandwidth_hz: int,
    gain_mode: GainMode,
    manual_gain_db: tuple[float, ...] | None,
    fir_enabled: bool,
) -> IioRxSignalPathAttestation:
    find_device = getattr(context, "find_device", None)
    phy = find_device("ad9361-phy") if callable(find_device) else None
    find_channel = getattr(phy, "find_channel", None)
    if phy is None or not callable(find_channel):
        raise RadioConfigurationError("AD936x PHY does not expose receive channels")

    channels: list[Any] = []
    for receiver_channel in expected_rx_layout.receiver_channels:
        channel = find_channel(f"voltage{receiver_channel}", False)
        if channel is None:
            raise RadioConfigurationError(
                f"AD936x PHY is missing receiver channel {receiver_channel}"
            )
        for name in ("rf_bandwidth", "gain_control_mode", "hardwaregain", "filter_fir_en"):
            _required_iio_attribute(
                channel, name, label=f"AD936x RX{receiver_channel} channel"
            )
        channels.append(channel)

    try:
        for index, channel in enumerate(channels):
            channel.attrs["rf_bandwidth"].value = str(rf_bandwidth_hz)
            channel.attrs["filter_fir_en"].value = "1" if fir_enabled else "0"
            channel.attrs["gain_control_mode"].value = gain_mode.value
            if manual_gain_db is not None:
                channel.attrs["hardwaregain"].value = str(manual_gain_db[index])

        bandwidths = tuple(
            int(_parse_iio_float(channel.attrs["rf_bandwidth"].value, label="RF bandwidth"))
            for channel in channels
        )
        fir_states = tuple(bool(int(channel.attrs["filter_fir_en"].value)) for channel in channels)
        gain_modes = tuple(
            GainMode(str(channel.attrs["gain_control_mode"].value).strip())
            for channel in channels
        )
        hardware_gains = tuple(
            _parse_iio_float(channel.attrs["hardwaregain"].value, label="hardware gain")
            for channel in channels
        )
        rx_path_rates = str(
            _required_iio_attribute(phy, "rx_path_rates", label="AD936x PHY").value
        ).strip()
        trx_rate_governor = str(
            _required_iio_attribute(phy, "trx_rate_governor", label="AD936x PHY").value
        ).strip()
    except (AttributeError, KeyError, OSError, TypeError, ValueError) as error:
        if isinstance(error, RadioConfigurationError):
            raise
        raise RadioConfigurationError("AD936x receive signal-path attestation failed") from error

    if bandwidths != (rf_bandwidth_hz,) * len(channels):
        raise RadioConfigurationError(
            f"RX RF bandwidth readback mismatch: {bandwidths!r}, expected {rf_bandwidth_hz}"
        )
    if fir_states != (fir_enabled,) * len(channels):
        raise RadioConfigurationError(
            f"RX FIR readback mismatch: {fir_states!r}, expected {fir_enabled}"
        )
    if gain_modes != (gain_mode,) * len(channels):
        raise RadioConfigurationError(
            f"RX gain-mode readback mismatch: {gain_modes!r}, expected {gain_mode.value}"
        )
    if manual_gain_db is not None and hardware_gains != manual_gain_db:
        raise RadioConfigurationError(
            f"manual RX gain readback mismatch: {hardware_gains!r}, expected {manual_gain_db!r}"
        )
    if not rx_path_rates or not trx_rate_governor:
        raise RadioConfigurationError("AD936x path-rate/governor readback is empty")

    return IioRxSignalPathAttestation(
        receiver_channels=expected_rx_layout.receiver_channels,
        requested_rf_bandwidth_hz=rf_bandwidth_hz,
        rf_bandwidth_hz=bandwidths,
        requested_gain_mode=gain_mode,
        gain_modes=gain_modes,
        requested_manual_gain_db=manual_gain_db,
        hardware_gain_db=hardware_gains,
        requested_fir_enabled=fir_enabled,
        fir_enabled=fir_states,
        rx_path_rates=rx_path_rates,
        trx_rate_governor=trx_rate_governor,
    )


def _attest_context_sample_counter_slope(
    context: Any,
    *,
    expected_rate_hz: int,
    observation_seconds: float,
    tolerance_ppm: float,
) -> IioSampleCounterSlopeAttestation:
    find_device = getattr(context, "find_device", None)
    capture = find_device("cf-ad9361-lpc") if callable(find_device) else None
    reader = getattr(capture, "reg_read", None)
    if not callable(reader):
        raise RadioConfigurationError("FPGA capture device does not expose sample-counter readback")

    start_before_ns = time.monotonic_ns()
    try:
        counter_start = int(reader(ADC_SAMPLE_COUNTER_LOW_REG)) & 0xFFFFFFFF
    except (AttributeError, OSError, TypeError, ValueError) as error:
        raise RadioConfigurationError("FPGA sample-counter start read failed") from error
    start_after_ns = time.monotonic_ns()
    time.sleep(observation_seconds)
    end_before_ns = time.monotonic_ns()
    try:
        counter_end = int(reader(ADC_SAMPLE_COUNTER_LOW_REG)) & 0xFFFFFFFF
    except (AttributeError, OSError, TypeError, ValueError) as error:
        raise RadioConfigurationError("FPGA sample-counter end read failed") from error
    end_after_ns = time.monotonic_ns()

    start_midpoint_ns = (start_before_ns + start_after_ns) // 2
    end_midpoint_ns = (end_before_ns + end_after_ns) // 2
    elapsed_ns = end_midpoint_ns - start_midpoint_ns
    if elapsed_ns <= 0:
        raise RadioConfigurationError("host monotonic clock did not advance")
    counter_delta = (counter_end - counter_start) & 0xFFFFFFFF
    measured_rate_hz = counter_delta * 1_000_000_000.0 / elapsed_ns
    error_ppm = (measured_rate_hz - expected_rate_hz) * 1_000_000.0 / expected_rate_hz
    within_tolerance = abs(error_ppm) <= tolerance_ppm
    attestation = IioSampleCounterSlopeAttestation(
        expected_rate_hz=expected_rate_hz,
        observation_seconds_requested=float(observation_seconds),
        counter_start_low32=counter_start,
        counter_end_low32=counter_end,
        counter_delta=counter_delta,
        host_elapsed_ns=elapsed_ns,
        start_read_span_ns=start_after_ns - start_before_ns,
        end_read_span_ns=end_after_ns - end_before_ns,
        measured_rate_hz=measured_rate_hz,
        error_ppm=error_ppm,
        tolerance_ppm=float(tolerance_ppm),
        within_tolerance=within_tolerance,
    )
    if not within_tolerance:
        raise RadioConfigurationError(
            "FPGA sample-counter slope is outside tolerance: " f"{attestation!r}"
        )
    return attestation


def _configure_context_source_locked_rx_rate(
    context: Any, rate_hz: int
) -> IioCaptureRateAttestation:
    find_device = getattr(context, "find_device", None)
    phy = find_device("ad9361-phy") if callable(find_device) else None
    capture = find_device("cf-ad9361-lpc") if callable(find_device) else None
    phy_channel = _required_rate_channel(phy, label="AD936x source")
    capture_channel = _required_rate_channel(capture, label="FPGA capture")
    reader = getattr(capture, "reg_read", None)
    if not callable(reader):
        raise RadioConfigurationError("FPGA capture device does not expose register readback")
    try:
        phy_frequency = phy_channel.attrs["sampling_frequency"]
        phy_frequency.value = str(rate_hz)
        phy_rate_hz = int(phy_frequency.value)
        capture_frequency = capture_channel.attrs["sampling_frequency"]
        capture_frequency.value = str(rate_hz)
        capture_rate_hz = int(capture_frequency.value)
        capture_rates_available_hz = tuple(
            int(value)
            for value in str(
                capture_channel.attrs["sampling_frequency_available"].value
            )
            .strip()
            .replace("[", "")
            .replace("]", "")
            .split()
        )
        adc_gp_control = int(reader(ADC_GP_CONTROL_REG)) & 0xFFFFFFFF
    except (AttributeError, OSError, TypeError, ValueError) as error:
        raise RadioConfigurationError("direct RX-only capture-rate attestation failed") from error
    fpga_decimation_factor = 8 if adc_gp_control & 1 else 1
    attestation = IioCaptureRateAttestation(
        requested_rate_hz=rate_hz,
        phy_rate_hz=phy_rate_hz,
        capture_rate_hz=capture_rate_hz,
        capture_rates_available_hz=capture_rates_available_hz,
        fpga_decimation_factor=fpga_decimation_factor,
        fpga_decimation_bypass=fpga_decimation_factor == 1,
        adc_gp_control=adc_gp_control,
    )
    if (
        phy_rate_hz != rate_hz
        or capture_rate_hz != rate_hz
        or capture_rates_available_hz != (rate_hz, rate_hz // 8)
        or not attestation.fpga_decimation_bypass
    ):
        raise RadioConfigurationError(
            "direct RX-only source rate did not produce an exact factor-one capture path: "
            f"{attestation!r}"
        )
    return attestation


def _required_rate_channel(device: Any, *, label: str) -> Any:
    find_channel = getattr(device, "find_channel", None)
    channel = find_channel("voltage0", False) if callable(find_channel) else None
    required = {"sampling_frequency", "sampling_frequency_available"}
    attributes = getattr(channel, "attrs", {}) if channel is not None else {}
    if channel is None or not required.issubset(attributes):
        raise RadioConfigurationError(
            f"{label} channel does not expose sampling-frequency controls"
        )
    return channel


def _mute_transmit(device: Any) -> None:
    # Attenuate first so a later buffer/DDS selector transition cannot briefly
    # expose a previously configured waveform at useful power.
    gain_attributes: list[str] = []
    for name in ("tx_hardwaregain_chan0", "tx_hardwaregain_chan1"):
        present, _ = _optional_attribute(device, name)
        if present:
            setattr(device, name, -80.0)
            gain_attributes.append(name)

    close_tx = getattr(device, "tx_destroy_buffer", None)
    if callable(close_tx):
        close_tx()
    has_tx_channels, _ = _optional_attribute(device, "tx_enabled_channels")
    if has_tx_channels:
        device.tx_enabled_channels = []

    has_scales, scales = _optional_attribute(device, "dds_scales")
    if has_scales and scales is not None:
        device.dds_scales = [0.0] * len(scales)
    disable_dds = getattr(device, "disable_dds", None)
    if callable(disable_dds):
        # Keep this last: changing TX scan selection can select DDS internally.
        disable_dds()

    has_tx_channels, tx_channels = _optional_attribute(device, "tx_enabled_channels")
    if has_tx_channels and list(tx_channels):
        raise RadioConfigurationError("TX channels remained enabled after mute")
    for name in gain_attributes:
        if float(getattr(device, name)) > -80.0:
            raise RadioConfigurationError(f"{name} did not reach the -80 dB safety limit")
    has_muted_scales, muted_scales = _optional_attribute(device, "dds_scales")
    if (
        has_muted_scales
        and muted_scales is not None
        and any(float(value) != 0.0 for value in muted_scales)
    ):
        raise RadioConfigurationError("DDS scale remained nonzero after mute")
    has_dds_enabled, dds_enabled = _optional_attribute(device, "dds_enabled")
    if (
        has_dds_enabled
        and dds_enabled is not None
        and any(str(value).strip().lower() not in {"0", "false"} for value in dds_enabled)
    ):
        raise RadioConfigurationError("DDS source remained enabled after mute")


def _optional_attribute(device: Any, name: str) -> tuple[bool, Any]:
    """Probe a pyadi property without disguising transport or I/O failures."""

    try:
        return True, getattr(device, name)
    except AttributeError:
        return False, None
    except Exception as error:
        # pyadi raises a bare Exception for a property backed by an absent IIO
        # channel. This is absence, not an I/O failure. Everything else remains
        # fail-closed and propagates to the caller.
        if "no channel found with name:" in str(error).lower():
            return False, None
        raise


def _require_canonical_rx_layout(facts: Mapping[str, object]) -> None:
    """Raise a typed, diagnosable failure for a conclusive non-2R2T context."""

    phy_model = _optional_string(facts.get("phy_model"))
    raw_scan_channels = facts.get("rx_scan_channels")
    scan_channels = (
        tuple(str(item) for item in raw_scan_channels)
        if isinstance(raw_scan_channels, (tuple, list, set, frozenset))
        else ()
    )
    required = {"voltage0", "voltage1", "voltage2", "voltage3"}
    wrong_phy = phy_model is not None and phy_model not in SUPPORTED_AD936X_PHY_MODELS
    incomplete_scan = bool(scan_channels) and not required.issubset(scan_channels)
    if wrong_phy or incomplete_scan:
        raise RadioSetupRequiredError(
            "radio requires a supported AD936x paired-RX setup "
            f"(phy_model={phy_model or 'unknown'}, rx_scan_channels={scan_channels})"
        )


def _require_rx_layout(
    facts: Mapping[str, object],
    expectation: RxLayoutExpectation | None,
) -> None:
    """Preserve the legacy gate or require an explicitly selected exact layout."""

    if expectation is None:
        _require_canonical_rx_layout(facts)
        return
    phy_model = _optional_string(facts.get("phy_model"))
    raw_scan_channels = facts.get("rx_scan_channels")
    scan_channels = (
        tuple(str(item) for item in raw_scan_channels)
        if isinstance(raw_scan_channels, (tuple, list, set, frozenset))
        else ()
    )
    observed = set(scan_channels)
    expected = set(expectation.scan_channels)
    scan_matches = (
        expected.issubset(observed)
        if expectation.allow_additional_scan_channels
        else observed == expected
    )
    if phy_model not in expectation.live_phy_models or not scan_matches:
        raise RadioSetupRequiredError(
            "radio does not match the selected RX layout "
            f"(phy_model={phy_model or 'unknown'}, rx_scan_channels={scan_channels})"
        )


def _release_device(device: Any) -> None:
    errors: list[BaseException] = []
    try:
        device.rx_destroy_buffer()
    except BaseException as error:
        errors.append(error)
    try:
        _mute_transmit(device)
    except BaseException as error:
        errors.append(error)
    context = getattr(device, "ctx", None)
    close = getattr(context, "close", None)
    if callable(close):
        try:
            close()
        except BaseException as error:
            errors.append(error)
    if errors:
        raise errors[0]


def _close_context_only(device: Any) -> None:
    """Release an unattested host context without touching the opened radio."""

    context = getattr(device, "ctx", None)
    close = getattr(context, "close", None)
    if callable(close):
        close()


def _optional_string(value: object) -> str | None:
    return None if value is None else str(value)
