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
from pluto_plus.hardware.base import DEFAULT_RESTORE_LO_SEARCH_HZ, SampleBlock
from pluto_plus.hardware.iio_metadata import (
    ABI3_METADATA_LAYOUTS,
    IioMetadataCaptureSession,
    configure_iio_context_timeout,
    metadata_iio_context_timeout_ms,
    parse_metadata_layout_capabilities,
)
from pluto_plus.hardware.preflight import MetadataRuntimeVerification, verify_metadata_runtime
from pluto_plus.models import (
    GainMode,
    RadioCapabilities,
    RadioIdentity,
    RadioSettings,
    Transport,
)
from pluto_plus.tandem import TandemSessionRequestV1

PLUTO_USB_VENDOR = "0456"
PLUTO_RUNTIME_PRODUCT = "b673"
ADC_SAMPLE_COUNTER_LOW_REG = 0x800000B8
AD9361_FASTLOCK_PROFILE_COUNT = 8
_CONCRETE_USB_URI = re.compile(r"^usb:[0-9]+[.][0-9]+[.][0-9]+$")


@dataclass(frozen=True, slots=True)
class IioReceiverSettingsReadback:
    center_frequency_hz: float
    sample_rate_hz: float
    bandwidth_hz: float
    channels: tuple[int, ...]
    gain_modes: tuple[GainMode, ...]
    gain_db: tuple[float, ...]


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
        mutation_preflight: Callable[[], None] | None = None,
        require_idle_tandem_owner: bool = False,
        radio_id: str | None = None,
        adi_module: ModuleType | Any | None = None,
        iio_module: ModuleType | Any | None = None,
        iio_contexts: Mapping[str, str] | None = None,
        expected_metadata_abi: int | None = None,
    ) -> None:
        if expected_metadata_abi not in {None, 1, 2, 3}:
            raise ValueError("expected_metadata_abi must be 1, 2, 3, or None")
        normalized = uri.removeprefix("pluto://")
        self._configured_uri = normalized
        self._requested_serial = serial
        self._expected_usb_path = expected_usb_path
        self._mutation_preflight = mutation_preflight
        self._require_idle_tandem_owner = require_idle_tandem_owner
        self._radio_id = radio_id or serial or normalized
        self._adi_module = adi_module
        self._iio_module = iio_module
        self._iio_contexts = iio_contexts
        self._expected_metadata_abi = expected_metadata_abi
        self._metadata_runtime: MetadataRuntimeVerification | None = None
        self._device: Any | None = None
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

    def open(self) -> None:
        if self._device is not None:
            raise RuntimeError("IIO radio is already open")
        self._diagnostic_facts = {}
        self._metadata_runtime = None
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
        uri = resolve_iio_uri(
            self._configured_uri,
            self._requested_serial,
            contexts=self._iio_contexts,
        )
        device = module.ad9361(uri=uri)
        attested = False
        try:
            configure_iio_context_timeout(device.ctx)
            facts = context_facts(device.ctx)
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
            _require_canonical_rx_layout(facts)
            actual_metadata_abi = facts.get("buffer_metadata_abi")
            if (
                self._expected_metadata_abi is not None
                and actual_metadata_abi != self._expected_metadata_abi
            ):
                raise RadioConfigurationError(
                    "radio metadata ABI does not match the release-local host runtime: "
                    f"radio={actual_metadata_abi!r}, host={self._expected_metadata_abi}"
                )
            injected_runtime = self._adi_module is not None and self._iio_module is not None
            if actual_metadata_abi == 3 and facts.get("buffer_metadata_layouts") != (
                ABI3_METADATA_LAYOUTS
            ):
                raise RadioConfigurationError(
                    "metadata ABI 3 radio did not advertise the canonical RX layouts"
                )
            runtime_ready = actual_metadata_abi in {1, 2, 3} and (
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
        except BaseException as failure:
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
            channels = (0, 1)
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
        raw = device.rx()
        after = time.time_ns()
        values = np.asarray(raw)
        expected_receivers = len(tuple(device.rx_enabled_channels))
        if expected_receivers == 1 and values.ndim == 1:
            values = values[np.newaxis, :]
        if values.ndim != 2 or values.shape != (expected_receivers, sample_count):
            raise RuntimeError(
                f"paired Pluto read returned {values.shape}, expected "
                f"({expected_receivers}, {sample_count})"
            )
        return SampleBlock(utc_ns=(before + after) // 2, samples=values.astype(np.complex64))

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
    ) -> IioMetadataCaptureSession:
        """Reset and arm one fail-closed FPGA-metadata capture generation."""

        from pluto_plus.data_plane import require_safe_iio_buffer

        if sample_count <= 0:
            raise ValueError("sample_count must be positive")
        device = self._require_device()
        self.reset_receive_buffer()
        channels = tuple(int(item) for item in device.rx_enabled_channels)
        if channels not in {(0,), (1,), (0, 1)}:
            raise RadioConfigurationError("metadata capture receiver selection is not canonical")
        require_safe_iio_buffer(sample_count, len(channels))
        facts = context_facts(device.ctx)
        metadata_abi = facts.get("buffer_metadata_abi")
        if metadata_abi not in {1, 2, 3}:
            raise RadioConfigurationError(
                "metadata capture requires supported context capability "
                "iio,buffer-metadata=1, 2, or 3"
            )
        if metadata_abi in {1, 2} and channels != (0, 1):
            raise RadioConfigurationError("metadata ABI 1 and 2 require paired RX channels")
        if metadata_abi == 3:
            layouts = facts.get("buffer_metadata_layouts")
            if layouts != ABI3_METADATA_LAYOUTS:
                raise RadioConfigurationError(
                    "metadata ABI 3 requires the exact canonical RX layout capability"
                )
            expected_mask = {(0,): 0x03, (1,): 0x0C, (0, 1): 0x0F}[channels]
            layout = next(item for item in layouts if item.scan_mask == expected_mask)
            if sample_count % layout.sample_count_multiple:
                raise RadioConfigurationError(
                    "metadata sample count violates the advertised RX layout multiple"
                )
        if metadata_abi in {2, 3} and not facts.get("tandem_agc"):
            raise RadioConfigurationError(
                "metadata ABI 2 and 3 capture requires the tandem-agc IIO device"
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
            timeout_ms=metadata_iio_context_timeout_ms(sample_rate_hz, sample_count),
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


def context_facts(context: Any) -> dict[str, object]:
    attrs = dict(getattr(context, "attrs", {}) or {})
    metadata = parse_metadata_abi(attrs.get("iio,buffer-metadata"))
    layouts_raw = attrs.get("iio,buffer-metadata-layouts")
    try:
        layouts = parse_metadata_layout_capabilities(layouts_raw)
        layouts_state = "available"
    except ValueError:
        layouts = ()
        layouts_state = "absent" if layouts_raw in {None, ""} else "malformed"
    return {
        "serial": attrs.get("hw_serial") or attrs.get("usb,serial"),
        "model": attrs.get("hw_model") or attrs.get("usb,product"),
        "firmware_version": attrs.get("fw_version"),
        "kernel_version": attrs.get("local,kernel"),
        "usb_path": attrs.get("usb,path"),
        "context_uri": attrs.get("uri"),
        "phy_model": attrs.get("ad9361-phy,model"),
        "buffer_metadata": metadata.abi is not None,
        "buffer_metadata_abi": metadata.abi,
        "buffer_metadata_raw": metadata.raw,
        "buffer_metadata_state": metadata.state.value,
        "buffer_metadata_layouts_raw": layouts_raw,
        "buffer_metadata_layouts": layouts,
        "buffer_metadata_layouts_state": layouts_state,
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
