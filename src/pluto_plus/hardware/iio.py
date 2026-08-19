"""Lazy receive-only libiio/pyadi adapter with stable serial attestation."""

from __future__ import annotations

import importlib
import time
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

import numpy as np

from pluto_plus.diagnostic_profiles import parse_metadata_abi
from pluto_plus.errors import RadioConfigurationError, RadioSetupRequiredError
from pluto_plus.hardware.base import SampleBlock
from pluto_plus.models import (
    GainMode,
    RadioCapabilities,
    RadioIdentity,
    RadioSettings,
    Transport,
)

PLUTO_USB_VENDOR = "0456"
PLUTO_RUNTIME_PRODUCT = "b673"


class IioRadioDevice:
    """One pyadi context controlling one or both Pluto+ receive channels."""

    def __init__(
        self,
        uri: str,
        *,
        serial: str | None = None,
        radio_id: str | None = None,
        adi_module: ModuleType | Any | None = None,
        iio_contexts: Mapping[str, str] | None = None,
    ) -> None:
        normalized = uri.removeprefix("pluto://")
        self._configured_uri = normalized
        self._requested_serial = serial
        self._radio_id = radio_id or serial or normalized
        self._adi_module = adi_module
        self._iio_contexts = iio_contexts
        self._device: Any | None = None
        self._buffer_size: int | None = None
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

    def open(self) -> None:
        if self._device is not None:
            raise RuntimeError("IIO radio is already open")
        self._diagnostic_facts = {}
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
        try:
            device.rx_destroy_buffer()
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
            # Capture identity and passive context facts before accessing any
            # per-channel pyadi properties. A 1R1T device raises a bare Exception
            # from those getters rather than AttributeError.
            _mute_transmit(device)
            _require_canonical_rx_layout(facts)
            self._device = device
        except Exception:
            _release_device(device)
            raise

    def close(self) -> None:
        device, self._device = self._device, None
        self._buffer_size = None
        self._diagnostic_facts = {}
        if device is not None:
            _release_device(device)

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
                float(getattr(device, f"rx_hardwaregain_chan{channel}"))
                for channel in channels
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
        device.rx_destroy_buffer()
        self._buffer_size = None
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

    def read_block(self, sample_count: int) -> SampleBlock:
        device = self._require_device()
        if sample_count <= 0:
            raise ValueError("sample_count must be positive")
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

    def configure_kernel_buffers(self, count: int) -> None:
        """Set the libiio RX kernel-buffer count before creating a userspace buffer."""

        if count < 1 or count > 64:
            raise ValueError("kernel buffer count must be between 1 and 64")
        device = self._require_device()
        device.rx_destroy_buffer()
        self._buffer_size = None
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
        if actual is not None and int(actual) != count:
            raise RadioConfigurationError(
                f"RX kernel buffer read-back is {actual}, expected {count}"
            )

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


def find_usb_sysfs_path(
    serial: str, usb_root: Path = Path("/sys/bus/usb/devices")
) -> str | None:
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
        "tandem_agc": _device_exists(context, "tandem-agc"),
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
    if has_muted_scales and muted_scales is not None and any(
        float(value) != 0.0 for value in muted_scales
    ):
        raise RadioConfigurationError("DDS scale remained nonzero after mute")
    has_dds_enabled, dds_enabled = _optional_attribute(device, "dds_enabled")
    if has_dds_enabled and dds_enabled is not None and any(
        str(value).strip().lower() not in {"0", "false"} for value in dds_enabled
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
    wrong_phy = phy_model is not None and phy_model != "ad9361"
    incomplete_scan = bool(scan_channels) and not required.issubset(scan_channels)
    if wrong_phy or incomplete_scan:
        raise RadioSetupRequiredError(
            "radio requires canonical AD9361/2R2T setup "
            f"(phy_model={phy_model or 'unknown'}, rx_scan_channels={scan_channels})"
        )


def _release_device(device: Any) -> None:
    try:
        device.rx_destroy_buffer()
    finally:
        _mute_transmit(device)
        context = getattr(device, "ctx", None)
        close = getattr(context, "close", None)
        if callable(close):
            close()


def _optional_string(value: object) -> str | None:
    return None if value is None else str(value)
