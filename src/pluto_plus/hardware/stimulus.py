"""Finite, serial-bound DDS stimulus with fail-muted cleanup."""

from __future__ import annotations

import importlib
import math
import time
from collections.abc import Mapping
from dataclasses import dataclass
from types import ModuleType
from typing import Any

import numpy as np

from pluto_plus.errors import RadioConfigurationError
from pluto_plus.hardware.base import SampleBlock
from pluto_plus.hardware.iio import (
    _mute_transmit,
    _optional_attribute,
    _release_device,
    context_facts,
    find_usb_sysfs_path,
    resolve_iio_uri,
)
from pluto_plus.models import GainMode, RadioIdentity, RadioSettings, Transport

MAX_TONE_CAPTURE_SAMPLES = 1_048_576


@dataclass(frozen=True, slots=True)
class SafeDdsTonePlan:
    """Reviewed bounds for one finite USB loopback capture."""

    uri: str
    serial: str
    center_frequency_hz: int
    sample_rate_hz: int
    bandwidth_hz: int
    tone_frequency_hz: int
    tx_channel: int
    tx_hardware_gain_db: float
    dds_scale: float
    receiver_gain_db: float
    source_peak_output_bound_dbm: float
    load_input_limit_dbm: float
    path_attenuation_before_load_db: float
    required_margin_db: float = 10.0
    settle_ms: int = 50

    def __post_init__(self) -> None:
        if not self.serial.strip():
            raise ValueError("serial must be non-empty")
        if not self.uri.removeprefix("pluto://").startswith("usb:"):
            raise ValueError("safe DDS stimulus requires an exact USB IIO URI")
        if self.center_frequency_hz <= 0:
            raise ValueError("center frequency must be positive")
        if self.sample_rate_hz <= 0 or self.bandwidth_hz <= 0:
            raise ValueError("sample rate and bandwidth must be positive")
        if self.bandwidth_hz > self.sample_rate_hz:
            raise ValueError("bandwidth cannot exceed sample rate")
        usable_half_bandwidth = min(self.sample_rate_hz, self.bandwidth_hz) / 2
        if not 0 < abs(self.tone_frequency_hz) < usable_half_bandwidth:
            raise ValueError("tone must be nonzero and inside the sampled RF bandwidth")
        if self.tx_channel not in (0, 1):
            raise ValueError("TX channel must be 0 or 1")
        if not -80.0 <= self.tx_hardware_gain_db <= 0.0:
            raise ValueError("TX hardware gain must be between -80 and 0 dB")
        if not 0.0 < self.dds_scale <= 1.0:
            raise ValueError("DDS scale must be in the interval (0, 1]")
        if not -10.0 <= self.receiver_gain_db <= 80.0:
            raise ValueError("receiver gain must be between -10 and 80 dB")
        numeric_bounds = (
            self.source_peak_output_bound_dbm,
            self.load_input_limit_dbm,
            self.path_attenuation_before_load_db,
            self.required_margin_db,
        )
        if not all(math.isfinite(value) for value in numeric_bounds):
            raise ValueError("RF safety bounds must be finite")
        if self.path_attenuation_before_load_db < 0 or self.required_margin_db < 0:
            raise ValueError("attenuation and required margin cannot be negative")
        if not 0 <= self.settle_ms <= 1000:
            raise ValueError("settle time must be between 0 and 1000 ms")
        allowed = self.load_input_limit_dbm - self.required_margin_db
        if self.worst_case_load_input_dbm > allowed:
            raise ValueError(
                "unsafe tone plan: worst-case load input "
                f"{self.worst_case_load_input_dbm:.2f} dBm exceeds {allowed:.2f} dBm"
            )

    @property
    def worst_case_load_input_dbm(self) -> float:
        return (
            self.source_peak_output_bound_dbm
            + self.tx_hardware_gain_db
            + 20.0 * math.log10(self.dds_scale)
            - self.path_attenuation_before_load_db
        )


@dataclass(frozen=True, slots=True)
class SafeDdsToneCapture:
    plan: SafeDdsTonePlan
    identity: RadioIdentity
    settings: RadioSettings
    block: SampleBlock
    tx_gain_readback_db: float


def capture_safe_dds_tone(
    plan: SafeDdsTonePlan,
    *,
    sample_count: int,
    adi_module: ModuleType | Any | None = None,
    iio_contexts: Mapping[str, str] | None = None,
) -> SafeDdsToneCapture:
    """Emit one bounded tone, capture paired RX, then prove TX is muted."""

    if sample_count < 1 or sample_count > MAX_TONE_CAPTURE_SAMPLES:
        raise ValueError(f"sample_count must be 1..{MAX_TONE_CAPTURE_SAMPLES}")
    module = adi_module
    if module is None:
        try:
            module = importlib.import_module("adi")
        except (ImportError, AttributeError) as error:
            raise ImportError(
                "DDS stimulus requires the 'hardware' extra and compatible native libiio"
            ) from error
    resolved_uri = resolve_iio_uri(plan.uri, plan.serial, contexts=iio_contexts)
    device = module.ad9361(uri=resolved_uri)
    try:
        _mute_transmit(device)
        facts = context_facts(device.ctx)
        detected_serial = str(facts.get("serial") or "")
        if detected_serial != plan.serial:
            raise RadioConfigurationError(
                f"opened Pluto serial {detected_serial!r}, expected {plan.serial!r}"
            )

        device.rx_destroy_buffer()
        device.sample_rate = plan.sample_rate_hz
        device.rx_rf_bandwidth = plan.bandwidth_hz
        device.tx_rf_bandwidth = plan.bandwidth_hz
        device.rx_lo = plan.center_frequency_hz
        device.tx_lo = plan.center_frequency_hz
        device.rx_enabled_channels = [0, 1]
        device.gain_control_mode_chan0 = GainMode.MANUAL.value
        device.gain_control_mode_chan1 = GainMode.MANUAL.value
        device.rx_hardwaregain_chan0 = plan.receiver_gain_db
        device.rx_hardwaregain_chan1 = plan.receiver_gain_db
        device.rx_buffer_size = sample_count

        # Mute again after all shared transceiver configuration, then expose
        # exactly one bounded DDS source at the reviewed attenuation.
        _mute_transmit(device)
        gain_name = f"tx_hardwaregain_chan{plan.tx_channel}"
        setattr(device, gain_name, plan.tx_hardware_gain_db)
        device.dds_single_tone(
            plan.tone_frequency_hz,
            plan.dds_scale,
            channel=plan.tx_channel,
        )
        readback_gain = float(getattr(device, gain_name))
        if readback_gain > plan.tx_hardware_gain_db + 0.25:
            raise RadioConfigurationError(
                f"TX attenuation read-back {readback_gain:g} dB is above the plan"
            )
        has_scales, scales = _optional_attribute(device, "dds_scales")
        if not has_scales or scales is None:
            raise RadioConfigurationError("DDS scale read-back is unavailable")
        scale_values = tuple(abs(float(value)) for value in scales)
        if not any(scale_values) or max(scale_values) > plan.dds_scale + 1e-6:
            raise RadioConfigurationError("DDS scale read-back is outside the plan")

        time.sleep(plan.settle_ms / 1000.0)
        before = time.time_ns()
        values = np.asarray(device.rx())
        after = time.time_ns()
        if values.shape != (2, sample_count) or not np.iscomplexobj(values):
            raise RadioConfigurationError(
                f"paired tone capture returned {values.shape}, expected (2, {sample_count})"
            )

        settings = RadioSettings(
            center_frequency_hz=float(device.rx_lo),
            sample_rate_hz=float(device.sample_rate),
            bandwidth_hz=float(device.rx_rf_bandwidth),
            gain_mode=GainMode.MANUAL,
            gain_db=plan.receiver_gain_db,
            channels=(0, 1),
        )
        identity = RadioIdentity(
            radio_id=plan.serial,
            serial=plan.serial,
            uri=resolved_uri,
            transport=Transport.IIO_USB,
            model=str(facts.get("model") or "Pluto+"),
            firmware_version=(
                None if facts.get("firmware_version") is None else str(facts["firmware_version"])
            ),
            usb_path=find_usb_sysfs_path(plan.serial),
        )
        return SafeDdsToneCapture(
            plan=plan,
            identity=identity,
            settings=settings,
            block=SampleBlock(
                utc_ns=(before + after) // 2,
                samples=values.astype(np.complex64, copy=False),
            ),
            tx_gain_readback_db=readback_gain,
        )
    finally:
        _release_device(device)
