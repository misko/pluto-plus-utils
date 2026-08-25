"""Finite, serial-bound DDS stimulus with fail-muted cleanup."""

from __future__ import annotations

import importlib
import math
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from types import ModuleType
from typing import Any

import numpy as np

from pluto_plus.direct_radio.usb import MetadataFlags
from pluto_plus.errors import RadioConfigurationError
from pluto_plus.hardware.base import SampleBlock, SampleBlockV2
from pluto_plus.hardware.iio import (
    _mute_transmit,
    _optional_attribute,
    _release_device,
    _require_canonical_rx_layout,
    context_facts,
    find_usb_sysfs_path,
    resolve_iio_uri,
)
from pluto_plus.hardware.iio_metadata import IioMetadataCaptureSession
from pluto_plus.hardware.preflight import V7_FIRMWARE_VERSION, verify_metadata_runtime
from pluto_plus.models import GainMode, RadioIdentity, RadioSettings, Transport
from pluto_plus.tandem import TandemMode, TandemSessionRequestV1

MAX_TONE_CAPTURE_SAMPLES = 1_048_576
MAX_CONTINUOUS_TONE_CAPTURE_SAMPLES = 15_000_000
MIN_CONTINUOUS_KERNEL_BUFFERS = 3
_METADATA_FAILURE_FLAGS = (
    MetadataFlags.DEVICE_IIO_OVERFLOW
    | MetadataFlags.GAIN_READ_FAILED
    | MetadataFlags.FPGA_EVENT_OVERFLOW
    | MetadataFlags.RSSI_READ_FAILED
    | MetadataFlags.GAIN_OBSERVATION_OVERFLOW
)


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
    dds_enabled_readback: tuple[bool, ...]
    dds_scale_readback: tuple[float, ...]


@dataclass(frozen=True, slots=True)
class ContinuousFrameProof:
    """Lightweight proof retained for each persisted metadata refill."""

    utc_ns: int
    stream_id: int
    buffer_sequence: int
    first_sample_sequence: int
    last_sample_sequence_exclusive: int
    sample_count: int
    metadata_flags: int
    metadata_abi: int
    sample_time_realtime_start_ns: int
    sample_time_realtime_end_ns: int
    sample_time_monotonic_start_ns: int
    sample_time_monotonic_end_ns: int
    sample_time_uncertainty_ns: int


@dataclass(frozen=True, slots=True)
class SafeContinuousDdsToneCapture:
    """One bounded multi-refill tone capture with an exact sample timeline."""

    plan: SafeDdsTonePlan
    identity: RadioIdentity
    settings: RadioSettings
    frames: tuple[ContinuousFrameProof, ...]
    kernel_buffers: int
    tx_gain_readback_db: float
    dds_enabled_readback: tuple[bool, ...]
    dds_scale_readback: tuple[float, ...]
    dds_frequency_readback_hz: tuple[int, ...]

    @property
    def sample_count(self) -> int:
        return sum(frame.sample_count for frame in self.frames)

    @property
    def duration_s(self) -> float:
        return self.sample_count / self.settings.sample_rate_hz


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
        has_enabled, enabled = _optional_attribute(device, "dds_enabled")
        if not has_enabled or enabled is None:
            raise RadioConfigurationError("DDS enable read-back is unavailable")
        enabled_values = tuple(
            str(value).strip().lower() not in {"0", "false"} for value in enabled
        )
        if not any(enabled_values):
            raise RadioConfigurationError("DDS source did not enable")

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
            dds_enabled_readback=enabled_values,
            dds_scale_readback=tuple(float(value) for value in scales),
        )
    finally:
        _release_device(device)


def capture_continuous_safe_dds_tone(
    plan: SafeDdsTonePlan,
    *,
    samples_per_frame: int,
    frame_count: int,
    kernel_buffers: int,
    block_consumer: Callable[[SampleBlockV2], None] | None = None,
    iio_contexts: Mapping[str, str] | None = None,
) -> SafeContinuousDdsToneCapture:
    """Capture fixed metadata refills while emitting one reviewed finite tone.

    Real hardware is accepted only with the exact V7 firmware/runtime pair.
    Every refill must be gap-free on both the firmware buffer sequence and the
    FPGA sample counter.  The consumer runs synchronously, allowing IQ to be
    persisted without retaining the full capture in memory.
    """

    if samples_per_frame < 1 or samples_per_frame > MAX_TONE_CAPTURE_SAMPLES:
        raise ValueError(
            f"samples_per_frame must be 1..{MAX_TONE_CAPTURE_SAMPLES}"
        )
    if frame_count < 1:
        raise ValueError("frame_count must be positive")
    total_samples = samples_per_frame * frame_count
    if total_samples > MAX_CONTINUOUS_TONE_CAPTURE_SAMPLES:
        raise ValueError(
            "continuous tone capture exceeds the reviewed sample-count bound"
        )
    if not MIN_CONTINUOUS_KERNEL_BUFFERS <= kernel_buffers <= 64:
        raise ValueError(
            f"kernel_buffers must be {MIN_CONTINUOUS_KERNEL_BUFFERS}..64"
        )
    if (
        not 0 <= plan.receiver_gain_db <= 62
        or not float(plan.receiver_gain_db).is_integer()
    ):
        raise ValueError(
            "continuous V7 HOLD capture requires an integer receiver gain in 0..62 dB"
        )
    # Preload and attest the exact native/Python pair before pyadi can map an
    # ambient object with the same SONAME into this process.  Unlike the legacy
    # one-block helper, this continuity-claiming path intentionally exposes no
    # public runtime-injection bypass.
    verify_metadata_runtime(
        2,
        expected_firmware_version=V7_FIRMWARE_VERSION,
    )
    try:
        iio_runtime = importlib.import_module("iio")
        adi_runtime = importlib.import_module("adi")
    except (ImportError, AttributeError, OSError) as error:
        raise ImportError(
            "continuous DDS capture requires the exact metadata hardware runtime"
        ) from error

    metadata_buffer_type = getattr(iio_runtime, "MetadataBuffer", None)
    if metadata_buffer_type is None:
        raise RadioConfigurationError("installed pylibiio does not expose MetadataBuffer")
    resolved_uri = resolve_iio_uri(plan.uri, plan.serial, contexts=iio_contexts)
    device = adi_runtime.ad9361(uri=resolved_uri)
    session: IioMetadataCaptureSession | None = None
    try:
        _mute_transmit(device)
        facts = context_facts(device.ctx)
        _validate_continuous_target(plan, facts)

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
        device.rx_buffer_size = samples_per_frame
        settings = _read_continuous_settings(device, plan)
        actual_kernel_buffers = _configure_kernel_buffers(device, kernel_buffers)

        # Enabling occurs only after all shared transceiver settings are fixed.
        # Session.open() then performs the required ordinary prime/destroy and
        # creates a fresh metadata generation whose first buffer is sequence 0.
        _mute_transmit(device)
        (
            readback_gain,
            enabled_values,
            scale_values,
            frequency_values,
        ) = _enable_reviewed_tone(device, plan)
        time.sleep(plan.settle_ms / 1000.0)
        session = IioMetadataCaptureSession(
            device,
            metadata_buffer_type,
            sample_rate_hz=round(settings.sample_rate_hz),
            samples_per_channel=samples_per_frame,
            kernel_buffers=actual_kernel_buffers,
            metadata_abi=2,
            tandem_request=TandemSessionRequestV1(
                mode=TandemMode.HOLD,
                initial_gain_db=int(plan.receiver_gain_db),
            ),
        )
        session.open()
        for channel in (0, 1):
            held_gain = float(getattr(device, f"rx_hardwaregain_chan{channel}"))
            if abs(held_gain - plan.receiver_gain_db) > 0.25:
                raise RadioConfigurationError(
                    f"RX{channel + 1} HOLD gain read-back is outside the plan"
                )

        proofs: list[ContinuousFrameProof] = []
        previous: SampleBlockV2 | None = None
        for _ in range(frame_count):
            block = session.read_block()
            _validate_continuous_block(
                block,
                previous=previous,
                samples_per_frame=samples_per_frame,
            )
            if block_consumer is not None:
                block_consumer(block)
            proofs.append(_frame_proof(block))
            previous = block

        if not proofs:
            raise RuntimeError("continuous capture returned no metadata frames")
        if (
            proofs[-1].last_sample_sequence_exclusive
            - proofs[0].first_sample_sequence
            != total_samples
        ):
            raise RuntimeError("continuous capture sample-counter span is incomplete")

        return SafeContinuousDdsToneCapture(
            plan=plan,
            identity=_identity_from_facts(plan, resolved_uri, facts),
            settings=settings,
            frames=tuple(proofs),
            kernel_buffers=actual_kernel_buffers,
            tx_gain_readback_db=readback_gain,
            dds_enabled_readback=enabled_values,
            dds_scale_readback=scale_values,
            dds_frequency_readback_hz=frequency_values,
        )
    finally:
        # Remove RF energy before any metadata-buffer CLOSE can block or fail.
        try:
            _mute_transmit(device)
        finally:
            try:
                if session is not None:
                    session.close()
            finally:
                _release_device(device)


def _validate_continuous_target(
    plan: SafeDdsTonePlan, facts: Mapping[str, object]
) -> None:
    detected_serial = str(facts.get("serial") or "")
    if detected_serial != plan.serial:
        raise RadioConfigurationError(
            f"opened Pluto serial {detected_serial!r}, expected {plan.serial!r}"
        )
    firmware_version = str(facts.get("firmware_version") or "")
    if firmware_version != V7_FIRMWARE_VERSION:
        raise RadioConfigurationError(
            "continuous metadata capture requires exact firmware "
            f"{V7_FIRMWARE_VERSION!r}, observed {firmware_version!r}"
        )
    if facts.get("buffer_metadata_abi") != 2 or not facts.get("tandem_agc"):
        raise RadioConfigurationError(
            "continuous capture requires V7 metadata ABI 2 and tandem-agc"
        )
    _require_canonical_rx_layout(facts)


def _read_continuous_settings(device: Any, plan: SafeDdsTonePlan) -> RadioSettings:
    exact_values = (
        ("sample rate", float(device.sample_rate), float(plan.sample_rate_hz)),
        ("RX bandwidth", float(device.rx_rf_bandwidth), float(plan.bandwidth_hz)),
        ("RX LO", float(device.rx_lo), float(plan.center_frequency_hz)),
        ("TX LO", float(device.tx_lo), float(plan.center_frequency_hz)),
    )
    for name, actual, expected in exact_values:
        if actual != expected:
            raise RadioConfigurationError(
                f"{name} read-back is {actual:g}, expected {expected:g}"
            )
    if tuple(int(value) for value in device.rx_enabled_channels) != (0, 1):
        raise RadioConfigurationError("continuous metadata capture requires RX1 and RX2")
    for channel in (0, 1):
        mode = str(getattr(device, f"gain_control_mode_chan{channel}"))
        gain = float(getattr(device, f"rx_hardwaregain_chan{channel}"))
        if mode != GainMode.MANUAL.value or abs(gain - plan.receiver_gain_db) > 0.25:
            raise RadioConfigurationError(
                f"RX{channel + 1} manual gain read-back is outside the plan"
            )
    return RadioSettings(
        center_frequency_hz=float(device.rx_lo),
        sample_rate_hz=float(device.sample_rate),
        bandwidth_hz=float(device.rx_rf_bandwidth),
        gain_mode=GainMode.MANUAL,
        gain_db=plan.receiver_gain_db,
        channels=(0, 1),
    )


def _configure_kernel_buffers(device: Any, count: int) -> int:
    device.rx_destroy_buffer()
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
    if actual is None or int(actual) != count:
        raise RadioConfigurationError(
            f"RX kernel-buffer read-back is {actual!r}, expected {count}"
        )
    return int(actual)


def _enable_reviewed_tone(
    device: Any, plan: SafeDdsTonePlan
) -> tuple[float, tuple[bool, ...], tuple[float, ...], tuple[int, ...]]:
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
    for channel in (0, 1):
        channel_gain = float(getattr(device, f"tx_hardwaregain_chan{channel}"))
        expected_gain = plan.tx_hardware_gain_db if channel == plan.tx_channel else -80.0
        if abs(channel_gain - expected_gain) > 0.25:
            raise RadioConfigurationError(
                f"TX{channel + 1} gain read-back does not match the one-port plan"
            )
    has_scales, scales = _optional_attribute(device, "dds_scales")
    if not has_scales or scales is None:
        raise RadioConfigurationError("DDS scale read-back is unavailable")
    scale_values = tuple(float(value) for value in scales)
    if len(scale_values) != 8:
        raise RadioConfigurationError("DDS scale read-back is not the canonical 2T2R layout")
    active_indices = {plan.tx_channel * 4, plan.tx_channel * 4 + 2}
    for index, value in enumerate(scale_values):
        expected_scale = plan.dds_scale if index in active_indices else 0.0
        if abs(abs(value) - expected_scale) > 1e-6:
            raise RadioConfigurationError(
                "DDS scale read-back does not select exactly one TX I/Q pair"
            )
    has_enabled, enabled = _optional_attribute(device, "dds_enabled")
    if not has_enabled or enabled is None:
        raise RadioConfigurationError("DDS enable read-back is unavailable")
    enabled_values = tuple(
        str(value).strip().lower() not in {"0", "false"} for value in enabled
    )
    if not any(enabled_values):
        raise RadioConfigurationError("DDS source did not enable")
    if any(not enabled_values[index] for index in active_indices):
        raise RadioConfigurationError("selected TX I/Q DDS source did not enable")
    has_frequencies, frequencies = _optional_attribute(device, "dds_frequencies")
    if not has_frequencies or frequencies is None:
        raise RadioConfigurationError("DDS frequency read-back is unavailable")
    frequency_values = tuple(int(value) for value in frequencies)
    frequency_tolerance_hz = math.ceil(plan.sample_rate_hz / (1 << 16))
    if len(frequency_values) != len(scale_values) or any(
        abs(abs(frequency_values[index]) - abs(plan.tone_frequency_hz))
        > frequency_tolerance_hz
        for index in active_indices
    ):
        raise RadioConfigurationError("selected TX I/Q DDS frequency is outside the plan")
    return readback_gain, enabled_values, scale_values, frequency_values


def _validate_continuous_block(
    block: SampleBlockV2,
    *,
    previous: SampleBlockV2 | None,
    samples_per_frame: int,
) -> None:
    if block.metadata_abi != 2 or block.sample_count != samples_per_frame:
        raise RuntimeError("metadata frame shape or ABI changed during capture")
    if block.missing_samples_before:
        raise RuntimeError("metadata frame reports missing FPGA samples")
    required_flags = (
        MetadataFlags.SAMPLE_SEQUENCE_VALID
        | MetadataFlags.HARDWARE_SAMPLE_COUNTER_VALID
    )
    if MetadataFlags(block.metadata_flags) & required_flags != required_flags:
        raise RuntimeError(
            "metadata frame lacks valid sample-sequence or hardware-counter flags"
        )
    failure_flags = MetadataFlags(block.metadata_flags) & _METADATA_FAILURE_FLAGS
    if failure_flags:
        raise RuntimeError(
            f"metadata frame reports overflow or capture failure flags: "
            f"0x{int(failure_flags):x}"
        )
    times = (
        block.sample_time_realtime_start_ns,
        block.sample_time_realtime_end_ns,
        block.sample_time_monotonic_start_ns,
        block.sample_time_monotonic_end_ns,
        block.sample_time_uncertainty_ns,
    )
    if any(value is None for value in times):
        raise RuntimeError("metadata frame lacks host timing provenance")
    if previous is None:
        if block.buffer_sequence != 0:
            raise RuntimeError("metadata capture did not begin at buffer sequence zero")
        return
    if block.stream_id != previous.stream_id:
        raise RuntimeError("metadata stream changed during continuous capture")
    if block.buffer_sequence != previous.buffer_sequence + 1:
        raise RuntimeError("metadata buffer sequence is not continuous")
    if block.first_sample_sequence != previous.last_sample_sequence_exclusive:
        raise RuntimeError("FPGA sample sequence is not continuous")


def _frame_proof(block: SampleBlockV2) -> ContinuousFrameProof:
    assert block.sample_time_realtime_start_ns is not None
    assert block.sample_time_realtime_end_ns is not None
    assert block.sample_time_monotonic_start_ns is not None
    assert block.sample_time_monotonic_end_ns is not None
    assert block.sample_time_uncertainty_ns is not None
    return ContinuousFrameProof(
        utc_ns=block.utc_ns,
        stream_id=block.stream_id,
        buffer_sequence=block.buffer_sequence,
        first_sample_sequence=block.first_sample_sequence,
        last_sample_sequence_exclusive=block.last_sample_sequence_exclusive,
        sample_count=block.sample_count,
        metadata_flags=block.metadata_flags,
        metadata_abi=block.metadata_abi,
        sample_time_realtime_start_ns=block.sample_time_realtime_start_ns,
        sample_time_realtime_end_ns=block.sample_time_realtime_end_ns,
        sample_time_monotonic_start_ns=block.sample_time_monotonic_start_ns,
        sample_time_monotonic_end_ns=block.sample_time_monotonic_end_ns,
        sample_time_uncertainty_ns=block.sample_time_uncertainty_ns,
    )


def _identity_from_facts(
    plan: SafeDdsTonePlan,
    resolved_uri: str,
    facts: Mapping[str, object],
) -> RadioIdentity:
    return RadioIdentity(
        radio_id=plan.serial,
        serial=plan.serial,
        uri=resolved_uri,
        transport=Transport.IIO_USB,
        model=str(facts.get("model") or "Pluto+"),
        firmware_version=str(facts["firmware_version"]),
        usb_path=find_usb_sysfs_path(plan.serial),
    )
