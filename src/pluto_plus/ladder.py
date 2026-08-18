"""Bounded, receive-only standard-libiio transport throughput ladder."""

from __future__ import annotations

import math
import re
import time
from collections.abc import Callable, Sequence
from typing import Protocol

import numpy as np
from pydantic import Field

from pluto_plus.hardware.base import SampleBlock
from pluto_plus.hardware.iio import IioRadioDevice
from pluto_plus.models import ApiModel, RadioCapabilities, RadioIdentity, RadioSettings

DEFAULT_RATE_LADDER = "1M,1.5M,2M,2.5M,3M,5M,10M,20M,30M"
MIN_SAMPLES_PER_CHANNEL = 16_384
MAX_SAMPLES_PER_CHANNEL = 4_194_304
MAX_RATE_RUNGS = 32
MAX_TIMED_FRAMES = 100
MAX_WARMUP_FRAMES = 20
WIRE_BYTES_PER_COMPLEX_SAMPLE = 4
KEEP_PACE_FRACTION = 0.90
_RATE_PATTERN = re.compile(r"^([0-9]+(?:\.[0-9]+)?)([kKmMgG]?)$")
_RATE_MULTIPLIERS = {"": 1, "k": 1_000, "m": 1_000_000, "g": 1_000_000_000}


class LadderCell(ApiModel):
    sample_rate_hz: int = Field(gt=0)
    actual_sample_rate_hz: int = Field(gt=0)
    samples_per_channel: int = Field(gt=0)
    frames: int = Field(gt=0)
    wire_bytes: int = Field(ge=0)
    elapsed_seconds: float = Field(ge=0)
    offered_payload_mbps: float = Field(ge=0)
    achieved_payload_mbps: float = Field(ge=0)
    achieved_payload_mibps: float = Field(ge=0)
    transferred_mb_per_minute: float = Field(ge=0)
    delivered_sample_rate_sps: float = Field(ge=0)
    delivery_fraction: float = Field(ge=0)
    latency_p50_ms: float = Field(ge=0)
    latency_p95_ms: float = Field(ge=0)
    kept_pace: bool


class LadderFailure(ApiModel):
    sample_rate_hz: int = Field(gt=0)
    error_type: str
    message: str


class LadderReport(ApiModel):
    serial: str
    uri: str
    transport: str
    model: str
    firmware_version: str | None
    channels: tuple[int, ...]
    kernel_buffers: int = Field(ge=1, le=64)
    wire_bytes_per_sample_period: int
    warmup_frames: int
    cells: tuple[LadderCell, ...]
    failures: tuple[LadderFailure, ...]
    original_settings_restored: bool
    continuity_claim: str = (
        "kept_pace means host delivery reached at least 90% of the configured rate; "
        "ordinary libiio capture does not prove a gapless FPGA timeline"
    )


class LadderRadio(Protocol):
    @property
    def identity(self) -> RadioIdentity: ...

    @property
    def capabilities(self) -> RadioCapabilities: ...

    def open(self) -> None: ...

    def close(self) -> None: ...

    def read_settings(self) -> RadioSettings: ...

    def apply_settings(self, settings: RadioSettings) -> RadioSettings: ...

    def configure_kernel_buffers(self, count: int) -> None: ...

    def read_block(self, sample_count: int) -> SampleBlock: ...


def parse_rate_ladder(specification: str) -> tuple[int, ...]:
    """Parse a strictly increasing decimal Hz/K/M/G rate ladder."""

    values: list[int] = []
    for raw in specification.split(","):
        token = raw.strip()
        match = _RATE_PATTERN.fullmatch(token)
        if match is None:
            raise ValueError(f"invalid sample-rate rung {token!r}")
        value = float(match.group(1)) * _RATE_MULTIPLIERS[match.group(2).lower()]
        rounded = round(value)
        if not math.isfinite(value) or rounded <= 0 or not math.isclose(value, rounded):
            raise ValueError(f"sample-rate rung must resolve to a positive integer Hz: {token!r}")
        values.append(rounded)
    if not values:
        raise ValueError("sample-rate ladder must not be empty")
    if len(values) > MAX_RATE_RUNGS:
        raise ValueError(f"sample-rate ladder is limited to {MAX_RATE_RUNGS} rungs")
    if any(right <= left for left, right in zip(values, values[1:], strict=False)):
        raise ValueError("sample-rate ladder must be strictly increasing")
    return tuple(values)


def run_iio_ladder(
    *,
    uri: str,
    serial: str | None,
    rates_hz: Sequence[int],
    samples_per_channel: int = 262_144,
    frames: int = 12,
    warmup_frames: int = 2,
    kernel_buffers: int = 8,
    radio_factory: Callable[[str, str | None], LadderRadio] | None = None,
    clock_ns: Callable[[], int] = time.perf_counter_ns,
) -> LadderReport:
    """Run a bounded paired-RX ladder and restore the exact original RX settings."""

    _validate_shape(rates_hz, samples_per_channel, frames, warmup_frames, kernel_buffers)
    factory = radio_factory or _default_radio_factory
    radio = factory(uri, serial)
    opened = False
    original: RadioSettings | None = None
    cells: list[LadderCell] = []
    failures: list[LadderFailure] = []
    restored = False
    try:
        radio.open()
        opened = True
        original = radio.read_settings()
        radio.configure_kernel_buffers(kernel_buffers)
        channels = tuple(radio.capabilities.receiver_channels)
        if len(channels) < 2:
            raise RuntimeError("speed ladder requires a paired-RX Pluto context")
        channels = channels[:2]
        for rate in rates_hz:
            try:
                _validate_rate(rate, radio.capabilities)
                requested = original.model_copy(
                    update={
                        "sample_rate_hz": rate,
                        "bandwidth_hz": min(max(rate, 200_000), 20_000_000),
                        "channels": channels,
                    }
                )
                actual = radio.apply_settings(requested)
                for _ in range(warmup_frames):
                    _validate_block(
                        radio.read_block(samples_per_channel), channels, samples_per_channel
                    )
                latencies_ns: list[int] = []
                started_ns = clock_ns()
                for _ in range(frames):
                    frame_started_ns = clock_ns()
                    block = radio.read_block(samples_per_channel)
                    frame_ended_ns = clock_ns()
                    _validate_block(block, channels, samples_per_channel)
                    latencies_ns.append(frame_ended_ns - frame_started_ns)
                elapsed_seconds = (clock_ns() - started_ns) / 1_000_000_000
                if elapsed_seconds <= 0:
                    raise RuntimeError("benchmark clock did not advance")
                wire_bytes = (
                    frames * samples_per_channel * len(channels) * WIRE_BYTES_PER_COMPLEX_SAMPLE
                )
                achieved_mbps = wire_bytes / elapsed_seconds / 1_000_000
                delivered_rate = frames * samples_per_channel / elapsed_seconds
                fraction = delivered_rate / float(actual.sample_rate_hz)
                cells.append(
                    LadderCell(
                        sample_rate_hz=rate,
                        actual_sample_rate_hz=round(actual.sample_rate_hz),
                        samples_per_channel=samples_per_channel,
                        frames=frames,
                        wire_bytes=wire_bytes,
                        elapsed_seconds=elapsed_seconds,
                        offered_payload_mbps=actual.sample_rate_hz
                        * len(channels)
                        * WIRE_BYTES_PER_COMPLEX_SAMPLE
                        / 1_000_000,
                        achieved_payload_mbps=achieved_mbps,
                        achieved_payload_mibps=wire_bytes / elapsed_seconds / (1024 * 1024),
                        transferred_mb_per_minute=achieved_mbps * 60,
                        delivered_sample_rate_sps=delivered_rate,
                        delivery_fraction=fraction,
                        latency_p50_ms=_percentile_ms(latencies_ns, 50),
                        latency_p95_ms=_percentile_ms(latencies_ns, 95),
                        kept_pace=fraction >= KEEP_PACE_FRACTION,
                    )
                )
            except Exception as error:
                failures.append(
                    LadderFailure(
                        sample_rate_hz=rate,
                        error_type=type(error).__name__,
                        message=str(error),
                    )
                )
        identity = radio.identity
    finally:
        try:
            if opened and original is not None:
                restored = radio.apply_settings(original) == original
        finally:
            if opened:
                radio.close()
    if not restored:
        raise RuntimeError("speed ladder could not verify restoration of original RX settings")
    return LadderReport(
        serial=identity.serial,
        uri=identity.uri,
        transport=identity.transport.value,
        model=identity.model,
        firmware_version=identity.firmware_version,
        channels=channels,
        kernel_buffers=kernel_buffers,
        wire_bytes_per_sample_period=len(channels) * WIRE_BYTES_PER_COMPLEX_SAMPLE,
        warmup_frames=warmup_frames,
        cells=tuple(cells),
        failures=tuple(failures),
        original_settings_restored=restored,
    )


def _default_radio_factory(uri: str, serial: str | None) -> LadderRadio:
    return IioRadioDevice(uri, serial=serial, radio_id=serial or uri)


def _validate_shape(
    rates_hz: Sequence[int],
    samples_per_channel: int,
    frames: int,
    warmup_frames: int,
    kernel_buffers: int,
) -> None:
    if not rates_hz or len(rates_hz) > MAX_RATE_RUNGS:
        raise ValueError(f"speed ladder requires between 1 and {MAX_RATE_RUNGS} rungs")
    if any(right <= left for left, right in zip(rates_hz, rates_hz[1:], strict=False)):
        raise ValueError("sample-rate ladder must be strictly increasing")
    if not MIN_SAMPLES_PER_CHANNEL <= samples_per_channel <= MAX_SAMPLES_PER_CHANNEL:
        raise ValueError(
            f"samples per channel must be between {MIN_SAMPLES_PER_CHANNEL} "
            f"and {MAX_SAMPLES_PER_CHANNEL}"
        )
    if not 1 <= frames <= MAX_TIMED_FRAMES:
        raise ValueError(f"timed frames must be between 1 and {MAX_TIMED_FRAMES}")
    if not 0 <= warmup_frames <= MAX_WARMUP_FRAMES:
        raise ValueError(f"warmup frames must be between 0 and {MAX_WARMUP_FRAMES}")
    if not 1 <= kernel_buffers <= 64:
        raise ValueError("kernel buffer count must be between 1 and 64")


def _validate_rate(rate: int, capabilities: RadioCapabilities) -> None:
    if rate <= 0:
        raise ValueError("sample rate must be positive")
    minimum = capabilities.minimum_sample_rate_hz
    maximum = capabilities.maximum_sample_rate_hz
    if minimum is not None and rate < minimum:
        raise ValueError(f"sample rate {rate} is below device minimum {minimum:g}")
    if maximum is not None and rate > maximum:
        raise ValueError(f"sample rate {rate} is above device maximum {maximum:g}")


def _validate_block(block: SampleBlock, channels: tuple[int, ...], samples: int) -> None:
    expected = (len(channels), samples)
    if block.samples.shape != expected:
        raise RuntimeError(
            f"paired capture returned shape {block.samples.shape}, expected {expected}"
        )
    if not np.isfinite(block.samples).all():
        raise RuntimeError("paired capture contains non-finite samples")


def _percentile_ms(values_ns: Sequence[int], percentile: int) -> float:
    if not values_ns:
        return 0.0
    return float(np.percentile(np.asarray(values_ns, dtype=np.float64), percentile) / 1_000_000)
