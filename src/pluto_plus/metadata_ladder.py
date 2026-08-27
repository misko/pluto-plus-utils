"""Counter-observable metadata refill-size qualification ladder."""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from typing import Literal, Protocol, cast

from pydantic import Field, model_validator

from pluto_plus.hardware.base import (
    MetadataCapture,
    RadioDevice,
    SampleBlockV2,
    restore_settings_exact,
)
from pluto_plus.hardware.iio import IioRadioDevice
from pluto_plus.ladder import MAX_SAMPLES_PER_CHANNEL, MIN_SAMPLES_PER_CHANNEL
from pluto_plus.models import ApiModel, RadioSettings

DEFAULT_METADATA_SAMPLE_LADDER = "4194304,2097152,1048576,524288,262144,131072"
MAX_METADATA_SAMPLE_RUNGS = 16
MAX_METADATA_FRAMES = 32
MINIMUM_OBSERVED_FRACTION = 0.95


class MetadataContinuityCell(ApiModel):
    samples_per_channel: int = Field(
        ge=MIN_SAMPLES_PER_CHANNEL,
        le=MAX_SAMPLES_PER_CHANNEL,
    )
    requested_frames: int = Field(gt=0)
    observed_frames: int = Field(gt=0)
    observed_sample_count: int = Field(gt=0)
    device_span_sample_count: int = Field(gt=0)
    missing_sample_count: int = Field(ge=0)
    gap_count: int = Field(ge=0)
    overflow_count: int = Field(ge=0)
    elapsed_seconds: float = Field(gt=0)
    observed_fraction: float = Field(ge=0.0, le=1.0)
    passed: bool

    @model_validator(mode="after")
    def validate_closure(self) -> MetadataContinuityCell:
        if self.observed_frames != self.requested_frames:
            raise ValueError("metadata ladder must return every requested host frame")
        if self.observed_sample_count != self.observed_frames * self.samples_per_channel:
            raise ValueError("metadata ladder observed sample count does not close")
        if self.device_span_sample_count != (
            self.observed_sample_count + self.missing_sample_count
        ):
            raise ValueError("metadata ladder device span does not close")
        expected_fraction = self.observed_sample_count / self.device_span_sample_count
        if abs(self.observed_fraction - expected_fraction) > 1e-12:
            raise ValueError("metadata ladder observed fraction does not close")
        expected_pass = (
            self.observed_fraction >= MINIMUM_OBSERVED_FRACTION and self.overflow_count == 0
        )
        if self.passed is not expected_pass:
            raise ValueError("metadata ladder pass result is non-canonical")
        return self


class MetadataContinuityFailure(ApiModel):
    samples_per_channel: int = Field(
        ge=MIN_SAMPLES_PER_CHANNEL,
        le=MAX_SAMPLES_PER_CHANNEL,
    )
    error_type: str = Field(min_length=1)
    message: str = Field(min_length=1)


class MetadataContinuityLadderReport(ApiModel):
    serial: str
    uri: str
    transport: str
    model: str
    firmware_version: str | None
    metadata_abi: Literal[1, 2]
    sample_rate_hz: int = Field(gt=0)
    rf_bandwidth_hz: int = Field(gt=0)
    channels: tuple[int, int]
    kernel_buffers: int = Field(ge=4, le=64)
    minimum_observed_fraction: float = Field(
        default=MINIMUM_OBSERVED_FRACTION,
        ge=MINIMUM_OBSERVED_FRACTION,
        le=MINIMUM_OBSERVED_FRACTION,
    )
    cells: tuple[MetadataContinuityCell, ...]
    failures: tuple[MetadataContinuityFailure, ...]
    largest_passing_samples_per_channel: int | None = Field(
        default=None,
        ge=MIN_SAMPLES_PER_CHANNEL,
        le=MAX_SAMPLES_PER_CHANNEL,
    )
    original_settings_restored: bool
    continuity_claim: str = (
        "passed binds FPGA counter coverage >=95%, zero overflow, exact paired-RX geometry, "
        "and at least four kernel buffers; it is not inferred from host throughput"
    )

    @model_validator(mode="after")
    def validate_largest_pass(self) -> MetadataContinuityLadderReport:
        expected = next((cell.samples_per_channel for cell in self.cells if cell.passed), None)
        if self.largest_passing_samples_per_channel != expected:
            raise ValueError("largest passing metadata refill is non-canonical")
        return self


class MetadataLadderRadio(RadioDevice, Protocol):
    def begin_metadata_capture(
        self,
        sample_count: int,
        *,
        kernel_buffers: int,
    ) -> MetadataCapture: ...


def parse_metadata_sample_ladder(specification: str) -> tuple[int, ...]:
    """Parse a strictly descending comma-separated refill-size ladder."""

    try:
        values = tuple(int(item.strip()) for item in specification.split(","))
    except ValueError as error:
        raise ValueError("metadata sample ladder must contain decimal integers") from error
    if not values or len(values) > MAX_METADATA_SAMPLE_RUNGS:
        raise ValueError(f"metadata sample ladder requires 1 to {MAX_METADATA_SAMPLE_RUNGS} rungs")
    if any(value < MIN_SAMPLES_PER_CHANNEL or value > MAX_SAMPLES_PER_CHANNEL for value in values):
        raise ValueError(
            f"metadata sample rungs must be in [{MIN_SAMPLES_PER_CHANNEL}, "
            f"{MAX_SAMPLES_PER_CHANNEL}]"
        )
    if any(right >= left for left, right in zip(values, values[1:], strict=False)):
        raise ValueError("metadata sample ladder must be strictly descending")
    return values


def run_metadata_continuity_ladder(
    *,
    uri: str,
    serial: str,
    sample_rate_hz: int,
    rf_bandwidth_hz: int,
    metadata_abi: Literal[1, 2] = 1,
    samples_per_channel: Sequence[int],
    frames: int = 6,
    kernel_buffers: int = 4,
    radio_factory: Callable[[str, str, Literal[1, 2]], MetadataLadderRadio] | None = None,
    clock_ns: Callable[[], int] = time.perf_counter_ns,
) -> MetadataContinuityLadderReport:
    """Measure device-axis continuity for each refill size and restore RX settings."""

    _validate_request(
        sample_rate_hz=sample_rate_hz,
        rf_bandwidth_hz=rf_bandwidth_hz,
        samples_per_channel=samples_per_channel,
        frames=frames,
        kernel_buffers=kernel_buffers,
    )
    factory = radio_factory or _default_radio_factory
    radio = factory(uri, serial, metadata_abi)
    opened = False
    original: RadioSettings | None = None
    cells: list[MetadataContinuityCell] = []
    failures: list[MetadataContinuityFailure] = []
    restored = False
    try:
        radio.open()
        opened = True
        original = radio.read_settings()
        requested = original.model_copy(
            update={
                "sample_rate_hz": sample_rate_hz,
                "bandwidth_hz": rf_bandwidth_hz,
                "channels": (0, 1),
            }
        )
        actual = radio.apply_settings(requested)
        if (
            round(actual.sample_rate_hz) != sample_rate_hz
            or round(actual.bandwidth_hz) != rf_bandwidth_hz
            or tuple(actual.channels) != (0, 1)
        ):
            raise RuntimeError("metadata ladder RX settings did not read back exactly")
        identity = radio.identity
        for samples in samples_per_channel:
            try:
                cells.append(
                    _run_cell(
                        radio,
                        samples_per_channel=samples,
                        frames=frames,
                        kernel_buffers=kernel_buffers,
                        clock_ns=clock_ns,
                    )
                )
            except Exception as error:
                failures.append(
                    MetadataContinuityFailure(
                        samples_per_channel=samples,
                        error_type=type(error).__name__,
                        message=str(error),
                    )
                )
    finally:
        try:
            if opened and original is not None:
                restored = restore_settings_exact(radio, original).restored == original
        finally:
            if opened:
                radio.close()
    if not restored:
        raise RuntimeError("metadata ladder could not verify restoration of original RX settings")
    return MetadataContinuityLadderReport(
        serial=identity.serial,
        uri=identity.uri,
        transport=identity.transport.value,
        model=identity.model,
        firmware_version=identity.firmware_version,
        metadata_abi=metadata_abi,
        sample_rate_hz=sample_rate_hz,
        rf_bandwidth_hz=rf_bandwidth_hz,
        channels=(0, 1),
        kernel_buffers=kernel_buffers,
        cells=tuple(cells),
        failures=tuple(failures),
        largest_passing_samples_per_channel=next(
            (cell.samples_per_channel for cell in cells if cell.passed),
            None,
        ),
        original_settings_restored=restored,
    )


def _run_cell(
    radio: MetadataLadderRadio,
    *,
    samples_per_channel: int,
    frames: int,
    kernel_buffers: int,
    clock_ns: Callable[[], int],
) -> MetadataContinuityCell:
    blocks: list[SampleBlockV2] = []
    started_ns = clock_ns()
    with radio.begin_metadata_capture(
        samples_per_channel,
        kernel_buffers=kernel_buffers,
    ) as capture:
        if capture.kernel_buffers != kernel_buffers:
            raise RuntimeError("metadata ladder kernel-buffer readback is not exact")
        for _ in range(frames):
            block = capture.read_block()
            if block.samples.shape != (2, samples_per_channel):
                raise RuntimeError("metadata ladder block shape is not exact paired RX")
            blocks.append(block)
    elapsed_seconds = (clock_ns() - started_ns) / 1_000_000_000
    if elapsed_seconds <= 0:
        raise RuntimeError("metadata ladder clock did not advance")
    observed = len(blocks) * samples_per_channel
    missing = sum(block.missing_samples_before for block in blocks)
    span = blocks[-1].last_sample_sequence_exclusive - blocks[0].first_sample_sequence
    if span != observed + missing:
        raise RuntimeError("metadata ladder FPGA counter span does not close")
    fraction = observed / span
    overflow_count = sum(1 for block in blocks if block.overflow_observed)
    return MetadataContinuityCell(
        samples_per_channel=samples_per_channel,
        requested_frames=frames,
        observed_frames=len(blocks),
        observed_sample_count=observed,
        device_span_sample_count=span,
        missing_sample_count=missing,
        gap_count=sum(1 for block in blocks if block.missing_samples_before),
        overflow_count=overflow_count,
        elapsed_seconds=elapsed_seconds,
        observed_fraction=fraction,
        passed=fraction >= MINIMUM_OBSERVED_FRACTION and overflow_count == 0,
    )


def _validate_request(
    *,
    sample_rate_hz: int,
    rf_bandwidth_hz: int,
    samples_per_channel: Sequence[int],
    frames: int,
    kernel_buffers: int,
) -> None:
    if sample_rate_hz <= 0:
        raise ValueError("metadata ladder sample rate must be positive")
    if rf_bandwidth_hz <= 0 or rf_bandwidth_hz > sample_rate_hz:
        raise ValueError("metadata ladder RF bandwidth must be in (0, sample rate]")
    canonical = tuple(samples_per_channel)
    if canonical != parse_metadata_sample_ladder(",".join(str(item) for item in canonical)):
        raise ValueError("metadata sample ladder is not canonical")
    if not 2 <= frames <= MAX_METADATA_FRAMES:
        raise ValueError(f"metadata frames must be in [2, {MAX_METADATA_FRAMES}]")
    if not 4 <= kernel_buffers <= 64:
        raise ValueError("metadata ladder requires between 4 and 64 kernel buffers")


def _default_radio_factory(
    uri: str,
    serial: str,
    metadata_abi: Literal[1, 2],
) -> MetadataLadderRadio:
    return cast(
        MetadataLadderRadio,
        IioRadioDevice(
            uri,
            serial=serial,
            radio_id=serial,
            expected_metadata_abi=metadata_abi,
        ),
    )
