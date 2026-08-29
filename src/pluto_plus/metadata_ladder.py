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
# Fifty 1,000,000-sample CI16 frames are the reviewed 200-MB/two-second
# single-RX burst geometry at 25 MS/s. Keep a small bounded margin above that
# exact release gate without encouraging larger DMA frames or unbounded runs.
MAX_METADATA_FRAMES = 64
MINIMUM_OBSERVED_FRACTION = 0.95
# Hardware qualification found intermittent whole-frame loss at 8 ms.  The
# first passing boundary was 10 ms; retain 50% headroom over the failure point
# so client admission agrees with iiOD's conservative scheduling envelope.
DDR_BURST_MIN_FRAME_DURATION_US = 12_000
MAX_DDR_RING_IQ_BYTES = 200_000_000
MetadataAbi = Literal[1, 2, 3]
MetadataChannels = Literal["rx0", "rx1", "dual"]
METADATA_CHANNEL_SELECTIONS: dict[MetadataChannels, tuple[int, ...]] = {
    "rx0": (0,),
    "rx1": (1,),
    "dual": (0, 1),
}


class DdrRingFinalStatus(ApiModel):
    state: str
    terminal_reason: str
    error_code: int
    requested_capacity_iq_bytes: int = Field(gt=0)
    admitted_capacity_iq_bytes: int = Field(gt=0)
    target_frames: int = Field(gt=0)
    produced_frames: int = Field(ge=0)
    consumed_frames: int = Field(ge=0)
    high_water_frames: int = Field(gt=0)
    wrap_count: int = Field(ge=0)
    producer_position: int = Field(ge=0)
    consumer_position: int = Field(ge=0)
    last_contiguous_sample_sequence: int | None = Field(default=None, ge=0)
    first_unavailable_sample_sequence: int | None = Field(default=None, ge=0)

    @model_validator(mode="after")
    def validate_complete_capture(self) -> DdrRingFinalStatus:
        if (
            self.state != "complete"
            or self.terminal_reason != "target_complete"
            or self.error_code != 0
        ):
            raise ValueError("DDR ring did not reach a clean target-complete state")
        if not (
            self.produced_frames == self.consumed_frames == self.target_frames
        ):
            raise ValueError("DDR ring producer/consumer frame counts do not close")
        if self.first_unavailable_sample_sequence is not None:
            raise ValueError("DDR ring reported an unavailable sample boundary")
        return self


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
    ddr_burst_requested_iq_bytes: int = Field(default=0, ge=0)
    ddr_burst_admitted_iq_bytes: int = Field(default=0, ge=0)
    ddr_burst_frames: int = Field(default=0, ge=0)
    ddr_ring_status: DdrRingFinalStatus | None = None
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
        expected_burst_bytes = self.samples_per_channel * 4 * self.requested_frames
        if self.ddr_burst_requested_iq_bytes:
            if (
                self.ddr_burst_requested_iq_bytes != expected_burst_bytes
                or self.ddr_burst_admitted_iq_bytes != expected_burst_bytes
                or self.ddr_burst_frames != self.requested_frames
            ):
                raise ValueError("metadata ladder DDR burst admission does not close")
        elif self.ddr_burst_admitted_iq_bytes or self.ddr_burst_frames:
            raise ValueError("ordinary metadata ladder cannot report DDR burst admission")
        if self.ddr_ring_status is not None:
            status = self.ddr_ring_status
            if (
                status.target_frames != self.requested_frames
                or status.last_contiguous_sample_sequence is None
            ):
                raise ValueError("metadata ladder DDR ring status does not close")
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
    metadata_abi: MetadataAbi
    sample_rate_hz: int = Field(gt=0)
    rf_bandwidth_hz: int = Field(gt=0)
    channels: tuple[int, ...]
    kernel_buffers: int = Field(ge=4, le=64)
    ddr_burst_enabled: bool = False
    ddr_ring_requested_iq_bytes: int = Field(default=0, ge=0)
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
        "passed binds FPGA counter coverage >=95%, zero overflow, exact selected-RX geometry, "
        "and at least four kernel buffers; it is not inferred from host throughput"
    )

    @model_validator(mode="after")
    def validate_largest_pass(self) -> MetadataContinuityLadderReport:
        expected = next((cell.samples_per_channel for cell in self.cells if cell.passed), None)
        if self.largest_passing_samples_per_channel != expected:
            raise ValueError("largest passing metadata refill is non-canonical")
        if any(bool(cell.ddr_burst_frames) is not self.ddr_burst_enabled for cell in self.cells):
            raise ValueError("metadata ladder DDR burst mode is inconsistent")
        if self.ddr_burst_enabled and self.ddr_ring_requested_iq_bytes:
            raise ValueError("metadata ladder cannot combine DDR burst and DDR ring")
        if any(
            (cell.ddr_ring_status is not None) is not bool(self.ddr_ring_requested_iq_bytes)
            for cell in self.cells
        ):
            raise ValueError("metadata ladder DDR ring mode is inconsistent")
        if any(
            cell.ddr_ring_status is not None
            and cell.ddr_ring_status.requested_capacity_iq_bytes
            != self.ddr_ring_requested_iq_bytes
            for cell in self.cells
        ):
            raise ValueError("metadata ladder DDR ring request is inconsistent")
        for cell in self.cells:
            status = cell.ddr_ring_status
            if status is None:
                continue
            frame_iq_bytes = cell.samples_per_channel * len(self.channels) * 4
            capacity_frames, remainder = divmod(
                status.admitted_capacity_iq_bytes, frame_iq_bytes
            )
            expected_admitted = (
                self.ddr_ring_requested_iq_bytes // frame_iq_bytes
            ) * frame_iq_bytes
            if (
                remainder
                or status.admitted_capacity_iq_bytes != expected_admitted
                or capacity_frames < 1
                or status.high_water_frames > capacity_frames
            ):
                raise ValueError("metadata ladder DDR ring capacity does not close")
        return self


class MetadataLadderRadio(RadioDevice, Protocol):
    def begin_metadata_capture(
        self,
        sample_count: int,
        *,
        kernel_buffers: int,
        ddr_burst_bytes: int = 0,
        ddr_ring_bytes: int = 0,
        ddr_ring_frames: int = 0,
        ddr_ring_continuous: bool = False,
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
    metadata_abi: MetadataAbi = 1,
    channels: tuple[int, ...] = (0, 1),
    samples_per_channel: Sequence[int],
    frames: int = 6,
    kernel_buffers: int = 4,
    ddr_burst: bool = False,
    ddr_ring_bytes: int = 0,
    radio_factory: Callable[[str, str, MetadataAbi], MetadataLadderRadio] | None = None,
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
    selected_channels = tuple(channels)
    if metadata_abi not in {1, 2, 3}:
        raise ValueError("metadata ABI must be 1, 2, or 3")
    if selected_channels not in set(METADATA_CHANNEL_SELECTIONS.values()):
        raise ValueError("metadata channels must be RX0, RX1, or dual")
    if metadata_abi in {1, 2} and selected_channels != (0, 1):
        raise ValueError("metadata ABI 1 and 2 require dual RX")
    if ddr_burst and (metadata_abi != 3 or len(selected_channels) != 1):
        raise ValueError("device DDR burst ladder requires metadata ABI 3 and one receiver")
    if isinstance(ddr_ring_bytes, bool) or not isinstance(ddr_ring_bytes, int):
        raise TypeError("DDR ring byte budget must be an integer")
    if not 0 <= ddr_ring_bytes <= MAX_DDR_RING_IQ_BYTES:
        raise ValueError(
            f"DDR ring byte budget must be in [0, {MAX_DDR_RING_IQ_BYTES}]"
        )
    if ddr_burst and ddr_ring_bytes:
        raise ValueError("device DDR burst and DDR ring are mutually exclusive")
    if ddr_ring_bytes and metadata_abi != 3:
        raise ValueError("device DDR ring ladder requires metadata ABI 3")
    if metadata_abi == 3 and len(selected_channels) == 1 and any(
        samples & 1 for samples in samples_per_channel
    ):
        raise ValueError("metadata ABI 3 single-RX sample counts must be even")
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
                "channels": selected_channels,
            }
        )
        actual = radio.apply_settings(requested)
        if (
            round(actual.sample_rate_hz) != sample_rate_hz
            or round(actual.bandwidth_hz) != rf_bandwidth_hz
            or tuple(actual.channels) != selected_channels
        ):
            raise RuntimeError("metadata ladder RX settings did not read back exactly")
        identity = radio.identity
        for samples in samples_per_channel:
            try:
                cells.append(
                    _run_cell(
                        radio,
                        samples_per_channel=samples,
                        sample_rate_hz=sample_rate_hz,
                        frames=frames,
                        kernel_buffers=kernel_buffers,
                        receiver_count=len(selected_channels),
                        ddr_burst=ddr_burst,
                        ddr_ring_bytes=ddr_ring_bytes,
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
        channels=selected_channels,
        kernel_buffers=kernel_buffers,
        ddr_burst_enabled=ddr_burst,
        ddr_ring_requested_iq_bytes=ddr_ring_bytes,
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
    sample_rate_hz: int,
    frames: int,
    kernel_buffers: int,
    receiver_count: int,
    ddr_burst: bool,
    ddr_ring_bytes: int,
    clock_ns: Callable[[], int],
) -> MetadataContinuityCell:
    if ddr_burst:
        frame_duration_us = samples_per_channel * 1_000_000 / sample_rate_hz
        if samples_per_channel * 1_000_000 < (
            sample_rate_hz * DDR_BURST_MIN_FRAME_DURATION_US
        ):
            raise ValueError(
                "DDR burst requires at least a 12 ms frame period; "
                f"samples={samples_per_channel} rate={sample_rate_hz} "
                f"duration_us={frame_duration_us:.3f}"
            )
    blocks: list[SampleBlockV2] = []
    ddr_burst_bytes = samples_per_channel * receiver_count * 4 * frames if ddr_burst else 0
    frame_iq_bytes = samples_per_channel * receiver_count * 4
    expected_ring_admitted_bytes = (
        0 if not ddr_ring_bytes else (ddr_ring_bytes // frame_iq_bytes) * frame_iq_bytes
    )
    started_ns = clock_ns()
    with radio.begin_metadata_capture(
        samples_per_channel,
        kernel_buffers=kernel_buffers,
        ddr_burst_bytes=ddr_burst_bytes,
        ddr_ring_bytes=ddr_ring_bytes,
        ddr_ring_frames=frames if ddr_ring_bytes else 0,
    ) as capture:
        if capture.kernel_buffers != kernel_buffers:
            raise RuntimeError("metadata ladder kernel-buffer readback is not exact")
        if (
            capture.ddr_burst_enabled is not ddr_burst
            or capture.ddr_burst_requested_bytes != ddr_burst_bytes
            or capture.ddr_burst_admitted_bytes != ddr_burst_bytes
            or capture.ddr_burst_frames != (frames if ddr_burst else 0)
        ):
            raise RuntimeError("metadata ladder DDR burst admission readback is not exact")
        if (
            capture.ddr_ring_enabled is not bool(ddr_ring_bytes)
            or capture.ddr_ring_requested_bytes != ddr_ring_bytes
            or capture.ddr_ring_admitted_bytes != expected_ring_admitted_bytes
            or capture.ddr_ring_capacity_frames
            != (0 if not ddr_ring_bytes else expected_ring_admitted_bytes // frame_iq_bytes)
            or capture.ddr_ring_capture_frames != (frames if ddr_ring_bytes else 0)
            or capture.ddr_ring_continuous
        ):
            raise RuntimeError("metadata ladder DDR ring admission readback is not exact")
        for _ in range(frames):
            block = capture.read_block()
            if block.samples.shape != (receiver_count, samples_per_channel):
                raise RuntimeError("metadata ladder block shape is not the selected RX layout")
            blocks.append(block)
        ring_status = (
            None
            if not ddr_ring_bytes
            else DdrRingFinalStatus.model_validate(capture.ddr_ring_status())
        )
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
    if (
        ring_status is not None
        and ring_status.last_contiguous_sample_sequence
        != blocks[-1].last_sample_sequence_exclusive
    ):
        raise RuntimeError("DDR ring sample boundary disagrees with captured metadata")
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
        ddr_burst_requested_iq_bytes=ddr_burst_bytes,
        ddr_burst_admitted_iq_bytes=ddr_burst_bytes,
        ddr_burst_frames=frames if ddr_burst else 0,
        ddr_ring_status=ring_status,
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
    metadata_abi: MetadataAbi,
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
