"""Bounded direct-async rate/duration qualification matrix."""

from __future__ import annotations

import math
import re
import time
from collections.abc import Callable, Sequence
from typing import Literal, Protocol, cast

from pydantic import Field, model_validator

from pluto_plus.ddr_ring import DdrRingStatusSnapshot
from pluto_plus.hardware.base import MetadataCapture, RadioDevice, restore_settings_exact
from pluto_plus.hardware.iio import IioRadioDevice
from pluto_plus.hardware.iio_iq_decode import IioIqDecoder, validate_iq_decoder
from pluto_plus.ladder import (
    MAX_RATE_RUNGS,
    MAX_SAMPLES_PER_CHANNEL,
    MIN_SAMPLES_PER_CHANNEL,
    parse_rate_ladder,
)
from pluto_plus.models import ApiModel, RadioSettings
from pluto_plus.tandem import TandemMode, TandemSessionRequestV1

DEFAULT_DIRECT_ASYNC_RATES = "5M,10M,15M,25M"
DEFAULT_DIRECT_ASYNC_DURATIONS = "3,10"
MAX_DURATION_RUNGS = 8
MAX_DURATION_SECONDS = 60.0
MAX_TOTAL_FRAMES_PER_CELL = 4_096
MAX_DIRECT_ASYNC_FRAMES = 64
MAX_DIRECT_DMA_BYTES = 64 * 1024 * 1024
MAX_DIRECT_RAM_BYTES = 200_000_000
WIRE_BYTES_PER_COMPLEX_SAMPLE = 4
DirectAsyncMode = Literal["direct", "direct-ram"]
DirectAsyncTandemMode = Literal["hold", "auto"]
_DURATION_PATTERN = re.compile(r"^[0-9]+(?:\.[0-9]+)?$")


class DirectAsyncLadderCell(ApiModel):
    sample_rate_hz: int = Field(gt=0)
    requested_duration_seconds: float = Field(gt=0)
    nominal_capture_seconds: float = Field(gt=0)
    samples_per_frame: int = Field(
        ge=MIN_SAMPLES_PER_CHANNEL,
        le=MAX_SAMPLES_PER_CHANNEL,
    )
    requested_frames: int = Field(gt=0)
    observed_frames: int = Field(gt=0)
    capture_segments: int = Field(gt=0)
    iq_bytes: int = Field(gt=0)
    elapsed_seconds: float = Field(gt=0)
    offered_payload_mbps: float = Field(gt=0)
    achieved_payload_mbps: float = Field(gt=0)
    achieved_payload_mibps: float = Field(gt=0)
    gap_frames: int = Field(ge=0)
    missing_sample_count: int = Field(ge=0)
    overflow_frames: int = Field(ge=0)
    inter_segment_skipped_samples: int = Field(ge=0)
    ram_spilled_frames: int = Field(ge=0)
    ram_drained_frames: int = Field(ge=0)
    ram_high_water_frames: int = Field(ge=0)
    passed: bool

    @model_validator(mode="after")
    def validate_closure(self) -> DirectAsyncLadderCell:
        if self.observed_frames != self.requested_frames:
            raise ValueError("direct ladder must return every requested frame")
        if self.capture_segments != math.ceil(self.requested_frames / MAX_DIRECT_ASYNC_FRAMES):
            raise ValueError("direct ladder segment count does not close")
        expected_nominal = self.requested_frames * self.samples_per_frame / self.sample_rate_hz
        if abs(self.nominal_capture_seconds - expected_nominal) > 1e-12:
            raise ValueError("direct ladder nominal duration does not close")
        if self.iq_bytes != (
            self.observed_frames * self.samples_per_frame * WIRE_BYTES_PER_COMPLEX_SAMPLE
        ):
            raise ValueError("direct ladder IQ byte count does not close")
        expected_offered = self.sample_rate_hz * WIRE_BYTES_PER_COMPLEX_SAMPLE / 1_000_000
        if abs(self.offered_payload_mbps - expected_offered) > 1e-12:
            raise ValueError("direct ladder offered payload rate does not close")
        expected_mbps = self.iq_bytes / self.elapsed_seconds / 1_000_000
        expected_mibps = self.iq_bytes / self.elapsed_seconds / (1024 * 1024)
        if abs(self.achieved_payload_mbps - expected_mbps) > 1e-9:
            raise ValueError("direct ladder decimal payload rate does not close")
        if abs(self.achieved_payload_mibps - expected_mibps) > 1e-9:
            raise ValueError("direct ladder binary payload rate does not close")
        if self.ram_spilled_frames != self.ram_drained_frames:
            raise ValueError("direct ladder RAM spill/drain counts do not close")
        expected_pass = (
            self.gap_frames == 0 and self.missing_sample_count == 0 and self.overflow_frames == 0
        )
        if self.passed is not expected_pass:
            raise ValueError("direct ladder pass result is non-canonical")
        return self


class DirectAsyncLadderFailure(ApiModel):
    sample_rate_hz: int = Field(gt=0)
    requested_duration_seconds: float = Field(gt=0)
    error_type: str
    message: str
    last_ring_status: DdrRingStatusSnapshot | None = None


class DirectAsyncLadderReport(ApiModel):
    serial: str
    uri: str
    transport: str
    model: str
    firmware_version: str | None
    metadata_abi: Literal[3] = 3
    mode: DirectAsyncMode
    channels: tuple[int, ...]
    rates_hz: tuple[int, ...]
    durations_seconds: tuple[float, ...]
    samples_per_frame: int = Field(
        ge=MIN_SAMPLES_PER_CHANNEL,
        le=MAX_SAMPLES_PER_CHANNEL,
    )
    kernel_buffers: int = Field(ge=2, le=64)
    ram_ring_slots: int = Field(ge=0)
    tandem_mode: DirectAsyncTandemMode
    iq_decoder: IioIqDecoder
    cells: tuple[DirectAsyncLadderCell, ...]
    failures: tuple[DirectAsyncLadderFailure, ...]
    original_settings_restored: bool
    continuity_claim: str = (
        "gap and missing-sample counts are counter-proven within each bounded "
        "direct-async segment; inter-segment source samples are reported separately"
    )

    @model_validator(mode="after")
    def validate_matrix(self) -> DirectAsyncLadderReport:
        expected = tuple(
            (rate, duration) for rate in self.rates_hz for duration in self.durations_seconds
        )
        observed = tuple(
            (cell.sample_rate_hz, cell.requested_duration_seconds) for cell in self.cells
        ) + tuple(
            (failure.sample_rate_hz, failure.requested_duration_seconds)
            for failure in self.failures
        )
        if sorted(observed) != sorted(expected) or len(observed) != len(set(observed)):
            raise ValueError("direct ladder rate/duration matrix does not close")
        if self.mode == "direct" and (
            self.ram_ring_slots or any(cell.ram_spilled_frames for cell in self.cells)
        ):
            raise ValueError("ringless direct ladder reported RAM storage")
        if self.mode == "direct-ram" and self.ram_ring_slots < 1:
            raise ValueError("direct-RAM ladder has no RAM slots")
        return self


class DirectAsyncLadderRadio(RadioDevice, Protocol):
    def begin_metadata_capture(
        self,
        sample_count: int,
        *,
        kernel_buffers: int,
        ddr_burst_bytes: int = 0,
        ddr_ring_bytes: int = 0,
        ddr_ring_frames: int = 0,
        ddr_ring_continuous: bool = False,
        direct_async_frames: int = 0,
        tandem_request: TandemSessionRequestV1 | None = None,
    ) -> MetadataCapture: ...


def parse_duration_ladder(specification: str) -> tuple[float, ...]:
    """Parse a strictly increasing bounded duration ladder."""

    values: list[float] = []
    for raw in specification.split(","):
        token = raw.strip()
        if _DURATION_PATTERN.fullmatch(token) is None:
            raise ValueError(f"invalid duration rung {token!r}")
        value = float(token)
        if not math.isfinite(value) or not 0 < value <= MAX_DURATION_SECONDS:
            raise ValueError(
                f"duration rungs must be greater than 0 and at most "
                f"{MAX_DURATION_SECONDS:g} seconds"
            )
        values.append(value)
    if not values or len(values) > MAX_DURATION_RUNGS:
        raise ValueError(f"duration ladder requires between 1 and {MAX_DURATION_RUNGS} rungs")
    if any(right <= left for left, right in zip(values, values[1:], strict=False)):
        raise ValueError("duration ladder must be strictly increasing")
    return tuple(values)


def run_direct_async_ladder(
    *,
    uri: str,
    serial: str,
    rates_hz: Sequence[int],
    durations_seconds: Sequence[float],
    channels: tuple[int, ...] = (0,),
    samples_per_frame: int = 1_048_576,
    kernel_buffers: int = 15,
    ram_ring_slots: int = 0,
    tandem_mode: DirectAsyncTandemMode = "hold",
    iq_decoder: IioIqDecoder = "pyadi",
    radio_factory: (Callable[[str, str, IioIqDecoder], DirectAsyncLadderRadio] | None) = None,
    clock_ns: Callable[[], int] = time.perf_counter_ns,
) -> DirectAsyncLadderReport:
    """Run every rate/duration cell and restore the exact original settings."""

    rates = tuple(rates_hz)
    durations = tuple(durations_seconds)
    if rates != parse_rate_ladder(",".join(str(rate) for rate in rates)):
        raise ValueError("direct ladder rates are not canonical")
    if durations != parse_duration_ladder(",".join(str(value) for value in durations)):
        raise ValueError("direct ladder durations are not canonical")
    validate_iq_decoder(iq_decoder)
    _validate_shape(
        rates,
        durations,
        channels=channels,
        samples_per_frame=samples_per_frame,
        kernel_buffers=kernel_buffers,
        ram_ring_slots=ram_ring_slots,
        tandem_mode=tandem_mode,
    )
    radio = (
        radio_factory(uri, serial, iq_decoder)
        if radio_factory is not None
        else _default_radio_factory(uri, serial, iq_decoder)
    )
    opened = False
    original: RadioSettings | None = None
    cells: list[DirectAsyncLadderCell] = []
    failures: list[DirectAsyncLadderFailure] = []
    restored = False
    identity = None
    try:
        try:
            radio.open()
        except Exception as error:
            raise RuntimeError(f"direct ladder could not open radio: {error}") from error
        opened = True
        identity = radio.identity
        original = radio.read_settings()
        for rate in rates:
            try:
                requested = original.model_copy(
                    update={
                        "sample_rate_hz": rate,
                        "bandwidth_hz": rate,
                        "channels": channels,
                    }
                )
                actual = radio.apply_settings(requested)
                if (
                    round(actual.sample_rate_hz) != rate
                    or round(actual.bandwidth_hz) != rate
                    or tuple(actual.channels) != channels
                ):
                    raise RuntimeError(f"direct ladder RX settings did not read back at {rate} Hz")
            except Exception as error:
                failures.extend(
                    DirectAsyncLadderFailure(
                        sample_rate_hz=rate,
                        requested_duration_seconds=duration,
                        error_type=type(error).__name__,
                        message=str(error),
                    )
                    for duration in durations
                )
                continue
            for duration in durations:
                try:
                    cells.append(
                        _run_cell(
                            radio,
                            sample_rate_hz=rate,
                            requested_duration_seconds=duration,
                            samples_per_frame=samples_per_frame,
                            kernel_buffers=kernel_buffers,
                            ram_ring_slots=ram_ring_slots,
                            tandem_mode=tandem_mode,
                            clock_ns=clock_ns,
                        )
                    )
                except _DirectAsyncCellError as error:
                    failures.append(
                        DirectAsyncLadderFailure(
                            sample_rate_hz=rate,
                            requested_duration_seconds=duration,
                            error_type=type(error.cause).__name__,
                            message=str(error.cause),
                            last_ring_status=error.last_ring_status,
                        )
                    )
                except Exception as error:
                    failures.append(
                        DirectAsyncLadderFailure(
                            sample_rate_hz=rate,
                            requested_duration_seconds=duration,
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
        raise RuntimeError("direct ladder could not verify restoration of original RX settings")
    if identity is None:
        raise RuntimeError("direct ladder opened no radio identity")
    return DirectAsyncLadderReport(
        serial=identity.serial,
        uri=identity.uri,
        transport=identity.transport.value,
        model=identity.model,
        firmware_version=identity.firmware_version,
        mode="direct-ram" if ram_ring_slots else "direct",
        channels=channels,
        rates_hz=rates,
        durations_seconds=durations,
        samples_per_frame=samples_per_frame,
        kernel_buffers=kernel_buffers,
        ram_ring_slots=ram_ring_slots,
        tandem_mode=tandem_mode,
        iq_decoder=iq_decoder,
        cells=tuple(cells),
        failures=tuple(failures),
        original_settings_restored=restored,
    )


class _DirectAsyncCellError(RuntimeError):
    def __init__(
        self,
        cause: Exception,
        last_ring_status: DdrRingStatusSnapshot | None,
    ) -> None:
        super().__init__(str(cause))
        self.cause = cause
        self.last_ring_status = last_ring_status


def _run_cell(
    radio: DirectAsyncLadderRadio,
    *,
    sample_rate_hz: int,
    requested_duration_seconds: float,
    samples_per_frame: int,
    kernel_buffers: int,
    ram_ring_slots: int,
    tandem_mode: DirectAsyncTandemMode,
    clock_ns: Callable[[], int],
) -> DirectAsyncLadderCell:
    requested_frames = math.ceil(requested_duration_seconds * sample_rate_hz / samples_per_frame)
    remaining = requested_frames
    observed_frames = 0
    elapsed_ns = 0
    gap_frames = 0
    missing_samples = 0
    overflow_frames = 0
    inter_segment_skipped_samples = 0
    ram_spilled_frames = 0
    ram_drained_frames = 0
    ram_high_water_frames = 0
    previous_segment_end: int | None = None
    last_ring_status: DdrRingStatusSnapshot | None = None
    frame_iq_bytes = samples_per_frame * WIRE_BYTES_PER_COMPLEX_SAMPLE
    ring_bytes = ram_ring_slots * frame_iq_bytes
    while remaining:
        segment_frames = min(remaining, MAX_DIRECT_ASYNC_FRAMES)
        try:
            with radio.begin_metadata_capture(
                samples_per_frame,
                kernel_buffers=kernel_buffers,
                ddr_ring_bytes=ring_bytes,
                ddr_ring_frames=0,
                ddr_ring_continuous=False,
                direct_async_frames=segment_frames,
                tandem_request=(
                    TandemSessionRequestV1(mode=TandemMode.HOLD)
                    if tandem_mode == "hold"
                    else TandemSessionRequestV1.auto_for_sample_count(
                        samples_per_frame,
                        retention_frames=2,
                    )
                ),
            ) as capture:
                if capture.kernel_buffers != kernel_buffers:
                    raise RuntimeError("direct ladder kernel-buffer readback is not exact")
                if capture.direct_async_frames != segment_frames:
                    raise RuntimeError("direct ladder finite target readback is not exact")
                if capture.direct_async_ring_extension is not bool(ram_ring_slots):
                    raise RuntimeError("direct ladder RAM-extension admission is not exact")
                if (
                    capture.ddr_ring_requested_bytes != ring_bytes
                    or capture.ddr_ring_admitted_bytes != ring_bytes
                    or capture.ddr_ring_capacity_frames != ram_ring_slots
                    or capture.ddr_ring_capture_frames
                    or capture.ddr_ring_continuous
                ):
                    raise RuntimeError("direct ladder RAM-ring geometry is not exact")
                started_ns = clock_ns()
                previous_frame_end: int | None = None
                segment_first: int | None = None
                for _ in range(segment_frames):
                    block = capture.read_block()
                    if block.samples.shape != (1, samples_per_frame):
                        raise RuntimeError(
                            "direct ladder block shape is not the selected single RX layout"
                        )
                    if segment_first is None:
                        segment_first = block.first_sample_sequence
                    if previous_frame_end is not None:
                        expected = previous_frame_end + block.missing_samples_before
                        if block.first_sample_sequence != expected:
                            raise RuntimeError(
                                "direct ladder metadata gap does not close against counters"
                            )
                    previous_frame_end = block.last_sample_sequence_exclusive
                    observed_frames += 1
                    missing_samples += block.missing_samples_before
                    gap_frames += int(bool(block.missing_samples_before))
                    overflow_frames += int(block.overflow_observed)
                elapsed_ns += clock_ns() - started_ns
                if segment_first is None or previous_frame_end is None:
                    raise RuntimeError("direct ladder segment returned no frames")
                if previous_segment_end is not None:
                    if segment_first < previous_segment_end:
                        raise RuntimeError("direct ladder device counter moved backwards")
                    inter_segment_skipped_samples += segment_first - previous_segment_end
                previous_segment_end = previous_frame_end
                if ram_ring_slots:
                    last_ring_status = DdrRingStatusSnapshot.model_validate(
                        capture.ddr_ring_status()
                    )
                    if (
                        last_ring_status.state != "complete"
                        or last_ring_status.terminal_reason != "target_complete"
                        or last_ring_status.error_code
                        or last_ring_status.requested_capacity_iq_bytes != ring_bytes
                        or last_ring_status.admitted_capacity_iq_bytes != ring_bytes
                        or last_ring_status.target_frames
                        or last_ring_status.produced_frames != last_ring_status.consumed_frames
                        or last_ring_status.high_water_frames > ram_ring_slots
                    ):
                        raise RuntimeError("direct ladder RAM extension did not close cleanly")
                    ram_spilled_frames += last_ring_status.produced_frames
                    ram_drained_frames += last_ring_status.consumed_frames
                    ram_high_water_frames = max(
                        ram_high_water_frames,
                        last_ring_status.high_water_frames,
                    )
        except Exception as error:
            raise _DirectAsyncCellError(error, last_ring_status) from error
        remaining -= segment_frames
    elapsed_seconds = elapsed_ns / 1_000_000_000
    if elapsed_seconds <= 0:
        raise RuntimeError("direct ladder clock did not advance")
    iq_bytes = observed_frames * frame_iq_bytes
    return DirectAsyncLadderCell(
        sample_rate_hz=sample_rate_hz,
        requested_duration_seconds=requested_duration_seconds,
        nominal_capture_seconds=requested_frames * samples_per_frame / sample_rate_hz,
        samples_per_frame=samples_per_frame,
        requested_frames=requested_frames,
        observed_frames=observed_frames,
        capture_segments=math.ceil(requested_frames / MAX_DIRECT_ASYNC_FRAMES),
        iq_bytes=iq_bytes,
        elapsed_seconds=elapsed_seconds,
        offered_payload_mbps=(sample_rate_hz * WIRE_BYTES_PER_COMPLEX_SAMPLE / 1_000_000),
        achieved_payload_mbps=iq_bytes / elapsed_seconds / 1_000_000,
        achieved_payload_mibps=iq_bytes / elapsed_seconds / (1024 * 1024),
        gap_frames=gap_frames,
        missing_sample_count=missing_samples,
        overflow_frames=overflow_frames,
        inter_segment_skipped_samples=inter_segment_skipped_samples,
        ram_spilled_frames=ram_spilled_frames,
        ram_drained_frames=ram_drained_frames,
        ram_high_water_frames=ram_high_water_frames,
        passed=not (gap_frames or missing_samples or overflow_frames),
    )


def _validate_shape(
    rates_hz: Sequence[int],
    durations_seconds: Sequence[float],
    *,
    channels: tuple[int, ...],
    samples_per_frame: int,
    kernel_buffers: int,
    ram_ring_slots: int,
    tandem_mode: DirectAsyncTandemMode,
) -> None:
    if not 1 <= len(rates_hz) <= MAX_RATE_RUNGS:
        raise ValueError(f"direct ladder requires between 1 and {MAX_RATE_RUNGS} rates")
    if not 1 <= len(durations_seconds) <= MAX_DURATION_RUNGS:
        raise ValueError(f"direct ladder requires between 1 and {MAX_DURATION_RUNGS} durations")
    if channels not in {(0,), (1,)}:
        raise ValueError("direct ladder channels must be rx0 or rx1")
    if (
        isinstance(samples_per_frame, bool)
        or not isinstance(samples_per_frame, int)
        or not MIN_SAMPLES_PER_CHANNEL <= samples_per_frame <= MAX_SAMPLES_PER_CHANNEL
        or samples_per_frame & 1
    ):
        raise ValueError(
            "direct ladder samples per frame must be an even integer in "
            f"[{MIN_SAMPLES_PER_CHANNEL}, {MAX_SAMPLES_PER_CHANNEL}]"
        )
    minimum_kernel_buffers = 3 if ram_ring_slots else 2
    if not minimum_kernel_buffers <= kernel_buffers <= 64:
        raise ValueError(
            f"direct ladder requires between {minimum_kernel_buffers} and 64 kernel buffers"
        )
    dma_bytes = kernel_buffers * samples_per_frame * WIRE_BYTES_PER_COMPLEX_SAMPLE
    if dma_bytes > MAX_DIRECT_DMA_BYTES:
        raise ValueError(
            f"direct ladder DMA request is {dma_bytes} bytes; maximum is {MAX_DIRECT_DMA_BYTES}"
        )
    if isinstance(ram_ring_slots, bool) or not isinstance(ram_ring_slots, int):
        raise TypeError("direct ladder RAM slots must be an integer")
    ring_bytes = ram_ring_slots * samples_per_frame * WIRE_BYTES_PER_COMPLEX_SAMPLE
    if ram_ring_slots < 0 or ring_bytes > MAX_DIRECT_RAM_BYTES:
        raise ValueError(f"direct ladder RAM request must be in [0, {MAX_DIRECT_RAM_BYTES}] bytes")
    if tandem_mode not in {"hold", "auto"}:
        raise ValueError("direct ladder tandem mode must be hold or auto")
    maximum_frames = max(
        math.ceil(duration * rate / samples_per_frame)
        for rate in rates_hz
        for duration in durations_seconds
    )
    if maximum_frames > MAX_TOTAL_FRAMES_PER_CELL:
        raise ValueError(
            f"direct ladder requires up to {maximum_frames} frames per cell, above "
            f"the bounded limit {MAX_TOTAL_FRAMES_PER_CELL}"
        )


def _default_radio_factory(
    uri: str,
    serial: str,
    iq_decoder: IioIqDecoder,
) -> DirectAsyncLadderRadio:
    return cast(
        DirectAsyncLadderRadio,
        IioRadioDevice(
            uri,
            serial=serial,
            radio_id=serial,
            expected_metadata_abi=3,
            iq_decoder=iq_decoder,
        ),
    )
