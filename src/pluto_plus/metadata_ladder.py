"""Counter-observable metadata refill-size qualification ladder."""

from __future__ import annotations

import time
from collections.abc import Callable, Sequence
from typing import Literal, Protocol, cast

from pydantic import Field, model_validator

from pluto_plus.hardware.base import (
    MetadataCapture,
    RadioDevice,
    restore_settings_exact,
)
from pluto_plus.hardware.iio import IioRadioDevice
from pluto_plus.hardware.iio_iq_decode import IioIqDecoder, validate_iq_decoder
from pluto_plus.ladder import MAX_SAMPLES_PER_CHANNEL, MIN_SAMPLES_PER_CHANNEL
from pluto_plus.models import ApiModel, RadioSettings
from pluto_plus.tandem import TandemMode, TandemSessionRequestV1

DEFAULT_METADATA_SAMPLE_LADDER = "4194304,2097152,1048576,524288,262144,131072"
MAX_METADATA_SAMPLE_RUNGS = 16
# Keep the ladder bounded while allowing the release throughput matrix to cover
# 20 nominal seconds at 30 MS/s with 1,000,000-sample refills.  That 2.4-GB
# target proves twelve complete reuses of a 200-MB ring.  Cell accounting is
# constant-memory; IQ frames are validated and released as they arrive instead
# of accumulating on the host.
MAX_METADATA_FRAMES = 600
MINIMUM_OBSERVED_FRACTION = 0.95
# Hardware qualification found intermittent whole-frame loss at 8 ms.  The
# first passing boundary was 10 ms; retain 50% headroom over the failure point
# so client admission agrees with iiOD's conservative scheduling envelope.
DDR_BURST_MIN_FRAME_DURATION_US = 12_000
MAX_DDR_RING_IQ_BYTES = 200_000_000
MetadataAbi = Literal[1, 2, 3]
MetadataChannels = Literal["rx0", "rx1", "dual"]
MetadataTandemMode = Literal["hold", "auto"]
MetadataAcceptanceMode = Literal["continuity", "capture-completion"]
METADATA_CHANNEL_SELECTIONS: dict[MetadataChannels, tuple[int, ...]] = {
    "rx0": (0,),
    "rx1": (1,),
    "dual": (0, 1),
}


class DdrRingStatusSnapshot(ApiModel):
    state: str
    terminal_reason: str
    error_code: int
    requested_capacity_iq_bytes: int = Field(gt=0)
    admitted_capacity_iq_bytes: int = Field(gt=0)
    target_frames: int = Field(gt=0)
    produced_frames: int = Field(ge=0)
    consumed_frames: int = Field(ge=0)
    high_water_frames: int = Field(ge=0)
    wrap_count: int = Field(ge=0)
    producer_position: int = Field(ge=0)
    consumer_position: int = Field(ge=0)
    last_contiguous_sample_sequence: int | None = Field(default=None, ge=0)
    first_unavailable_sample_sequence: int | None = Field(default=None, ge=0)


class DdrRingFinalStatus(DdrRingStatusSnapshot):
    """A terminal ring status that proves every requested host frame arrived."""

    @model_validator(mode="after")
    def validate_complete_capture(self) -> DdrRingFinalStatus:
        if (
            self.state != "complete"
            or self.terminal_reason != "target_complete"
            or self.error_code != 0
        ):
            raise ValueError("DDR ring did not reach a clean target-complete state")
        if not (self.produced_frames == self.consumed_frames == self.target_frames):
            raise ValueError("DDR ring producer/consumer frame counts do not close")
        if self.high_water_frames < 1:
            raise ValueError("DDR ring did not report occupied storage")
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
    first_sample_sequence: int = Field(ge=0)
    last_sample_sequence_exclusive: int = Field(gt=0)
    missing_sample_count: int = Field(ge=0)
    gap_count: int = Field(ge=0)
    overflow_count: int = Field(ge=0)
    iq_bytes: int = Field(gt=0)
    elapsed_seconds: float = Field(gt=0)
    achieved_payload_mbps: float = Field(gt=0)
    achieved_payload_mibps: float = Field(gt=0)
    observed_fraction: float = Field(ge=0.0, le=1.0)
    tandem_metadata_frames: int = Field(default=0, ge=0)
    gain_observation_interval_samples: int | None = Field(default=None, ge=1)
    gain_observation_count: int = Field(default=0, ge=0)
    gain_observation_overflow_count: int = Field(default=0, ge=0)
    ddr_burst_requested_iq_bytes: int = Field(default=0, ge=0)
    ddr_burst_admitted_iq_bytes: int = Field(default=0, ge=0)
    ddr_burst_frames: int = Field(default=0, ge=0)
    ddr_ring_status: DdrRingFinalStatus | None = None
    ddr_ring_prefix_frames: int = Field(default=0, ge=0)
    ddr_ring_prefix_iq_bytes: int = Field(default=0, ge=0)
    ddr_ring_prefix_contiguous: bool = False
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
        if self.last_sample_sequence_exclusive - self.first_sample_sequence != (
            self.device_span_sample_count
        ):
            raise ValueError("metadata ladder sample boundaries do not close")
        expected_fraction = self.observed_sample_count / self.device_span_sample_count
        if abs(self.observed_fraction - expected_fraction) > 1e-12:
            raise ValueError("metadata ladder observed fraction does not close")
        expected_mbps = self.iq_bytes / self.elapsed_seconds / 1_000_000
        expected_mibps = self.iq_bytes / self.elapsed_seconds / (1024 * 1024)
        if abs(self.achieved_payload_mbps - expected_mbps) > 1e-9:
            raise ValueError("metadata ladder decimal payload rate does not close")
        if abs(self.achieved_payload_mibps - expected_mibps) > 1e-9:
            raise ValueError("metadata ladder binary payload rate does not close")
        expected_pass = (
            self.observed_fraction >= MINIMUM_OBSERVED_FRACTION and self.overflow_count == 0
        )
        if self.passed is not expected_pass:
            raise ValueError("metadata ladder pass result is non-canonical")
        if self.tandem_metadata_frames:
            if (
                self.tandem_metadata_frames != self.observed_frames
                or self.gain_observation_interval_samples is None
                or self.gain_observation_count < self.tandem_metadata_frames
            ):
                raise ValueError("metadata ladder tandem observation accounting does not close")
        elif (
            self.gain_observation_interval_samples is not None
            or self.gain_observation_count
            or self.gain_observation_overflow_count
        ):
            raise ValueError("metadata ladder cannot report observations without tandem metadata")
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
            if (
                self.ddr_ring_prefix_frames < 1
                or self.ddr_ring_prefix_iq_bytes < 1
                or not self.ddr_ring_prefix_contiguous
            ):
                raise ValueError("metadata ladder DDR ring prefix is not proven contiguous")
        elif (
            self.ddr_ring_prefix_frames
            or self.ddr_ring_prefix_iq_bytes
            or self.ddr_ring_prefix_contiguous
        ):
            raise ValueError("ordinary metadata ladder cannot report a DDR ring prefix")
        return self


class MetadataContinuityFailure(ApiModel):
    samples_per_channel: int = Field(
        ge=MIN_SAMPLES_PER_CHANNEL,
        le=MAX_SAMPLES_PER_CHANNEL,
    )
    error_type: str = Field(min_length=1)
    message: str = Field(min_length=1)
    ddr_ring_status: DdrRingStatusSnapshot | None = None
    ddr_ring_status_error: str | None = Field(default=None, min_length=1)


class _MetadataCellCaptureError(RuntimeError):
    """Preserve a cell's original error together with live ring evidence."""

    def __init__(
        self,
        cause: Exception,
        ddr_ring_status: DdrRingStatusSnapshot | None,
        ddr_ring_status_error: str | None,
    ) -> None:
        super().__init__(str(cause))
        self.cause = cause
        self.ddr_ring_status = ddr_ring_status
        self.ddr_ring_status_error = ddr_ring_status_error


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
    tandem_mode: MetadataTandemMode = "hold"
    acceptance_mode: MetadataAcceptanceMode = "continuity"
    iq_decoder: IioIqDecoder = "pyadi"
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
            and cell.ddr_ring_status.requested_capacity_iq_bytes != self.ddr_ring_requested_iq_bytes
            for cell in self.cells
        ):
            raise ValueError("metadata ladder DDR ring request is inconsistent")
        for cell in self.cells:
            expected_iq_bytes = cell.observed_sample_count * len(self.channels) * 4
            if cell.iq_bytes != expected_iq_bytes:
                raise ValueError("metadata ladder IQ payload size does not match RX layout")
            status = cell.ddr_ring_status
            if status is None:
                continue
            frame_iq_bytes = cell.samples_per_channel * len(self.channels) * 4
            capacity_frames, remainder = divmod(status.admitted_capacity_iq_bytes, frame_iq_bytes)
            expected_admitted = (
                self.ddr_ring_requested_iq_bytes // frame_iq_bytes
            ) * frame_iq_bytes
            expected_prefix_frames = min(status.target_frames, capacity_frames)
            if (
                remainder
                or status.admitted_capacity_iq_bytes != expected_admitted
                or capacity_frames < 1
                or status.high_water_frames != expected_prefix_frames
                or cell.ddr_ring_prefix_frames != expected_prefix_frames
                or cell.ddr_ring_prefix_iq_bytes != expected_prefix_frames * frame_iq_bytes
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
        tandem_request: TandemSessionRequestV1 | None = None,
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
    tandem_mode: MetadataTandemMode = "hold",
    acceptance_mode: MetadataAcceptanceMode = "continuity",
    iq_decoder: IioIqDecoder = "pyadi",
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
    validate_iq_decoder(iq_decoder)
    if metadata_abi not in {1, 2, 3}:
        raise ValueError("metadata ABI must be 1, 2, or 3")
    if tandem_mode not in {"hold", "auto"}:
        raise ValueError("metadata tandem mode must be hold or auto")
    if acceptance_mode not in {"continuity", "capture-completion"}:
        raise ValueError(
            "metadata acceptance mode must be continuity or capture-completion"
        )
    if selected_channels not in set(METADATA_CHANNEL_SELECTIONS.values()):
        raise ValueError("metadata channels must be RX0, RX1, or dual")
    if metadata_abi in {1, 2} and selected_channels != (0, 1):
        raise ValueError("metadata ABI 1 and 2 require dual RX")
    if ddr_burst and (metadata_abi != 3 or len(selected_channels) != 1):
        raise ValueError("device DDR burst ladder requires metadata ABI 3 and one receiver")
    if isinstance(ddr_ring_bytes, bool) or not isinstance(ddr_ring_bytes, int):
        raise TypeError("DDR ring byte budget must be an integer")
    if not 0 <= ddr_ring_bytes <= MAX_DDR_RING_IQ_BYTES:
        raise ValueError(f"DDR ring byte budget must be in [0, {MAX_DDR_RING_IQ_BYTES}]")
    if ddr_burst and ddr_ring_bytes:
        raise ValueError("device DDR burst and DDR ring are mutually exclusive")
    if ddr_ring_bytes and metadata_abi != 3:
        raise ValueError("device DDR ring ladder requires metadata ABI 3")
    if (
        metadata_abi == 3
        and len(selected_channels) == 1
        and any(samples & 1 for samples in samples_per_channel)
    ):
        raise ValueError("metadata ABI 3 single-RX sample counts must be even")
    radio = (
        radio_factory(uri, serial, metadata_abi)
        if radio_factory is not None
        else _default_radio_factory(uri, serial, metadata_abi, iq_decoder=iq_decoder)
    )
    opened = False
    original: RadioSettings | None = None
    cells: list[MetadataContinuityCell] = []
    failures: list[MetadataContinuityFailure] = []
    restored = False
    try:
        try:
            radio.open()
        except Exception as error:
            raise RuntimeError(f"metadata ladder could not open radio: {error}") from error
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
                        tandem_mode=tandem_mode,
                        clock_ns=clock_ns,
                    )
                )
            except _MetadataCellCaptureError as error:
                failures.append(
                    MetadataContinuityFailure(
                        samples_per_channel=samples,
                        error_type=type(error.cause).__name__,
                        message=str(error.cause),
                        ddr_ring_status=error.ddr_ring_status,
                        ddr_ring_status_error=error.ddr_ring_status_error,
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
        tandem_mode=tandem_mode,
        acceptance_mode=acceptance_mode,
        iq_decoder=iq_decoder,
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
    tandem_mode: MetadataTandemMode,
    clock_ns: Callable[[], int],
) -> MetadataContinuityCell:
    if ddr_burst:
        frame_duration_us = samples_per_channel * 1_000_000 / sample_rate_hz
        if samples_per_channel * 1_000_000 < (sample_rate_hz * DDR_BURST_MIN_FRAME_DURATION_US):
            raise ValueError(
                "DDR burst requires at least a 12 ms frame period; "
                f"samples={samples_per_channel} rate={sample_rate_hz} "
                f"duration_us={frame_duration_us:.3f}"
            )
    observed_frames = 0
    first_sample_sequence: int | None = None
    last_sample_sequence_exclusive: int | None = None
    missing = 0
    gap_count = 0
    overflow_count = 0
    tandem_metadata_frames = 0
    gain_observation_interval_samples: int | None = None
    gain_observation_count = 0
    gain_observation_overflow_count = 0
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
        tandem_request=(
            TandemSessionRequestV1(mode=TandemMode.HOLD)
            if tandem_mode == "hold"
            else TandemSessionRequestV1.auto_for_sample_count(samples_per_channel)
        ),
    ) as capture:
        try:
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
                if first_sample_sequence is None:
                    first_sample_sequence = block.first_sample_sequence
                last_sample_sequence_exclusive = block.last_sample_sequence_exclusive
                observed_frames += 1
                missing += block.missing_samples_before
                gap_count += int(bool(block.missing_samples_before))
                overflow_count += int(block.overflow_observed)
                if block.tandem_metadata is not None:
                    tandem = block.tandem_metadata.base
                    interval = tandem.gain_observation_interval_samples
                    if gain_observation_interval_samples is None:
                        gain_observation_interval_samples = interval
                    elif gain_observation_interval_samples != interval:
                        raise RuntimeError(
                            "metadata ladder gain-observation interval changed within a rung"
                        )
                    tandem_metadata_frames += 1
                    gain_observation_count += len(tandem.gain_observations)
                    gain_observation_overflow_count += tandem.gain_observation_overflow_count
            ring_status = (
                None
                if not ddr_ring_bytes
                else DdrRingFinalStatus.model_validate(capture.ddr_ring_status())
            )
        except Exception as error:
            failure_status = None
            failure_status_error = None
            if ddr_ring_bytes:
                try:
                    failure_status = DdrRingStatusSnapshot.model_validate(capture.ddr_ring_status())
                except Exception as status_error:
                    failure_status_error = f"{type(status_error).__name__}: {status_error}"
            raise _MetadataCellCaptureError(
                error,
                failure_status,
                failure_status_error,
            ) from error
    elapsed_seconds = (clock_ns() - started_ns) / 1_000_000_000
    if elapsed_seconds <= 0:
        raise RuntimeError("metadata ladder clock did not advance")
    if first_sample_sequence is None or last_sample_sequence_exclusive is None:
        raise RuntimeError("metadata ladder returned no frames")
    observed = observed_frames * samples_per_channel
    span = last_sample_sequence_exclusive - first_sample_sequence
    if span != observed + missing:
        raise RuntimeError("metadata ladder FPGA counter span does not close")
    fraction = observed / span
    iq_bytes = observed * receiver_count * 4
    ring_prefix_frames = 0
    ring_prefix_iq_bytes = 0
    ring_prefix_contiguous = False
    if ring_status is not None:
        ring_prefix_frames = min(frames, expected_ring_admitted_bytes // frame_iq_bytes)
        ring_prefix_iq_bytes = ring_prefix_frames * frame_iq_bytes
        prefix_end = first_sample_sequence + ring_prefix_frames * samples_per_channel
        ring_prefix_contiguous = (
            ring_status.high_water_frames >= ring_prefix_frames
            and ring_status.last_contiguous_sample_sequence is not None
            and ring_status.last_contiguous_sample_sequence >= prefix_end
            and (
                ring_status.first_unavailable_sample_sequence is None
                or ring_status.first_unavailable_sample_sequence >= prefix_end
            )
        )
        if not ring_prefix_contiguous:
            raise RuntimeError("DDR ring did not preserve its admitted contiguous prefix")
        if ring_status.first_unavailable_sample_sequence is None:
            if ring_status.last_contiguous_sample_sequence != last_sample_sequence_exclusive:
                raise RuntimeError("DDR ring final contiguous boundary disagrees with metadata")
        elif (
            ring_status.last_contiguous_sample_sequence
            != ring_status.first_unavailable_sample_sequence
        ):
            raise RuntimeError("DDR ring first unavailable boundary is not canonical")
    return MetadataContinuityCell(
        samples_per_channel=samples_per_channel,
        requested_frames=frames,
        observed_frames=observed_frames,
        observed_sample_count=observed,
        device_span_sample_count=span,
        first_sample_sequence=first_sample_sequence,
        last_sample_sequence_exclusive=last_sample_sequence_exclusive,
        missing_sample_count=missing,
        gap_count=gap_count,
        overflow_count=overflow_count,
        iq_bytes=iq_bytes,
        elapsed_seconds=elapsed_seconds,
        achieved_payload_mbps=iq_bytes / elapsed_seconds / 1_000_000,
        achieved_payload_mibps=iq_bytes / elapsed_seconds / (1024 * 1024),
        observed_fraction=fraction,
        tandem_metadata_frames=tandem_metadata_frames,
        gain_observation_interval_samples=gain_observation_interval_samples,
        gain_observation_count=gain_observation_count,
        gain_observation_overflow_count=gain_observation_overflow_count,
        ddr_burst_requested_iq_bytes=ddr_burst_bytes,
        ddr_burst_admitted_iq_bytes=ddr_burst_bytes,
        ddr_burst_frames=frames if ddr_burst else 0,
        ddr_ring_status=ring_status,
        ddr_ring_prefix_frames=ring_prefix_frames,
        ddr_ring_prefix_iq_bytes=ring_prefix_iq_bytes,
        ddr_ring_prefix_contiguous=ring_prefix_contiguous,
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
    *,
    iq_decoder: IioIqDecoder = "pyadi",
) -> MetadataLadderRadio:
    return cast(
        MetadataLadderRadio,
        IioRadioDevice(
            uri,
            serial=serial,
            radio_id=serial,
            expected_metadata_abi=metadata_abi,
            iq_decoder=iq_decoder,
        ),
    )
