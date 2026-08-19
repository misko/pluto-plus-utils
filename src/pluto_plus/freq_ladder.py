"""Recover reference errors by observing an uncontrolled transmitted frequency ladder.

This module is the hardware-free core of the ``freq_ladder`` analyzer. It never
talks to a radio: it turns a per-frame SNR/peak-frequency series into identified
bursts and then into two separated reference errors.

Physics
-------
A transmitter that this receiver does not control (an ADF5355 on the bench) emits
``rung_count`` CW carriers stepped across ``[rung_start_hz, rung_stop_hz]``. Rung
``n`` keys on for ``n * unit_seconds`` and then stays quiet for ``n *
unit_seconds``, so one full pass takes::

    total_seconds = sum(2 * n * unit_seconds for n in 1..N) = N * (N + 1) * unit_seconds
    unit_seconds  = total_seconds / (N * (N + 1))

Every rung therefore has a unique burst length. A downstream receiver that knows
only the published ladder parameters - never the keying phase, never which rung is
live - recovers the rung from the burst duration alone::

    rung    = round(burst_seconds / unit_seconds)
    f_RF(n) = rung_start_hz + (rung_stop_hz - rung_start_hz) * (n - 1) / (N - 1)

The carrier reaches the receiver through an LNB downconverter, so the observed
intermediate frequency is ``f_IF = f_RF - f_LO``. Writing ``d`` for a reference's
fractional error, the measured frequency of an identified rung is::

    reported ~= (f_RF - f_LO_nom * (1 + d_lnb)) * (1 - d_rx)
    Df = reported - f_IF_nom ~= -d_rx * f_IF_nom - d_lnb * f_LO_nom

The receiver's own clock error scales with the intermediate frequency; the LNB's
LO error is a constant additive term. Fitting::

    Df = a * f_IF_nom + b * t + c

separates them: ``d_rx = -a`` is the receiver clock error (the slope) and
``d_lnb = -c / f_LO_nom`` is the LNB LO error (the intercept). A single tone
cannot separate the two - that is the whole reason the transmitter steps
frequency.

Why frame timing is exact here
------------------------------
Burst durations are measured from a stored contiguous capture, so a frame's time
is exactly ``frame_index * frame_size / sample_rate_hz``. A live receiver has to
timestamp frames with the wall clock instead, and on this bench that clock lies.
Measured on a Raspberry Pi 4 reading a Pluto at 2.5 MS/s in 32768-sample buffers,
one buffer holds 13.11 ms of signal and real time is 76.3 frames/s::

    capture only            76.3 frames/s   100.0% of real time
    capture plus one FFT    45.6 frames/s    59.8% of real time (1.67x behind)

A live decoder that transforms every buffer therefore cannot keep up: buffers
queue and the wall-clock timestamps drift later than the signal they describe.
The same ladder decoded live returned 0.595 s for a published 0.400 s burst
(1.49x) and 1.578 s for a published 1.200 s burst (1.32x), both in line with the
1.67x processing deficit, and those inflated durations identified the wrong
rungs. That is a timestamping artefact, not a transmitter fault. Deriving frame
time from sample counts over an immutable artifact removes the failure mode
outright, which is the single strongest reason to do this offline rather than in
a live loop.

Why the tone search is narrow-band
----------------------------------
The IF band is not empty. With the synthesiser idle, this bench still shows 40 dB
SNR peaks from spurs and live satellite carriers. A whole-capture argmax locks
onto those and reports one continuous "burst" forever. The peak search is
therefore restricted to a window around each rung's expected intermediate
frequency, wide enough to cover the LNB LO error (+94 kHz measured on this unit)
but far narrower than the capture bandwidth.

Why detection needs hysteresis
------------------------------
A single threshold fragments real bursts: one 0.8 s rung on this bench decomposed
into eleven separate 0.069 s detections. Detection enters at ``threshold_db``,
leaves only at ``threshold_db - hysteresis_db``, and adjacent segments closer than
a fraction of ``unit_seconds`` are merged - the true quiet period between rungs is
never shorter than ``unit_seconds``, so that merge can not fuse two real bursts.

Why rungs are rejected rather than clamped
------------------------------------------
Clamping ``round(duration / unit_seconds)`` into ``[1, N]`` turns a nonsense
estimate of 11.13 into a confident "rung 4". Out-of-range or off-integer
estimates are rejected with a reason and excluded from the fit; the unrounded
``rung_estimate`` is always reported so a caller can see the confidence for
itself.

Why the time term ``b`` exists
------------------------------
A ladder steps frequency monotonically in time, so any LO drift maps directly onto
the slope being measured. On this bench a single monotonic pass reported
+9.011 ppm while several interleaved passes with the time regressor reported
+8.94 ppm and exposed a real -3 to -7 Hz/s drift. The time term is therefore
included only when the observations span multiple passes; within one monotonic
pass time and frequency are collinear and the term is not identifiable, so it is
dropped and a warning is emitted instead.

Why the reported uncertainty is a resample, not the covariance
--------------------------------------------------------------
The receiver has a tuning-dependent systematic: the same unmoving tone measured
from eight different ``rx_lo`` settings on this bench returned answers spanning
362 Hz. Least-squares covariance assumes independent per-row noise and called that
+/-0.02 ppm; leave-one-rung-out refits called it +/-0.3 ppm, more than ten times
larger and consistent with the observed spread. The covariance standard error is
still reported, but only as a labelled diagnostic - the headline uncertainty is
the resampled one.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

import numpy as np
from pydantic import Field, model_validator

from pluto_plus.models import ApiModel

DEFAULT_FRAME_SIZE = 32_768
DEFAULT_THRESHOLD_DB = 35.0
DEFAULT_HYSTERESIS_DB = 6.0
DEFAULT_DC_NOTCH_HZ = 20_000.0
DEFAULT_SEARCH_HALF_WIDTH_HZ = 300_000.0
DEFAULT_MERGE_GAP_FRACTION = 0.25
DEFAULT_RUNG_TOLERANCE = 0.25
MINIMUM_FIT_RUNGS = 3
CONFIDENT_IDENTIFICATION = 0.5
LEAVE_ONE_RUNG_OUT = "leave_one_rung_out"
COVARIANCE_FALLBACK = "covariance_fallback"
UNCERTAINTY_CLAIM = (
    "the reported uncertainty is a leave-one-rung-out resample; the least-squares "
    "covariance standard error assumes independent per-burst noise and understates "
    "the receiver's tuning-dependent systematic by more than ten times"
)
_TINY = float(np.finfo(float).tiny)


class FreqLadderSchedule(ApiModel):
    """Published parameters of a transmitted duration-coded frequency ladder."""

    rung_start_hz: float = Field(gt=0)
    rung_stop_hz: float = Field(gt=0)
    rung_count: int = Field(ge=2)
    total_seconds: float = Field(gt=0)

    @model_validator(mode="after")
    def validate_span(self) -> FreqLadderSchedule:
        if self.rung_stop_hz <= self.rung_start_hz:
            raise ValueError("rung_stop_hz must be above rung_start_hz")
        return self

    @property
    def unit_seconds(self) -> float:
        """Duration quantum: rung ``n`` transmits for ``n`` of these."""

        return self.total_seconds / (self.rung_count * (self.rung_count + 1))

    @property
    def rungs(self) -> tuple[int, ...]:
        return tuple(range(1, self.rung_count + 1))

    def rung_frequency_hz(self, rung: int) -> float:
        """Nominal transmitted frequency of one rung."""

        if not 1 <= rung <= self.rung_count:
            raise ValueError(f"rung must be between 1 and {self.rung_count}")
        span = self.rung_stop_hz - self.rung_start_hz
        return self.rung_start_hz + span * (rung - 1) / (self.rung_count - 1)

    def rung_estimate(self, burst_seconds: float) -> float:
        """Unrounded rung index implied by a burst duration."""

        return burst_seconds / self.unit_seconds

    def identify(
        self, burst_seconds: float, tolerance: float = DEFAULT_RUNG_TOLERANCE
    ) -> int | None:
        """Return the rung a burst duration identifies, or None when ambiguous.

        An estimate outside ``[1, rung_count]`` is rejected, never clamped into
        range: a clamped rung is a confident wrong answer.
        """

        estimate = self.rung_estimate(burst_seconds)
        rung = round(estimate)
        if abs(estimate - rung) > tolerance:
            return None
        if not 1 <= rung <= self.rung_count:
            return None
        return rung


@dataclass(frozen=True, slots=True)
class CaptureContext:
    """Identity and time base of the capture a burst series came from."""

    artifact_id: str
    receiver: int
    epoch_seconds: float


@dataclass(frozen=True, slots=True)
class FrameSeries:
    """Per-frame detection statistics of one contiguous capture."""

    snr_db: np.ndarray
    frequency_hz: np.ndarray
    frame_seconds: float
    searched_bin_count: int = 0

    @property
    def frame_count(self) -> int:
        return int(self.snr_db.size)


@dataclass(frozen=True, slots=True)
class BurstSpan:
    """Inclusive frame indices of one detected burst."""

    first_frame: int
    last_frame: int

    @property
    def frame_count(self) -> int:
        return self.last_frame - self.first_frame + 1


class FreqLadderBurst(ApiModel):
    """One observed burst, identified against the published ladder schedule."""

    artifact_id: str
    receiver: int = Field(ge=0)
    first_frame: int = Field(ge=0)
    last_frame: int = Field(ge=0)
    frame_count: int = Field(gt=0)
    complete: bool
    start_seconds: float = Field(ge=0)
    center_seconds: float = Field(ge=0)
    epoch_seconds: float
    duration_seconds: float = Field(ge=0)
    duration_lower_seconds: float = Field(ge=0)
    duration_upper_seconds: float = Field(ge=0)
    rung_estimate: float = Field(ge=0)
    rung_offset: float = Field(ge=0)
    rung: int | None = None
    identified: bool = False
    rejection: str | None = None
    lo_hz: float = Field(gt=0)
    nominal_rf_hz: float | None = None
    nominal_if_hz: float | None = None
    measured_frequency_hz: float
    frequency_error_hz: float | None = None
    snr_db: float


class FreqLadderIdentification(ApiModel):
    """How confidently the observed burst durations mapped onto ladder rungs."""

    burst_count: int = Field(ge=0)
    complete_burst_count: int = Field(ge=0)
    identified_burst_count: int = Field(ge=0)
    rejected_burst_count: int = Field(ge=0)
    median_rung_offset: float = Field(ge=0)
    maximum_rung_offset: float = Field(ge=0)
    rung_tolerance: float = Field(gt=0)
    confidence: float = Field(ge=0, le=1)
    confident: bool
    rejections: dict[str, int] = Field(default_factory=dict)


class FreqLadderFit(ApiModel):
    """Separated receiver clock error and LNB LO error with an honest interval."""

    lo_hz: float = Field(gt=0)
    burst_count: int = Field(gt=0)
    rung_count: int = Field(gt=0)
    rungs: tuple[int, ...]
    receiver_clock_error_ppm: float
    receiver_clock_error_ppm_uncertainty: float = Field(ge=0)
    receiver_clock_error_ppm_covariance_stderr: float = Field(ge=0)
    lnb_lo_error_hz: float
    lnb_lo_error_hz_uncertainty: float = Field(ge=0)
    lnb_lo_error_hz_covariance_stderr: float = Field(ge=0)
    lnb_lo_error_ppm: float
    drift_hz_per_second: float | None
    drift_included: bool
    spans_multiple_passes: bool
    uncertainty_method: str
    fold_count: int = Field(ge=0)
    residual_rms_hz: float = Field(ge=0)
    reference_epoch_seconds: float
    warnings: tuple[str, ...] = ()
    uncertainty_claim: str = UNCERTAINTY_CLAIM


def iter_frames(values: np.ndarray, frame_size: int) -> Iterator[np.ndarray]:
    """Split a contiguous complex capture into whole non-overlapping frames."""

    if frame_size <= 0:
        raise ValueError("frame_size must be positive")
    for index in range(int(values.size) // frame_size):
        yield values[index * frame_size : (index + 1) * frame_size]


def visible_rungs(
    schedule: FreqLadderSchedule,
    *,
    lo_hz: float,
    center_frequency_hz: float,
    sample_rate_hz: float,
) -> tuple[int, ...]:
    """Rungs whose expected intermediate frequency lands inside this capture.

    A capture is taken at one centre frequency and bandwidth, so it usually sees
    exactly one rung. Searching only for the rungs that can be present is what
    keeps the detector off the spurs and satellite carriers elsewhere in the band.
    """

    limit = sample_rate_hz / 2
    return tuple(
        rung
        for rung in schedule.rungs
        if abs(schedule.rung_frequency_hz(rung) - lo_hz - center_frequency_hz) < limit
    )


def measure_frames(
    frames: Iterable[np.ndarray],
    *,
    sample_rate_hz: float,
    center_frequency_hz: float,
    frame_size: int,
    search_centers_hz: Sequence[float],
    search_half_width_hz: float = DEFAULT_SEARCH_HALF_WIDTH_HZ,
    dc_notch_hz: float = DEFAULT_DC_NOTCH_HZ,
) -> FrameSeries:
    """Reduce each frame to a detection SNR and an interpolated peak frequency.

    Each frame has its mean removed, is Hann windowed and transformed, and has the
    bins within ``dc_notch_hz`` of baseband DC zeroed. The peak is taken only
    inside ``search_half_width_hz`` of one of the expected ``search_centers_hz``,
    so an unrelated in-band carrier cannot masquerade as a ladder burst. SNR is
    ``20 * log10(peak / median)`` where the median noise floor uses every
    un-notched bin, and the peak frequency uses quadratic interpolation of the log
    magnitude of the peak and its two neighbours.
    """

    if sample_rate_hz <= 0:
        raise ValueError("sample_rate_hz must be positive")
    if frame_size < 8:
        raise ValueError("frame_size must be at least eight samples")
    if dc_notch_hz < 0:
        raise ValueError("dc_notch_hz cannot be negative")
    if search_half_width_hz <= 0:
        raise ValueError("search_half_width_hz must be positive")
    if not search_centers_hz:
        raise ValueError("no expected rung frequency lands inside this capture band")
    window = np.hanning(frame_size)
    bin_width_hz = sample_rate_hz / frame_size
    offsets = np.fft.fftfreq(frame_size, 1 / sample_rate_hz)
    keep = np.abs(offsets) > dc_notch_hz
    if not bool(keep.any()):
        raise ValueError("dc_notch_hz removes the entire spectrum")
    searched = np.zeros(frame_size, dtype=bool)
    for target in search_centers_hz:
        searched |= np.abs(offsets - (target - center_frequency_hz)) <= search_half_width_hz
    searched &= keep
    if not bool(searched.any()):
        raise ValueError("the search band around the expected rungs contains no usable bins")
    snr_db: list[float] = []
    frequency_hz: list[float] = []
    for frame in frames:
        values = np.asarray(frame)
        if values.size != frame_size:
            raise ValueError("every frame must contain exactly frame_size samples")
        centered = values - values.mean()
        magnitude = np.abs(np.fft.fft(centered * window))
        magnitude[~keep] = 0.0
        peak_index = int(np.argmax(np.where(searched, magnitude, 0.0)))
        peak = float(magnitude[peak_index])
        floor = float(np.median(magnitude[keep]))
        snr_db.append(20 * (math.log10(peak + _TINY) - math.log10(floor + _TINY)))
        offset_hz = _interpolated_offset_hz(magnitude, peak_index, bin_width_hz, frame_size)
        frequency_hz.append(center_frequency_hz + offset_hz)
    return FrameSeries(
        snr_db=np.asarray(snr_db, dtype=float),
        frequency_hz=np.asarray(frequency_hz, dtype=float),
        frame_seconds=frame_size / sample_rate_hz,
        searched_bin_count=int(np.count_nonzero(searched)),
    )


def _interpolated_offset_hz(
    magnitude: np.ndarray, peak_index: int, bin_width_hz: float, frame_size: int
) -> float:
    """Quadratic log-magnitude interpolation around one FFT peak."""

    left = math.log10(float(magnitude[(peak_index - 1) % frame_size]) + _TINY)
    center = math.log10(float(magnitude[peak_index]) + _TINY)
    right = math.log10(float(magnitude[(peak_index + 1) % frame_size]) + _TINY)
    denominator = left - 2 * center + right
    delta = 0.0 if denominator == 0 else 0.5 * (left - right) / denominator
    delta = min(0.5, max(-0.5, delta))
    position = peak_index + delta
    if position >= frame_size / 2:
        position -= frame_size
    return position * bin_width_hz


def segment_bursts(
    snr_db: np.ndarray,
    threshold_db: float,
    *,
    hysteresis_db: float = DEFAULT_HYSTERESIS_DB,
    merge_gap_frames: int = 0,
) -> tuple[BurstSpan, ...]:
    """Group frames into bursts with Schmitt-trigger detection and gap merging.

    Detection enters at ``threshold_db`` and leaves only below
    ``threshold_db - hysteresis_db``; segments separated by at most
    ``merge_gap_frames`` frames are then joined. Without both, a single fading
    burst fragments into a shower of short false bursts whose durations identify
    the wrong rungs.
    """

    if hysteresis_db < 0:
        raise ValueError("hysteresis_db cannot be negative")
    if merge_gap_frames < 0:
        raise ValueError("merge_gap_frames cannot be negative")
    values = np.asarray(snr_db)
    release_db = threshold_db - hysteresis_db
    spans: list[BurstSpan] = []
    first: int | None = None
    for index in range(int(values.size)):
        level = float(values[index])
        if first is None:
            if level >= threshold_db:
                first = index
        elif level < release_db:
            spans.append(BurstSpan(first_frame=first, last_frame=index - 1))
            first = None
    if first is not None:
        spans.append(BurstSpan(first_frame=first, last_frame=int(values.size) - 1))
    return _merge_spans(spans, merge_gap_frames)


def _merge_spans(spans: Sequence[BurstSpan], merge_gap_frames: int) -> tuple[BurstSpan, ...]:
    merged: list[BurstSpan] = []
    for span in spans:
        if merged and span.first_frame - merged[-1].last_frame - 1 <= merge_gap_frames:
            merged[-1] = BurstSpan(
                first_frame=merged[-1].first_frame, last_frame=span.last_frame
            )
        else:
            merged.append(span)
    return tuple(merged)


def burst_duration_bounds(span: BurstSpan, frame_seconds: float) -> tuple[float, float, float]:
    """Bound one burst duration between its inner and outer frame estimates.

    The frames at each end straddle the keying transition, so the burst is at
    least the span excluding both edge frames and at most the span including
    them. The reported duration is the mean of those bounds.
    """

    outer = span.frame_count * frame_seconds
    inner = max(0.0, (span.frame_count - 2) * frame_seconds)
    return inner, (inner + outer) / 2, outer


def build_bursts(
    series: FrameSeries,
    *,
    schedule: FreqLadderSchedule,
    context: CaptureContext,
    lo_hz: float,
    threshold_db: float = DEFAULT_THRESHOLD_DB,
    hysteresis_db: float = DEFAULT_HYSTERESIS_DB,
    merge_gap_fraction: float = DEFAULT_MERGE_GAP_FRACTION,
    rung_tolerance: float = DEFAULT_RUNG_TOLERANCE,
) -> tuple[FreqLadderBurst, ...]:
    """Segment, identify, and price every burst in one capture."""

    if lo_hz <= 0:
        raise ValueError("lo_hz must be positive")
    if not 0 < rung_tolerance <= 0.5:
        raise ValueError("rung_tolerance must be between zero and one half")
    if not 0 <= merge_gap_fraction < 1:
        raise ValueError("merge_gap_fraction must be at least zero and below one")
    merge_gap_frames = int(merge_gap_fraction * schedule.unit_seconds / series.frame_seconds)
    rows: list[FreqLadderBurst] = []
    for span in segment_bursts(
        series.snr_db,
        threshold_db,
        hysteresis_db=hysteresis_db,
        merge_gap_frames=merge_gap_frames,
    ):
        lower, duration, upper = burst_duration_bounds(span, series.frame_seconds)
        frames = slice(span.first_frame, span.last_frame + 1)
        measured = float(np.median(series.frequency_hz[frames]))
        start_seconds = span.first_frame * series.frame_seconds
        center_seconds = start_seconds + (span.frame_count * series.frame_seconds) / 2
        complete = span.first_frame > 0 and span.last_frame < series.frame_count - 1
        estimate = schedule.rung_estimate(duration)
        rung: int | None = None
        rejection: str | None = None
        if not complete:
            # A burst touching a capture edge has an unknown duration, so it can
            # neither be identified nor fitted.
            rejection = "clipped_by_capture_edge"
        else:
            rung = schedule.identify(duration, rung_tolerance)
            if rung is None:
                rejection = (
                    "duration_is_not_a_rung_multiple"
                    if 1 <= round(estimate) <= schedule.rung_count
                    else "duration_outside_ladder"
                )
        nominal_rf_hz = None if rung is None else schedule.rung_frequency_hz(rung)
        nominal_if_hz = None if nominal_rf_hz is None else nominal_rf_hz - lo_hz
        rows.append(
            FreqLadderBurst(
                artifact_id=context.artifact_id,
                receiver=context.receiver,
                first_frame=span.first_frame,
                last_frame=span.last_frame,
                frame_count=span.frame_count,
                complete=complete,
                start_seconds=start_seconds,
                center_seconds=center_seconds,
                epoch_seconds=context.epoch_seconds + center_seconds,
                duration_seconds=duration,
                duration_lower_seconds=lower,
                duration_upper_seconds=upper,
                rung_estimate=estimate,
                rung_offset=abs(estimate - round(estimate)),
                rung=rung,
                identified=rung is not None,
                rejection=rejection,
                lo_hz=lo_hz,
                nominal_rf_hz=nominal_rf_hz,
                nominal_if_hz=nominal_if_hz,
                measured_frequency_hz=measured,
                frequency_error_hz=(None if nominal_if_hz is None else measured - nominal_if_hz),
                snr_db=float(np.median(series.snr_db[frames])),
            )
        )
    return tuple(rows)


def summarize_identification(
    bursts: Sequence[FreqLadderBurst], rung_tolerance: float = DEFAULT_RUNG_TOLERANCE
) -> FreqLadderIdentification:
    """Score how well the observed durations actually landed on ladder multiples.

    Per-burst rounding alone cannot expose corrupted transmitter timing: bursts
    stretched by 1.4x still round onto *some* rung. The distance from an integer,
    aggregated over the capture, does expose it.
    """

    if not 0 < rung_tolerance <= 0.5:
        raise ValueError("rung_tolerance must be between zero and one half")
    complete = [row for row in bursts if row.complete]
    offsets = [row.rung_offset for row in complete]
    median_offset = float(np.median(offsets)) if offsets else 0.0
    maximum_offset = max(offsets, default=0.0)
    confidence = max(0.0, min(1.0, 1.0 - median_offset / rung_tolerance)) if offsets else 0.0
    rejections = Counter(row.rejection for row in bursts if row.rejection is not None)
    return FreqLadderIdentification(
        burst_count=len(bursts),
        complete_burst_count=len(complete),
        identified_burst_count=sum(1 for row in bursts if row.identified),
        rejected_burst_count=sum(1 for row in bursts if row.rejection is not None),
        median_rung_offset=median_offset,
        maximum_rung_offset=maximum_offset,
        rung_tolerance=rung_tolerance,
        confidence=confidence,
        confident=bool(offsets) and confidence >= CONFIDENT_IDENTIFICATION,
        rejections={str(reason): count for reason, count in sorted(rejections.items())},
    )


def usable_bursts(bursts: Iterable[FreqLadderBurst]) -> tuple[FreqLadderBurst, ...]:
    """Keep only complete, identified bursts that carry a frequency error."""

    return tuple(
        row
        for row in bursts
        if row.identified
        and row.complete
        and row.rung is not None
        and row.nominal_if_hz is not None
        and row.frequency_error_hz is not None
    )


def merge_burst_rows(payloads: Iterable[Mapping[str, Any]]) -> tuple[FreqLadderBurst, ...]:
    """Validate burst rows emitted by several analyses into one time-ordered set."""

    rows = [FreqLadderBurst.model_validate(dict(payload)) for payload in payloads]
    return tuple(sorted(rows, key=lambda row: (row.epoch_seconds, row.first_frame)))


def burst_rows_from_results(documents: Iterable[Mapping[str, Any]]) -> tuple[FreqLadderBurst, ...]:
    """Collect burst rows from stored ``freq_ladder`` analysis documents."""

    payloads: list[Mapping[str, Any]] = []
    for document in documents:
        result = document.get("result", document)
        if not isinstance(result, Mapping):
            raise ValueError("analysis document does not contain a result object")
        rows = result.get("bursts")
        if not isinstance(rows, Sequence) or isinstance(rows, (str, bytes)):
            raise ValueError("analysis result does not contain a bursts list")
        for row in rows:
            if not isinstance(row, Mapping):
                raise ValueError("every burst row must be an object")
            payloads.append(row)
    return merge_burst_rows(payloads)


def spans_multiple_passes(bursts: Sequence[FreqLadderBurst]) -> bool:
    """Report whether the bursts revisit rungs instead of one monotonic sweep.

    Only then is a drift term identifiable: within a single monotonic pass the
    time regressor is collinear with the frequency regressor it would correct.
    """

    ordered = sorted(bursts, key=lambda row: row.epoch_seconds)
    rungs = [row.rung for row in ordered if row.rung is not None]
    if len(rungs) < 2:
        return False
    if len(set(rungs)) < len(rungs):
        return True
    increasing = all(right > left for left, right in zip(rungs, rungs[1:], strict=False))
    decreasing = all(right < left for left, right in zip(rungs, rungs[1:], strict=False))
    return not (increasing or decreasing)


def fit_freq_ladder(
    bursts: Sequence[FreqLadderBurst],
    *,
    lo_hz: float,
    include_drift: bool | None = None,
    minimum_rungs: int = MINIMUM_FIT_RUNGS,
) -> FreqLadderFit:
    """Separate receiver clock error (slope) from LNB LO error (intercept).

    ``include_drift`` defaults to automatic: the nuisance time regressor is used
    only when the bursts span multiple passes, because a single monotonic pass
    confounds drift with the very slope being measured. When the drift term is
    used the intercept - and therefore the reported LNB LO error - is the value
    at ``reference_epoch_seconds``, the mean burst time.
    """

    if lo_hz <= 0:
        raise ValueError("lo_hz must be positive")
    if minimum_rungs < 2:
        raise ValueError("minimum_rungs must be at least two")
    rows = usable_bursts(bursts)
    if any(row.lo_hz != lo_hz for row in rows):
        raise ValueError("bursts were identified against a different lo_hz")
    rungs = sorted({row.rung for row in rows if row.rung is not None})
    if len(rungs) < minimum_rungs:
        raise ValueError(
            "separating receiver clock error from LNB LO error needs at least "
            f"{minimum_rungs} distinct rungs; got {len(rungs)}"
        )
    if_hz, time_seconds, error_hz = _fit_inputs(rows)
    reference_epoch = float(np.mean(time_seconds))
    multiple_passes = spans_multiple_passes(rows)
    drift_included = multiple_passes if include_drift is None else include_drift
    if drift_included and if_hz.size < 4:
        raise ValueError("fitting a drift term needs at least four identified bursts")

    coefficients, covariance_stderr, residual_rms = _solve(
        if_hz, time_seconds - reference_epoch, error_hz, drift_included
    )
    clock_ppm = -float(coefficients[0]) * 1e6
    lo_error_hz = -float(coefficients[-1])
    folds = _leave_one_rung_out(rows, drift_included, reference_epoch)
    if len(folds) >= 2:
        method = LEAVE_ONE_RUNG_OUT
        clock_uncertainty = _jackknife_error([value for value, _ in folds])
        lo_uncertainty = _jackknife_error([value for _, value in folds])
    else:
        method = COVARIANCE_FALLBACK
        clock_uncertainty = float(covariance_stderr[0]) * 1e6
        lo_uncertainty = float(covariance_stderr[-1])

    warnings: list[str] = []
    if not multiple_passes:
        warnings.append("single_monotonic_pass_confounds_drift_with_slope")
    if method == COVARIANCE_FALLBACK:
        warnings.append("too_few_rungs_to_resample_uncertainty")
    return FreqLadderFit(
        lo_hz=lo_hz,
        burst_count=len(rows),
        rung_count=len(rungs),
        rungs=tuple(rungs),
        receiver_clock_error_ppm=clock_ppm,
        receiver_clock_error_ppm_uncertainty=abs(clock_uncertainty),
        receiver_clock_error_ppm_covariance_stderr=abs(float(covariance_stderr[0]) * 1e6),
        lnb_lo_error_hz=lo_error_hz,
        lnb_lo_error_hz_uncertainty=abs(lo_uncertainty),
        lnb_lo_error_hz_covariance_stderr=abs(float(covariance_stderr[-1])),
        lnb_lo_error_ppm=lo_error_hz / lo_hz * 1e6,
        drift_hz_per_second=float(coefficients[1]) if drift_included else None,
        drift_included=drift_included,
        spans_multiple_passes=multiple_passes,
        uncertainty_method=method,
        fold_count=len(folds),
        residual_rms_hz=residual_rms,
        reference_epoch_seconds=reference_epoch,
        warnings=tuple(warnings),
    )


def _fit_inputs(rows: Sequence[FreqLadderBurst]) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    if_hz: list[float] = []
    time_seconds: list[float] = []
    error_hz: list[float] = []
    for row in rows:
        if row.nominal_if_hz is None or row.frequency_error_hz is None:
            continue
        if_hz.append(row.nominal_if_hz)
        time_seconds.append(row.epoch_seconds)
        error_hz.append(row.frequency_error_hz)
    return (
        np.asarray(if_hz, dtype=float),
        np.asarray(time_seconds, dtype=float),
        np.asarray(error_hz, dtype=float),
    )


def _solve(
    if_hz: np.ndarray,
    time_seconds: np.ndarray,
    error_hz: np.ndarray,
    drift_included: bool,
) -> tuple[np.ndarray, np.ndarray, float]:
    """Least squares for ``Df = a * f_IF + b * t + c`` with column preconditioning.

    Intermediate frequencies are around 1e9 Hz while the constant column is one,
    so each column is normalised before the solve and the coefficients are scaled
    back afterwards. Returns the coefficients ``(a, b, c)`` or ``(a, c)``, their
    covariance standard errors, and the residual RMS.
    """

    ones = np.ones_like(if_hz)
    columns = [if_hz, time_seconds, ones] if drift_included else [if_hz, ones]
    matrix = np.column_stack(columns)
    if matrix.shape[0] < matrix.shape[1]:
        raise ValueError("fewer bursts than fitted terms")
    scale = np.sqrt(np.mean(matrix * matrix, axis=0))
    scale[scale == 0] = 1.0
    scaled = matrix / scale
    solution = np.linalg.lstsq(scaled, error_hz, rcond=None)[0]
    coefficients = solution / scale
    residual = error_hz - matrix @ coefficients
    degrees_of_freedom = matrix.shape[0] - matrix.shape[1]
    residual_rms = float(np.sqrt(np.mean(residual * residual))) if residual.size else 0.0
    if degrees_of_freedom <= 0:
        return coefficients, np.zeros(matrix.shape[1]), residual_rms
    variance = float(residual @ residual) / degrees_of_freedom
    try:
        inverse = np.linalg.inv(scaled.T @ scaled)
    except np.linalg.LinAlgError as error:  # pragma: no cover - degenerate ladders
        raise ValueError("ladder geometry is degenerate; rungs must differ") from error
    covariance = variance * inverse / np.outer(scale, scale)
    stderr = np.sqrt(np.abs(np.diag(covariance)))
    return coefficients, stderr, residual_rms


def _leave_one_rung_out(
    rows: Sequence[FreqLadderBurst], drift_included: bool, reference_epoch: float
) -> list[tuple[float, float]]:
    """Refit with each rung held out; the spread is the honest uncertainty.

    Holding out whole rungs rather than individual bursts is deliberate: the
    dominant error is a per-tuning systematic shared by every burst of a rung,
    which per-burst resampling would average away exactly as the covariance does.
    """

    rungs = sorted({row.rung for row in rows if row.rung is not None})
    folds: list[tuple[float, float]] = []
    for held_out in rungs:
        kept = [row for row in rows if row.rung != held_out]
        if len({row.rung for row in kept}) < 2:
            continue
        if_hz, time_seconds, error_hz = _fit_inputs(kept)
        if if_hz.size < (3 if drift_included else 2):
            continue
        coefficients = _solve(if_hz, time_seconds - reference_epoch, error_hz, drift_included)[0]
        folds.append((-float(coefficients[0]) * 1e6, -float(coefficients[-1])))
    return folds


def _jackknife_error(values: Sequence[float]) -> float:
    """Delete-one jackknife standard error over the leave-one-rung-out refits."""

    count = len(values)
    if count < 2:
        return 0.0
    mean = sum(values) / count
    return math.sqrt((count - 1) / count * sum((value - mean) ** 2 for value in values))
