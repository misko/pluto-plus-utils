"""Decode a seeded pseudorandom frequency hop, where duration coding could not.

This module is the hardware-free core of the ``seeded_hop`` analyzer. It never
talks to a radio: it regenerates a transmitted schedule from a shared seed and
turns one contiguous capture into a per-point frequency error.

Identity comes from the seed, not from the signal
-------------------------------------------------
A transmitter that this receiver does not control hops among ``points``
frequencies spread evenly across ``[rung_start_hz, rung_stop_hz]``. The visiting
*order* is a Fisher-Yates shuffle driven by SplitMix64 seeded with a number both
ends already know, so a receiver never has to infer which point it is hearing.
The only unknown left is the epoch - where in the pattern the capture happens to
start - and that is a single one-dimensional search. After it, every frame's
point is known exactly.

This is the whole reason the method works. The predecessor
(:mod:`pluto_plus.freq_ladder`) encoded identity in *burst duration*: rung ``n``
keyed for ``n`` time units, so the decoder had to measure a length. Duration
estimation needs threshold hysteresis, gap merging and a rounding tolerance, and
it collapses when several points share the capture band, because then the
envelope never returns to the floor between them and the bursts merge. Measured
on this bench, over identical hardware and equal capture time:

===================================  =========================================
duration-coded ladder                never identified more than 1 burst in 95
seeded hop, every configuration      100% of transmitted points identified
===================================  =========================================

Why a random order, and not a ramp
----------------------------------
A monotonic ladder steps frequency in lockstep with time, so oscillator drift
lands squarely on the frequency-dependent term being measured: the two are
collinear within one pass and cannot be separated. A pseudorandom order
decorrelates frequency from time, making drift orthogonal to the quantity of
interest instead of confounded with it. A pseudorandom pattern also
autocorrelates sharply, so the epoch search has one unambiguous peak, whereas a
ramp correlates broadly and aligns poorly. Finally hopping wastes no time: it
costs ``sum(dwell)`` with no muted gaps, against ``u * N * (N + 1)`` for duration
coding, half of it silent.

Why the receiver hears every point at once
------------------------------------------
The whole hop span must fit inside the receiver's instantaneous bandwidth, so a
single tuning hears the entire comb and no retuning happens mid-decode. The
recommended span - 20 points, 90 kHz apart, 1.71 MHz wide - fits a 2.5 MS/s
capture with margin.

Precision follows dwell, not jitter
-----------------------------------
Dwell is ``hop_seconds * (1 + jitter * uniform() * 2)``. Measured over 8 s
captures of the same link, the standard deviation of the recovered per-point
frequency tracked the integration time and nothing else::

    fixed  2 ms, 20 points   20/20 points   sd 2946 Hz
    fixed  5 ms, 20 points   20/20 points   sd 1361 Hz
    fixed 10 ms, 20 points   20/20 points   sd  730 Hz   <- recommended
    fixed  5 ms, 40 points   40/40 points   sd 1552 Hz
    jitter 5 ms, 40 points   40/40 points   sd 1552 Hz

Jitter changed nothing measurable, which is expected once identity no longer
lives in time: with a fixed dwell the epoch search is a uniform grid and every
hop boundary is known from one scalar. ``jitter = 0`` is therefore the default.

Why the comb offset is searched before anything else
----------------------------------------------------
The LNB's local oscillator is off nominal - about +94 kHz on this bench, seen as
about -106 kHz of comb offset at a 1.25 GHz intermediate frequency - which is far
more than the slot half-width used to follow individual points. Because the
transmitted points form a comb of *known* spacing, the offset can be recovered
before any point is identified: slide the expected comb across the time-averaged
spectrum and keep the shift that maximises summed energy at the expected bins.
The reported sharpness (peak over median of that search) is the confidence, and
it ran 38x to 422x on real captures. Recovered offsets of -105.6 to -106.6 kHz
agree with the -105.9 kHz the older duration-coded ladder measured independently.

Why a per-point envelope, not one broadband envelope
----------------------------------------------------
A single wideband power envelope merges adjacent points into one continuous
excursion - the transmitter never stops, it only retunes - so there is nothing to
segment. Instead each point gets its own narrow slot around its offset-corrected
expected frequency, and the per-frame maximum inside that slot is its envelope.
Alignment then scores a candidate epoch by how much energy sits in exactly the
slots the schedule predicts, which is a matched filter over identity rather than
over amplitude.

Why the epoch search is bounded to one period
---------------------------------------------
The pattern repeats every ``period_cycles`` permutations, so every possible epoch
is already contained in one period; searching the whole capture would only
rediscover the same alignment ``capture_seconds / period_seconds`` times over.
Bounding the search is what keeps the decode cheap on an 8 s capture, and the
bound is exact rather than heuristic.

What is reported when the decode is weak
----------------------------------------
Low confidence is reported, never hidden. A capture whose comb search is flat or
whose alignment does not stand out above the rest of the shifts returns
``confident = false`` with named warnings, and points with too few strong frames
report ``measured_if_hz = null`` instead of a median of noise. A confident wrong
answer is the failure this design exists to avoid.
"""

from __future__ import annotations

import math
from collections.abc import Callable, Iterable, Iterator, Sequence
from dataclasses import dataclass

import numpy as np
from pydantic import Field

from pluto_plus.models import ApiModel

_MASK = (1 << 64) - 1
_GOLDEN_GAMMA = 0x9E3779B97F4A7C15
_MIX_A = 0xBF58476D1CE4E5B9
_MIX_B = 0x94D049BB133111EB
_TINY = float(np.finfo(float).tiny)

DEFAULT_SEED = 0xC0FFEE
DEFAULT_POINTS = 20
DEFAULT_START_HZ = 11_000_000_000
DEFAULT_STOP_HZ = 11_001_710_000
DEFAULT_HOP_SECONDS = 0.010
DEFAULT_JITTER = 0.0
DEFAULT_PERIOD_CYCLES = 1
DEFAULT_FRAME_SIZE = 512
DEFAULT_BLOCK_FRAMES = 4096
DEFAULT_THRESHOLD_DB = 15.0
DEFAULT_SEARCH_HALF_WIDTH_HZ = 400_000.0
DEFAULT_SLOT_HALF_WIDTH_HZ = 30_000.0
SLOT_SPACING_FRACTION = 0.6
COMB_SEARCH_STEPS_PER_BIN = 8
COMB_BACKGROUND_PERCENTILE = 20.0
MINIMUM_COMB_SHIFTS = 3
EPOCH_STEPS_PER_FRAME = 2
MINIMUM_STRONG_FRAMES = 5
MINIMUM_ALIGNMENT_REFERENCE = 8
CONFIDENT_COMB_SHARPNESS = 4.0
MAXIMUM_COMB_SHARPNESS = 1.0e6
CONFIDENT_EPOCH_SIGMA = 6.0
CONFIDENT_POINT_FRACTION = 0.5
LOW_COMB_SHARPNESS = "comb_search_is_flat"
LOW_EPOCH_SHARPNESS = "epoch_alignment_does_not_stand_out"
FEW_POINTS = "too_few_points_measured"
IDENTITY_CLAIM = (
    "point identity comes from the seeded schedule, never from burst duration; "
    "the only quantity estimated from the signal is the epoch"
)


class SplitMix64:
    """Deterministic 64-bit generator, identical in any language.

    This is a protocol, not an implementation detail. The transmitter
    (``adf5355_tester``'s ``adf5355/hopper.py``) and every receiver must produce
    the same stream for a seed forever: if this generator drifts, receivers keep
    decoding confidently against a schedule the transmitter never sent. The
    published vectors for seed 0 are pinned in this repository's tests.
    """

    __slots__ = ("_state",)

    def __init__(self, seed: int) -> None:
        self._state = seed & _MASK

    def next_u64(self) -> int:
        self._state = (self._state + _GOLDEN_GAMMA) & _MASK
        value = self._state
        value = ((value ^ (value >> 30)) * _MIX_A) & _MASK
        value = ((value ^ (value >> 27)) * _MIX_B) & _MASK
        return value ^ (value >> 31)

    def uniform(self) -> float:
        """Uniform in ``[0, 1)`` from the top 53 bits, as IEEE doubles do it."""

        return (self.next_u64() >> 11) * (2.0**-53)

    def below(self, bound: int) -> int:
        """Unbiased integer in ``[0, bound)`` by rejection, never by modulo bias."""

        if bound <= 0:
            raise ValueError("bound must be positive")
        limit = _MASK - (_MASK % bound)
        while True:
            value = self.next_u64()
            if value <= limit:
                return value % bound


def plan_frequencies(start_hz: int, stop_hz: int, points: int) -> tuple[int, ...]:
    """Evenly spaced transmitted frequencies, rounded exactly as the transmitter does."""

    if points < 2:
        raise ValueError("need at least 2 frequency points")
    if stop_hz < start_hz:
        raise ValueError("stop must not be below start")
    step = (stop_hz - start_hz) / (points - 1)
    return tuple(round(start_hz + step * index) for index in range(points))


def _permutation(rng: SplitMix64, count: int) -> list[int]:
    """Fisher-Yates, so every point is visited exactly once per cycle."""

    order = list(range(count))
    for index in range(count - 1, 0, -1):
        other = rng.below(index + 1)
        order[index], order[other] = order[other], order[index]
    return order


@dataclass(frozen=True, slots=True)
class Hop:
    """One dwell of the transmitted schedule."""

    sequence: int
    cycle: int
    point: int
    frequency_hz: int
    dwell_seconds: float
    start_seconds: float
    end_seconds: float


@dataclass(frozen=True, slots=True)
class HopSchedule:
    """One period of the transmitted pattern, regenerated from shared parameters.

    Only one period is ever needed: the pattern repeats, so a capture of any
    length is decoded by taking frame time modulo :attr:`period_seconds`.
    """

    seed: int
    frequencies_hz: tuple[int, ...]
    hop_seconds: float
    jitter: float
    period_cycles: int
    hops: tuple[Hop, ...]

    @property
    def point_count(self) -> int:
        return len(self.frequencies_hz)

    @property
    def period_seconds(self) -> float:
        return self.hops[-1].end_seconds

    @property
    def spacing_hz(self) -> float:
        return (self.frequencies_hz[-1] - self.frequencies_hz[0]) / (self.point_count - 1)

    def intermediate_frequencies_hz(self, lo_hz: float) -> np.ndarray:
        """Nominal intermediate frequency of every point behind a downconverter."""

        return np.asarray(self.frequencies_hz, dtype=float) - lo_hz


def build_schedule(
    *,
    seed: int = DEFAULT_SEED,
    start_hz: int,
    stop_hz: int,
    points: int = DEFAULT_POINTS,
    hop_seconds: float = DEFAULT_HOP_SECONDS,
    jitter: float = DEFAULT_JITTER,
    period_cycles: int = DEFAULT_PERIOD_CYCLES,
) -> HopSchedule:
    """Regenerate exactly one period of the transmitted hop schedule.

    This must stay byte-for-byte equivalent to the transmitter's generator: the
    draw order is one Fisher-Yates permutation followed by one dwell draw per
    hop, repeated ``period_cycles`` times from a single seeded stream.
    """

    if hop_seconds <= 0:
        raise ValueError("hop_seconds must be positive")
    if not 0.0 <= jitter <= 1.0:
        raise ValueError("jitter must be between 0 and 1")
    if period_cycles < 1:
        raise ValueError("period_cycles must be at least 1")
    frequencies = plan_frequencies(start_hz, stop_hz, points)
    rng = SplitMix64(seed)
    period: list[tuple[int, float]] = []
    for _ in range(period_cycles):
        for point in _permutation(rng, len(frequencies)):
            period.append((point, hop_seconds * (1.0 + jitter * rng.uniform() * 2.0)))
    hops: list[Hop] = []
    elapsed = 0.0
    for sequence, (point, dwell) in enumerate(period):
        hops.append(
            Hop(
                sequence=sequence,
                cycle=sequence // len(frequencies),
                point=point,
                frequency_hz=frequencies[point],
                dwell_seconds=dwell,
                start_seconds=elapsed,
                end_seconds=elapsed + dwell,
            )
        )
        elapsed += dwell
    return HopSchedule(
        seed=seed,
        frequencies_hz=frequencies,
        hop_seconds=hop_seconds,
        jitter=jitter,
        period_cycles=period_cycles,
        hops=tuple(hops),
    )


class SeededHopPlan(ApiModel):
    """Published parameters both ends must already agree on."""

    seed: int = Field(ge=0)
    points: int = Field(ge=2)
    start_hz: float = Field(gt=0)
    stop_hz: float = Field(gt=0)
    spacing_hz: float = Field(gt=0)
    hop_seconds: float = Field(gt=0)
    jitter: float = Field(ge=0, le=1)
    period_cycles: int = Field(ge=1)
    period_seconds: float = Field(gt=0)
    lo_hz: float = Field(gt=0)
    frequencies_hz: tuple[int, ...]
    intermediate_frequencies_hz: tuple[float, ...]


class CombOffset(ApiModel):
    """Bulk frequency offset of the whole comb, found before any point is identified."""

    offset_hz: float
    sharpness: float = Field(ge=0)
    confident: bool
    search_half_width_hz: float = Field(gt=0)
    search_step_hz: float = Field(gt=0)
    search_count: int = Field(gt=0)


class EpochAlignment(ApiModel):
    """Where in the repeating pattern this capture started."""

    shift_seconds: float = Field(ge=0)
    score_db: float
    sharpness_sigma: float
    confident: bool
    search_span_seconds: float = Field(gt=0)
    search_step_seconds: float = Field(gt=0)
    search_count: int = Field(gt=0)
    bounded_to_one_period: bool = True


class HopPointMeasurement(ApiModel):
    """One transmitted point, measured over the frames the schedule assigns to it."""

    point: int = Field(ge=0)
    nominal_rf_hz: float = Field(gt=0)
    nominal_if_hz: float
    assigned_frame_count: int = Field(ge=0)
    strong_frame_count: int = Field(ge=0)
    measured_if_hz: float | None = None
    frequency_error_hz: float | None = None
    frequency_spread_hz: float | None = None
    median_envelope_db: float | None = None
    measured: bool = False
    rejection: str | None = None


class SeededHopDecode(ApiModel):
    """Everything one capture of a seeded hop yields, confidence included."""

    plan: SeededHopPlan
    comb: CombOffset
    epoch: EpochAlignment
    frame_size: int = Field(gt=0)
    frame_seconds: float = Field(gt=0)
    frame_count: int = Field(ge=0)
    slot_half_width_hz: float = Field(gt=0)
    threshold_db: float
    points: tuple[HopPointMeasurement, ...]
    measured_point_count: int = Field(ge=0)
    measured_points: tuple[int, ...]
    median_frequency_error_hz: float | None = None
    mean_frequency_error_hz: float | None = None
    frequency_error_stdev_hz: float | None = None
    confident: bool
    warnings: tuple[str, ...] = ()
    identity_claim: str = IDENTITY_CLAIM


def bin_frequencies_hz(
    frame_size: int, sample_rate_hz: float, center_frequency_hz: float
) -> np.ndarray:
    """Absolute frequency of every FFT bin, in ascending (fftshifted) order."""

    if frame_size < 8:
        raise ValueError("frame_size must be at least eight samples")
    if sample_rate_hz <= 0:
        raise ValueError("sample_rate_hz must be positive")
    offsets = np.fft.fftshift(np.fft.fftfreq(frame_size, 1 / sample_rate_hz))
    return np.asarray(offsets + center_frequency_hz, dtype=float)


def iter_blocks(
    values: np.ndarray, *, frame_size: int, block_frames: int = DEFAULT_BLOCK_FRAMES
) -> Iterator[np.ndarray]:
    """Cut a contiguous complex capture into blocks of whole non-overlapping frames."""

    if frame_size <= 0:
        raise ValueError("frame_size must be positive")
    if block_frames <= 0:
        raise ValueError("block_frames must be positive")
    frame_count = int(np.asarray(values).size) // frame_size
    for start in range(0, frame_count, block_frames):
        count = min(block_frames, frame_count - start)
        block = np.asarray(values)[start * frame_size : (start + count) * frame_size]
        yield block.reshape(count, frame_size)


def block_power_spectra(block: np.ndarray, window: np.ndarray) -> np.ndarray:
    """Mean-removed, Hann-windowed, fftshifted power spectra of a block of frames.

    The per-frame mean is removed first: a receiver's DC offset otherwise plants a
    permanent spike at baseband zero that outranks every transmitted point in
    whichever slot happens to straddle it.
    """

    values = np.asarray(block, dtype=np.complex128)
    if values.ndim != 2:
        raise ValueError("a block must be two-dimensional (frames, frame_size)")
    if values.shape[1] != int(window.size):
        raise ValueError("every frame must contain exactly frame_size samples")
    centered = values - values.mean(axis=1, keepdims=True)
    transformed = np.fft.fftshift(np.fft.fft(centered * window, axis=1), axes=1)
    return np.asarray(np.abs(transformed) ** 2, dtype=float)


def average_power_spectrum(blocks: Iterable[np.ndarray], *, frame_size: int) -> np.ndarray:
    """Time-averaged power spectrum, the surface the comb search slides over."""

    window = np.hanning(frame_size)
    total = np.zeros(frame_size, dtype=float)
    used = 0
    for block in blocks:
        spectra = block_power_spectra(block, window)
        total += spectra.sum(axis=0)
        used += int(spectra.shape[0])
    if used == 0:
        raise ValueError("capture contains no whole frames")
    return total / used


def estimate_comb_offset(
    spectrum: np.ndarray,
    *,
    bins_hz: np.ndarray,
    expected_if_hz: Sequence[float] | np.ndarray,
    search_half_width_hz: float = DEFAULT_SEARCH_HALF_WIDTH_HZ,
    search_step_hz: float | None = None,
) -> CombOffset:
    """Slide the expected comb over the averaged spectrum and keep the best shift.

    Only the comb *spacing* is assumed, never which point is which, so this runs
    before identity is known and absorbs the downconverter's local-oscillator
    error in one scalar. Sharpness is the winning score over the median score of
    the search: a real comb towers over its neighbourhood, noise does not. Shifts
    that would push any point past the edge of the capture are not scored at all,
    because clamping them to the edge bin fabricates energy that was never there
    and makes an impossible shift look plausible.
    """

    if search_half_width_hz <= 0:
        raise ValueError("search_half_width_hz must be positive")
    expected = np.asarray(expected_if_hz, dtype=float)
    if expected.size < 2:
        raise ValueError("a comb needs at least two points")
    values = np.asarray(spectrum, dtype=float)
    if values.size != int(bins_hz.size):
        raise ValueError("spectrum and bins_hz must have the same length")
    bin_width_hz = float(bins_hz[1] - bins_hz[0])
    default_step_hz = bin_width_hz / COMB_SEARCH_STEPS_PER_BIN
    step = default_step_hz if search_step_hz is None else search_step_hz
    if step <= 0:
        raise ValueError("search_step_hz must be positive")
    background = float(np.percentile(values, COMB_BACKGROUND_PERCENTILE))
    comb = np.maximum(values - background, 0.0)
    candidates = np.arange(-search_half_width_hz, search_half_width_hz + step / 2, step)
    positions = np.rint((expected[None, :] + candidates[:, None] - bins_hz[0]) / bin_width_hz)
    inside = (positions.min(axis=1) >= 0) & (positions.max(axis=1) <= values.size - 1)
    if int(np.count_nonzero(inside)) < MINIMUM_COMB_SHIFTS:
        raise ValueError(
            "the comb search window pushes the transmitted points outside the capture "
            "band; narrow search_half_width_hz or widen the capture"
        )
    offsets = candidates[inside]
    indices = positions[inside].astype(np.int64)
    scores = comb[indices].sum(axis=1)
    best = int(np.argmax(scores))
    sharpness = _comb_sharpness(peak=float(scores[best]), median=float(np.median(scores)))
    return CombOffset(
        offset_hz=float(offsets[best]),
        sharpness=sharpness,
        confident=bool(sharpness >= CONFIDENT_COMB_SHARPNESS),
        search_half_width_hz=search_half_width_hz,
        search_step_hz=step,
        search_count=int(offsets.size),
    )


def _comb_sharpness(*, peak: float, median: float) -> float:
    """How far the winning comb shift towers over a typical one.

    A noiseless comb leaves the background-subtracted spectrum empty everywhere
    but the transmitted bins, so the typical shift scores exactly zero. That is
    the sharpest possible result, not a flat search, so the ratio saturates at a
    finite cap instead of dividing by zero.
    """

    if peak <= 0:
        return 0.0
    if median <= 0:
        return MAXIMUM_COMB_SHARPNESS
    return min(peak / median, MAXIMUM_COMB_SHARPNESS)


def slot_half_width_hz(
    spacing_hz: float, maximum_hz: float = DEFAULT_SLOT_HALF_WIDTH_HZ
) -> float:
    """Half-width of one point's tracking slot.

    Narrow enough that neighbouring points cannot leak into each other - hence the
    fraction of the spacing - and capped so a wide comb does not open the slot far
    enough to admit an unrelated in-band carrier.
    """

    if spacing_hz <= 0:
        raise ValueError("spacing_hz must be positive")
    if maximum_hz <= 0:
        raise ValueError("maximum_hz must be positive")
    return min(maximum_hz, spacing_hz / 2 * SLOT_SPACING_FRACTION)


def slot_bounds(
    bins_hz: np.ndarray,
    expected_if_hz: Sequence[float] | np.ndarray,
    *,
    offset_hz: float,
    half_width_hz: float,
) -> tuple[tuple[int, int], ...]:
    """Inclusive-exclusive bin bounds of every point's offset-corrected slot."""

    if half_width_hz <= 0:
        raise ValueError("half_width_hz must be positive")
    expected = np.asarray(expected_if_hz, dtype=float)
    size = int(bins_hz.size)
    bin_width_hz = float(bins_hz[1] - bins_hz[0])
    bounds: list[tuple[int, int]] = []
    for center in expected + offset_hz:
        position = (center - float(bins_hz[0])) / bin_width_hz
        if not -0.5 <= position <= size - 0.5:
            raise ValueError(
                "a frequency point falls outside the capture band; the whole hop span "
                "must fit the receiver bandwidth so one tuning hears every point"
            )
        low = max(0, int(np.searchsorted(bins_hz, center - half_width_hz)))
        high = min(size, int(np.searchsorted(bins_hz, center + half_width_hz)))
        if high <= low:
            nearest = int(np.clip(np.argmin(np.abs(bins_hz - center)), 0, size - 1))
            low, high = nearest, nearest + 1
        bounds.append((low, high))
    return tuple(bounds)


@dataclass(frozen=True, slots=True)
class PointEnvelope:
    """Per-point, per-frame slot power and interpolated peak frequency."""

    power: np.ndarray
    peak_hz: np.ndarray

    @property
    def point_count(self) -> int:
        return int(self.power.shape[0])

    @property
    def frame_count(self) -> int:
        return int(self.power.shape[1])


def build_envelope(
    blocks: Iterable[np.ndarray],
    *,
    frame_size: int,
    bins_hz: np.ndarray,
    slots: Sequence[tuple[int, int]],
) -> PointEnvelope:
    """Follow every point separately, one narrow slot at a time.

    A single broadband envelope is useless here: the transmitter never mutes, it
    only retunes, so adjacent points merge into one unbroken excursion. Tracking
    each point in its own slot is what turns a continuous signal back into a
    per-identity time series.
    """

    window = np.hanning(frame_size)
    bin_width_hz = float(bins_hz[1] - bins_hz[0])
    power_chunks: list[np.ndarray] = []
    peak_chunks: list[np.ndarray] = []
    for block in blocks:
        spectra = block_power_spectra(block, window)
        count = int(spectra.shape[0])
        power = np.empty((len(slots), count), dtype=float)
        peak = np.empty((len(slots), count), dtype=float)
        rows = np.arange(count)
        for index, (low, high) in enumerate(slots):
            segment = spectra[:, low:high]
            local = np.argmax(segment, axis=1)
            absolute = local + low
            power[index] = segment[rows, local]
            peak[index] = _interpolated_peak_hz(spectra, rows, absolute, bins_hz, bin_width_hz)
        power_chunks.append(power)
        peak_chunks.append(peak)
    if not power_chunks:
        raise ValueError("capture contains no whole frames")
    return PointEnvelope(
        power=np.concatenate(power_chunks, axis=1),
        peak_hz=np.concatenate(peak_chunks, axis=1),
    )


def _interpolated_peak_hz(
    spectra: np.ndarray,
    rows: np.ndarray,
    peak_index: np.ndarray,
    bins_hz: np.ndarray,
    bin_width_hz: float,
) -> np.ndarray:
    """Quadratic log-power interpolation around each frame's slot peak.

    Without it the answer is quantised to the bin width, which at a 512-point
    frame and 2.5 MS/s is 4.9 kHz - larger than the errors being measured.
    """

    limit = int(spectra.shape[1]) - 2
    center_index = np.clip(peak_index, 1, max(limit, 1))
    left = np.log10(spectra[rows, center_index - 1] + _TINY)
    center = np.log10(spectra[rows, center_index] + _TINY)
    right = np.log10(spectra[rows, center_index + 1] + _TINY)
    denominator = left - 2 * center + right
    safe = np.where(denominator == 0, 1.0, denominator)
    delta = np.where(denominator == 0, 0.0, 0.5 * (left - right) / safe)
    delta = np.clip(delta, -0.5, 0.5)
    return np.asarray(bins_hz[0] + (center_index + delta) * bin_width_hz, dtype=float)


def envelope_db(power: np.ndarray) -> np.ndarray:
    """Per-point slot power in dB above that point's own median frame.

    Each point is normalised against itself, so an uneven receive response across
    the comb cannot make one point look permanently present and another absent.
    """

    values = np.asarray(power, dtype=float)
    median = np.median(values, axis=1, keepdims=True)
    median = np.maximum(median, _TINY)
    return np.asarray(10 * np.log10(values / median + _TINY), dtype=float)


def assigned_points(
    schedule: HopSchedule, *, frame_count: int, frame_seconds: float, shift_seconds: float
) -> np.ndarray:
    """Which transmitted point the schedule expects in each frame."""

    if frame_count < 0:
        raise ValueError("frame_count cannot be negative")
    if frame_seconds <= 0:
        raise ValueError("frame_seconds must be positive")
    ends = np.asarray([hop.end_seconds for hop in schedule.hops], dtype=float)
    points = np.asarray([hop.point for hop in schedule.hops], dtype=np.int64)
    times = (np.arange(frame_count) * frame_seconds + shift_seconds) % schedule.period_seconds
    index = np.clip(np.searchsorted(ends, times), 0, ends.size - 1)
    return np.asarray(points[index], dtype=np.int64)


def align_epoch(
    envelope_db_values: np.ndarray,
    schedule: HopSchedule,
    *,
    frame_seconds: float,
    step_seconds: float | None = None,
) -> EpochAlignment:
    """Find where in the repeating pattern this capture started.

    The search is bounded to exactly one period because the pattern repeats:
    every distinguishable epoch already occurs inside ``[0, period_seconds)``, so
    a longer search cannot find anything new. Each candidate is scored by the mean
    envelope level of the point the schedule expects at each frame - a matched
    filter over identity - and sharpness is how many standard deviations the
    winner stands above the rest of the search.
    """

    if frame_seconds <= 0:
        raise ValueError("frame_seconds must be positive")
    values = np.asarray(envelope_db_values, dtype=float)
    if values.ndim != 2:
        raise ValueError("envelope must be two-dimensional (points, frames)")
    if values.shape[0] != schedule.point_count:
        raise ValueError("envelope point count does not match the schedule")
    frame_count = int(values.shape[1])
    if frame_count == 0:
        raise ValueError("capture contains no whole frames")
    step = step_seconds if step_seconds is not None else frame_seconds / EPOCH_STEPS_PER_FRAME
    if step <= 0:
        raise ValueError("step_seconds must be positive")
    ends = np.asarray([hop.end_seconds for hop in schedule.hops], dtype=float)
    points = np.asarray([hop.point for hop in schedule.hops], dtype=np.int64)
    columns = np.arange(frame_count)
    times = np.arange(frame_count) * frame_seconds
    shifts = np.arange(0.0, schedule.period_seconds, step)
    scores = np.empty(shifts.size, dtype=float)
    for index, shift in enumerate(shifts):
        wrapped = (times + shift) % schedule.period_seconds
        expected = points[np.clip(np.searchsorted(ends, wrapped), 0, ends.size - 1)]
        scores[index] = float(values[expected, columns].mean())
    best = int(np.argmax(scores))
    sigma = _alignment_sigma(
        scores,
        best=best,
        step_seconds=step,
        guard_seconds=schedule.hop_seconds,
        period_seconds=schedule.period_seconds,
    )
    return EpochAlignment(
        shift_seconds=float(shifts[best]),
        score_db=float(scores[best]),
        sharpness_sigma=sigma,
        confident=bool(sigma >= CONFIDENT_EPOCH_SIGMA),
        search_span_seconds=schedule.period_seconds,
        search_step_seconds=step,
        search_count=int(shifts.size),
    )


def _alignment_sigma(
    scores: np.ndarray,
    *,
    best: int,
    step_seconds: float,
    guard_seconds: float,
    period_seconds: float,
) -> float:
    """How far the winning shift stands above the genuinely misaligned ones.

    Shifts within one dwell of the winner still assign most frames correctly, so
    they form a broad lobe around the peak. Including that lobe in the reference
    population would let a good alignment argue itself down towards a bad one, so
    the lobe is excluded - circularly, because shift space wraps at the period.
    """

    count = int(scores.size)
    distance = np.abs(np.arange(count) - best) * step_seconds
    distance = np.minimum(distance, period_seconds - distance)
    reference = scores[distance > guard_seconds]
    if reference.size < MINIMUM_ALIGNMENT_REFERENCE:
        reference = np.delete(scores, best)
    if reference.size < 2:
        return 0.0
    spread = float(reference.std())
    if spread <= 0:
        return 0.0
    return (float(scores[best]) - float(reference.mean())) / spread


def measure_points(
    envelope: PointEnvelope,
    envelope_db_values: np.ndarray,
    *,
    schedule: HopSchedule,
    lo_hz: float,
    assigned: np.ndarray,
    threshold_db: float = DEFAULT_THRESHOLD_DB,
    minimum_strong_frames: int = MINIMUM_STRONG_FRAMES,
) -> tuple[HopPointMeasurement, ...]:
    """Measure each point over the frames the schedule assigns to it.

    The median of the strong frames is used rather than the mean: a retune lands
    inside the dwell it precedes, so the first frame or two of every dwell can
    still hold the previous point, and one outlier must not move the answer.
    Points with too few strong frames are reported unmeasured, never as a median
    of noise.
    """

    nominal_if = schedule.intermediate_frequencies_hz(lo_hz)
    rows: list[HopPointMeasurement] = []
    for point in range(schedule.point_count):
        selected = assigned == point
        strong = selected & (envelope_db_values[point] > threshold_db)
        strong_count = int(np.count_nonzero(strong))
        row = HopPointMeasurement(
            point=point,
            nominal_rf_hz=float(schedule.frequencies_hz[point]),
            nominal_if_hz=float(nominal_if[point]),
            assigned_frame_count=int(np.count_nonzero(selected)),
            strong_frame_count=strong_count,
        )
        if strong_count < minimum_strong_frames:
            rows.append(
                row.model_copy(
                    update={
                        "rejection": (
                            f"only {strong_count} frames exceeded {threshold_db:g} dB; "
                            f"{minimum_strong_frames} are required"
                        )
                    }
                )
            )
            continue
        peaks = envelope.peak_hz[point][strong]
        measured = float(np.median(peaks))
        rows.append(
            row.model_copy(
                update={
                    "measured_if_hz": measured,
                    "frequency_error_hz": measured - float(nominal_if[point]),
                    "frequency_spread_hz": float(np.std(peaks)),
                    "median_envelope_db": float(np.median(envelope_db_values[point][strong])),
                    "measured": True,
                }
            )
        )
    return tuple(rows)


def decode_capture(
    blocks: Callable[[], Iterable[np.ndarray]],
    *,
    schedule: HopSchedule,
    lo_hz: float,
    sample_rate_hz: float,
    center_frequency_hz: float,
    frame_size: int = DEFAULT_FRAME_SIZE,
    threshold_db: float = DEFAULT_THRESHOLD_DB,
    search_half_width_hz: float = DEFAULT_SEARCH_HALF_WIDTH_HZ,
) -> SeededHopDecode:
    """Comb offset, then epoch, then per-point frequency error, in that order.

    ``blocks`` is called twice and must yield the same frames each time: the comb
    offset has to be known before the tracking slots can be placed, and streaming
    the capture twice costs far less memory than holding every spectrum.
    """

    if lo_hz <= 0:
        raise ValueError("lo_hz must be positive")
    if frame_size < 8:
        raise ValueError("frame_size must be at least eight samples")
    bins_hz = bin_frequencies_hz(frame_size, sample_rate_hz, center_frequency_hz)
    expected_if = schedule.intermediate_frequencies_hz(lo_hz)
    average = average_power_spectrum(blocks(), frame_size=frame_size)
    comb = estimate_comb_offset(
        average,
        bins_hz=bins_hz,
        expected_if_hz=expected_if,
        search_half_width_hz=search_half_width_hz,
    )
    half_width = slot_half_width_hz(schedule.spacing_hz)
    slots = slot_bounds(
        bins_hz, expected_if, offset_hz=comb.offset_hz, half_width_hz=half_width
    )
    envelope = build_envelope(blocks(), frame_size=frame_size, bins_hz=bins_hz, slots=slots)
    levels = envelope_db(envelope.power)
    frame_seconds = frame_size / sample_rate_hz
    epoch = align_epoch(levels, schedule, frame_seconds=frame_seconds)
    assigned = assigned_points(
        schedule,
        frame_count=envelope.frame_count,
        frame_seconds=frame_seconds,
        shift_seconds=epoch.shift_seconds,
    )
    points = measure_points(
        envelope,
        levels,
        schedule=schedule,
        lo_hz=lo_hz,
        assigned=assigned,
        threshold_db=threshold_db,
    )
    return summarize_decode(
        plan=SeededHopPlan(
            seed=schedule.seed,
            points=schedule.point_count,
            start_hz=float(schedule.frequencies_hz[0]),
            stop_hz=float(schedule.frequencies_hz[-1]),
            spacing_hz=schedule.spacing_hz,
            hop_seconds=schedule.hop_seconds,
            jitter=schedule.jitter,
            period_cycles=schedule.period_cycles,
            period_seconds=schedule.period_seconds,
            lo_hz=lo_hz,
            frequencies_hz=schedule.frequencies_hz,
            intermediate_frequencies_hz=tuple(float(value) for value in expected_if),
        ),
        comb=comb,
        epoch=epoch,
        frame_size=frame_size,
        frame_seconds=frame_seconds,
        frame_count=envelope.frame_count,
        slot_half_width=half_width,
        threshold_db=threshold_db,
        points=points,
    )


def summarize_decode(
    *,
    plan: SeededHopPlan,
    comb: CombOffset,
    epoch: EpochAlignment,
    frame_size: int,
    frame_seconds: float,
    frame_count: int,
    slot_half_width: float,
    threshold_db: float,
    points: Sequence[HopPointMeasurement],
) -> SeededHopDecode:
    """Collect one decode, and say plainly how much of it to believe."""

    errors = [row.frequency_error_hz for row in points if row.frequency_error_hz is not None]
    measured = tuple(row.point for row in points if row.measured)
    warnings: list[str] = []
    if not comb.confident:
        warnings.append(LOW_COMB_SHARPNESS)
    if not epoch.confident:
        warnings.append(LOW_EPOCH_SHARPNESS)
    enough = len(measured) >= math.ceil(CONFIDENT_POINT_FRACTION * plan.points)
    if not enough:
        warnings.append(FEW_POINTS)
    return SeededHopDecode(
        plan=plan,
        comb=comb,
        epoch=epoch,
        frame_size=frame_size,
        frame_seconds=frame_seconds,
        frame_count=frame_count,
        slot_half_width_hz=slot_half_width,
        threshold_db=threshold_db,
        points=tuple(points),
        measured_point_count=len(measured),
        measured_points=measured,
        median_frequency_error_hz=float(np.median(errors)) if errors else None,
        mean_frequency_error_hz=float(np.mean(errors)) if errors else None,
        frequency_error_stdev_hz=float(np.std(errors, ddof=1)) if len(errors) > 1 else None,
        confident=bool(comb.confident and epoch.confident and enough),
        warnings=tuple(warnings),
    )
