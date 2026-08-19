"""Seeded-hop core: the schedule is a shared protocol, and the decode admits doubt."""

from __future__ import annotations

import importlib.util

import numpy as np
import pytest

from pluto_plus.seeded_hop import (
    CONFIDENT_COMB_SHARPNESS,
    CONFIDENT_EPOCH_SIGMA,
    DEFAULT_JITTER,
    DEFAULT_PERIOD_CYCLES,
    DEFAULT_SEED,
    FEW_POINTS,
    LOW_COMB_SHARPNESS,
    LOW_EPOCH_SHARPNESS,
    PointEnvelope,
    SplitMix64,
    align_epoch,
    assigned_points,
    bin_frequencies_hz,
    build_envelope,
    build_schedule,
    decode_capture,
    envelope_db,
    estimate_comb_offset,
    iter_blocks,
    measure_points,
    plan_frequencies,
    slot_bounds,
    slot_half_width_hz,
)

# Published SplitMix64 outputs for seed 0. These are a cross-implementation
# contract: if this generator ever drifts, every receiver silently decodes
# against a schedule the transmitter never sent.
SPLITMIX64_SEED_ZERO = (0xE220A8397B1DCDAF, 0x6E789E6AA1B965F4, 0x06C45D188009454F)

# Visiting order emitted by the transmitter of record, adf5355_tester's
# adf5355/hopper.py at 5be028d, for the recommended 20-point plan.
REFERENCE_ORDERS = {
    0: (10, 14, 4, 6, 18, 5, 12, 3, 9, 13, 7, 19, 8, 17, 0, 11, 2, 1, 16, 15),
    1: (1, 14, 10, 3, 19, 4, 6, 16, 15, 13, 2, 0, 11, 7, 18, 9, 17, 12, 8, 5),
    0xC0FFEE: (6, 18, 5, 1, 10, 11, 12, 4, 16, 7, 9, 13, 19, 17, 2, 8, 15, 3, 0, 14),
    0xDEADBEEF: (18, 2, 9, 6, 4, 0, 19, 8, 1, 3, 10, 13, 17, 14, 5, 16, 12, 11, 15, 7),
}
# Two-permutation period with jittered dwells, same reference implementation.
REFERENCE_JITTER_ORDER = (6, 1, 7, 4, 0, 3, 5, 2, 6, 1, 0, 2, 3, 4, 5, 7)
REFERENCE_JITTER_DWELLS = (
    0.009368005567387911,
    0.005513646982068361,
    0.0081851616627713,
    0.006930070176986194,
    0.00657107527369603,
    0.007297794699275254,
)

RECOMMENDED_START_HZ = 11_000_000_000
RECOMMENDED_STOP_HZ = 11_001_710_000
# The first eight of the 40-point plan over the same span, where the step is
# 43846.153... Hz rather than a whole number of Hertz. Emitted by the same
# transmitter of record; pinned because rounding-to-nearest is part of the shared
# protocol and a truncating plan differs from it at over half the points.
FRACTIONAL_STEP_PLAN = (
    11_000_000_000,
    11_000_043_846,
    11_000_087_692,
    11_000_131_538,
    11_000_175_385,
    11_000_219_231,
    11_000_263_077,
    11_000_306_923,
)

# A bench-shaped but test-sized link: eight points 20 kHz apart behind a
# downconverter, captured at 200 kS/s so the whole comb fits one tuning.
SAMPLE_RATE_HZ = 200_000.0
LO_HZ = 10_999_000_000.0
START_HZ = 11_000_000_000
STOP_HZ = 11_000_140_000
POINTS = 8
HOP_SECONDS = 0.005
CENTER_HZ = (START_HZ + STOP_HZ) / 2 - LO_HZ
OFFSET_HZ = -15_000.0
FRAME_SIZE = 128
SEARCH_HALF_WIDTH_HZ = 40_000.0
CAPTURE_SECONDS = 0.4
EPOCH_SECONDS = 0.017


def reference_schedule(seed: int = DEFAULT_SEED, **overrides: object) -> object:
    arguments = {
        "seed": seed,
        "start_hz": START_HZ,
        "stop_hz": STOP_HZ,
        "points": POINTS,
        "hop_seconds": HOP_SECONDS,
    }
    arguments.update(overrides)
    return build_schedule(**arguments)  # type: ignore[arg-type]


def hop_samples(
    schedule,
    *,
    seconds: float = CAPTURE_SECONDS,
    epoch_seconds: float = EPOCH_SECONDS,
    offset_hz: float = OFFSET_HZ,
    lo_hz: float = LO_HZ,
    center_frequency_hz: float = CENTER_HZ,
    sample_rate_hz: float = SAMPLE_RATE_HZ,
    amplitude: float = 900.0,
    noise: float = 30.0,
    seed: int = 20260819,
) -> np.ndarray:
    """Synthesise what a receiver hears: one continuous carrier that retunes.

    The transmitter never mutes, so the signal is phase-continuous across hops
    and there is no on/off pattern to segment - exactly the situation that broke
    duration coding.
    """

    random = np.random.default_rng(seed)
    count = int(seconds * sample_rate_hz)
    times = np.arange(count) / sample_rate_hz
    ends = np.asarray([hop.end_seconds for hop in schedule.hops])
    points = np.asarray([hop.point for hop in schedule.hops])
    wrapped = (times + epoch_seconds) % schedule.period_seconds
    index = np.clip(np.searchsorted(ends, wrapped), 0, ends.size - 1)
    baseband = (
        schedule.intermediate_frequencies_hz(lo_hz)[points[index]]
        + offset_hz
        - center_frequency_hz
    )
    values = amplitude * np.exp(1j * 2 * np.pi * np.cumsum(baseband) / sample_rate_hz)
    return values + noise * (random.standard_normal(count) + 1j * random.standard_normal(count))


def decode(samples: np.ndarray, schedule, **overrides: object):
    arguments = {
        "lo_hz": LO_HZ,
        "sample_rate_hz": SAMPLE_RATE_HZ,
        "center_frequency_hz": CENTER_HZ,
        "frame_size": FRAME_SIZE,
        "search_half_width_hz": SEARCH_HALF_WIDTH_HZ,
    }
    arguments.update(overrides)
    return decode_capture(
        lambda: iter_blocks(samples, frame_size=int(arguments["frame_size"]), block_frames=512),
        schedule=schedule,
        **arguments,  # type: ignore[arg-type]
    )


def test_splitmix64_matches_the_published_vectors_for_seed_zero() -> None:
    generator = SplitMix64(0)

    assert tuple(generator.next_u64() for _ in range(3)) == SPLITMIX64_SEED_ZERO


def test_uniform_and_below_draw_from_the_same_stream_as_next_u64() -> None:
    assert SplitMix64(0).uniform() == (SPLITMIX64_SEED_ZERO[0] >> 11) * 2.0**-53
    assert SplitMix64(0).below(1_000) == SPLITMIX64_SEED_ZERO[0] % 1_000
    assert 0.0 <= SplitMix64(12345).uniform() < 1.0
    with pytest.raises(ValueError, match="bound must be positive"):
        SplitMix64(0).below(0)


@pytest.mark.parametrize("seed", sorted(REFERENCE_ORDERS))
def test_schedule_matches_the_transmitter_reference_for_several_seeds(seed: int) -> None:
    schedule = build_schedule(
        seed=seed,
        start_hz=RECOMMENDED_START_HZ,
        stop_hz=RECOMMENDED_STOP_HZ,
        points=20,
        hop_seconds=0.010,
    )

    assert tuple(hop.point for hop in schedule.hops) == REFERENCE_ORDERS[seed]
    assert sorted(hop.point for hop in schedule.hops) == list(range(20))
    assert schedule.period_seconds == pytest.approx(0.2)
    assert schedule.spacing_hz == pytest.approx(90_000)


def test_jittered_two_cycle_period_matches_the_transmitter_reference() -> None:
    schedule = build_schedule(
        seed=DEFAULT_SEED,
        start_hz=START_HZ,
        stop_hz=STOP_HZ,
        points=POINTS,
        hop_seconds=HOP_SECONDS,
        jitter=0.5,
        period_cycles=2,
    )

    assert tuple(hop.point for hop in schedule.hops) == REFERENCE_JITTER_ORDER
    dwells = tuple(hop.dwell_seconds for hop in schedule.hops[: len(REFERENCE_JITTER_DWELLS)])
    assert dwells == pytest.approx(REFERENCE_JITTER_DWELLS, rel=0, abs=1e-15)
    assert schedule.period_seconds == pytest.approx(
        sum(hop.dwell_seconds for hop in schedule.hops)
    )


@pytest.mark.skipif(
    importlib.util.find_spec("adf5355") is None,
    reason="the transmitter of record is not installed here",
)
def test_schedule_matches_the_installed_transmitter_exactly() -> None:
    from adf5355.hopper import make_schedule
    from adf5355.hopper import plan_frequencies as reference_plan

    for seed in (0, 1, DEFAULT_SEED, 0xDEADBEEF):
        for jitter, cycles in ((0.0, 1), (0.5, 2), (1.0, 3)):
            frequencies = reference_plan(START_HZ, STOP_HZ, POINTS)
            expected = make_schedule(seed, frequencies, HOP_SECONDS, cycles, jitter, cycles)
            schedule = build_schedule(
                seed=seed,
                start_hz=START_HZ,
                stop_hz=STOP_HZ,
                points=POINTS,
                hop_seconds=HOP_SECONDS,
                jitter=jitter,
                period_cycles=cycles,
            )
            assert tuple(schedule.frequencies_hz) == tuple(frequencies)
            assert [hop.point for hop in schedule.hops] == [hop.point for hop in expected]
            assert [hop.dwell_seconds for hop in schedule.hops] == [
                hop.dwell_s for hop in expected
            ]
            assert [hop.start_seconds for hop in schedule.hops] == [
                hop.start_s for hop in expected
            ]


def test_plan_frequencies_rounds_like_the_transmitter_and_rejects_bad_spans() -> None:
    assert plan_frequencies(RECOMMENDED_START_HZ, RECOMMENDED_STOP_HZ, 20)[:3] == (
        11_000_000_000,
        11_000_090_000,
        11_000_180_000,
    )
    with pytest.raises(ValueError, match="at least 2"):
        plan_frequencies(START_HZ, STOP_HZ, 1)
    with pytest.raises(ValueError, match="not be below"):
        plan_frequencies(STOP_HZ, START_HZ, 4)


def test_plan_frequencies_rounds_a_fractional_step_the_transmitter_way() -> None:
    """A whole-Hertz step hides how the plan rounds; the 40-point span does not.

    The recommended 20-point plan steps by exactly 90 kHz, so rounding is a no-op
    and any rounding rule at all reproduces it. Forty points over the same span
    step by 43846.153... Hz, where truncating instead of rounding to nearest
    shifts more than half the points by a Hertz - a silent one-Hertz disagreement
    between the two ends' idea of what was transmitted. These are the values the
    transmitter of record emits.
    """

    plan = plan_frequencies(RECOMMENDED_START_HZ, RECOMMENDED_STOP_HZ, 40)

    assert plan[:8] == FRACTIONAL_STEP_PLAN
    assert plan[-1] == RECOMMENDED_STOP_HZ
    truncated = tuple(
        int(RECOMMENDED_START_HZ + i * (RECOMMENDED_STOP_HZ - RECOMMENDED_START_HZ) / 39)
        for i in range(8)
    )
    assert plan[:8] != truncated


def test_build_schedule_rejects_parameters_the_transmitter_would_reject() -> None:
    with pytest.raises(ValueError, match="hop_seconds"):
        reference_schedule(hop_seconds=0)
    with pytest.raises(ValueError, match="jitter"):
        reference_schedule(jitter=1.5)
    with pytest.raises(ValueError, match="period_cycles"):
        reference_schedule(period_cycles=0)


def test_comb_offset_is_recovered_from_a_synthetic_comb() -> None:
    schedule = reference_schedule()
    bins_hz = bin_frequencies_hz(FRAME_SIZE, SAMPLE_RATE_HZ, CENTER_HZ)
    expected = schedule.intermediate_frequencies_hz(LO_HZ)
    spectrum = np.full(bins_hz.size, 1.0)
    for center in expected + OFFSET_HZ:
        spectrum[int(np.argmin(np.abs(bins_hz - center)))] = 5_000.0

    comb = estimate_comb_offset(
        spectrum,
        bins_hz=bins_hz,
        expected_if_hz=expected,
        search_half_width_hz=SEARCH_HALF_WIDTH_HZ,
    )

    bin_width_hz = float(bins_hz[1] - bins_hz[0])
    assert comb.offset_hz == pytest.approx(OFFSET_HZ, abs=bin_width_hz)
    assert comb.sharpness > CONFIDENT_COMB_SHARPNESS
    assert comb.confident is True
    assert comb.search_step_hz == pytest.approx(bin_width_hz / 8)


def test_comb_offset_reports_a_flat_search_instead_of_inventing_a_shift() -> None:
    schedule = reference_schedule()
    bins_hz = bin_frequencies_hz(FRAME_SIZE, SAMPLE_RATE_HZ, CENTER_HZ)
    random = np.random.default_rng(5)

    comb = estimate_comb_offset(
        random.exponential(size=bins_hz.size),
        bins_hz=bins_hz,
        expected_if_hz=schedule.intermediate_frequencies_hz(LO_HZ),
        search_half_width_hz=SEARCH_HALF_WIDTH_HZ,
    )

    assert comb.sharpness < CONFIDENT_COMB_SHARPNESS
    assert comb.confident is False


def test_comb_search_refuses_a_comb_wider_than_the_capture_band() -> None:
    bins_hz = bin_frequencies_hz(FRAME_SIZE, SAMPLE_RATE_HZ, CENTER_HZ)

    too_wide = np.linspace(CENTER_HZ - 150_000, CENTER_HZ + 150_000, POINTS)

    with pytest.raises(ValueError, match="outside the capture"):
        estimate_comb_offset(
            np.ones(bins_hz.size),
            bins_hz=bins_hz,
            expected_if_hz=too_wide,
            search_half_width_hz=SEARCH_HALF_WIDTH_HZ,
        )


def test_slots_stay_narrower_than_the_spacing_and_must_lie_in_band() -> None:
    schedule = reference_schedule()
    bins_hz = bin_frequencies_hz(FRAME_SIZE, SAMPLE_RATE_HZ, CENTER_HZ)
    half_width = slot_half_width_hz(schedule.spacing_hz)

    assert half_width == pytest.approx(6_000.0)
    assert slot_half_width_hz(1_000_000.0) == 30_000.0
    bounds = slot_bounds(
        bins_hz,
        schedule.intermediate_frequencies_hz(LO_HZ),
        offset_hz=OFFSET_HZ,
        half_width_hz=half_width,
    )
    assert len(bounds) == POINTS
    assert all(high > low for low, high in bounds)
    with pytest.raises(ValueError, match="outside the capture band"):
        slot_bounds(
            bins_hz,
            schedule.intermediate_frequencies_hz(LO_HZ),
            offset_hz=-90_000.0,
            half_width_hz=half_width,
        )


def test_epoch_alignment_recovers_the_injected_start_of_the_pattern() -> None:
    schedule = reference_schedule()
    samples = hop_samples(schedule)
    bins_hz = bin_frequencies_hz(FRAME_SIZE, SAMPLE_RATE_HZ, CENTER_HZ)
    slots = slot_bounds(
        bins_hz,
        schedule.intermediate_frequencies_hz(LO_HZ),
        offset_hz=OFFSET_HZ,
        half_width_hz=slot_half_width_hz(schedule.spacing_hz),
    )
    envelope = build_envelope(
        iter_blocks(samples, frame_size=FRAME_SIZE, block_frames=512),
        frame_size=FRAME_SIZE,
        bins_hz=bins_hz,
        slots=slots,
    )
    frame_seconds = FRAME_SIZE / SAMPLE_RATE_HZ

    alignment = align_epoch(envelope_db(envelope.power), schedule, frame_seconds=frame_seconds)

    assert alignment.shift_seconds == pytest.approx(EPOCH_SECONDS, abs=frame_seconds)
    assert alignment.sharpness_sigma > 20
    assert alignment.confident is True
    assigned = assigned_points(
        schedule,
        frame_count=envelope.frame_count,
        frame_seconds=frame_seconds,
        shift_seconds=alignment.shift_seconds,
    )
    assert set(assigned.tolist()) == set(range(POINTS))


def test_the_epoch_search_is_bounded_to_exactly_one_period() -> None:
    schedule = reference_schedule()
    frame_seconds = FRAME_SIZE / SAMPLE_RATE_HZ
    inside = decode(hop_samples(schedule, epoch_seconds=EPOCH_SECONDS), schedule)
    wrapped = decode(
        hop_samples(schedule, epoch_seconds=EPOCH_SECONDS + 3 * schedule.period_seconds),
        schedule,
    )

    assert schedule.period_seconds == pytest.approx(POINTS * HOP_SECONDS)
    assert inside.epoch.search_span_seconds == pytest.approx(schedule.period_seconds)
    assert inside.epoch.bounded_to_one_period is True
    assert inside.epoch.search_count == int(
        np.ceil(schedule.period_seconds / (frame_seconds / 2))
    )
    # The capture spans ten periods; the search still covers exactly one.
    assert inside.frame_count * frame_seconds >= 10 * schedule.period_seconds
    assert inside.epoch.search_count * inside.epoch.search_step_seconds <= (
        schedule.period_seconds + inside.epoch.search_step_seconds
    )
    assert 0 <= inside.epoch.shift_seconds < schedule.period_seconds
    assert wrapped.epoch.shift_seconds == pytest.approx(inside.epoch.shift_seconds)


def test_every_point_recovers_the_injected_frequency_offset() -> None:
    schedule = reference_schedule()

    result = decode(hop_samples(schedule), schedule)

    assert result.measured_point_count == POINTS
    assert result.measured_points == tuple(range(POINTS))
    assert result.comb.offset_hz == pytest.approx(OFFSET_HZ, abs=1_000.0)
    assert result.median_frequency_error_hz == pytest.approx(OFFSET_HZ, abs=100.0)
    assert result.frequency_error_stdev_hz is not None
    assert result.frequency_error_stdev_hz < 200.0
    for row in result.points:
        assert row.measured is True
        assert row.rejection is None
        assert row.frequency_error_hz == pytest.approx(OFFSET_HZ, abs=200.0)
        assert row.nominal_if_hz == pytest.approx(row.nominal_rf_hz - LO_HZ)
        assert row.strong_frame_count >= 10
    assert result.confident is True
    assert result.warnings == ()
    assert result.plan.seed == DEFAULT_SEED
    assert result.plan.jitter == DEFAULT_JITTER
    assert result.plan.period_cycles == DEFAULT_PERIOD_CYCLES


def test_a_receiver_dc_offset_does_not_capture_the_slot_that_straddles_baseband() -> None:
    """Every real receiver has a DC offset, and one slot always sits on top of it.

    A hardware DC offset is a permanent spike at baseband zero. In this plan
    point 4 lands 5 kHz below centre with a 6 kHz slot, so that spike is inside
    its slot on every single frame: without removing each frame's mean first the
    spike outranks the transmitted carrier whenever it is elsewhere, the comb
    search locks onto the spike instead of the comb, and the point stops being
    measurable. Nothing in a synthetic capture supplies that offset unless a test
    puts it there deliberately.
    """

    schedule = reference_schedule()
    baseband_hz = schedule.intermediate_frequencies_hz(LO_HZ) + OFFSET_HZ - CENTER_HZ
    straddling = int(np.argmin(np.abs(baseband_hz)))
    half_width_hz = slot_half_width_hz(schedule.spacing_hz)
    assert abs(baseband_hz[straddling]) < half_width_hz

    clean = decode(hop_samples(schedule), schedule)
    offset = decode(hop_samples(schedule) + 2_000.0 * (1 + 0.6j), schedule)

    assert offset.comb.offset_hz == pytest.approx(clean.comb.offset_hz)
    assert offset.comb.offset_hz == pytest.approx(OFFSET_HZ, abs=1_000.0)
    assert offset.measured_point_count == POINTS
    assert offset.points[straddling].measured is True
    assert offset.median_frequency_error_hz == pytest.approx(OFFSET_HZ, abs=100.0)
    assert offset.confident is True


def test_a_minority_of_stale_frames_cannot_move_a_point_off_its_frequency() -> None:
    """The retune lands inside the dwell it precedes, so early frames are stale.

    The first frames of a dwell can still hold the previous point, which is why
    the reported frequency is the median of the strong frames and not their mean.
    Here three frames in ten carry the neighbouring point, one whole spacing
    away: the median ignores them, while a mean would report the point 30% of a
    spacing off - an error six times the scatter this method is trying to measure.
    """

    schedule = reference_schedule()
    stale, total = 3, 10
    frame_count = POINTS * total
    assigned = np.repeat(np.arange(POINTS), total)
    nominal_if = schedule.intermediate_frequencies_hz(LO_HZ)
    peak_hz = np.empty((POINTS, frame_count), dtype=float)
    for point in range(POINTS):
        peak_hz[point] = nominal_if[point] + OFFSET_HZ
        window = np.flatnonzero(assigned == point)[:stale]
        peak_hz[point, window] += schedule.spacing_hz
    envelope = PointEnvelope(power=np.ones((POINTS, frame_count)), peak_hz=peak_hz)
    levels = np.full((POINTS, frame_count), 30.0)

    rows = measure_points(
        envelope, levels, schedule=schedule, lo_hz=LO_HZ, assigned=assigned
    )

    contaminated = OFFSET_HZ + schedule.spacing_hz * stale / total
    for row in rows:
        assert row.measured is True
        assert row.strong_frame_count == total
        assert row.frequency_error_hz == pytest.approx(OFFSET_HZ)
        assert row.frequency_error_hz != pytest.approx(contaminated, abs=1.0)


def test_noise_is_reported_as_low_confidence_rather_than_answered() -> None:
    schedule = reference_schedule()
    random = np.random.default_rng(4)
    count = int(CAPTURE_SECONDS * SAMPLE_RATE_HZ)
    noise = 60 * (random.standard_normal(count) + 1j * random.standard_normal(count))

    result = decode(noise, schedule)

    assert result.confident is False
    assert LOW_COMB_SHARPNESS in result.warnings
    assert FEW_POINTS in result.warnings
    assert result.measured_point_count == 0
    assert result.median_frequency_error_hz is None
    assert all(row.rejection is not None for row in result.points)


@pytest.mark.parametrize("wrong_seed", [DEFAULT_SEED + 1, DEFAULT_SEED + 2, 0xDEADBEEF])
def test_the_wrong_seed_decodes_to_low_confidence_not_a_wrong_answer(wrong_seed: int) -> None:
    """A listener holding the wrong seed must not be able to align at all.

    This is the failure that has to stay loud: the comb is seed-independent, so
    it still lands and the decode still *looks* like it is working. Only the
    alignment can tell, so the epoch itself has to be reported unconfident, not
    merely accompanied by a thin points count. A wrong seed scores a few sigma
    here, well under ``CONFIDENT_EPOCH_SIGMA``, which is the margin that floor
    exists to keep.
    """

    transmitted = reference_schedule(seed=DEFAULT_SEED)
    listener = reference_schedule(seed=wrong_seed)

    result = decode(hop_samples(transmitted), listener)

    assert result.comb.confident is True
    assert result.epoch.confident is False
    assert result.epoch.sharpness_sigma < CONFIDENT_EPOCH_SIGMA
    assert result.confident is False
    assert LOW_EPOCH_SHARPNESS in result.warnings
    assert result.measured_point_count < POINTS


def test_iter_blocks_yields_whole_frames_only() -> None:
    values = np.arange(1_000, dtype=np.complex128)

    blocks = list(iter_blocks(values, frame_size=128, block_frames=3))

    assert [block.shape for block in blocks] == [(3, 128), (3, 128), (1, 128)]
    with pytest.raises(ValueError, match="frame_size must be positive"):
        list(iter_blocks(values, frame_size=0))
