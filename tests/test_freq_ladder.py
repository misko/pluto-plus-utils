"""Hardware-free truth for the observed-ladder offset analyzer.

Every capture here is synthesised: a complex tone with a known injected receiver
clock error and LNB LO error, gated on and off by a known ladder schedule, plus
noise, written through this repository's CI16 capture writer.
"""

from __future__ import annotations

import json
from pathlib import Path

import numpy as np
import pytest

from pluto_plus.analysis import AnalysisService, FreqLadderAnalyzer
from pluto_plus.artifacts import CaptureWriter
from pluto_plus.freq_ladder import (
    FreqLadderBurst,
    FreqLadderSchedule,
    burst_rows_from_results,
    fit_freq_ladder,
    merge_burst_rows,
    usable_bursts,
)
from pluto_plus.hardware.base import SampleBlock
from pluto_plus.models import ArtifactSummary, RadioIdentity, RadioSettings, Transport

RATE_HZ = 400_000.0
FRAME_SIZE = 256
DC_NOTCH_HZ = 2_000.0
LO_HZ = 9.75e9
LNB_ERROR_HZ = 94_000.0
CLOCK_ERROR = 8.94e-6

# A real ladder spans hundreds of MHz: that lever arm is what separates the
# IF-proportional receiver clock error from the constant LNB LO error.
LADDER = FreqLadderSchedule(
    rung_start_hz=10.30e9, rung_stop_hz=10.70e9, rung_count=5, total_seconds=0.6
)
# A deliberately compressed ladder so that every rung is inside one capture
# bandwidth. Durations still identify the rungs, but 40 kHz of frequency lever
# arm cannot separate slope from intercept, so no fit value here is meaningful.
COMPRESSED = LADDER.model_copy(update={"rung_stop_hz": LADDER.rung_start_hz + 40_000})


def _artifact(root: Path, values: np.ndarray, *, center_frequency_hz: float) -> ArtifactSummary:
    settings = RadioSettings(
        center_frequency_hz=center_frequency_hz,
        sample_rate_hz=RATE_HZ,
        bandwidth_hz=RATE_HZ,
        channels=(0,),
    )
    writer = CaptureWriter(
        root,
        radio=RadioIdentity(
            radio_id="synthetic",
            serial="synthetic",
            uri="fake:synthetic",
            transport=Transport.FAKE,
        ),
        settings=settings,
        label="synthetic ladder",
    )
    writer.append(SampleBlock(utc_ns=1, samples=values[None, :]), settings, revision=0)
    return writer.finalize()


def _gated(
    events: list[tuple[float, float, float]],
    total_seconds: float,
    *,
    seed: int = 11,
    amplitude: float = 800.0,
    noise: float = 2.0,
    continuous_hz: float | None = None,
    continuous_amplitude: float = 0.0,
) -> np.ndarray:
    """Complex noise with tones keyed on for ``(start, duration, frequency)``."""

    count = int(round(total_seconds * RATE_HZ))
    random = np.random.default_rng(seed)
    values = random.normal(0, noise, count) + 1j * random.normal(0, noise, count)
    axis = np.arange(count)
    if continuous_hz is not None:
        values += continuous_amplitude * np.exp(2j * np.pi * continuous_hz * axis / RATE_HZ)
    for start_seconds, duration_seconds, frequency_hz in events:
        first = int(round(start_seconds * RATE_HZ))
        last = min(count, first + int(round(duration_seconds * RATE_HZ)))
        span = axis[first:last]
        values[first:last] += amplitude * np.exp(2j * np.pi * frequency_hz * span / RATE_HZ)
    return values


def _baseband_hz(
    schedule: FreqLadderSchedule,
    rung: int,
    center_frequency_hz: float,
    *,
    clock_error: float = CLOCK_ERROR,
    lnb_error_hz: float = LNB_ERROR_HZ,
) -> float:
    """Where a rung actually lands at baseband given both injected errors."""

    intermediate_hz = schedule.rung_frequency_hz(rung) - (LO_HZ + lnb_error_hz)
    return (intermediate_hz - center_frequency_hz * (1 + clock_error)) / (1 + clock_error)


def _parameters(schedule: FreqLadderSchedule, **overrides: float | int) -> dict[str, float | int]:
    parameters: dict[str, float | int] = {
        "rung_start_hz": schedule.rung_start_hz,
        "rung_stop_hz": schedule.rung_stop_hz,
        "rung_count": schedule.rung_count,
        "total_seconds": schedule.total_seconds,
        "lo_hz": LO_HZ,
        "frame_size": FRAME_SIZE,
        "dc_notch_hz": DC_NOTCH_HZ,
        "search_half_width_hz": RATE_HZ / 2,
    }
    parameters.update(overrides)
    return parameters


def _compressed_capture(
    root: Path, *, stretch: float = 1.0, seed: int = 5
) -> tuple[ArtifactSummary, float]:
    """One capture holding a whole pass of the compressed ladder."""

    unit = COMPRESSED.unit_seconds
    center = COMPRESSED.rung_frequency_hz(3) - LO_HZ + 3_000
    events: list[tuple[float, float, float]] = []
    cursor = unit / 2
    for rung in COMPRESSED.rungs:
        events.append(
            (
                cursor,
                stretch * rung * unit,
                _baseband_hz(COMPRESSED, rung, center, clock_error=0.0, lnb_error_hz=0.0),
            )
        )
        cursor += max(stretch, 1.0) * rung * unit + rung * unit
    return _artifact(root, _gated(events, cursor, seed=seed), center_frequency_hz=center), center


def _single_rung_capture(
    root: Path,
    rung: int,
    *,
    duration_seconds: float | None = None,
    lead_seconds: float | None = None,
    trail_seconds: float | None = None,
    schedule: FreqLadderSchedule = LADDER,
    **noise: float,
) -> ArtifactSummary:
    """A capture tuned to one rung's nominal IF, holding one burst."""

    unit = schedule.unit_seconds
    duration = rung * unit if duration_seconds is None else duration_seconds
    lead = unit if lead_seconds is None else lead_seconds
    trail = unit if trail_seconds is None else trail_seconds
    center = schedule.rung_frequency_hz(rung) - LO_HZ
    values = _gated(
        [(lead, duration, _baseband_hz(schedule, rung, center))],
        lead + duration + trail,
        **noise,
    )
    return _artifact(root, values, center_frequency_hz=center)


def _rows(
    schedule: FreqLadderSchedule, offsets_hz: dict[int, float], *, epoch: float = 1.0e9
) -> list[FreqLadderBurst]:
    """Synthetic identified bursts with an exact model plus per-rung offsets."""

    rows: list[FreqLadderBurst] = []
    for index, (rung, systematic_hz) in enumerate(sorted(offsets_hz.items())):
        nominal_if = schedule.rung_frequency_hz(rung) - LO_HZ
        error = -CLOCK_ERROR * nominal_if - LNB_ERROR_HZ + systematic_hz
        rows.append(
            FreqLadderBurst(
                artifact_id=f"artifact-{rung}",
                receiver=0,
                first_frame=1,
                last_frame=9,
                frame_count=9,
                complete=True,
                start_seconds=0.1,
                center_seconds=0.2,
                epoch_seconds=epoch + index,
                duration_seconds=rung * schedule.unit_seconds,
                duration_lower_seconds=rung * schedule.unit_seconds,
                duration_upper_seconds=rung * schedule.unit_seconds,
                rung_estimate=float(rung),
                rung_offset=0.0,
                rung=rung,
                identified=True,
                lo_hz=LO_HZ,
                nominal_rf_hz=schedule.rung_frequency_hz(rung),
                nominal_if_hz=nominal_if,
                measured_frequency_hz=nominal_if + error,
                frequency_error_hz=error,
                snr_db=70.0,
            )
        )
    return rows


def test_every_rung_is_identified_from_its_duration_alone(tmp_path: Path) -> None:
    artifact, _ = _compressed_capture(tmp_path)

    result = FreqLadderAnalyzer().run(artifact, _parameters(COMPRESSED))

    assert [row["rung"] for row in result["bursts"]] == [1, 2, 3, 4, 5]
    assert all(row["complete"] for row in result["bursts"])
    assert all(row["rejection"] is None for row in result["bursts"])
    assert result["identified_rungs"] == [1, 2, 3, 4, 5]
    for row in result["bursts"]:
        rung = row["rung"]
        assert row["rung_estimate"] == pytest.approx(rung, abs=0.1)
        assert row["nominal_rf_hz"] == pytest.approx(COMPRESSED.rung_frequency_hz(rung))
        assert row["nominal_if_hz"] == pytest.approx(COMPRESSED.rung_frequency_hz(rung) - LO_HZ)
        assert row["duration_lower_seconds"] <= row["duration_seconds"]
        assert row["duration_seconds"] <= row["duration_upper_seconds"]
        assert row["snr_db"] > 60
    assert result["identification"]["confident"] is True
    assert result["identification"]["confidence"] > 0.8
    assert result["fit_status"] == "fitted"


def test_burst_durations_come_from_sample_counts_not_the_wall_clock(tmp_path: Path) -> None:
    """Timing is derived from frame indices, so it cannot inflate under load."""

    artifact, _ = _compressed_capture(tmp_path)

    result = FreqLadderAnalyzer().run(artifact, _parameters(COMPRESSED))

    frame_seconds = result["frame_seconds"]
    assert frame_seconds == FRAME_SIZE / RATE_HZ
    assert result["frame_count"] == artifact.sample_count // FRAME_SIZE
    for row in result["bursts"]:
        published = row["rung"] * COMPRESSED.unit_seconds
        assert row["start_seconds"] == row["first_frame"] * frame_seconds
        assert row["center_seconds"] == pytest.approx(
            row["start_seconds"] + row["frame_count"] * frame_seconds / 2
        )
        # Accurate to the frame quantisation only. A live decoder that fell
        # 1.67x behind real time reported 1.32x to 1.49x of the true length.
        assert row["duration_seconds"] == pytest.approx(published, abs=2 * frame_seconds)
        assert abs(row["duration_seconds"] / published - 1) < 0.1


def test_schedule_maths_matches_the_published_ladder() -> None:
    assert LADDER.unit_seconds == pytest.approx(0.6 / (5 * 6))
    assert LADDER.rung_frequency_hz(1) == pytest.approx(10.30e9)
    assert LADDER.rung_frequency_hz(5) == pytest.approx(10.70e9)
    assert LADDER.rung_frequency_hz(3) == pytest.approx(10.50e9)
    assert LADDER.rung_estimate(3 * LADDER.unit_seconds) == pytest.approx(3.0)
    assert LADDER.identify(3.05 * LADDER.unit_seconds) == 3
    assert LADDER.identify(3.4 * LADDER.unit_seconds) is None
    with pytest.raises(ValueError, match="rung must be between"):
        LADDER.rung_frequency_hz(6)
    with pytest.raises(ValueError, match="rung_stop_hz"):
        FreqLadderSchedule(
            rung_start_hz=10e9, rung_stop_hz=10e9, rung_count=4, total_seconds=1.0
        )


def test_merged_captures_recover_the_injected_clock_and_lnb_errors(tmp_path: Path) -> None:
    documents = []
    for rung in LADDER.rungs:
        artifact = _single_rung_capture(tmp_path, rung, seed=20 + rung)
        result = FreqLadderAnalyzer().run(artifact, _parameters(LADDER))
        assert [row["rung"] for row in result["bursts"]] == [rung]
        assert result["fit"] is None
        assert "at least 3 distinct rungs" in result["fit_status"]
        documents.append({"result": result})

    rows = burst_rows_from_results(documents)
    fit = fit_freq_ladder(usable_bursts(rows), lo_hz=LO_HZ)

    assert fit.rungs == (1, 2, 3, 4, 5)
    assert fit.receiver_clock_error_ppm == pytest.approx(CLOCK_ERROR * 1e6, abs=0.3)
    assert fit.lnb_lo_error_hz == pytest.approx(LNB_ERROR_HZ, abs=300)
    assert fit.lnb_lo_error_ppm == pytest.approx(LNB_ERROR_HZ / LO_HZ * 1e6, abs=0.05)
    assert fit.uncertainty_method == "leave_one_rung_out"
    assert fit.drift_included is False
    assert fit.drift_hz_per_second is None
    assert fit.warnings == ("single_monotonic_pass_confounds_drift_with_slope",)


def test_bursts_touching_a_capture_edge_are_excluded(tmp_path: Path) -> None:
    unit = LADDER.unit_seconds
    center = LADDER.rung_frequency_hz(3) - LO_HZ
    tone = _baseband_hz(LADDER, 3, center)
    values = _gated(
        [(0.0, 2 * unit, tone), (3 * unit, 3 * unit, tone)],
        6 * unit,
    )
    artifact = _artifact(tmp_path, values, center_frequency_hz=center)

    result = FreqLadderAnalyzer().run(artifact, _parameters(LADDER))

    assert len(result["bursts"]) == 2
    assert [row["complete"] for row in result["bursts"]] == [False, False]
    assert {row["rejection"] for row in result["bursts"]} == {"clipped_by_capture_edge"}
    assert all(row["rung"] is None for row in result["bursts"])
    assert all(row["frequency_error_hz"] is None for row in result["bursts"])
    assert result["identified_rungs"] == []
    assert usable_bursts(merge_burst_rows(result["bursts"])) == ()


def test_a_duration_between_rungs_is_rejected(tmp_path: Path) -> None:
    artifact = _single_rung_capture(
        tmp_path, 3, duration_seconds=2.5 * LADDER.unit_seconds
    )

    result = FreqLadderAnalyzer().run(artifact, _parameters(LADDER))

    row = result["bursts"][0]
    assert row["complete"] is True
    assert row["rung"] is None
    assert row["rejection"] == "duration_is_not_a_rung_multiple"
    assert row["rung_estimate"] == pytest.approx(2.5, abs=0.1)
    assert row["rung_offset"] > 0.25
    assert result["identification"]["confident"] is False


def test_an_out_of_range_duration_is_rejected_not_clamped(tmp_path: Path) -> None:
    artifact = _single_rung_capture(
        tmp_path, 3, duration_seconds=11.13 * LADDER.unit_seconds
    )

    result = FreqLadderAnalyzer().run(artifact, _parameters(LADDER))

    row = result["bursts"][0]
    assert row["rung_estimate"] == pytest.approx(11.13, abs=0.15)
    assert row["rung"] is None
    assert row["rejection"] == "duration_outside_ladder"
    assert result["identified_rungs"] == []


def test_a_dip_inside_a_burst_stays_one_burst(tmp_path: Path) -> None:
    unit = LADDER.unit_seconds
    center = LADDER.rung_frequency_hz(4) - LO_HZ
    tone = _baseband_hz(LADDER, 4, center)
    dropout = 0.004
    first = 4 * unit / 2 - dropout / 2
    values = _gated(
        [
            (unit, first, tone),
            (unit + first + dropout, 4 * unit - first - dropout, tone),
        ],
        6 * unit,
    )
    artifact = _artifact(tmp_path, values, center_frequency_hz=center)

    result = FreqLadderAnalyzer().run(artifact, _parameters(LADDER))

    assert len(result["bursts"]) == 1
    assert result["bursts"][0]["rung"] == 4
    assert result["bursts"][0]["duration_seconds"] == pytest.approx(4 * unit, abs=unit / 8)

    fragmented = FreqLadderAnalyzer().run(
        artifact, _parameters(LADDER, hysteresis_db=0, merge_gap_fraction=0)
    )
    assert len(fragmented["bursts"]) == 2
    assert [row["rung"] for row in fragmented["bursts"]] == [2, 2]


def test_narrow_band_search_ignores_an_unrelated_in_band_carrier(tmp_path: Path) -> None:
    unit = LADDER.unit_seconds
    center = LADDER.rung_frequency_hz(2) - LO_HZ
    values = _gated(
        [(unit, 2 * unit, _baseband_hz(LADDER, 2, center))],
        4 * unit,
        continuous_hz=180_000.0,
        continuous_amplitude=2_000.0,
    )
    artifact = _artifact(tmp_path, values, center_frequency_hz=center)

    guarded = FreqLadderAnalyzer().run(
        artifact, _parameters(LADDER, search_half_width_hz=150_000)
    )

    assert [row["rung"] for row in guarded["bursts"]] == [2]
    assert guarded["bursts"][0]["complete"] is True
    assert guarded["searched_bin_count"] < FRAME_SIZE

    # A whole-band search locks onto the unrelated carrier and reports one
    # continuous "burst" that never ends: the failure this window prevents.
    unguarded = FreqLadderAnalyzer().run(
        artifact, _parameters(LADDER, search_half_width_hz=RATE_HZ / 2)
    )
    assert len(unguarded["bursts"]) == 1
    assert unguarded["bursts"][0]["complete"] is False
    assert unguarded["bursts"][0]["rejection"] == "clipped_by_capture_edge"


def test_corrupted_transmitter_timing_reports_low_confidence(tmp_path: Path) -> None:
    artifact, _ = _compressed_capture(tmp_path, stretch=1.4)

    result = FreqLadderAnalyzer().run(artifact, _parameters(COMPRESSED))

    identification = result["identification"]
    assert identification["complete_burst_count"] == 5
    assert identification["confident"] is False
    assert identification["confidence"] < 0.5
    assert identification["rejected_burst_count"] >= 3
    assert identification["median_rung_offset"] > 0.1
    assert "duration_outside_ladder" in identification["rejections"]


def test_the_reported_uncertainty_is_resampled_not_the_covariance() -> None:
    # One systematic per rung, shared by that rung's bursts, exactly like the
    # tuning-dependent error measured on the bench.
    systematic = {1: 120.0, 2: -80.0, 3: 40.0, 4: -150.0, 5: 90.0}
    rows: list[FreqLadderBurst] = []
    for repeat in range(4):
        for row in _rows(LADDER, systematic, epoch=1.0e9 + 10 * repeat):
            jitter = 0.5 * ((repeat % 2) - 0.5)
            rows.append(
                row.model_copy(
                    update={
                        "frequency_error_hz": row.frequency_error_hz + jitter,
                        "measured_frequency_hz": row.measured_frequency_hz + jitter,
                    }
                )
            )

    fit = fit_freq_ladder(rows, lo_hz=LO_HZ, include_drift=False)

    assert fit.burst_count == 20
    assert fit.fold_count == 5
    assert fit.uncertainty_method == "leave_one_rung_out"
    folds = [
        fit_freq_ladder(
            [row for row in rows if row.rung != held_out], lo_hz=LO_HZ, include_drift=False
        )
        for held_out in sorted(systematic)
    ]
    expected_ppm = _jackknife([fold.receiver_clock_error_ppm for fold in folds])
    expected_hz = _jackknife([fold.lnb_lo_error_hz for fold in folds])
    assert fit.receiver_clock_error_ppm_uncertainty == pytest.approx(expected_ppm, rel=1e-9)
    assert fit.lnb_lo_error_hz_uncertainty == pytest.approx(expected_hz, rel=1e-9)
    # The covariance interval is the optimistic one; it must not be the headline.
    assert (
        fit.receiver_clock_error_ppm_uncertainty
        > 2 * fit.receiver_clock_error_ppm_covariance_stderr
    )
    assert fit.lnb_lo_error_hz_uncertainty > 2 * fit.lnb_lo_error_hz_covariance_stderr
    assert "covariance standard error" in fit.uncertainty_claim


def _jackknife(values: list[float]) -> float:
    count = len(values)
    mean = sum(values) / count
    return float(np.sqrt((count - 1) / count * sum((value - mean) ** 2 for value in values)))


def test_multiple_passes_admit_the_drift_term(tmp_path: Path) -> None:
    drift_hz_per_second = -5.0
    rows: list[FreqLadderBurst] = []
    for pass_index in range(3):
        for row in _rows(LADDER, dict.fromkeys(LADDER.rungs, 0.0), epoch=1.0e9 + 60 * pass_index):
            elapsed = row.epoch_seconds - 1.0e9
            shift = drift_hz_per_second * elapsed
            rows.append(
                row.model_copy(
                    update={
                        "frequency_error_hz": row.frequency_error_hz + shift,
                        "measured_frequency_hz": row.measured_frequency_hz + shift,
                    }
                )
            )

    fit = fit_freq_ladder(rows, lo_hz=LO_HZ)

    assert fit.spans_multiple_passes is True
    assert fit.drift_included is True
    assert fit.drift_hz_per_second == pytest.approx(drift_hz_per_second, abs=1e-6)
    assert fit.receiver_clock_error_ppm == pytest.approx(CLOCK_ERROR * 1e6, abs=1e-6)
    assert fit.warnings == ()

    confounded = fit_freq_ladder(rows, lo_hz=LO_HZ, include_drift=False)
    assert confounded.drift_hz_per_second is None
    # Ignoring a real drift biases the slope, which is why the term exists.
    assert abs(confounded.receiver_clock_error_ppm - CLOCK_ERROR * 1e6) > 0.05


def test_the_fit_refuses_fewer_than_three_distinct_rungs() -> None:
    rows = _rows(LADDER, {1: 0.0, 4: 0.0})

    with pytest.raises(ValueError, match="at least 3 distinct rungs"):
        fit_freq_ladder(rows, lo_hz=LO_HZ)

    with pytest.raises(ValueError, match="different lo_hz"):
        fit_freq_ladder(_rows(LADDER, {1: 0.0, 3: 0.0, 5: 0.0}), lo_hz=LO_HZ + 1)

    with pytest.raises(ValueError, match="at least four identified bursts"):
        fit_freq_ladder(
            _rows(LADDER, {1: 0.0, 3: 0.0, 5: 0.0}), lo_hz=LO_HZ, include_drift=True
        )


def test_burst_rows_from_results_rejects_malformed_documents() -> None:
    with pytest.raises(ValueError, match="bursts list"):
        burst_rows_from_results([{"result": {}}])
    with pytest.raises(ValueError, match="result object"):
        burst_rows_from_results([{"result": 7}])
    with pytest.raises(ValueError, match="must be an object"):
        burst_rows_from_results([{"result": {"bursts": [3]}}])


@pytest.mark.parametrize(
    ("overrides", "message"),
    [
        ({"rung_start_hz": None}, "rung_start_hz"),
        ({"lo_hz": None}, "lo_hz"),
        ({"rung_stop_hz": LADDER.rung_start_hz}, "rung_stop_hz must be above"),
        ({"rung_count": 1}, "rung_count must be at least two"),
        ({"total_seconds": 0}, "total_seconds must be positive"),
        ({"lo_hz": LADDER.rung_start_hz}, "lo_hz must be below rung_start_hz"),
        ({"frame_size": 300}, "frame_size must be a power of two"),
        ({"frame_size": 1_048_576}, "capture is shorter than frame_size"),
        ({"threshold_db": 0}, "threshold_db must be positive"),
        ({"hysteresis_db": 40}, "hysteresis_db must be at least zero"),
        ({"dc_notch_hz": RATE_HZ}, "dc_notch_hz must be below half"),
        ({"search_half_width_hz": 0}, "search_half_width_hz must be positive"),
        ({"search_half_width_hz": RATE_HZ}, "search_half_width_hz must be positive"),
        ({"merge_gap_fraction": 0.9}, "merge_gap_fraction must be between"),
        ({"rung_tolerance": 0.6}, "rung_tolerance must be between"),
        ({"receiver": 1}, "receiver is outside the capture"),
    ],
)
def test_parameter_validation_is_explicit(
    tmp_path: Path, overrides: dict[str, float | int | None], message: str
) -> None:
    artifact = _single_rung_capture(tmp_path, 2)
    parameters = _parameters(LADDER)
    parameters.update(overrides)  # type: ignore[arg-type]

    with pytest.raises(ValueError, match=message):
        FreqLadderAnalyzer().run(artifact, parameters)


def test_a_capture_outside_every_rung_is_refused(tmp_path: Path) -> None:
    artifact = _single_rung_capture(tmp_path, 2)

    with pytest.raises(ValueError, match="no ladder rung"):
        FreqLadderAnalyzer().run(artifact, _parameters(LADDER, lo_hz=LO_HZ + 50e6))


def test_the_analysis_service_stores_a_json_safe_document(tmp_path: Path) -> None:
    artifact = _single_rung_capture(tmp_path / "captures", 2)
    service = AnalysisService(tmp_path / "analyses")

    document = service.analyze(artifact, "freq_ladder", _parameters(LADDER))

    assert "freq_ladder" in service.analyzer_names
    assert document.analyzer == "freq_ladder"
    assert document.analyzer_version == "1"
    stored = json.loads(Path(document.path).read_text())
    assert stored["result"]["bursts"][0]["rung"] == 2
    assert stored["result"]["identification"]["confident"] is True
    assert stored["result"]["fit"] is None
    assert stored["result"]["visible_rungs"] == [2]
