"""The seeded_hop analyzer over real on-disk artifacts, with no radio present."""

from __future__ import annotations

import numpy as np
import pytest
from test_seeded_hop import (
    CAPTURE_SECONDS,
    CENTER_HZ,
    EPOCH_SECONDS,
    FRAME_SIZE,
    HOP_SECONDS,
    LO_HZ,
    OFFSET_HZ,
    POINTS,
    SAMPLE_RATE_HZ,
    SEARCH_HALF_WIDTH_HZ,
    START_HZ,
    STOP_HZ,
    hop_samples,
    reference_schedule,
)

from pluto_plus.analysis import AnalysisService, SeededHopAnalyzer
from pluto_plus.artifacts import CaptureWriter
from pluto_plus.hardware.base import SampleBlock
from pluto_plus.models import RadioIdentity, RadioSettings, Transport
from pluto_plus.seeded_hop import DEFAULT_SEED, FEW_POINTS, LOW_COMB_SHARPNESS

PARAMETERS = {
    "seed": DEFAULT_SEED,
    "rung_start_hz": float(START_HZ),
    "rung_stop_hz": float(STOP_HZ),
    "points": POINTS,
    "hop_seconds": HOP_SECONDS,
    "lo_hz": LO_HZ,
    "frame_size": FRAME_SIZE,
    "search_half_width_hz": SEARCH_HALF_WIDTH_HZ,
}


def _artifact(tmp_path, samples: np.ndarray, *, center_frequency_hz: float = CENTER_HZ):
    """Write the capture in the artifact's own CI16 format, as plutod would."""

    receiver_count = samples.shape[0]
    settings = RadioSettings(
        sample_rate_hz=SAMPLE_RATE_HZ,
        bandwidth_hz=SAMPLE_RATE_HZ,
        center_frequency_hz=center_frequency_hz,
        channels=tuple(range(receiver_count)),
    )
    writer = CaptureWriter(
        tmp_path,
        radio=RadioIdentity(
            radio_id="synthetic",
            serial="synthetic",
            uri="fake:synthetic",
            transport=Transport.FAKE,
        ),
        settings=settings,
        label="synthetic seeded hop",
    )
    writer.append(SampleBlock(utc_ns=1, samples=samples), settings, revision=0)
    return writer.finalize()


def _hop_artifact(tmp_path, **overrides):
    schedule = reference_schedule()
    samples = hop_samples(schedule, **overrides)
    return _artifact(tmp_path, samples[None, :])


def test_seeded_hop_recovers_every_point_from_a_written_capture(tmp_path) -> None:
    artifact = _hop_artifact(tmp_path)

    result = SeededHopAnalyzer().run(artifact, PARAMETERS)

    assert result["receiver"] == 0
    assert result["capture_seconds"] == pytest.approx(CAPTURE_SECONDS)
    assert result["confident"] is True
    assert result["warnings"] == []
    assert result["measured_point_count"] == POINTS
    assert result["measured_points"] == list(range(POINTS))
    assert result["comb"]["offset_hz"] == pytest.approx(OFFSET_HZ, abs=1_000.0)
    assert result["comb"]["confident"] is True
    assert result["epoch"]["shift_seconds"] == pytest.approx(
        EPOCH_SECONDS, abs=FRAME_SIZE / SAMPLE_RATE_HZ
    )
    assert result["epoch"]["search_span_seconds"] == pytest.approx(POINTS * HOP_SECONDS)
    assert result["median_frequency_error_hz"] == pytest.approx(OFFSET_HZ, abs=100.0)
    for row in result["points"]:
        assert row["frequency_error_hz"] == pytest.approx(OFFSET_HZ, abs=200.0)
    assert result["plan"]["seed"] == DEFAULT_SEED
    assert result["plan"]["frequencies_hz"][0] == START_HZ
    assert result["plan"]["period_seconds"] == pytest.approx(POINTS * HOP_SECONDS)


def test_a_second_receiver_is_analysed_only_when_asked(tmp_path) -> None:
    schedule = reference_schedule()
    quiet = np.zeros(int(CAPTURE_SECONDS * SAMPLE_RATE_HZ), dtype=np.complex128)
    paired = np.stack((quiet, hop_samples(schedule)))
    artifact = _artifact(tmp_path, paired)

    default = SeededHopAnalyzer().run(artifact, PARAMETERS)
    selected = SeededHopAnalyzer().run(artifact, {**PARAMETERS, "receiver": 1})

    assert default["receiver"] == 0
    assert default["confident"] is False
    assert selected["receiver"] == 1
    assert selected["confident"] is True
    assert selected["measured_point_count"] == POINTS


def test_noise_is_reported_as_low_confidence_not_as_a_measurement(tmp_path) -> None:
    random = np.random.default_rng(9)
    count = int(CAPTURE_SECONDS * SAMPLE_RATE_HZ)
    noise = 60 * (random.standard_normal(count) + 1j * random.standard_normal(count))
    artifact = _artifact(tmp_path, noise[None, :])

    result = SeededHopAnalyzer().run(artifact, PARAMETERS)

    assert result["confident"] is False
    assert LOW_COMB_SHARPNESS in result["warnings"]
    assert FEW_POINTS in result["warnings"]
    assert result["measured_point_count"] == 0
    assert result["median_frequency_error_hz"] is None
    assert all(row["measured"] is False for row in result["points"])
    assert all(row["rejection"] for row in result["points"])


def test_the_analyzer_is_registered_and_stores_a_versioned_document(tmp_path) -> None:
    artifact = _hop_artifact(tmp_path / "captures")
    service = AnalysisService(tmp_path / "analyses")

    assert "seeded_hop" in service.analyzer_names
    document = service.analyze(artifact, "seeded_hop", PARAMETERS)

    assert document.analyzer == "seeded_hop"
    assert document.analyzer_version == "1"
    assert document.result["measured_point_count"] == POINTS
    assert document.result["identity_claim"].startswith("point identity comes from the seeded")


@pytest.mark.parametrize(
    ("parameters", "message"),
    [
        ({"seed": None}, "seeded_hop requires seed"),
        ({"lo_hz": None, "points": None}, "seeded_hop requires points, lo_hz"),
        ({"seed": 2**64}, "unsigned 64-bit"),
        ({"rung_stop_hz": float(START_HZ)}, "rung_stop_hz must be above"),
        ({"points": 1}, "points must be at least two"),
        ({"hop_seconds": 0}, "hop_seconds must be positive"),
        ({"jitter": 2.0}, "jitter must be between"),
        ({"period_cycles": 0}, "period_cycles must be at least one"),
        ({"lo_hz": float(STOP_HZ)}, "lo_hz must be below"),
        ({"frame_size": 300}, "power of two"),
        ({"threshold_db": 0}, "threshold_db must be positive"),
        ({"search_half_width_hz": SAMPLE_RATE_HZ}, "at most half the rate"),
        ({"receiver": 3}, "receiver is outside"),
        ({"frame_size": 1024}, "at most half a dwell"),
    ],
)
def test_invalid_parameters_are_rejected_with_their_own_reason(
    tmp_path, parameters, message
) -> None:
    artifact = _hop_artifact(tmp_path)

    with pytest.raises(ValueError, match=message):
        SeededHopAnalyzer().run(artifact, {**PARAMETERS, **parameters})


def test_a_capture_shorter_than_one_period_is_refused(tmp_path) -> None:
    artifact = _hop_artifact(tmp_path, seconds=0.02)

    with pytest.raises(ValueError, match="cannot exclude epoch aliases"):
        SeededHopAnalyzer().run(artifact, PARAMETERS)


def test_a_span_wider_than_the_capture_band_is_refused(tmp_path) -> None:
    artifact = _hop_artifact(tmp_path)

    with pytest.raises(ValueError, match="does not fit this capture band"):
        SeededHopAnalyzer().run(
            artifact, {**PARAMETERS, "rung_stop_hz": float(START_HZ) + 400_000}
        )
