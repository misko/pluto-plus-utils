from __future__ import annotations

import math

import numpy as np
import pytest

from pluto_plus.analysis import DualReceiverAnalyzer, SignalQualityAnalyzer
from pluto_plus.artifacts import CaptureWriter
from pluto_plus.hardware.base import SampleBlock
from pluto_plus.models import RadioIdentity, RadioSettings, Transport


def _artifact(tmp_path, samples: np.ndarray, *, sample_rate_hz: float = 1_000_000):
    receiver_count = samples.shape[0]
    settings = RadioSettings(
        sample_rate_hz=sample_rate_hz,
        bandwidth_hz=sample_rate_hz,
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
        label="synthetic truth",
    )
    writer.append(SampleBlock(utc_ns=1, samples=samples), settings, revision=0)
    return writer.finalize()


def test_quality_recovers_known_dc_power_and_balanced_iq(tmp_path) -> None:
    count = 4096
    axis = np.arange(count)
    tone = 1000 * np.exp(2j * np.pi * 17 * axis / count)
    artifact = _artifact(tmp_path, (tone + 100 - 50j)[None, :])

    result = SignalQualityAnalyzer().run(
        artifact,
        {"dc_warning_fraction": 0.2, "chunk_samples": 257},
    )["receivers"][0]

    assert result["sample_count"] == count
    assert result["mean_i_counts"] == pytest.approx(100, abs=0.05)
    assert result["mean_q_counts"] == pytest.approx(-50, abs=0.05)
    assert result["ac_power_counts_squared"] == pytest.approx(1_000_000, rel=2e-4)
    assert result["rms_magnitude_counts"] == pytest.approx(
        math.sqrt(1_000_000 + 100**2 + 50**2), rel=2e-4
    )
    assert result["iq_power_imbalance_db"] == pytest.approx(0, abs=0.002)
    assert result["iq_correlation"] == pytest.approx(0, abs=1e-4)
    assert result["flags"] == []


def test_quality_counts_clipped_samples_and_components(tmp_path) -> None:
    samples = np.zeros((1, 100), dtype=np.complex64)
    samples[0, 2] = 2047 + 1j
    samples[0, 7] = -1 - 2047j
    samples[0, 11] = 2047 + 2047j
    artifact = _artifact(tmp_path, samples)

    result = SignalQualityAnalyzer().run(artifact, {})["receivers"][0]

    assert result["clipped_sample_count"] == 3
    assert result["clipped_component_count"] == 4
    assert result["clipping_fraction"] == pytest.approx(0.03)
    assert "clipping_detected" in result["flags"]
    assert result["zero_pair_fraction"] == pytest.approx(0.97)


@pytest.mark.parametrize(
    ("parameters", "message"),
    [
        ({"clip_threshold_abs": 0}, "clip_threshold_abs"),
        ({"chunk_samples": 0}, "chunk_samples"),
        ({"dc_warning_fraction": 1.1}, "dc_warning_fraction"),
        ({"iq_imbalance_warning_db": -1}, "iq_imbalance_warning_db"),
    ],
)
def test_quality_rejects_invalid_parameters(tmp_path, parameters, message) -> None:
    artifact = _artifact(tmp_path, np.ones((1, 32), dtype=np.complex64))
    with pytest.raises(ValueError, match=message):
        SignalQualityAnalyzer().run(artifact, parameters)


def test_dual_receiver_recovers_delay_complex_gain_and_phase(tmp_path) -> None:
    random = np.random.default_rng(20260815)
    count = 8192
    first = 4000 * (
        random.choice((-1, 1), count) + 1j * random.choice((-1, 1), count)
    )
    delay = 5
    gain = 0.7 * np.exp(0.6j)
    second = np.zeros(count, dtype=np.complex128)
    second[delay:] = gain * first[:-delay]
    artifact = _artifact(tmp_path, np.stack((first, second)))

    result = DualReceiverAnalyzer().run(
        artifact,
        {"maximum_delay_samples": 8, "maximum_samples": count},
    )

    assert result["delay_samples"] == delay
    assert result["delay_seconds"] == pytest.approx(delay / 1_000_000)
    assert result["coherence"] > 0.999
    assert result["conjugate_coherence"] < 0.05
    assert result["gain_ratio_b_over_a"] == pytest.approx(0.7, abs=2e-4)
    assert result["relative_phase_rad_b_minus_a"] == pytest.approx(0.6, abs=2e-4)
    assert result["differential_power_fraction"] < 1e-6
    assert result["flags"] == []


def test_dual_receiver_reports_constant_input_and_validates_pair(tmp_path) -> None:
    pair = _artifact(tmp_path, np.ones((2, 32), dtype=np.complex64) * (3 + 4j))
    result = DualReceiverAnalyzer().run(pair, {"maximum_delay_samples": 2})
    assert result["coherence"] == 0
    assert result["flags"] == ["constant_or_zero_input", "low_coherence"]

    single = _artifact(tmp_path / "single", np.ones((1, 32), dtype=np.complex64))
    with pytest.raises(ValueError, match="receiver_b"):
        DualReceiverAnalyzer().run(single, {})
    with pytest.raises(ValueError, match="different"):
        DualReceiverAnalyzer().run(pair, {"receiver_a": 0, "receiver_b": 0})
    with pytest.raises(ValueError, match="smaller"):
        DualReceiverAnalyzer().run(pair, {"maximum_delay_samples": 32})
