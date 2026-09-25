from __future__ import annotations

import hashlib

import numpy as np
import pytest

from pluto_plus.starlink_pilot_loopback import (
    StarlinkPilotLoopbackError,
    analyze_starlink_pilot_parity,
    cyclic_tx_waveform,
    measure_starlink_pilot_parity,
    qin_lower_edge_pilot_frame,
    receiver_has_starlink_pilot_glrt,
    starlink_pilot_parity_failures,
)

SAMPLE_RATE_HZ = 10_000_000
RELEASE_RATES_HZ = (2_500_000, 5_000_000, 7_500_000, 10_000_000)


def _capture(
    *,
    sample_rate_hz: int = SAMPLE_RATE_HZ,
    rx1_scale: float = 0.92,
    symbol_roll: int = 0,
    seed: int = 17,
) -> np.ndarray:
    frame = qin_lower_edge_pilot_frame(sample_rate_hz, symbol_roll=symbol_roll)
    count = 5 * len(frame)
    index = np.arange(count)
    shifted = frame[(index + 1_937) % len(frame)]
    carrier = np.exp(2j * np.pi * 55.0 * index / sample_rate_hz)
    rng = np.random.default_rng(seed)
    rx0 = 350 * shifted * carrier + 8 * (
        rng.normal(size=count) + 1j * rng.normal(size=count)
    )
    rx1 = 350 * rx1_scale * shifted * carrier * np.exp(0.37j) + 8 * (
        rng.normal(size=count) + 1j * rng.normal(size=count)
    )
    return np.asarray((rx0, rx1), dtype=np.complex64)


def test_qin_template_is_stable_and_tx_waveform_is_bounded() -> None:
    frame = qin_lower_edge_pilot_frame(SAMPLE_RATE_HZ)
    assert len(frame) == 13_333
    assert hashlib.sha256(np.asarray(frame, dtype="<c8").tobytes()).hexdigest() == (
        "1c82b1fa79b422148629a4a28bf2f020c2fe4520eecf9c7e7d77e594e8a850ed"
    )
    waveform = cyclic_tx_waveform(SAMPLE_RATE_HZ)
    assert waveform.dtype == np.complex64
    assert len(waveform) == 3 * len(frame)
    assert np.max(np.abs(waveform)) == pytest.approx(0.55 * 2**14, rel=1e-6)


@pytest.mark.parametrize("sample_rate_hz", RELEASE_RATES_HZ)
def test_full_round_trip_recovers_qin_pilot_on_both_receivers(sample_rate_hz: int) -> None:
    result = analyze_starlink_pilot_parity(
        _capture(sample_rate_hz=sample_rate_hz), sample_rate_hz=sample_rate_hz
    )
    assert tuple(item.channel for item in result.receivers) == ("RX0", "RX1")
    assert all(item.glrt_score > 0.99 for item in result.receivers)
    assert all(item.glrt_margin > 0.9 for item in result.receivers)
    assert all(item.snr_db > 25 for item in result.receivers)
    assert result.rx_level_delta_db < 1
    assert result.timing_delta_samples == 0
    assert result.cfo_delta_hz < 1


def test_noise_only_capture_is_not_accepted_as_the_qin_pilot() -> None:
    rng = np.random.default_rng(51)
    noise = rng.normal(size=(2, 5 * 13_333)) + 1j * rng.normal(size=(2, 5 * 13_333))
    with pytest.raises(StarlinkPilotLoopbackError, match="GLRT"):
        analyze_starlink_pilot_parity(
            np.asarray(noise * 100, dtype=np.complex64), sample_rate_hz=SAMPLE_RATE_HZ
        )
    metrics = measure_starlink_pilot_parity(
        np.asarray(noise * 100, dtype=np.complex64), sample_rate_hz=SAMPLE_RATE_HZ
    )
    assert not any(receiver_has_starlink_pilot_glrt(item) for item in metrics.receivers)
    assert "GLRT detection score" in starlink_pilot_parity_failures(metrics)


def test_weaker_rx1_fails_receiver_parity_gate() -> None:
    with pytest.raises(StarlinkPilotLoopbackError, match="RX pilot level delta"):
        analyze_starlink_pilot_parity(_capture(rx1_scale=0.45), sample_rate_hz=SAMPLE_RATE_HZ)


@pytest.mark.parametrize(
    "bad",
    (
        np.zeros((1, 50_000), dtype=np.complex64),
        np.zeros((2, 1_000), dtype=np.complex64),
        np.zeros((2, 50_000), dtype=np.float32),
    ),
)
def test_capture_geometry_fails_closed(bad: np.ndarray) -> None:
    with pytest.raises(StarlinkPilotLoopbackError, match="requires two RX rows"):
        analyze_starlink_pilot_parity(bad, sample_rate_hz=SAMPLE_RATE_HZ)
