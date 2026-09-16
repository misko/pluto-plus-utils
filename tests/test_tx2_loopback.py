"""Pure signal-oracle tests for the physical TX2 splitter fixture."""

from __future__ import annotations

import numpy as np
import pytest

from pluto_plus.tx2_loopback import Tx2LoopbackError, analyze_tx2_splitter

RATE = 3_000_000
TONE = 100_000
COUNT = 24_576


def _capture(
    *,
    frequency_hz: float = TONE,
    amplitudes: tuple[float, float] = (300.0, 250.0),
    noise: float = 1.0,
    seed: int = 7,
) -> np.ndarray:
    rng = np.random.default_rng(seed)
    index = np.arange(COUNT)
    carrier = np.exp(2j * np.pi * frequency_hz * index / RATE)
    samples = np.vstack(
        (amplitudes[0] * carrier, amplitudes[1] * np.exp(0.37j) * carrier)
    )
    samples += noise * (
        rng.normal(size=(2, COUNT)) + 1j * rng.normal(size=(2, COUNT))
    )
    return samples


def test_tx2_tee_tone_proves_both_rx_legs() -> None:
    result = analyze_tx2_splitter(_capture(), sample_rate_hz=RATE, expected_tone_hz=TONE)

    assert abs(result.frequency_error_hz) < 100
    assert tuple(receiver.channel for receiver in result.receivers) == ("RX0", "RX1")
    assert all(receiver.snr_db > 40 for receiver in result.receivers)
    assert result.rx_level_delta_db < 2
    assert result.cross_channel_coherence > 0.99


@pytest.mark.parametrize("missing_leg", [0, 1])
def test_tx2_tee_rejects_either_missing_rx_leg(missing_leg: int) -> None:
    amplitudes = [300.0, 250.0]
    amplitudes[missing_leg] = 0.0
    with pytest.raises(Tx2LoopbackError, match="receiver SNR|receiver tone level"):
        analyze_tx2_splitter(
            _capture(amplitudes=(amplitudes[0], amplitudes[1])),
            sample_rate_hz=RATE,
            expected_tone_hz=TONE,
        )


def test_tx2_tee_rejects_wrong_frequency_or_negative_frequency_alias() -> None:
    for planted in (TONE + 12_000, -TONE):
        with pytest.raises(Tx2LoopbackError):
            analyze_tx2_splitter(
                _capture(frequency_hz=planted),
                sample_rate_hz=RATE,
                expected_tone_hz=TONE,
            )


def test_tx2_tee_rejects_excessive_leg_imbalance() -> None:
    with pytest.raises(Tx2LoopbackError, match="splitter leg level delta"):
        analyze_tx2_splitter(
            _capture(amplitudes=(300.0, 70.0)),
            sample_rate_hz=RATE,
            expected_tone_hz=TONE,
        )


def test_tx2_tee_rejects_unsettled_or_fading_capture() -> None:
    samples = _capture()
    samples[1, : COUNT // 3] *= 0.2
    with pytest.raises(Tx2LoopbackError, match="stability"):
        analyze_tx2_splitter(samples, sample_rate_hz=RATE, expected_tone_hz=TONE)


def test_tx2_tee_rejects_clipping() -> None:
    samples = _capture(amplitudes=(2_100.0, 1_900.0), noise=0.0)
    with pytest.raises(Tx2LoopbackError, match="tone level|clipping"):
        analyze_tx2_splitter(samples, sample_rate_hz=RATE, expected_tone_hz=TONE)


def test_tx2_tee_rejects_non_complex_or_single_receiver_geometry() -> None:
    for samples in (np.zeros((2, COUNT)), np.zeros((1, COUNT), dtype=np.complex64)):
        with pytest.raises(Tx2LoopbackError, match="2x12288"):
            analyze_tx2_splitter(samples, sample_rate_hz=RATE, expected_tone_hz=TONE)
