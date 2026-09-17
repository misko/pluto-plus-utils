"""Signal oracle for the physical TX2 -> attenuator -> RX0/RX1 fixture."""

from __future__ import annotations

import dataclasses
import math

import numpy as np


class Tx2LoopbackError(RuntimeError):
    """The captured signal does not prove both legs of the TX2 fixture."""


@dataclasses.dataclass(frozen=True, slots=True)
class Tx2LoopbackLimits:
    frequency_tolerance_hz: float = 2_000.0
    minimum_snr_db: float = 15.0
    minimum_tone_dbfs: float = -70.0
    maximum_tone_dbfs: float = -3.0
    maximum_clipping_fraction: float = 0.0
    minimum_cross_channel_coherence: float = 0.95
    maximum_rx_level_delta_db: float = 8.0
    maximum_segment_drift_db: float = 3.0


@dataclasses.dataclass(frozen=True, slots=True)
class Tx2ReceiverMetrics:
    channel: str
    tone_dbfs: float
    snr_db: float
    clipping_fraction: float
    segment_tone_dbfs: tuple[float, float, float]
    segment_drift_db: float


@dataclasses.dataclass(frozen=True, slots=True)
class Tx2LoopbackMetrics:
    sample_rate_hz: int
    expected_tone_hz: float
    measured_tone_hz: float
    frequency_error_hz: float
    receivers: tuple[Tx2ReceiverMetrics, Tx2ReceiverMetrics]
    rx_level_delta_db: float
    cross_channel_coherence: float


DEFAULT_LIMITS = Tx2LoopbackLimits()


def _tone_amplitude(signal: np.ndarray, frequency_hz: float, sample_rate_hz: int) -> np.ndarray:
    sample_index = np.arange(signal.shape[1], dtype=np.float64)
    reference = np.exp(-2j * np.pi * frequency_hz * sample_index / sample_rate_hz)
    return np.asarray(np.mean(signal * reference, axis=1))


def analyze_tx2_splitter(
    signal: np.ndarray,
    *,
    sample_rate_hz: int,
    expected_tone_hz: float,
    adc_full_scale: float = 2048.0,
    limits: Tx2LoopbackLimits = DEFAULT_LIMITS,
) -> Tx2LoopbackMetrics:
    """Prove one stable coherent tone on both tee outputs, or fail closed."""

    samples = np.asarray(signal)
    if (
        samples.ndim != 2
        or samples.shape[0] != 2
        or samples.shape[1] < 12_288
        or not np.iscomplexobj(samples)
    ):
        raise Tx2LoopbackError("TX2 splitter analysis requires 2x12288 or more complex samples")
    if sample_rate_hz <= 0 or not 0 < expected_tone_hz < sample_rate_hz / 2:
        raise Tx2LoopbackError("sample rate/tone geometry is invalid")
    if not math.isfinite(adc_full_scale) or adc_full_scale <= 0:
        raise Tx2LoopbackError("ADC full scale must be finite and positive")
    if not np.all(np.isfinite(samples)):
        raise Tx2LoopbackError("capture contains non-finite samples")

    count = samples.shape[1]
    window = np.hanning(count)
    spectra = np.fft.fft(samples * window, axis=1)
    frequencies = np.fft.fftfreq(count, 1 / sample_rate_hz)
    search = np.flatnonzero(np.abs(frequencies - expected_tone_hz) <= 25_000)
    if not search.size:
        raise Tx2LoopbackError("no FFT bins fall inside the expected tone search window")
    coarse = int(search[np.argmax(np.sum(np.abs(spectra[:, search]) ** 2, axis=0))])
    bin_width = sample_rate_hz / count
    trials = np.linspace(frequencies[coarse] - bin_width, frequencies[coarse] + bin_width, 81)
    trial_amplitudes = tuple(
        _tone_amplitude(samples, frequency, sample_rate_hz) for frequency in trials
    )
    selected = max(
        range(len(trials)),
        key=lambda index: float(np.sum(np.abs(trial_amplitudes[index]) ** 2)),
    )
    measured = float(trials[selected])
    tones = trial_amplitudes[selected]
    sample_index = np.arange(count, dtype=np.float64)
    carrier = np.exp(2j * np.pi * measured * sample_index / sample_rate_hz)
    residual = samples - tones[:, None] * carrier[None, :]
    tone_power = np.abs(tones) ** 2
    residual_power = np.mean(np.abs(residual) ** 2, axis=1)
    snr_db = 10 * np.log10(np.maximum(tone_power, 1e-20) / np.maximum(residual_power, 1e-20))
    tone_dbfs = 20 * np.log10(np.maximum(np.abs(tones), 1e-20) / adc_full_scale)
    clipping = np.mean(
        (np.abs(samples.real) >= adc_full_scale - 1)
        | (np.abs(samples.imag) >= adc_full_scale - 1),
        axis=1,
    )

    segment_levels: list[tuple[float, float, float]] = []
    for channel in range(2):
        parts = np.array_split(samples[channel], 3)
        levels = []
        for part in parts:
            local = part[None, :]
            amplitude = _tone_amplitude(local, measured, sample_rate_hz)[0]
            levels.append(float(20 * np.log10(max(abs(amplitude), 1e-20) / adc_full_scale)))
        segment_levels.append((levels[0], levels[1], levels[2]))

    denominator = math.sqrt(
        float(np.vdot(samples[0], samples[0]).real * np.vdot(samples[1], samples[1]).real)
    )
    coherence = (
        float(abs(np.vdot(samples[0], samples[1])) / denominator) if denominator else 0.0
    )
    receiver_metrics = tuple(
        Tx2ReceiverMetrics(
            channel=f"RX{channel}",
            tone_dbfs=float(tone_dbfs[channel]),
            snr_db=float(snr_db[channel]),
            clipping_fraction=float(clipping[channel]),
            segment_tone_dbfs=segment_levels[channel],
            segment_drift_db=max(segment_levels[channel]) - min(segment_levels[channel]),
        )
        for channel in range(2)
    )
    assert len(receiver_metrics) == 2
    result = Tx2LoopbackMetrics(
        sample_rate_hz=sample_rate_hz,
        expected_tone_hz=expected_tone_hz,
        measured_tone_hz=measured,
        frequency_error_hz=measured - expected_tone_hz,
        receivers=(receiver_metrics[0], receiver_metrics[1]),
        rx_level_delta_db=abs(float(tone_dbfs[0] - tone_dbfs[1])),
        cross_channel_coherence=coherence,
    )

    failures: list[str] = []
    if abs(result.frequency_error_hz) > limits.frequency_tolerance_hz:
        failures.append("tone frequency")
    if any(receiver.snr_db < limits.minimum_snr_db for receiver in result.receivers):
        failures.append("receiver SNR")
    if any(
        not limits.minimum_tone_dbfs <= receiver.tone_dbfs <= limits.maximum_tone_dbfs
        for receiver in result.receivers
    ):
        failures.append("receiver tone level")
    if any(
        receiver.clipping_fraction > limits.maximum_clipping_fraction
        for receiver in result.receivers
    ):
        failures.append("clipping")
    if result.cross_channel_coherence < limits.minimum_cross_channel_coherence:
        failures.append("cross-channel coherence")
    if result.rx_level_delta_db > limits.maximum_rx_level_delta_db:
        failures.append("splitter leg level delta")
    if any(
        receiver.segment_drift_db > limits.maximum_segment_drift_db
        for receiver in result.receivers
    ):
        failures.append("early/middle/late stability")
    if failures:
        raise Tx2LoopbackError(f"TX2 splitter gate failed ({', '.join(failures)}): {result!r}")
    return result
