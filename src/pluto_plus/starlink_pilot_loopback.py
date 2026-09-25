# ruff: noqa: E501
"""Starlink edge-pilot synthesis and dual-receiver GLRT parity oracle."""

from __future__ import annotations

import dataclasses
import math
from functools import lru_cache

import numpy as np

FRAME_RATE_HZ = 750.0
OFDM_SYMBOL_DURATION_S = 4.4e-6
CYCLIC_PREFIX_DURATION_S = 2 / 15 * 1e-6
SUBCARRIER_SPACING_HZ = 234_375.0
CONTROL_SYMBOL_ROLL = 17

# Qin et al., arXiv:2602.02627v1, Appendix A. Each value contains the 300
# published base-4 states for one lower-edge pilot subcarrier. The test sends
# only this eight-subcarrier pilot, centered at the configured RF LO.
QIN_LOWER_EDGE_PILOT_HEX = {
    528: "CCBF3A16929836160CEC6EB7417AE6C37DC1E828CEFB60CE0E6C3B546A76B0AE1E7BC0E9577528B0F78F82A4104EA2C316B945D385200C7E5A1C5B48F5F9F9AF5C4BA920ACA3A599DB9974",
    529: "9CF72F5F5B95CE7342C925CF1AAF457F182C32810E2F7486705D5FA2D9C8923B0173FB206B46045C6F162BB9FFD051DB5E5900EFD2DE24D4BB3FE87DD776F00B5613A7D22B2821E139A599",
    530: "296319D723210189953BB730DC6046E4EC5FB48F9718D5B600A01578CAC3159B58EE8A306663921FBE78EE7C1E8E049B4230A14EB4954933AB64F67B396DD6DB12BCBB3CCA60EA79E0614B",
    531: "1017FBBD3D03981EE9F4424D473B8A73E136C777956EAEBD4CA51E9B70D9F5D10657F268595A5C3687D2DD06C98630F817CABEF3EE660822350A70F10A29A8740212A9CF7E7D814D60A69C",
    532: "712EA482B28E96676E65D09994965587314F2B562D0E750FE566E89205A8D4DFED2C4FAFFC5ED1EA6FB63EC13513444006B78ADFB4BDB6CB05470601C9F8F4901423069C9FBD68D292C16F",
    533: "584E9F48ACA08784E696644C78ED9684FC484F32AA1B4DA8E95457358DF89FE8B9D84D47F30D3CA2F2DDF0E76E57F14A44675326EDCF15052CB62B7DF0EBE623057605CF2406E25BD56B3B",
    534: "4AF2ECF32983A9E781852F6E90DC6CCE901863F527E038DA22C0CE02E44FA0563718D93E7454293962B43594CC2EE427FAE6F15C1238D9C85ABC4E303F3AEC3404A52310CAC0378665E19A",
    535: "084AA73DF9F60535829A716EC94D95AA6901B41E81AEF28B03F08CDE7D45425B1164009D56459C4286E269F4B8EBDBA8BF6FC79847B08A69F79AF6E6A7AF05DA504455BA72727DD7BE7744",
}


class StarlinkPilotLoopbackError(RuntimeError):
    """The capture does not prove equivalent Starlink-pilot reception."""


@dataclasses.dataclass(frozen=True, slots=True)
class StarlinkPilotLimits:
    minimum_glrt_score: float = 0.35
    minimum_glrt_margin: float = 0.15
    # The eight-subcarrier waveform is intentionally sparse and is distorted
    # by the fixture/filter response. GLRT exact/control separation is the
    # primary detection gate; nonnegative fitted SNR rejects noise-only input.
    minimum_snr_db: float = 0.0
    minimum_pilot_dbfs: float = -70.0
    maximum_pilot_dbfs: float = -3.0
    maximum_rx_level_delta_db: float = 3.0
    maximum_snr_delta_db: float = 4.0
    maximum_glrt_delta: float = 0.20
    maximum_timing_delta_samples: int = 4
    maximum_cfo_delta_hz: float = 100.0


@dataclasses.dataclass(frozen=True, slots=True)
class StarlinkPilotReceiverMetrics:
    channel: str
    epoch_sample: int
    cfo_hz: float
    residual_cfo_hz: float
    glrt_score: float
    control_score: float
    glrt_margin: float
    pilot_dbfs: float
    snr_db: float


@dataclasses.dataclass(frozen=True, slots=True)
class StarlinkPilotParityMetrics:
    sample_rate_hz: int
    frame_samples: int
    receivers: tuple[StarlinkPilotReceiverMetrics, StarlinkPilotReceiverMetrics]
    rx_level_delta_db: float
    snr_delta_db: float
    glrt_delta: float
    timing_delta_samples: int
    cfo_delta_hz: float


DEFAULT_LIMITS = StarlinkPilotLimits()


def _pilot_states(*, symbol_roll: int = 0) -> np.ndarray:
    if isinstance(symbol_roll, bool) or not isinstance(symbol_roll, int):
        raise TypeError("symbol_roll must be an integer")
    indexes = tuple(QIN_LOWER_EDGE_PILOT_HEX)
    output = np.empty((300, len(indexes)), dtype=np.int8)
    for output_row in range(300):
        source_row = (output_row - symbol_roll) % 300
        shift = 2 * (299 - source_row)
        for column, index in enumerate(indexes):
            output[output_row, column] = (
                int(QIN_LOWER_EDGE_PILOT_HEX[index], 16) >> shift
            ) & 3
    return output


@lru_cache(maxsize=8)
def _cached_frame(sample_rate_hz: int, symbol_roll: int) -> np.ndarray:
    if sample_rate_hz <= 0:
        raise ValueError("sample rate must be positive")
    count = round(sample_rate_hz / FRAME_RATE_HZ)
    if not 1 <= count <= 1_000_000:
        raise ValueError("sample rate produces an unsupported pilot frame")
    time_s = np.arange(count, dtype=np.float64) / sample_rate_hz
    symbol_index = np.floor(time_s / OFDM_SYMBOL_DURATION_S).astype(int)
    states = _pilot_states(symbol_roll=symbol_roll)
    symbols = np.asarray(
        np.exp(0.5j * np.pi * (states.astype(float) + 0.5)), dtype=np.complex64
    )
    indexes = tuple(QIN_LOWER_EDGE_PILOT_HEX)
    absolute_hz = np.asarray(
        [(index if index < 512 else index - 1024) * SUBCARRIER_SPACING_HZ for index in indexes]
    )
    tuning_offset_hz = float(np.mean(absolute_hz))
    output = np.zeros(count, dtype=np.complex64)
    for symbol in range(2, 302):
        selected = np.flatnonzero(symbol_index == symbol)
        if not selected.size:
            continue
        local_time = time_s[selected] - symbol * OFDM_SYMBOL_DURATION_S
        values = np.zeros(selected.size, dtype=np.complex128)
        for column, subcarrier in enumerate(indexes):
            frequency_hz = (
                (subcarrier if subcarrier < 512 else subcarrier - 1024)
                * SUBCARRIER_SPACING_HZ
                - tuning_offset_hz
            )
            values += symbols[symbol - 2, column] * np.exp(
                2j * np.pi * frequency_hz * (local_time - CYCLIC_PREFIX_DURATION_S)
            )
        output[selected] = values / math.sqrt(8)
    output.flags.writeable = False
    return output


def qin_lower_edge_pilot_frame(sample_rate_hz: int, *, symbol_roll: int = 0) -> np.ndarray:
    """Return one sampled frame of the published lower-edge pilot."""

    return _cached_frame(sample_rate_hz, symbol_roll).copy()


def cyclic_tx_waveform(
    sample_rate_hz: int,
    *,
    peak: float = 0.55,
    frames: int = 3,
) -> np.ndarray:
    """Build a cyclic pyadi transmit buffer with bounded complex amplitude."""

    if not 0 < peak <= 0.8 or frames < 1:
        raise ValueError("TX peak/frames are outside the bounded test range")
    frame = qin_lower_edge_pilot_frame(sample_rate_hz)
    normalized = frame / max(float(np.max(np.abs(frame))), 1e-20)
    return np.asarray(np.tile(normalized * peak * (2**14), frames), dtype=np.complex64)


def _estimate_cfo(samples: np.ndarray, period: int, sample_rate_hz: int) -> float:
    product = np.vdot(samples[:-period], samples[period:])
    return float(np.angle(product) * sample_rate_hz / (2 * np.pi * period))


def _acquire_epoch(samples: np.ndarray, template: np.ndarray) -> int:
    count = len(template)
    block = samples[:count]
    correlation = np.fft.ifft(np.conj(np.fft.fft(template)) * np.fft.fft(block))
    return int(np.argmax(np.abs(correlation)))


def _glrt(
    samples: np.ndarray,
    sample_rate_hz: int,
    epoch_sample: int,
    template: np.ndarray,
) -> tuple[float, float]:
    frame_samples = len(template)
    symbol_samples = sample_rate_hz * OFDM_SYMBOL_DURATION_S
    correlations: list[list[complex]] = []
    times: list[list[float]] = []
    frame_start = epoch_sample
    while frame_start + round(66 * symbol_samples) <= len(samples):
        row: list[complex] = []
        moments: list[float] = []
        for symbol in range(2, 66):
            start = round(symbol * symbol_samples)
            stop = min(round((symbol + 1) * symbol_samples), frame_samples)
            received = samples[frame_start + start : frame_start + stop]
            reference = template[start:stop]
            row.append(complex(np.vdot(reference, received)))
            moments.append((start + (stop - start - 1) / 2) / sample_rate_hz)
        correlations.append(row)
        times.append(moments)
        frame_start += frame_samples
    values = np.asarray(correlations, dtype=np.complex128)
    if not values.size:
        return 0.0, 0.0
    local_times = np.asarray(times) - np.asarray(times)[:, :1]
    grid = np.fft.fftfreq(512, d=OFDM_SYMBOL_DURATION_S)
    phase = np.exp(-2j * np.pi * grid[:, None, None] * local_times[None, :, :])
    spectrum = np.sum(np.abs(np.sum(values[None, :, :] * phase, axis=2)) ** 2, axis=1)
    ceiling = float(np.sum(np.sum(np.abs(values), axis=1) ** 2))
    normalized = spectrum / ceiling if ceiling > 0 else spectrum
    best = int(np.argmax(normalized))
    return float(normalized[best]), float(grid[best])


def _receiver_metrics(
    samples: np.ndarray,
    sample_rate_hz: int,
    channel: int,
    adc_full_scale: float,
) -> StarlinkPilotReceiverMetrics:
    template = np.asarray(qin_lower_edge_pilot_frame(sample_rate_hz), np.complex128)
    period = len(template)
    values = np.asarray(samples, dtype=np.complex128)
    cfo_hz = _estimate_cfo(values, period, sample_rate_hz)
    index = np.arange(len(values), dtype=float)
    corrected = values * np.exp(-2j * np.pi * cfo_hz * index / sample_rate_hz)
    epoch = _acquire_epoch(corrected, template)
    exact, residual_cfo_hz = _glrt(corrected, sample_rate_hz, epoch, template)
    control, _ = _glrt(
        corrected,
        sample_rate_hz,
        epoch,
        np.asarray(
            qin_lower_edge_pilot_frame(sample_rate_hz, symbol_roll=CONTROL_SYMBOL_ROLL),
            np.complex128,
        ),
    )
    reference = template[(np.arange(len(values)) - epoch) % period]
    active = np.abs(reference) > 1e-8
    gain = np.vdot(reference[active], corrected[active]) / np.vdot(
        reference[active], reference[active]
    )
    modeled = gain * reference[active]
    residual = corrected[active] - modeled
    signal_power = float(np.mean(np.abs(modeled) ** 2))
    noise_power = float(np.mean(np.abs(residual) ** 2))
    return StarlinkPilotReceiverMetrics(
        channel=f"RX{channel}",
        epoch_sample=epoch,
        cfo_hz=cfo_hz,
        residual_cfo_hz=residual_cfo_hz,
        glrt_score=exact,
        control_score=control,
        glrt_margin=exact - control,
        pilot_dbfs=10 * math.log10(max(signal_power, 1e-20) / adc_full_scale**2),
        snr_db=10 * math.log10(max(signal_power, 1e-20) / max(noise_power, 1e-20)),
    )


def analyze_starlink_pilot_parity(
    signal: np.ndarray,
    *,
    sample_rate_hz: int,
    adc_full_scale: float = 2048.0,
    limits: StarlinkPilotLimits = DEFAULT_LIMITS,
) -> StarlinkPilotParityMetrics:
    """Recover the pilot with GLRT on each RX and enforce receiver parity."""

    samples = np.asarray(signal)
    frame_samples = round(sample_rate_hz / FRAME_RATE_HZ)
    if (
        samples.ndim != 2
        or samples.shape[0] != 2
        or samples.shape[1] < 3 * frame_samples
        or not np.iscomplexobj(samples)
    ):
        raise StarlinkPilotLoopbackError("analysis requires two RX rows and at least 3 frames")
    if sample_rate_hz <= 0 or not math.isfinite(adc_full_scale) or adc_full_scale <= 0:
        raise StarlinkPilotLoopbackError("sample rate or ADC full scale is invalid")
    if not np.all(np.isfinite(samples)):
        raise StarlinkPilotLoopbackError("capture contains non-finite samples")

    receivers = tuple(
        _receiver_metrics(samples[channel], sample_rate_hz, channel, adc_full_scale)
        for channel in range(2)
    )
    first, second = receivers
    raw_timing_delta = abs(first.epoch_sample - second.epoch_sample)
    timing_delta = min(raw_timing_delta, frame_samples - raw_timing_delta)
    result = StarlinkPilotParityMetrics(
        sample_rate_hz=sample_rate_hz,
        frame_samples=frame_samples,
        receivers=(first, second),
        rx_level_delta_db=abs(first.pilot_dbfs - second.pilot_dbfs),
        snr_delta_db=abs(first.snr_db - second.snr_db),
        glrt_delta=abs(first.glrt_score - second.glrt_score),
        timing_delta_samples=timing_delta,
        cfo_delta_hz=abs(first.cfo_hz - second.cfo_hz),
    )
    failures: list[str] = []
    if any(item.glrt_score < limits.minimum_glrt_score for item in receivers):
        failures.append("GLRT detection score")
    if any(item.glrt_margin < limits.minimum_glrt_margin for item in receivers):
        failures.append("GLRT exact/control margin")
    if any(item.snr_db < limits.minimum_snr_db for item in receivers):
        failures.append("pilot SNR")
    if any(
        not limits.minimum_pilot_dbfs <= item.pilot_dbfs <= limits.maximum_pilot_dbfs
        for item in receivers
    ):
        failures.append("pilot level")
    if result.rx_level_delta_db > limits.maximum_rx_level_delta_db:
        failures.append("RX pilot level delta")
    if result.snr_delta_db > limits.maximum_snr_delta_db:
        failures.append("RX SNR delta")
    if result.glrt_delta > limits.maximum_glrt_delta:
        failures.append("RX GLRT delta")
    if result.timing_delta_samples > limits.maximum_timing_delta_samples:
        failures.append("RX timing delta")
    if result.cfo_delta_hz > limits.maximum_cfo_delta_hz:
        failures.append("RX CFO delta")
    if failures:
        raise StarlinkPilotLoopbackError(
            f"Starlink pilot parity gate failed ({', '.join(failures)}): {result!r}"
        )
    return result
