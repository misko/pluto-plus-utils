"""Versioned offline analyzers for immutable SigMF captures."""

from __future__ import annotations

import math
import uuid
from collections.abc import Iterator, Mapping
from pathlib import Path
from typing import Any, Protocol

import numpy as np

from pluto_plus.artifacts import data_path
from pluto_plus.errors import AnalyzerNotFoundError
from pluto_plus.freq_ladder import (
    DEFAULT_DC_NOTCH_HZ,
    DEFAULT_FRAME_SIZE,
    DEFAULT_HYSTERESIS_DB,
    DEFAULT_MERGE_GAP_FRACTION,
    DEFAULT_RUNG_TOLERANCE,
    DEFAULT_SEARCH_HALF_WIDTH_HZ,
    DEFAULT_THRESHOLD_DB,
    MINIMUM_FIT_RUNGS,
    CaptureContext,
    FreqLadderSchedule,
    build_bursts,
    fit_freq_ladder,
    measure_frames,
    summarize_identification,
    usable_bursts,
    visible_rungs,
)
from pluto_plus.models import AnalysisResult, ArtifactSummary, utc_now


class Analyzer(Protocol):
    name: str
    version: str

    def run(self, artifact: ArtifactSummary, parameters: Mapping[str, Any]) -> dict[str, Any]: ...


def _samples(artifact: ArtifactSummary) -> np.ndarray:
    raw = np.memmap(data_path(artifact), dtype="<i2", mode="r")
    expected = artifact.sample_count * artifact.receiver_count * 2
    if raw.size != expected:
        raise ValueError(f"IQ size mismatch: found {raw.size} components, expected {expected}")
    return raw.reshape(artifact.sample_count, artifact.receiver_count, 2)


class SpectrumAnalyzer:
    name = "spectrum"
    version = "1"

    def run(self, artifact: ArtifactSummary, parameters: Mapping[str, Any]) -> dict[str, Any]:
        fft_size = int(parameters.get("fft_size", 4096))
        if fft_size < 256 or fft_size & (fft_size - 1):
            raise ValueError("fft_size must be a power of two of at least 256")
        if artifact.sample_count < fft_size:
            raise ValueError("capture is shorter than fft_size")
        maximum_frames = int(parameters.get("maximum_frames", 1024))
        if maximum_frames <= 0:
            raise ValueError("maximum_frames must be positive")
        raw = _samples(artifact)
        frame_count = min(artifact.sample_count // fft_size, maximum_frames)
        stride = max(1, (artifact.sample_count // fft_size) // frame_count)
        window = np.hanning(fft_size).astype(np.float32)
        scale = float(np.sum(window * window))
        spectra: list[list[float]] = []
        peaks: list[dict[str, float]] = []
        offsets = np.fft.fftshift(np.fft.fftfreq(fft_size, 1 / artifact.sample_rate_hz))
        for receiver in range(artifact.receiver_count):
            accumulated = np.zeros(fft_size, dtype=np.float64)
            used = 0
            for frame_index in range(0, artifact.sample_count // fft_size, stride):
                if used == frame_count:
                    break
                start = frame_index * fft_size
                components = raw[start : start + fft_size, receiver]
                values = components[:, 0].astype(np.float32) + 1j * components[:, 1]
                transformed = np.fft.fftshift(np.fft.fft(values * window))
                accumulated += np.abs(transformed) ** 2 / scale
                used += 1
            power_db = 10 * np.log10(accumulated / used + np.finfo(float).tiny)
            peak_index = int(np.argmax(power_db))
            spectra.append(power_db.astype(np.float32).tolist())
            peaks.append(
                {
                    "offset_hz": float(offsets[peak_index]),
                    "frequency_hz": float(artifact.center_frequency_hz + offsets[peak_index]),
                    "power_db": float(power_db[peak_index]),
                }
            )
        return {
            "fft_size": fft_size,
            "frames_used": frame_count,
            "bin_width_hz": artifact.sample_rate_hz / fft_size,
            "frequency_offset_start_hz": float(offsets[0]),
            "receiver_power_db": spectra,
            "peaks": peaks,
        }


class CarrierAnalyzer:
    name = "carrier"
    version = "1"

    def run(self, artifact: ArtifactSummary, parameters: Mapping[str, Any]) -> dict[str, Any]:
        spectrum = SpectrumAnalyzer().run(artifact, parameters)
        return {
            "method": "maximum averaged FFT bin",
            "bin_width_hz": spectrum["bin_width_hz"],
            "carriers": spectrum["peaks"],
        }


class OccupancyAnalyzer:
    name = "occupancy"
    version = "1"

    def run(self, artifact: ArtifactSummary, parameters: Mapping[str, Any]) -> dict[str, Any]:
        threshold_db = float(parameters.get("threshold_db", 6.0))
        spectrum = SpectrumAnalyzer().run(artifact, parameters)
        rows = []
        for receiver, power in enumerate(spectrum["receiver_power_db"]):
            values = np.asarray(power)
            baseline = float(np.median(values))
            occupied = values >= baseline + threshold_db
            rows.append(
                {
                    "receiver": receiver,
                    "baseline_db": baseline,
                    "threshold_db": baseline + threshold_db,
                    "occupied_bin_fraction": float(np.mean(occupied)),
                    "occupied_bandwidth_hz": float(
                        np.count_nonzero(occupied) * spectrum["bin_width_hz"]
                    ),
                }
            )
        return {"receivers": rows}


class SignalQualityAnalyzer:
    """Measure CI16 health without assuming a particular modulation."""

    name = "quality"
    version = "1"

    def run(self, artifact: ArtifactSummary, parameters: Mapping[str, Any]) -> dict[str, Any]:
        if artifact.sample_count <= 0:
            raise ValueError("quality analysis requires a non-empty capture")
        clip_threshold = int(parameters.get("clip_threshold_abs", 2047))
        chunk_samples = int(parameters.get("chunk_samples", 1_048_576))
        dc_warning_fraction = float(parameters.get("dc_warning_fraction", 0.1))
        iq_imbalance_warning_db = float(parameters.get("iq_imbalance_warning_db", 3.0))
        clipping_warning_fraction = float(
            parameters.get("clipping_warning_fraction", 0.0)
        )
        if not 1 <= clip_threshold <= 32768:
            raise ValueError("clip_threshold_abs must be between 1 and 32768")
        if chunk_samples <= 0:
            raise ValueError("chunk_samples must be positive")
        if not 0 <= dc_warning_fraction <= 1:
            raise ValueError("dc_warning_fraction must be between zero and one")
        if iq_imbalance_warning_db < 0:
            raise ValueError("iq_imbalance_warning_db cannot be negative")
        if not 0 <= clipping_warning_fraction <= 1:
            raise ValueError("clipping_warning_fraction must be between zero and one")

        raw = _samples(artifact)
        receivers: list[dict[str, Any]] = []
        for receiver in range(artifact.receiver_count):
            sum_i = 0
            sum_q = 0
            sum_i_squared = 0
            sum_q_squared = 0
            sum_iq = 0
            peak_abs_component = 0
            clipped_component_count = 0
            clipped_sample_count = 0
            zero_pair_count = 0
            for start in range(0, artifact.sample_count, chunk_samples):
                components = raw[start : start + chunk_samples, receiver]
                i_values = components[:, 0].astype(np.int64)
                q_values = components[:, 1].astype(np.int64)
                abs_i = np.abs(i_values)
                abs_q = np.abs(q_values)
                sum_i += int(np.sum(i_values))
                sum_q += int(np.sum(q_values))
                sum_i_squared += int(np.sum(i_values * i_values))
                sum_q_squared += int(np.sum(q_values * q_values))
                sum_iq += int(np.sum(i_values * q_values))
                peak_abs_component = max(
                    peak_abs_component,
                    int(np.max(abs_i, initial=0)),
                    int(np.max(abs_q, initial=0)),
                )
                clipped_i = abs_i >= clip_threshold
                clipped_q = abs_q >= clip_threshold
                clipped_component_count += int(np.count_nonzero(clipped_i))
                clipped_component_count += int(np.count_nonzero(clipped_q))
                clipped_sample_count += int(np.count_nonzero(clipped_i | clipped_q))
                zero_pair_count += int(np.count_nonzero((i_values == 0) & (q_values == 0)))

            count = artifact.sample_count
            mean_i = sum_i / count
            mean_q = sum_q / count
            mean_i_squared = sum_i_squared / count
            mean_q_squared = sum_q_squared / count
            mean_power = mean_i_squared + mean_q_squared
            variance_i = max(0.0, mean_i_squared - mean_i * mean_i)
            variance_q = max(0.0, mean_q_squared - mean_q * mean_q)
            covariance_iq = sum_iq / count - mean_i * mean_q
            ac_power = variance_i + variance_q
            rms_magnitude = math.sqrt(mean_power)
            ac_rms_magnitude = math.sqrt(ac_power)
            dc_magnitude = math.hypot(mean_i, mean_q)
            dc_fraction = dc_magnitude / rms_magnitude if rms_magnitude else 0.0
            if variance_i > 0 and variance_q > 0:
                iq_power_imbalance_db = 10 * math.log10(variance_i / variance_q)
                iq_correlation = covariance_iq / math.sqrt(variance_i * variance_q)
                iq_correlation = min(1.0, max(-1.0, iq_correlation))
            else:
                iq_power_imbalance_db = None
                iq_correlation = None

            clipping_fraction = clipped_sample_count / count
            flags: list[str] = []
            if clipping_fraction > clipping_warning_fraction:
                flags.append("clipping_detected")
            if ac_power == 0:
                flags.append("constant_or_zero_input")
            if rms_magnitude and dc_fraction > dc_warning_fraction:
                flags.append("high_dc_fraction")
            if (
                iq_power_imbalance_db is not None
                and abs(iq_power_imbalance_db) > iq_imbalance_warning_db
            ):
                flags.append("iq_power_imbalance")
            receivers.append(
                {
                    "receiver": receiver,
                    "sample_count": count,
                    "mean_i_counts": mean_i,
                    "mean_q_counts": mean_q,
                    "mean_power_counts_squared": mean_power,
                    "ac_power_counts_squared": ac_power,
                    "rms_magnitude_counts": rms_magnitude,
                    "ac_rms_magnitude_counts": ac_rms_magnitude,
                    "peak_abs_component_counts": peak_abs_component,
                    "dc_magnitude_counts": dc_magnitude,
                    "dc_fraction_of_rms": dc_fraction,
                    "iq_power_imbalance_db": iq_power_imbalance_db,
                    "iq_correlation": iq_correlation,
                    "clip_threshold_abs": clip_threshold,
                    "clipped_component_count": clipped_component_count,
                    "clipped_sample_count": clipped_sample_count,
                    "clipping_fraction": clipping_fraction,
                    "zero_pair_count": zero_pair_count,
                    "zero_pair_fraction": zero_pair_count / count,
                    "flags": flags,
                }
            )
        return {"receivers": receivers}


class DualReceiverAnalyzer:
    """Estimate delay, complex gain, and coherence between two receivers."""

    name = "dual_receiver"
    version = "1"

    def run(self, artifact: ArtifactSummary, parameters: Mapping[str, Any]) -> dict[str, Any]:
        if artifact.sample_count <= 0:
            raise ValueError("dual-receiver analysis requires a non-empty capture")
        receiver_a = int(parameters.get("receiver_a", 0))
        receiver_b = int(parameters.get("receiver_b", 1))
        maximum_delay = int(parameters.get("maximum_delay_samples", 8))
        maximum_samples = int(parameters.get("maximum_samples", 1_048_576))
        coherence_warning = float(parameters.get("coherence_warning", 0.8))
        if receiver_a == receiver_b:
            raise ValueError("receiver_a and receiver_b must be different")
        if not 0 <= receiver_a < artifact.receiver_count:
            raise ValueError("receiver_a is outside the capture")
        if not 0 <= receiver_b < artifact.receiver_count:
            raise ValueError("receiver_b is outside the capture")
        if maximum_delay < 0:
            raise ValueError("maximum_delay_samples cannot be negative")
        if maximum_samples <= 1:
            raise ValueError("maximum_samples must be greater than one")
        if not 0 <= coherence_warning <= 1:
            raise ValueError("coherence_warning must be between zero and one")

        samples_used = min(artifact.sample_count, maximum_samples)
        if maximum_delay >= samples_used:
            raise ValueError("maximum_delay_samples must be smaller than samples used")
        raw = _samples(artifact)[:samples_used]
        first_components = raw[:, receiver_a]
        second_components = raw[:, receiver_b]
        first = first_components[:, 0].astype(np.float64) + 1j * first_components[
            :, 1
        ].astype(np.float64)
        second = second_components[:, 0].astype(np.float64) + 1j * second_components[
            :, 1
        ].astype(np.float64)
        first -= np.mean(first)
        second -= np.mean(second)

        candidates: list[tuple[float, int, complex, float, float]] = []
        for delay in range(-maximum_delay, maximum_delay + 1):
            left, right = _delay_aligned(first, second, delay)
            left_energy = float(np.vdot(left, left).real)
            right_energy = float(np.vdot(right, right).real)
            numerator = complex(np.vdot(left, right))
            denominator = math.sqrt(left_energy * right_energy)
            coherence = abs(numerator) / denominator if denominator else 0.0
            candidates.append((coherence, delay, numerator, left_energy, right_energy))
        coherence, delay, numerator, left_energy, right_energy = max(
            candidates, key=lambda item: (item[0], -abs(item[1]), -item[1])
        )
        left, right = _delay_aligned(first, second, delay)
        complex_gain = numerator / left_energy if left_energy else 0j
        residual = right - complex_gain * left
        residual_energy = float(np.vdot(residual, residual).real)
        differential_power_fraction = residual_energy / right_energy if right_energy else 0.0
        conjugate_numerator = complex(np.sum(left * right))
        denominator = math.sqrt(left_energy * right_energy)
        conjugate_coherence = abs(conjugate_numerator) / denominator if denominator else 0.0
        flags: list[str] = []
        if not left_energy or not right_energy:
            flags.append("constant_or_zero_input")
        if coherence < coherence_warning:
            flags.append("low_coherence")
        return {
            "receiver_a": receiver_a,
            "receiver_b": receiver_b,
            "samples_used": samples_used,
            "maximum_delay_samples": maximum_delay,
            "delay_samples": delay,
            "delay_seconds": delay / artifact.sample_rate_hz,
            "coherence": coherence,
            "conjugate_coherence": conjugate_coherence,
            "gain_ratio_b_over_a": abs(complex_gain),
            "relative_phase_rad_b_minus_a": math.atan2(complex_gain.imag, complex_gain.real),
            "differential_power_fraction": differential_power_fraction,
            "flags": flags,
        }


def _delay_aligned(
    first: np.ndarray, second: np.ndarray, delay: int
) -> tuple[np.ndarray, np.ndarray]:
    """Align arrays where a positive delay means the second receiver lags."""

    if delay < 0:
        return first[-delay:], second[:delay]
    if delay > 0:
        return first[:-delay], second[delay:]
    return first, second


class FreqLadderAnalyzer:
    """Recover receiver clock error and LNB LO error from an observed ladder.

    The transmitter is not controlled from here. Each burst is identified purely
    by its duration against the published schedule, mapped back to that rung's
    nominal RF and intermediate frequency, and its frequency error recorded.
    Because the capture is a stored contiguous artifact, a frame's time is exactly
    ``frame_index * frame_size / sample_rate_hz`` rather than a wall-clock guess,
    which is what makes the durations - and therefore the rung identities -
    trustworthy. See :mod:`pluto_plus.freq_ladder` for the physics, the slope
    versus intercept separation, and why the reported uncertainty is a resample.
    """

    name = "freq_ladder"
    version = "1"

    def run(self, artifact: ArtifactSummary, parameters: Mapping[str, Any]) -> dict[str, Any]:
        required = ("rung_start_hz", "rung_stop_hz", "rung_count", "total_seconds", "lo_hz")
        missing = [name for name in required if parameters.get(name) is None]
        if missing:
            raise ValueError(f"freq_ladder requires {', '.join(missing)}")
        rung_start_hz = float(parameters["rung_start_hz"])
        rung_stop_hz = float(parameters["rung_stop_hz"])
        rung_count = int(parameters["rung_count"])
        total_seconds = float(parameters["total_seconds"])
        lo_hz = float(parameters["lo_hz"])
        frame_size = int(parameters.get("frame_size", DEFAULT_FRAME_SIZE))
        threshold_db = float(parameters.get("threshold_db", DEFAULT_THRESHOLD_DB))
        hysteresis_db = float(parameters.get("hysteresis_db", DEFAULT_HYSTERESIS_DB))
        dc_notch_hz = float(parameters.get("dc_notch_hz", DEFAULT_DC_NOTCH_HZ))
        search_half_width_hz = float(
            parameters.get("search_half_width_hz", DEFAULT_SEARCH_HALF_WIDTH_HZ)
        )
        merge_gap_fraction = float(
            parameters.get("merge_gap_fraction", DEFAULT_MERGE_GAP_FRACTION)
        )
        rung_tolerance = float(parameters.get("rung_tolerance", DEFAULT_RUNG_TOLERANCE))
        receiver = int(parameters.get("receiver", 0))

        if rung_start_hz <= 0:
            raise ValueError("rung_start_hz must be positive")
        if rung_stop_hz <= rung_start_hz:
            raise ValueError("rung_stop_hz must be above rung_start_hz")
        if rung_count < 2:
            raise ValueError("rung_count must be at least two")
        if total_seconds <= 0:
            raise ValueError("total_seconds must be positive")
        if lo_hz <= 0:
            raise ValueError("lo_hz must be positive")
        if lo_hz >= rung_start_hz:
            raise ValueError("lo_hz must be below rung_start_hz so every rung has a positive IF")
        if frame_size < 256 or frame_size & (frame_size - 1):
            raise ValueError("frame_size must be a power of two of at least 256")
        if artifact.sample_count < frame_size:
            raise ValueError("capture is shorter than frame_size")
        if threshold_db <= 0:
            raise ValueError("threshold_db must be positive")
        if not 0 <= hysteresis_db < threshold_db:
            raise ValueError("hysteresis_db must be at least zero and below threshold_db")
        if dc_notch_hz < 0:
            raise ValueError("dc_notch_hz cannot be negative")
        if dc_notch_hz >= artifact.sample_rate_hz / 2:
            raise ValueError("dc_notch_hz must be below half the sample rate")
        if not 0 < search_half_width_hz <= artifact.sample_rate_hz / 2:
            raise ValueError("search_half_width_hz must be positive and at most half the rate")
        if not 0 <= merge_gap_fraction <= 0.5:
            raise ValueError("merge_gap_fraction must be between zero and one half")
        if not 0 < rung_tolerance <= 0.5:
            raise ValueError("rung_tolerance must be between zero and one half")
        if not 0 <= receiver < artifact.receiver_count:
            raise ValueError("receiver is outside the capture")

        schedule = FreqLadderSchedule(
            rung_start_hz=rung_start_hz,
            rung_stop_hz=rung_stop_hz,
            rung_count=rung_count,
            total_seconds=total_seconds,
        )
        visible = visible_rungs(
            schedule,
            lo_hz=lo_hz,
            center_frequency_hz=artifact.center_frequency_hz,
            sample_rate_hz=artifact.sample_rate_hz,
        )
        if not visible:
            raise ValueError(
                "no ladder rung has a nominal intermediate frequency inside this capture; "
                "check lo_hz against the capture centre frequency"
            )

        raw = _samples(artifact)
        frame_count = artifact.sample_count // frame_size

        def frames() -> Iterator[np.ndarray]:
            for index in range(frame_count):
                block = raw[index * frame_size : (index + 1) * frame_size, receiver]
                yield block[:, 0].astype(np.float64) + 1j * block[:, 1].astype(np.float64)

        series = measure_frames(
            frames(),
            sample_rate_hz=artifact.sample_rate_hz,
            center_frequency_hz=artifact.center_frequency_hz,
            frame_size=frame_size,
            search_centers_hz=[schedule.rung_frequency_hz(rung) - lo_hz for rung in visible],
            search_half_width_hz=search_half_width_hz,
            dc_notch_hz=dc_notch_hz,
        )
        bursts = build_bursts(
            series,
            schedule=schedule,
            context=CaptureContext(
                artifact_id=artifact.artifact_id,
                receiver=receiver,
                epoch_seconds=artifact.created_at.timestamp(),
            ),
            lo_hz=lo_hz,
            threshold_db=threshold_db,
            hysteresis_db=hysteresis_db,
            merge_gap_fraction=merge_gap_fraction,
            rung_tolerance=rung_tolerance,
        )
        usable = usable_bursts(bursts)
        identified_rungs = sorted({row.rung for row in usable if row.rung is not None})
        fit: dict[str, Any] | None = None
        if len(identified_rungs) >= MINIMUM_FIT_RUNGS:
            fit = fit_freq_ladder(usable, lo_hz=lo_hz).model_dump(mode="json")
            fit_status = "fitted"
        else:
            fit_status = (
                f"a fit needs at least {MINIMUM_FIT_RUNGS} distinct rungs; this capture "
                f"identified {len(identified_rungs)}"
            )
        return {
            "receiver": receiver,
            "lo_hz": lo_hz,
            "schedule": {
                "rung_start_hz": rung_start_hz,
                "rung_stop_hz": rung_stop_hz,
                "rung_count": rung_count,
                "total_seconds": total_seconds,
                "unit_seconds": schedule.unit_seconds,
                "rung_frequencies_hz": [
                    schedule.rung_frequency_hz(rung) for rung in schedule.rungs
                ],
                "rung_intermediate_frequencies_hz": [
                    schedule.rung_frequency_hz(rung) - lo_hz for rung in schedule.rungs
                ],
            },
            "frame_size": frame_size,
            "frame_seconds": series.frame_seconds,
            "frame_count": series.frame_count,
            "capture_epoch_seconds": artifact.created_at.timestamp(),
            "threshold_db": threshold_db,
            "hysteresis_db": hysteresis_db,
            "dc_notch_hz": dc_notch_hz,
            "search_half_width_hz": search_half_width_hz,
            "searched_bin_count": series.searched_bin_count,
            "merge_gap_fraction": merge_gap_fraction,
            "rung_tolerance": rung_tolerance,
            "visible_rungs": list(visible),
            "identified_rungs": identified_rungs,
            "identification": summarize_identification(bursts, rung_tolerance).model_dump(
                mode="json"
            ),
            "bursts": [row.model_dump(mode="json") for row in bursts],
            "fit": fit,
            "fit_status": fit_status,
        }


class AnalysisService:
    def __init__(self, root: Path, analyzers: tuple[Analyzer, ...] | None = None) -> None:
        self.root = root
        selected = analyzers or (
            SpectrumAnalyzer(),
            CarrierAnalyzer(),
            OccupancyAnalyzer(),
            SignalQualityAnalyzer(),
            DualReceiverAnalyzer(),
            FreqLadderAnalyzer(),
        )
        self._analyzers = {analyzer.name: analyzer for analyzer in selected}

    @property
    def analyzer_names(self) -> tuple[str, ...]:
        return tuple(sorted(self._analyzers))

    def analyze(
        self,
        artifact: ArtifactSummary,
        analyzer_name: str,
        parameters: Mapping[str, Any],
    ) -> AnalysisResult:
        try:
            analyzer = self._analyzers[analyzer_name]
        except KeyError as error:
            raise AnalyzerNotFoundError(f"unknown analyzer: {analyzer_name}") from error
        result = analyzer.run(artifact, parameters)
        analysis_id = uuid.uuid4().hex
        destination = self.root / artifact.artifact_id
        destination.mkdir(parents=True, exist_ok=True)
        path = destination / f"{analysis_id}.json"
        document = AnalysisResult(
            analysis_id=analysis_id,
            artifact_id=artifact.artifact_id,
            analyzer=analyzer.name,
            analyzer_version=analyzer.version,
            created_at=utc_now(),
            result=_json_safe(result),
            path=str(path),
        )
        temporary = path.with_suffix(".json.partial")
        temporary.write_text(document.model_dump_json(indent=2) + "\n")
        os_replace(temporary, path)
        return document


def _json_safe(value: Any) -> Any:
    if isinstance(value, float) and not math.isfinite(value):
        raise ValueError("analysis produced a non-finite value")
    if isinstance(value, dict):
        return {str(key): _json_safe(item) for key, item in value.items()}
    if isinstance(value, (list, tuple)):
        return [_json_safe(item) for item in value]
    if isinstance(value, np.generic):
        return _json_safe(value.item())
    return value


def os_replace(source: Path, destination: Path) -> None:
    source.replace(destination)
