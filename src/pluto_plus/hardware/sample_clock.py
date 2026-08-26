"""Map an FPGA sample counter onto host monotonic and realtime clocks.

The hardware counter is the authoritative frame boundary.  Register reads are
only time anchors, so their host round-trip interval remains visible as an
uncertainty instead of being disguised as exact wall-clock time.
"""

from __future__ import annotations

import dataclasses
import math
import time
from collections.abc import Iterable

import numpy as np

from pluto_plus.direct_radio.usb import TimeAnchorV1

UINT32_MODULUS = 1 << 32
UINT32_HALF_RANGE = 1 << 31
DEFAULT_SAMPLE_CLOCK_RATE_TOLERANCE_PPM = 100.0


def extend_low32_near(reference: int, low: int) -> int:
    """Extend a low counter word to the closest uint64 value to ``reference``."""

    if not 0 <= reference <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("reference counter is outside uint64")
    if not 0 <= low <= 0xFFFFFFFF:
        raise ValueError("counter low word is outside uint32")
    candidate = (reference & 0xFFFFFFFF00000000) | low
    if candidate < reference and reference - candidate > UINT32_HALF_RANGE:
        candidate += UINT32_MODULUS
    elif candidate > reference and candidate - reference > UINT32_HALF_RANGE:
        if candidate < UINT32_MODULUS:
            raise ValueError("counter cannot extend below zero")
        candidate -= UINT32_MODULUS
    if not 0 <= candidate <= 0xFFFFFFFFFFFFFFFF:
        raise ValueError("extended counter is outside uint64")
    return candidate


@dataclasses.dataclass(frozen=True, slots=True)
class HostTimeAnchorMeasurement:
    """One FPGA counter register read bracketed by host monotonic timestamps."""

    anchor: TimeAnchorV1
    host_monotonic_before_ns: int
    host_monotonic_after_ns: int
    transport: str

    def __post_init__(self) -> None:
        if self.host_monotonic_before_ns < 0:
            raise ValueError("host monotonic time must be non-negative")
        if self.host_monotonic_after_ns < self.host_monotonic_before_ns:
            raise ValueError("host monotonic interval regressed")
        if not self.transport:
            raise ValueError("time-anchor transport is required")

    @property
    def round_trip_ns(self) -> int:
        return self.host_monotonic_after_ns - self.host_monotonic_before_ns

    @property
    def host_midpoint_ns(self) -> float:
        return (self.host_monotonic_before_ns + self.host_monotonic_after_ns) / 2.0

    @property
    def host_half_round_trip_ns(self) -> int:
        return (self.round_trip_ns + 1) // 2

    def extend_near(self, reference_counter: int) -> ExtendedTimeAnchor:
        before = extend_low32_near(reference_counter, self.anchor.sample_counter_before)
        after = before + self.anchor.counter_delta
        if after > 0xFFFFFFFFFFFFFFFF:
            raise ValueError("extended time-anchor counter overflowed uint64")
        return ExtendedTimeAnchor(
            measurement=self,
            sample_counter_before=before,
            sample_counter_after=after,
        )


@dataclasses.dataclass(frozen=True, slots=True)
class ExtendedTimeAnchor:
    measurement: HostTimeAnchorMeasurement
    sample_counter_before: int
    sample_counter_after: int

    @property
    def sample_counter_midpoint(self) -> float:
        return (self.sample_counter_before + self.sample_counter_after) / 2.0


@dataclasses.dataclass(frozen=True, slots=True)
class SampleClockFit:
    sample_origin: float
    host_monotonic_origin_ns: float
    nanoseconds_per_sample: float
    uncertainty_ns: int
    anchor_count: int
    maximum_round_trip_ns: int
    maximum_midpoint_residual_ns: float
    minimum_anchor_counter: float
    maximum_anchor_counter: float
    maximum_rate_error_ppm: float

    def host_monotonic_ns(self, sample_counter: int) -> int:
        if not 0 <= sample_counter <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("sample counter is outside uint64")
        value = self.host_monotonic_origin_ns + self.nanoseconds_per_sample * (
            sample_counter - self.sample_origin
        )
        return int(round(value))

    def uncertainty_ns_at(self, sample_counter: int) -> int:
        if not 0 <= sample_counter <= 0xFFFFFFFFFFFFFFFF:
            raise ValueError("sample counter is outside uint64")
        if sample_counter < self.minimum_anchor_counter:
            distance_samples = self.minimum_anchor_counter - sample_counter
        elif sample_counter > self.maximum_anchor_counter:
            distance_samples = sample_counter - self.maximum_anchor_counter
        else:
            distance_samples = 0.0
        drift_ns = (
            distance_samples
            * self.nanoseconds_per_sample
            * self.maximum_rate_error_ppm
            / 1_000_000.0
        )
        return self.uncertainty_ns + int(math.ceil(drift_ns))


@dataclasses.dataclass(frozen=True, slots=True)
class HostRealtimeMapping:
    monotonic_midpoint_ns: int
    realtime_ns_at_midpoint: int
    uncertainty_ns: int

    def realtime_ns(self, monotonic_ns: int) -> int:
        return int(self.realtime_ns_at_midpoint + monotonic_ns - self.monotonic_midpoint_ns)


def capture_host_realtime_mapping() -> HostRealtimeMapping:
    monotonic_before = time.monotonic_ns()
    realtime_ns = time.time_ns()
    monotonic_after = time.monotonic_ns()
    if monotonic_after < monotonic_before:
        raise RuntimeError("host monotonic clock regressed")
    return HostRealtimeMapping(
        monotonic_midpoint_ns=(monotonic_before + monotonic_after) // 2,
        realtime_ns_at_midpoint=realtime_ns,
        uncertainty_ns=(monotonic_after - monotonic_before + 1) // 2,
    )


def fit_sample_clock(
    anchors: Iterable[ExtendedTimeAnchor],
    *,
    nominal_sample_rate_hz: float | None = None,
    maximum_rate_error_ppm: float = 0.0,
) -> SampleClockFit:
    """Fit an affine clock map without discarding transport uncertainty."""

    observations = tuple(anchors)
    if not observations:
        raise ValueError("at least one extended time anchor is required")
    counters = np.asarray([item.sample_counter_midpoint for item in observations], dtype=np.float64)
    host_times = np.asarray(
        [item.measurement.host_midpoint_ns for item in observations], dtype=np.float64
    )
    sample_origin = float(np.mean(counters))
    host_origin = float(np.mean(host_times))
    x = counters - sample_origin
    y = host_times - host_origin
    if maximum_rate_error_ppm < 0 or not math.isfinite(maximum_rate_error_ppm):
        raise ValueError("maximum rate error must be non-negative and finite")
    if maximum_rate_error_ppm >= 1_000_000:
        raise ValueError("maximum rate error must be less than one million ppm")
    if nominal_sample_rate_hz is not None and (
        nominal_sample_rate_hz <= 0 or not math.isfinite(nominal_sample_rate_hz)
    ):
        raise ValueError("nominal sample rate must be positive and finite")
    denominator = float(np.dot(x, x))
    if denominator > 0:
        nanoseconds_per_sample = float(np.dot(x, y) / denominator)
    elif nominal_sample_rate_hz is not None and nominal_sample_rate_hz > 0:
        nanoseconds_per_sample = 1e9 / float(nominal_sample_rate_hz)
    else:
        raise ValueError("counter-separated anchors or a positive nominal sample rate are required")
    if not math.isfinite(nanoseconds_per_sample) or nanoseconds_per_sample <= 0:
        raise ValueError("fitted sample period is not positive and finite")
    if nominal_sample_rate_hz is not None:
        scale = maximum_rate_error_ppm / 1_000_000.0
        minimum_period = 1e9 / (float(nominal_sample_rate_hz) * (1.0 + scale))
        maximum_period = 1e9 / (float(nominal_sample_rate_hz) * (1.0 - scale))
        # Host transport jitter can dominate a short startup regression.  The
        # radio clock is nevertheless known to be within this declared bound,
        # so constrain the fit and retain the resulting residual as timing
        # uncertainty instead of publishing an impossible sample rate.
        nanoseconds_per_sample = min(max(nanoseconds_per_sample, minimum_period), maximum_period)
    predicted = host_origin + nanoseconds_per_sample * x
    maximum_residual = float(np.max(np.abs(host_times - predicted)))
    maximum_rtt = max(item.measurement.round_trip_ns for item in observations)
    maximum_half_rtt = max(item.measurement.host_half_round_trip_ns for item in observations)
    uncertainty = int(math.ceil(maximum_half_rtt + maximum_residual))
    return SampleClockFit(
        sample_origin=sample_origin,
        host_monotonic_origin_ns=host_origin,
        nanoseconds_per_sample=nanoseconds_per_sample,
        uncertainty_ns=uncertainty,
        anchor_count=len(observations),
        maximum_round_trip_ns=maximum_rtt,
        maximum_midpoint_residual_ns=maximum_residual,
        minimum_anchor_counter=float(np.min(counters)),
        maximum_anchor_counter=float(np.max(counters)),
        maximum_rate_error_ppm=float(maximum_rate_error_ppm),
    )
