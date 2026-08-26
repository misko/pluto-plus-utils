from __future__ import annotations

import pytest

from pluto_plus.direct_radio.usb import TimeAnchorFlags, TimeAnchorV1
from pluto_plus.hardware.sample_clock import (
    ExtendedTimeAnchor,
    HostTimeAnchorMeasurement,
    fit_sample_clock,
)


def _anchor(counter: int, host_ns: int, request_id: int) -> ExtendedTimeAnchor:
    anchor = TimeAnchorV1(
        flags=TimeAnchorFlags.COUNTER_INTERVAL_VALID
        | TimeAnchorFlags.MONOTONIC_INTERVAL_VALID,
        request_id=request_id,
        radio_monotonic_before_ns=0,
        sample_counter_before=counter,
        sample_counter_after=counter,
        radio_monotonic_after_ns=0,
    )
    measurement = HostTimeAnchorMeasurement(
        anchor=anchor,
        host_monotonic_before_ns=host_ns,
        host_monotonic_after_ns=host_ns,
        transport="test",
    )
    return ExtendedTimeAnchor(measurement, counter, counter)


def test_sample_clock_fit_is_constrained_to_declared_nominal_tolerance() -> None:
    fit = fit_sample_clock(
        (_anchor(0, 1_000_000, 1), _anchor(1_000, 2_000_000, 2)),
        nominal_sample_rate_hz=2_500_000,
        maximum_rate_error_ppm=100,
    )

    observed_rate = 1e9 / fit.nanoseconds_per_sample
    assert observed_rate == pytest.approx(2_500_000, rel=100 / 1_000_000)
    assert observed_rate >= 2_500_000 * (1 - 100 / 1_000_000)


def test_sample_clock_rejects_unbounded_or_invalid_nominal_rate() -> None:
    anchors = (_anchor(0, 1_000_000, 1), _anchor(1_000, 2_000_000, 2))
    with pytest.raises(ValueError, match="less than one million"):
        fit_sample_clock(
            anchors,
            nominal_sample_rate_hz=2_500_000,
            maximum_rate_error_ppm=1_000_000,
        )
    with pytest.raises(ValueError, match="nominal sample rate"):
        fit_sample_clock(anchors, nominal_sample_rate_hz=float("nan"))
