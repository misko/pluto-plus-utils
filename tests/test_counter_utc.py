from __future__ import annotations

import struct
import zlib

import pytest

from pluto_plus.counter_utc import (
    UNKNOWN_AGE,
    CounterObservation,
    CounterUtcEvidence,
    HostClock,
    TimeAnchor,
    TimingPolicy,
    pack_query,
)
from pluto_plus.counter_utc_capture import chrony_bound

UTC = 1_800_000_000_000_000_000
MONO = 1_000_000_000_000
COUNTER = 4_000_000_000


def clock(mono: int, error: int | None = 1_000_000) -> HostClock:
    return HostClock(
        monotonic_before_ns=mono,
        monotonic_after_ns=mono + 100,
        realtime_ns=UTC + mono - MONO + 50,
        source="instrumented-reference",
        utc_error_bound_ns=error,
        reason="fixture",
    )


def anchor(second: int, request: int, rate: int = 20_000_000, ppm: int = 0) -> TimeAnchor:
    # Strongly asymmetric transport: read near the far end of the bracket.
    event = MONO + second * 10**9
    send, receive = event - 18_000_000, event + 2_000_000
    observation = CounterObservation(
        request=request,
        session=11,
        generation=12,
        boot_id="01" * 16,
        epoch=99,
        counter=COUNTER + second * rate * (1_000_000 + ppm) // 1_000_000,
        device_before_ns=event - 100,
        device_after_ns=event + 100,
        sample_rate_hz=rate,
        maximum_snapshot_age_ns=10_000,
    )
    return TimeAnchor(
        observation=observation,
        send_monotonic_ns=send,
        receive_monotonic_ns=receive,
        clock_before=clock(send - 1000),
        clock_after=clock(receive + 1000),
    )


def evidence(rate: int = 20_000_000, ppm: int = 0) -> CounterUtcEvidence:
    return CounterUtcEvidence(
        session=11,
        generation=12,
        radio_serial="fixture",
        policy=TimingPolicy(
            calibration_reference="synthetic-independent-clock",
            calibration_radio_serial="fixture",
            calibration_boot_id="01" * 16,
            maximum_rate_error_ppm=100,
            maximum_acquisition_delay_ns=10_000,
        ),
        anchors=tuple(anchor(t, i + 1, rate, ppm) for i, t in enumerate(range(0, 301, 5))),
    )


@pytest.mark.parametrize("rate", [10_000_000, 15_000_000, 20_000_000])
@pytest.mark.parametrize("ppm", [-100, -37, 0, 51, 100])
def test_every_sample_time_is_bounded_through_wrap_and_drift(rate: int, ppm: int) -> None:
    value = evidence(rate, ppm)
    last = value.anchors[-1].observation.counter
    qualified, reason, bound = value.qualification(COUNTER, last, rate)
    assert qualified, reason
    assert bound is not None and bound <= 100_000_000
    lo, hi = value.interval(COUNTER)
    estimate = (lo + hi) // 2
    for second in range(301):
        counter = COUNTER + second * rate * (1_000_000 + ppm) // 1_000_000
        low, high = value.interval(counter)
        truth = UTC + second * 10**9
        assert low <= truth <= high
        nominal = estimate + (counter - COUNTER) * 10**9 // rate
        assert abs(nominal - truth) <= bound


@pytest.mark.parametrize(
    "failure",
    [
        "boot",
        "epoch",
        "request",
        "counter",
        "rate",
        "step",
        "utc",
        "age",
        "gap",
        "contradiction",
        "calibration",
    ],
)
def test_failure_modes_never_qualify(failure: str) -> None:
    value = evidence()
    anchors = list(value.anchors)
    middle = anchors[20]
    if failure in {"boot", "epoch", "request", "counter", "rate", "age", "contradiction"}:
        changes = {
            "boot": {"boot_id": "02" * 16},
            "epoch": {"epoch": 100},
            "request": {"request": 1},
            "counter": {"counter": 1},
            "rate": {"sample_rate_hz": 10_000_000},
            "age": {"maximum_snapshot_age_ns": UNKNOWN_AGE},
            "contradiction": {"counter": middle.observation.counter + 1_000_000},
        }[failure]
        anchors[20] = middle.model_copy(
            update={"observation": middle.observation.model_copy(update=changes)}
        )
    elif failure == "step":
        anchors[20] = middle.model_copy(
            update={
                "clock_after": middle.clock_after.model_copy(
                    update={"realtime_ns": middle.clock_after.realtime_ns + 50_000_000}
                )
            }
        )
    elif failure == "utc":
        anchors[20] = middle.model_copy(
            update={
                "clock_after": middle.clock_after.model_copy(update={"utc_error_bound_ns": None})
            }
        )
    elif failure == "gap":
        del anchors[20:24]
    elif failure == "calibration":
        value = value.model_copy(update={"policy": TimingPolicy()})
    value = value.model_copy(update={"anchors": tuple(anchors)})
    assert not value.qualification(COUNTER, COUNTER + 300 * 20_000_000, 20_000_000)[0]


def test_clock_stability_cannot_substitute_for_utc_accuracy() -> None:
    value = evidence()
    value = value.model_copy(
        update={
            "anchors": tuple(
                a.model_copy(
                    update={
                        "clock_before": a.clock_before.model_copy(
                            update={"utc_error_bound_ns": 1_000_000_000}
                        ),
                        "clock_after": a.clock_after.model_copy(
                            update={"utc_error_bound_ns": 1_000_000_000}
                        ),
                    }
                )
                for a in value.anchors
            )
        }
    )
    assert not value.qualification(COUNTER, COUNTER + 300 * 20_000_000, 20_000_000)[0]


def response_wire() -> bytes:
    wire = bytearray(128)
    struct.pack_into("<4sHHIIQQQ", wire, 0, b"SPTA", 1, 128, 255, 1, 1, 11, 12)
    wire[40:56] = b"\x01" * 16
    struct.pack_into("<QQQQIIQ", wire, 56, 99, COUNTER, 100, 200, 10_000_000, 64, UNKNOWN_AGE)
    struct.pack_into("<I", wire, 124, zlib.crc32(wire[:124]))
    return bytes(wire)


def test_wire_rejects_every_single_byte_corruption() -> None:
    wire = response_wire()
    assert CounterObservation.unpack(wire).maximum_snapshot_age_ns == UNKNOWN_AGE
    for index in range(128):
        bad = bytearray(wire)
        bad[index] ^= 1
        with pytest.raises(ValueError):
            CounterObservation.unpack(bytes(bad))
    assert len(pack_query(1, 11, 12)) == 48
    with pytest.raises(ValueError):
        pack_query(0, 11, 12)


def test_chrony_bound_and_failure() -> None:
    line = "12345678,2,1800000000,0.001,0,0,0,0,1,0.010,0.002,64,Normal"
    assert chrony_bound(line, UTC)[1] == 8_001_000
    for bad in (
        line.replace("Normal", "Not synchronised"),
        line.replace("12345678", "7F7F0101"),
        line.replace("0.010", "NaN"),
    ):
        with pytest.raises(ValueError):
            chrony_bound(bad, UTC)
    with pytest.raises(ValueError):
        chrony_bound(line, UTC + 1300 * 10**9)


def test_json_round_trip_preserves_raw_evidence() -> None:
    value = evidence()
    assert CounterUtcEvidence.model_validate_json(value.model_dump_json()) == value


def test_independent_marker_verifier_detects_absolute_bias_and_missing_support() -> None:
    from pluto_plus.counter_utc_verify import (
        IndependentReference,
        ReferenceMarker,
        verify_reference,
    )

    value = evidence()
    reference = IndependentReference(
        source="synthetic-PPS-RF-marker",
        instrument_receipt_sha256="a" * 64,
        radio_serial="fixture",
        boot_id="01" * 16,
        session=11,
        generation=12,
        sample_rate_hz=20_000_000,
        first_counter=COUNTER,
        final_counter=COUNTER + 300 * 20_000_000,
        markers=tuple(
            ReferenceMarker(
                counter=COUNTER + t * 20_000_000, utc_ns=UTC + t * 10**9, uncertainty_ns=1000
            )
            for t in range(301)
        ),
    )
    assert verify_reference(value, reference)["passed"]
    biased = reference.model_copy(
        update={
            "markers": tuple(
                m.model_copy(update={"utc_ns": m.utc_ns + 200_000_000}) for m in reference.markers
            )
        }
    )
    assert not verify_reference(value, biased)["passed"]
    sparse = reference.model_copy(update={"markers": reference.markers[100:200]})
    assert not verify_reference(value, sparse)["passed"]
    wrong_radio = reference.model_copy(update={"radio_serial": "another-radio"})
    assert not verify_reference(value, wrong_radio)["passed"]
