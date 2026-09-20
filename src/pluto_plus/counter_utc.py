"""Versioned counter/UTC evidence. Bounds, not network symmetry, authorize UTC.

Each observation is an interval. A rate envelope propagates it to any sample;
the intersection retains every time consistent with the declared bounds.
Unknown hardware bounds deliberately prevent qualification.
"""

from __future__ import annotations

import struct
import zlib
from fractions import Fraction
from typing import Annotated, Literal, Self

from pydantic import BaseModel, ConfigDict, Field, model_validator

U64 = Annotated[int, Field(strict=True, ge=0, le=(1 << 64) - 1)]
Positive = Annotated[int, Field(strict=True, gt=0)]
Nonnegative = Annotated[int, Field(strict=True, ge=0)]
UNKNOWN_AGE = (1 << 64) - 1
QUERY_BYTES = 48
RESPONSE_BYTES = 128


class EvidenceModel(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)


class CounterObservation(EvidenceModel):
    request: Positive
    session: Positive
    generation: Positive
    boot_id: Annotated[str, Field(pattern=r"^[0-9a-f]{32}$")]
    epoch: Positive
    counter: U64
    device_before_ns: U64
    device_after_ns: U64
    sample_rate_hz: Annotated[int, Field(strict=True, ge=520_833, le=61_440_000)]
    maximum_snapshot_age_ns: U64

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if self.device_after_ns < self.device_before_ns or int(self.boot_id, 16) == 0:
            raise ValueError("invalid counter observation identity or clock interval")
        return self

    @classmethod
    def unpack(cls, wire: bytes) -> CounterObservation:
        if len(wire) != RESPONSE_BYTES:
            raise ValueError("SCANTIME response size mismatch")
        if struct.unpack_from("<4sHHII", wire) != (b"SPTA", 1, 128, 255, 1):
            raise ValueError("SCANTIME response header mismatch")
        if zlib.crc32(wire[:-4]) != struct.unpack_from("<I", wire, 124)[0]:
            raise ValueError("SCANTIME response CRC mismatch")
        if any(wire[104:124]) or struct.unpack_from("<I", wire, 92)[0] != 64:
            raise ValueError("SCANTIME response reserved fields or counter width")
        request, session, generation = struct.unpack_from("<QQQ", wire, 16)
        epoch, counter, before, after, rate, _, age = struct.unpack_from("<QQQQIIQ", wire, 56)
        return cls(
            request=request,
            session=session,
            generation=generation,
            boot_id=wire[40:56].hex(),
            epoch=epoch,
            counter=counter,
            device_before_ns=before,
            device_after_ns=after,
            sample_rate_hz=rate,
            maximum_snapshot_age_ns=age,
        )


def pack_query(request: int, session: int, generation: int) -> bytes:
    if any(type(x) is not int or not 0 < x < 1 << 64 for x in (request, session, generation)):
        raise ValueError("SCANTIME query identity must contain nonzero uint64 values")
    wire = struct.pack("<4sHHIIQQQI", b"SPTQ", 1, 48, 255, 1, request, session, generation, 0)
    return wire + struct.pack("<I", zlib.crc32(wire))


class HostClock(EvidenceModel):
    monotonic_before_ns: U64
    realtime_ns: Positive
    monotonic_after_ns: U64
    source: str
    utc_error_bound_ns: Nonnegative | None
    reason: str
    tracking_csv: str | None = None

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if self.monotonic_after_ns < self.monotonic_before_ns:
            raise ValueError("host clock interval regressed")
        return self

    @property
    def offset(self) -> int:
        return self.realtime_ns - (self.monotonic_before_ns + self.monotonic_after_ns) // 2


class TimeAnchor(EvidenceModel):
    observation: CounterObservation
    send_monotonic_ns: U64
    receive_monotonic_ns: U64
    clock_before: HostClock
    clock_after: HostClock

    @model_validator(mode="after")
    def _ordered(self) -> Self:
        if not (
            self.clock_before.monotonic_after_ns
            <= self.send_monotonic_ns
            <= self.receive_monotonic_ns
            <= self.clock_after.monotonic_before_ns
        ):
            raise ValueError("counter query is not bracketed by host clock evidence")
        if (
            self.observation.device_after_ns - self.observation.device_before_ns
            > self.receive_monotonic_ns - self.send_monotonic_ns + 1_000_000
        ):
            raise ValueError("device observation interval exceeds host transaction")
        return self


class TimingPolicy(EvidenceModel):
    policy_id: Literal["counter-utc-100ms-v1"] = "counter-utc-100ms-v1"
    maximum_error_ns: Literal[100_000_000] = 100_000_000
    maximum_query_width_ns: Literal[50_000_000] = 50_000_000
    maximum_anchor_gap_ns: Positive = 10_000_000_000
    maximum_clock_step_ns: Positive = 1_000_000
    # Explicit calibration assumptions; defaults cannot qualify a capture.
    calibration_reference: str | None = None
    calibration_radio_serial: str | None = None
    calibration_boot_id: str | None = None
    maximum_rate_error_ppm: Annotated[int, Field(strict=True, ge=0, lt=1_000_000)] | None = None
    maximum_snapshot_age_ns: Nonnegative | None = None
    maximum_acquisition_delay_ns: Nonnegative | None = None


DEFAULT_TIMING_POLICY = TimingPolicy()


class CounterUtcEvidence(EvidenceModel):
    schema_version: Literal[1] = 1
    kind: Literal["adaptive-counter-utc"] = "adaptive-counter-utc"
    session: Positive
    generation: Positive
    radio_serial: str
    policy: TimingPolicy = DEFAULT_TIMING_POLICY
    anchors: tuple[TimeAnchor, ...] = ()
    errors: tuple[str, ...] = ()

    def _age(self, anchor: TimeAnchor) -> int:
        age: int | None = anchor.observation.maximum_snapshot_age_ns
        if age == UNKNOWN_AGE:
            age = self.policy.maximum_snapshot_age_ns
        if age is None:
            raise ValueError("counter snapshot age is not bounded")
        return age

    def interval(self, counter: int) -> tuple[int, int]:
        """UTC interval conditional on the recorded calibration bounds."""
        ppm = self.policy.maximum_rate_error_ppm
        delay = self.policy.maximum_acquisition_delay_ns
        if ppm is None or delay is None or not self.anchors:
            raise ValueError("sample clock/acquisition bounds or anchors are missing")
        intervals = []
        for anchor in self.anchors:
            clocks = (anchor.clock_before, anchor.clock_after)
            if any(c.utc_error_bound_ns is None for c in clocks):
                raise ValueError("host UTC source is unqualified")
            earliest_offset = min(
                c.realtime_ns - c.monotonic_after_ns - int(c.utc_error_bound_ns or 0)
                for c in clocks
            )
            latest_offset = max(
                c.realtime_ns - c.monotonic_before_ns + int(c.utc_error_bound_ns or 0)
                for c in clocks
            )
            delta = counter - anchor.observation.counter
            rate = anchor.observation.sample_rate_hz
            durations = [
                Fraction(delta * 10**15, rate * (1_000_000 + sign * ppm)) for sign in (-1, 1)
            ]
            lo = min(durations).__floor__()
            hi = max(durations).__ceil__()
            intervals.append(
                (
                    anchor.send_monotonic_ns + earliest_offset - self._age(anchor) + lo - delay,
                    anchor.receive_monotonic_ns + latest_offset + hi + delay,
                )
            )
        earliest, latest = max(x[0] for x in intervals), min(x[1] for x in intervals)
        if earliest > latest:
            raise ValueError("counter/UTC observations have contradictory intervals")
        return earliest, latest

    def qualification(self, first: int, last: int, rate: int) -> tuple[bool, str, int | None]:
        """Conservative bound for every sample, including between observations.

        Use one nominal affine map downstream. Each anchor bounds its intercept;
        add the maximum oscillator drift over the entire capture. This is more
        conservative than per-sample intersections and keeps consumers simple.
        """
        try:
            if self.errors:
                raise ValueError("timing collection reported errors: " + "; ".join(self.errors))
            if not 0 <= first <= last < 1 << 64:
                raise ValueError("capture counter interval is invalid")
            if not self.policy.calibration_reference:
                raise ValueError("hardware timing bounds lack a calibration reference")
            if not self.anchors:
                raise ValueError("no counter observations")
            origin = self.anchors[0].observation
            if (self.policy.calibration_radio_serial, self.policy.calibration_boot_id) != (
                self.radio_serial,
                origin.boot_id,
            ):
                raise ValueError("hardware calibration does not bind this radio boot")
            previous = None
            offsets: list[int] = []
            for anchor in self.anchors:
                o = anchor.observation
                if (o.session, o.generation, o.sample_rate_hz) != (
                    self.session,
                    self.generation,
                    rate,
                ):
                    raise ValueError("counter observation does not bind this capture")
                if (o.boot_id, o.epoch) != (origin.boot_id, origin.epoch):
                    raise ValueError("counter clock epoch changed")
                if previous is not None:
                    p = previous.observation
                    if o.request <= p.request or o.counter <= p.counter:
                        raise ValueError("counter observation is stale or regressed")
                    if o.device_before_ns < p.device_after_ns:
                        raise ValueError("device monotonic clock regressed")
                    if (
                        anchor.receive_monotonic_ns - previous.send_monotonic_ns
                        > self.policy.maximum_anchor_gap_ns
                    ):
                        raise ValueError("counter observation gap exceeded policy")
                previous = anchor
                if (
                    anchor.receive_monotonic_ns - anchor.send_monotonic_ns
                    > self.policy.maximum_query_width_ns
                ):
                    raise ValueError("counter query interval exceeded policy")
                offsets.extend((anchor.clock_before.offset, anchor.clock_after.offset))
                self.interval(o.counter)
            if max(offsets) - min(offsets) > self.policy.maximum_clock_step_ns:
                raise ValueError("host realtime/monotonic mapping changed")
            # No long unobserved prefix/suffix, even with a tiny claimed ppm.
            margin = self.policy.maximum_anchor_gap_ns * rate // 1_000_000_000
            if (
                abs(origin.counter - first) > margin
                or abs(self.anchors[-1].observation.counter - last) > margin
            ):
                raise ValueError("counter anchors do not cover capture endpoints")
            lo, hi = self.interval(first)
            self.interval(last)
            ppm = int(self.policy.maximum_rate_error_ppm or 0)
            drift = Fraction(
                (last - first) * 10**15 * ppm, rate * 1_000_000 * (1_000_000 - ppm)
            ).__ceil__()
            error = (hi - lo + 1) // 2 + drift
            if error > self.policy.maximum_error_ns:
                raise ValueError("whole-capture UTC uncertainty exceeded policy")
            return True, "counter/UTC intervals satisfy recorded timing bounds", error
        except ValueError as error:
            return False, str(error), None
