"""Actual-target IQ reconstruction over synthetic counters, never a radio."""

import dataclasses as dc
import math

import numpy as np
import pytest
from test_adaptive_hop import request
from test_persistent_hop import _active_status, _event

from pluto_plus.adaptive_hop import (
    AdaptiveHopChoiceV2,
    AdaptiveHopEvidenceV2,
    AdaptiveHopMode,
    AdaptiveHopStatusV2,
)
from pluto_plus.adaptive_hop_stream import AdaptiveHopStreamV2
from pluto_plus.persistent_hop import (
    PersistentHopClientError,
    PersistentHopEvidenceV1,
    PersistentHopProtocolError,
    PersistentHopWireBlock,
)
from pluto_plus.persistent_hop import (
    PersistentHopSessionState as State,
)
from pluto_plus.persistent_hop import (
    PersistentHopStatusFlag as Flag,
)
from pluto_plus.persistent_hop import (
    PersistentHopTerminalReason as Reason,
)

FIRST = (1 << 53) + 101
FLAGS = Flag.RESTORE_REQUIRED | Flag.TERMINAL | Flag.RESTORE_ATTEMPTED | Flag.RESTORE_SUCCEEDED


class Capture:
    def __init__(self, rate=2500000, mode=AdaptiveHopMode.ADAPTIVE, block=131072, delay=0):
        self.request = r = dc.replace(
            request(rate, mode),
            geometry=dc.replace(
                request(rate, mode).geometry, dwell_count=64, capture_span_samples=rate * 4
            ),
        )
        self.block, self.delay = block, delay
        self.events, self.choices = [], []
        counter = FIRST + 3
        while counter - FIRST - 3 < r.geometry.capture_span_samples:
            i = len(self.events)
            proposed = (0, 2, 3, 0, 2, 3, 0, 2, 3, 1)[i % 10]
            actual = i % 8 if mode == AdaptiveHopMode.SHADOW else proposed
            event = dc.replace(
                _event(sequence=i, dwell=i, invalid_start=counter),
                to_profile_index=actual,
                from_profile_index=self.events[-1].to_profile_index if i else 255,
                fastlock_slot=r.geometry.profiles[actual].fastlock_profile_index,
                actual_lo_frequency_hz=r.geometry.profiles[actual].lo_hz,
            )
            self.events.append(event)
            self.choices.append(
                AdaptiveHopChoiceV2(
                    counter,
                    i - 1 if i else (1 << 64) - 1,
                    0,
                    9,
                    proposed,
                    1,
                    13,
                    242,
                    0,
                    mode,
                )
            )
            counter = event.invalid_end_counter_exclusive + r.geometry.dwell_samples
        self.final = counter
        self.blocks = math.ceil((counter - FIRST) / block)

    def stream(self):
        return AdaptiveHopStreamV2(self.request, samples_per_block=self.block)

    def wires(self):
        next_event = 0
        for sequence in range(self.blocks):
            start = FIRST + sequence * self.block
            end = start + self.block
            events, choices = [], []
            while (
                next_event < len(self.events)
                and self.events[next_event].transition_after_counter < end - self.delay * self.block
            ):
                events.append(self.events[next_event])
                choices.append(self.choices[next_event])
                next_event += 1
            terminal = sequence + 1 == self.blocks
            assert not terminal or next_event == len(self.events)
            base = PersistentHopEvidenceV1(
                FLAGS if terminal else Flag.RESTORE_REQUIRED,
                self.request.geometry.session_id,
                sequence,
                start,
                end,
                State.COMPLETED if terminal else State.RUNNING,
                Reason.PLAN_COMPLETE if terminal else Reason.NONE,
                0,
                tuple(events),
            )
            iq = np.full((self.block, 4), 32767, dtype="<i2")
            for event in self.events:
                a = max(start, event.invalid_end_counter_exclusive)
                b = min(
                    end, event.invalid_end_counter_exclusive + self.request.geometry.dwell_samples
                )
                if a < b:
                    iq[a - start : b - start] = self.expected(a, b, event.to_profile_index)
            yield PersistentHopWireBlock(
                AdaptiveHopEvidenceV2(base, tuple(choices)).pack(), iq.tobytes(), 13
            )

    @staticmethod
    def expected(first, end, target):
        # Absolute counters are never converted to float, even above 2**53.
        x = (np.arange(end - first, dtype=np.int64) + first % 97) % 97 + target * 1000
        return np.column_stack((x, -x, x + 123, -x - 456)).astype("<i2")

    def status(self, *, sequence=None, cancelled=False, extra_tail=0):
        sequence = self.blocks - 1 if sequence is None else sequence
        end = FIRST + (sequence + 1) * self.block
        count = sum(e.transition_after_counter < end - self.delay * self.block for e in self.events)
        final = end + extra_tail if cancelled else self.final
        return AdaptiveHopStatusV2(
            dc.replace(
                _active_status(),
                session_id=self.request.geometry.session_id,
                planned_dwells=64,
                state=State.CANCELLED if cancelled else State.COMPLETED,
                reason=Reason.CLIENT_CLOSE if cancelled else Reason.PLAN_COMPLETE,
                flags=FLAGS,
                visits_started=count,
                events_emitted=count,
                next_event_sequence=count,
                first_counter=FIRST + 3,
                final_counter=final,
                last_block_sequence=sequence,
                last_block_end_counter=end,
                restore_before_counter=max(final, end),
                restore_after_counter=max(final, end) + 1,
                restored_lo_frequency_hz=915000000,
                startup_invalid_start_counter=FIRST + 3,
                startup_invalid_end_counter_exclusive=FIRST + 14,
            )
        )


def assert_sampled(capture, sampled):
    visit = sampled.visit
    words = capture.expected(
        visit.valid_start_counter, visit.valid_end_counter_exclusive, visit.event.to_profile_index
    )
    np.testing.assert_array_equal(sampled.samples[0], words[:, 0] + words[:, 1] * np.complex64(1j))
    np.testing.assert_array_equal(sampled.samples[1], words[:, 2] + words[:, 3] * np.complex64(1j))
    assert not hasattr(visit, "sweep_index")
    assert visit.profile.target_index == visit.event.to_profile_index


@pytest.mark.parametrize("rate", [2500000, 5000000])
@pytest.mark.parametrize("mode", list(AdaptiveHopMode))
@pytest.mark.parametrize("block,delay", [(131072, 0), (100003, 1), (131072, 2)])
def test_complete_dual_rx_iq_actual_targets_uneven_boundaries_and_delayed_events(
    rate, mode, block, delay
):
    capture = Capture(rate, mode, block, delay)
    stream = capture.stream()
    seen = []
    for wire in capture.wires():
        for sampled in stream.feed(wire):
            assert_sampled(capture, sampled)
            seen.append(sampled.visit)
        assert stream.retained_sample_count <= stream.maximum_retained_samples
    receipt, last = stream.finish(capture.status())
    for sampled in last:
        assert_sampled(capture, sampled)
        seen.append(sampled.visit)
    assert receipt.visits == tuple(seen) and len(seen) == len(capture.events) == 34
    assert receipt.events == tuple(capture.events)
    assert receipt.choices == tuple(capture.choices)
    assert receipt.stream_generation == 13
    assert receipt.valid_sample_count == 34 * rate * 120 // 1000
    assert (
        receipt.valid_sample_count + receipt.transition_invalid_sample_count
        == receipt.duty_denominator_sample_count
    )
    assert (
        receipt.valid_duty_ppm
        == receipt.valid_sample_count * 1000000 // receipt.duty_denominator_sample_count
    )
    assert receipt.duty_target_met and not receipt.unclassified_sample_count
    assert not receipt.unreceived_tail_sample_count and not stream.retained_sample_count
    for coverage in receipt.target_coverage:
        assert coverage.visit_count == sum(
            e.to_profile_index == coverage.target_index for e in capture.events
        )
    if mode == AdaptiveHopMode.SHADOW:
        assert any(v.choice.proposed_target != v.event.to_profile_index for v in seen)
    else:
        assert not receipt.target_coverage[4].visit_count
    with pytest.raises(PersistentHopClientError, match="finished"):
        stream.finish(capture.status())


@pytest.mark.parametrize("rate", [2500000, 5000000])
@pytest.mark.parametrize("sequence", [0, 7, 15])
@pytest.mark.parametrize("tail", [0, 103])
def test_cancel_retains_all_decisions_and_distinguishes_partial_from_full_dwell(
    rate, sequence, tail
):
    capture = Capture(rate)
    stream = capture.stream()
    seen = []
    for i, wire in enumerate(capture.wires()):
        seen.extend(stream.feed(wire))
        if i == sequence:
            break
    receipt, last = stream.finish(
        capture.status(sequence=sequence, cancelled=True, extra_tail=tail)
    )
    seen.extend(last)
    for sampled in seen:
        assert_sampled(capture, sampled)
    assert len(receipt.visits) + 1 == len(receipt.events)
    assert (
        receipt.valid_sample_count
        + receipt.transition_invalid_sample_count
        + receipt.unclassified_sample_count
        == receipt.duty_denominator_sample_count
    )
    assert receipt.unreceived_tail_sample_count == tail
    assert receipt.unclassified_sample_count >= tail


@pytest.mark.parametrize(
    "field,value",
    [
        ("stream_generation", None),
        ("stream_generation", 0),
        ("stream_generation", True),
        ("stream_generation", 1 << 64),
        ("iq_payload", b""),
        ("evidence", b"bad"),
    ],
)
def test_bad_block_latches_error_without_allowing_resume(field, value):
    capture = Capture()
    stream = capture.stream()
    first = next(capture.wires())
    with pytest.raises((PersistentHopClientError, PersistentHopProtocolError)):
        stream.feed(dc.replace(first, **{field: value}))
    assert not stream.retained_sample_count
    with pytest.raises(PersistentHopClientError, match="failed"):
        stream.feed(first)


@pytest.mark.parametrize(
    "fault",
    [
        "generation",
        "sequence",
        "counter",
        "previous_target",
        "device_id",
        "decision_time",
        "policy",
        "guard",
    ],
)
def test_cross_block_corruption_cannot_be_accepted(fault):
    capture = Capture()
    stream = capture.stream()
    for wire in capture.wires():
        evidence = AdaptiveHopEvidenceV2.unpack(wire.evidence)
        if evidence.geometry.events and evidence.geometry.events[0].dwell_index == 1:
            base = evidence.geometry
            if fault == "generation":
                wire = dc.replace(wire, stream_generation=14)
            elif fault == "sequence":
                wire = dc.replace(
                    wire,
                    evidence=dc.replace(
                        evidence, geometry=dc.replace(base, buffer_sequence=99)
                    ).pack(),
                )
            elif fault == "counter":
                wire = dc.replace(
                    wire,
                    evidence=dc.replace(
                        evidence,
                        geometry=dc.replace(
                            base,
                            block_first_counter=base.block_first_counter + 1,
                            block_end_counter_exclusive=base.block_end_counter_exclusive + 1,
                        ),
                    ).pack(),
                )
            else:
                event, choice = base.events[0], evidence.choices[0]
                if fault == "previous_target":
                    event = dc.replace(event, from_profile_index=7)
                elif fault == "device_id":
                    event = dc.replace(event, device_event_id=1)
                elif fault == "decision_time":
                    choice = dc.replace(choice, decision_counter=choice.decision_counter - 1)
                elif fault == "policy":
                    choice = dc.replace(choice, generation=10)
                else:
                    event = dc.replace(
                        event, invalid_end_counter_exclusive=event.invalid_end_counter_exclusive + 1
                    )
                wire = dc.replace(
                    wire,
                    evidence=dc.replace(
                        evidence,
                        geometry=dc.replace(base, events=(event,)),
                        choices=(choice,),
                    ).pack(),
                )
            with pytest.raises((PersistentHopClientError, PersistentHopProtocolError)):
                stream.feed(wire)
            break
        stream.feed(wire)
    else:
        pytest.fail("fixture never delivered its second event")


@pytest.mark.parametrize(
    "field,delta",
    [
        ("session_id", 1),
        ("planned_dwells", 1),
        ("last_block_sequence", 1),
        ("last_block_end_counter", 1),
        ("first_counter", 1),
        ("startup_invalid_end_counter_exclusive", 1),
        ("final_counter", -1),
        ("device_dropped_events", 1),
    ],
)
def test_corrupt_terminal_cannot_publish_success(field, delta):
    capture = Capture()
    stream = capture.stream()
    for wire in capture.wires():
        stream.feed(wire)
    status = capture.status()
    status = dc.replace(
        status,
        geometry=dc.replace(status.geometry, **{field: getattr(status.geometry, field) + delta}),
    )
    with pytest.raises((PersistentHopClientError, PersistentHopProtocolError)):
        stream.finish(status)


def test_missing_events_exhaust_explicit_retention_bound():
    capture = Capture()
    stream = capture.stream()
    with pytest.raises(PersistentHopClientError, match="bounded"):
        for wire in capture.wires():
            evidence = AdaptiveHopEvidenceV2.unpack(wire.evidence)
            stream.feed(
                dc.replace(
                    wire,
                    evidence=dc.replace(
                        evidence,
                        geometry=dc.replace(evidence.geometry, events=()),
                        choices=(),
                    ).pack(),
                )
            )
    assert not stream.retained_sample_count


@pytest.mark.parametrize(
    "kwargs",
    [
        dict(samples_per_block=True),
        dict(samples_per_block=0),
        dict(maximum_event_lag_blocks=9),
        dict(minimum_valid_duty_ppm=-1),
    ],
)
def test_invalid_resource_bounds_fail_before_processing(kwargs):
    with pytest.raises(ValueError):
        AdaptiveHopStreamV2(request(), **(dict(samples_per_block=131072) | kwargs))
