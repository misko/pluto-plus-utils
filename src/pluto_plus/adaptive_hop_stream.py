"""Bounded, source-attested adaptive visit reconstruction; no radio or storage IO.

This is an explicit V2 consumer, not a permissive mode of the fixed V1 session.
Only a following transition or successful terminal receipt closes a full dwell.
Callers own acquisition/cancellation, metadata extensions, and durable publication.
"""

from __future__ import annotations

import dataclasses
from collections import deque

import numpy as np
import numpy.typing as npt

from .adaptive_hop import (
    AdaptiveHopChoiceV2,
    AdaptiveHopEvidenceV2,
    AdaptiveHopRequestV2,
    AdaptiveHopStatusV2,
)
from .direct_radio.samples import ci16_dual_rx
from .persistent_hop import (
    PersistentHopClientError,
    PersistentHopEventKind,
    PersistentHopEventV1,
    PersistentHopProfileV1,
    PersistentHopSessionState,
    PersistentHopStatusFlag,
    PersistentHopTargetCoverageV1,
    PersistentHopWireBlock,
)

_NO_VISIT = (1 << 64) - 1
_LOST = PersistentHopStatusFlag.DEVICE_EVENT_OVERFLOW | PersistentHopStatusFlag.CONTINUITY_FAULT
_TERMINAL = {
    PersistentHopSessionState.COMPLETED,
    PersistentHopSessionState.CANCELLED,
    PersistentHopSessionState.FAILED,
}


@dataclasses.dataclass(frozen=True, slots=True)
class AdaptiveHopVisitV2:
    """An actual target and full valid interval; deliberately no sweep index."""

    event: PersistentHopEventV1
    choice: AdaptiveHopChoiceV2
    profile: PersistentHopProfileV1
    valid_end_counter_exclusive: int

    @property
    def valid_start_counter(self) -> int:
        return self.event.invalid_end_counter_exclusive

    @property
    def valid_sample_count(self) -> int:
        return self.valid_end_counter_exclusive - self.valid_start_counter


@dataclasses.dataclass(frozen=True, slots=True)
class AdaptiveHopSampledVisitV2:
    visit: AdaptiveHopVisitV2
    samples: npt.NDArray[np.complex64]

    def __post_init__(self) -> None:
        if self.samples.dtype != np.complex64 or self.samples.shape != (
            2,
            self.visit.valid_sample_count,
        ):
            raise ValueError("adaptive visit IQ disagrees with its dual-RX valid interval")


@dataclasses.dataclass(frozen=True, slots=True)
class AdaptiveHopStreamReceiptV2:
    """Stream facts, not proof of host cleanup, detector quality or publication.

    On cancellation, unclassified time is never reported as a complete dwell.
    Its unreceived suffix is explicit even if restoration occurs after last IQ.
    Both-RX samples count once in duty, not twice.
    """

    request: AdaptiveHopRequestV2
    status: AdaptiveHopStatusV2
    stream_generation: int | None
    visits: tuple[AdaptiveHopVisitV2, ...]
    events: tuple[PersistentHopEventV1, ...]
    choices: tuple[AdaptiveHopChoiceV2, ...]
    target_coverage: tuple[PersistentHopTargetCoverageV1, ...]
    valid_sample_count: int
    transition_invalid_sample_count: int
    unclassified_sample_count: int
    unreceived_tail_sample_count: int
    duty_denominator_sample_count: int
    valid_duty_ppm: int
    duty_target_met: bool
    source_span_attested: bool


class AdaptiveHopStreamV2:
    """Single-owner consumer. A malformed block permanently poisons the stream.

    Retains bounded IQ plus at most the requested 2,500 event/decision records.
    Returned arrays own their memory. No detector latency can block this object.
    """

    def __init__(
        self,
        request: AdaptiveHopRequestV2,
        *,
        samples_per_block: int,
        minimum_valid_duty_ppm: int = 900_000,
        maximum_event_lag_blocks: int = 2,
    ) -> None:
        request.pack()
        if (
            type(samples_per_block) is not int
            or not 0 < samples_per_block <= 1 << 24
            or type(minimum_valid_duty_ppm) is not int
            or not 0 <= minimum_valid_duty_ppm <= 1_000_000
            or type(maximum_event_lag_blocks) is not int
            or not 0 <= maximum_event_lag_blocks <= 8
        ):
            raise ValueError("invalid adaptive stream block/duty bounds")
        self.request = request
        self.samples_per_block = samples_per_block
        self.minimum_valid_duty_ppm = minimum_valid_duty_ppm
        # One dwell, the explicitly bounded delivery lag, and a boundary refill.
        self.maximum_retained_samples = (
            request.geometry.dwell_samples + (maximum_event_lag_blocks + 1) * samples_per_block
        )
        self._segments: deque[tuple[int, int, npt.NDArray[np.complex64]]] = deque()
        self._events: list[PersistentHopEventV1] = []
        self._choices: list[AdaptiveHopChoiceV2] = []
        self._visits: list[AdaptiveHopVisitV2] = []
        self._emitted = 0
        self._previous: AdaptiveHopEvidenceV2 | None = None
        self._first_block_counter: int | None = None
        self._generation: int | None = None
        self._failed = False
        self._receipt: AdaptiveHopStreamReceiptV2 | None = None

    @property
    def retained_sample_count(self) -> int:
        return sum(end - start for start, end, _ in self._segments)

    def feed(self, wire: PersistentHopWireBlock) -> tuple[AdaptiveHopSampledVisitV2, ...]:
        self._require_open()
        try:
            return self._feed(wire)
        except Exception:
            self._failed = True
            self._segments.clear()
            raise

    def _feed(self, wire: PersistentHopWireBlock) -> tuple[AdaptiveHopSampledVisitV2, ...]:
        evidence = AdaptiveHopEvidenceV2.unpack(wire.evidence)
        evidence.validate_binding(self.request)
        base = evidence.geometry
        previous = self._previous.geometry if self._previous is not None else None
        if base.flags & _LOST or base.state not in {PersistentHopSessionState.RUNNING, *_TERMINAL}:
            raise PersistentHopClientError("adaptive stream reports lost/invalid capture state")
        if previous is not None and previous.state in _TERMINAL:
            raise PersistentHopClientError("adaptive IQ arrived after terminal evidence")
        if base.buffer_sequence != (previous.buffer_sequence + 1 if previous else 0):
            raise PersistentHopClientError("adaptive block sequence is not contiguous")
        if (
            previous is not None
            and base.block_first_counter != previous.block_end_counter_exclusive
        ):
            raise PersistentHopClientError("adaptive block counters are not contiguous")
        count = base.block_end_counter_exclusive - base.block_first_counter
        if count > self.samples_per_block or len(wire.iq_payload) != count * 8:
            raise PersistentHopClientError("adaptive dual-RX IQ length disagrees with block bounds")
        generation = wire.stream_generation
        if type(generation) is not int or not 0 < generation < 1 << 64:
            raise PersistentHopClientError("adaptive ABI-3 stream generation is missing/invalid")
        if self._generation is not None and generation != self._generation:
            raise PersistentHopClientError("adaptive ABI-3 stream generation changed")
        if self._first_block_counter is None:
            self._first_block_counter = base.block_first_counter
        self._generation = generation
        for event, choice in zip(base.events, evidence.choices, strict=True):
            self._accept_event(event, choice)
        self._segments.append(
            (
                base.block_first_counter,
                base.block_end_counter_exclusive,
                ci16_dual_rx(wire.iq_payload),
            )
        )
        self._previous = evidence
        output = self._emit_ready()
        retain_from = (
            self._visits[self._emitted].valid_start_counter
            if self._emitted < len(self._visits)
            else self._events[-1].invalid_end_counter_exclusive
            if self._events
            else self._first_block_counter
        )
        self._trim(retain_from)
        if self.retained_sample_count > self.maximum_retained_samples:
            raise PersistentHopClientError("adaptive event delivery exceeded bounded IQ retention")
        return output

    def _accept_event(self, event: PersistentHopEventV1, choice: AdaptiveHopChoiceV2) -> None:
        index = len(self._events)
        geometry = self.request.geometry
        previous = self._events[-1] if self._events else None
        if (
            index >= geometry.dwell_count
            or event.event_sequence != index
            or event.dwell_index != index
            or event.kind
            != (PersistentHopEventKind.RETUNE if previous else PersistentHopEventKind.STARTUP)
            or event.from_profile_index != (previous.to_profile_index if previous else 255)
            or event.invalid_end_counter_exclusive + geometry.dwell_samples >= 1 << 64
        ):
            raise PersistentHopClientError("adaptive actual visit/event chain is invalid")
        if previous is None:
            if (
                self._first_block_counter is None
                or event.invalid_start_counter < self._first_block_counter
            ):
                raise PersistentHopClientError("adaptive startup precedes received IQ")
        elif (
            event.invalid_start_counter
            != previous.invalid_end_counter_exclusive + geometry.dwell_samples
            or event.device_event_id <= previous.device_event_id
            or choice.decision_counter < event.invalid_start_counter
            or event.invalid_start_counter - self._events[0].invalid_start_counter
            >= geometry.capture_span_samples
            or (self._choices[-1].basis_visit != _NO_VISIT and choice.basis_visit == _NO_VISIT)
            or (
                choice.basis_visit != _NO_VISIT
                and self._choices[-1].basis_visit != _NO_VISIT
                and choice.basis_visit < self._choices[-1].basis_visit
            )
        ):
            raise PersistentHopClientError(
                "adaptive cross-block dwell/decision continuity is invalid"
            )
        if choice.basis_visit != _NO_VISIT and (
            self._events[choice.basis_visit].invalid_end_counter_exclusive + geometry.dwell_samples
            > choice.decision_counter
        ):
            raise PersistentHopClientError("adaptive decision uses an unfinished source dwell")
        if previous is not None:
            self._close_visit(previous, self._choices[-1], event.invalid_start_counter)
        self._events.append(event)
        self._choices.append(choice)

    def _close_visit(
        self, event: PersistentHopEventV1, choice: AdaptiveHopChoiceV2, end: int
    ) -> None:
        if end - event.invalid_end_counter_exclusive != self.request.geometry.dwell_samples:
            raise PersistentHopClientError("adaptive visit is not a complete requested dwell")
        self._visits.append(
            AdaptiveHopVisitV2(
                event, choice, self.request.geometry.profiles[event.to_profile_index], end
            )
        )

    def _emit_ready(self) -> tuple[AdaptiveHopSampledVisitV2, ...]:
        output = []
        while self._emitted < len(self._visits):
            visit = self._visits[self._emitted]
            if not self._segments or self._segments[-1][1] < visit.valid_end_counter_exclusive:
                break
            pieces = tuple(
                samples[
                    :,
                    max(start, visit.valid_start_counter) - start : min(
                        end, visit.valid_end_counter_exclusive
                    )
                    - start,
                ]
                for start, end, samples in self._segments
                if end > visit.valid_start_counter and start < visit.valid_end_counter_exclusive
            )
            if sum(piece.shape[1] for piece in pieces) != visit.valid_sample_count:
                raise PersistentHopClientError(
                    "adaptive IQ does not cover the complete valid dwell"
                )
            samples = pieces[0].copy() if len(pieces) == 1 else np.concatenate(pieces, axis=1)
            output.append(AdaptiveHopSampledVisitV2(visit, samples))
            self._emitted += 1
            self._trim(visit.valid_end_counter_exclusive)
        return tuple(output)

    def _trim(self, first: int) -> None:
        while self._segments and self._segments[0][1] <= first:
            self._segments.popleft()
        if self._segments and self._segments[0][0] < first:
            start, end, samples = self._segments[0]
            self._segments[0] = (first, end, samples[:, first - start :])

    def finish(
        self, status: AdaptiveHopStatusV2
    ) -> tuple[AdaptiveHopStreamReceiptV2, tuple[AdaptiveHopSampledVisitV2, ...]]:
        self._require_open()
        try:
            return self._finish(status)
        except Exception:
            self._failed = True
            self._segments.clear()
            raise

    def _finish(
        self, wrapped: AdaptiveHopStatusV2
    ) -> tuple[AdaptiveHopStreamReceiptV2, tuple[AdaptiveHopSampledVisitV2, ...]]:
        wrapped.pack()
        status = wrapped.geometry
        geometry = self.request.geometry
        if (
            status.session_id != geometry.session_id
            or status.planned_dwells != geometry.dwell_count
            or status.state
            not in {PersistentHopSessionState.COMPLETED, PersistentHopSessionState.CANCELLED}
            or status.flags & _LOST
            or not status.flags & PersistentHopStatusFlag.RESTORE_SUCCEEDED
            or status.events_emitted != len(self._events)
            or status.visits_started != len(self._events)
        ):
            raise PersistentHopClientError(
                "adaptive terminal identity/inventory/restoration is invalid"
            )
        previous = self._previous.geometry if self._previous is not None else None
        if previous is not None and (
            status.last_block_sequence != previous.buffer_sequence
            or status.last_block_end_counter != previous.block_end_counter_exclusive
            or (
                previous.state in _TERMINAL
                and (
                    status.state != previous.state
                    or status.reason != previous.reason
                    or status.flags != previous.flags
                    or status.error_code != previous.error_code
                )
            )
        ):
            raise PersistentHopClientError(
                "adaptive terminal status disagrees with received blocks"
            )
        if previous is None and (
            self._events or status.last_block_end_counter or status.last_block_sequence
        ):
            raise PersistentHopClientError("adaptive terminal claims undelivered IQ")
        if self._events:
            first = self._events[0]
            if (
                status.first_counter,
                status.startup_invalid_start_counter,
                status.startup_invalid_end_counter_exclusive,
            ) != (
                first.invalid_start_counter,
                first.invalid_start_counter,
                first.invalid_end_counter_exclusive,
            ):
                raise PersistentHopClientError("adaptive terminal startup interval changed")
        # Before the first actual startup event, HOPT's first_counter may be
        # unset (zero) while final_counter is the absolute device clock. Their
        # difference is not an observed scan duration. Preserve raw HOPT but
        # make elapsed/duty accounting explicitly unavailable in that case.
        source_span_attested = bool(self._events)
        denominator = status.final_counter - status.first_counter if source_span_attested else 0
        if status.state == PersistentHopSessionState.COMPLETED:
            if previous is None or previous.state != status.state or not self._events:
                raise PersistentHopClientError("adaptive completion lacks terminal block/events")
            last = self._events[-1]
            overshoot = (
                geometry.dwell_samples
                + last.invalid_end_counter_exclusive
                - last.invalid_start_counter
            )
            if (
                not geometry.capture_span_samples
                <= denominator
                <= geometry.capture_span_samples + overshoot
                or not 0
                <= status.last_block_end_counter - status.final_counter
                <= self.samples_per_block
            ):
                raise PersistentHopClientError("adaptive completion duration/overshoot is invalid")
            self._close_visit(last, self._choices[-1], status.final_counter)
        output = self._emit_ready()
        if self._emitted != len(self._visits):
            raise PersistentHopClientError("adaptive terminal has undelivered complete visit IQ")
        valid = sum(visit.valid_sample_count for visit in self._visits)
        invalid = sum(
            max(
                0,
                min(status.final_counter, e.invalid_end_counter_exclusive)
                - max(status.first_counter, e.invalid_start_counter),
            )
            for e in self._events
        )
        unclassified = denominator - valid - invalid
        if unclassified < 0 or (
            status.state == PersistentHopSessionState.COMPLETED and unclassified
        ):
            raise PersistentHopClientError("adaptive spans do not partition terminal capture")
        duty = valid * 1_000_000 // denominator if denominator else 0
        coverage = tuple(
            PersistentHopTargetCoverageV1(
                target_index=profile.target_index,
                target=profile.target,
                visit_count=sum(
                    v.profile.target_index == profile.target_index for v in self._visits
                ),
                valid_sample_count=sum(
                    v.valid_sample_count
                    for v in self._visits
                    if v.profile.target_index == profile.target_index
                ),
            )
            for profile in geometry.profiles
        )
        receipt = AdaptiveHopStreamReceiptV2(
            self.request,
            wrapped,
            self._generation,
            tuple(self._visits),
            tuple(self._events),
            tuple(self._choices),
            coverage,
            valid,
            invalid,
            unclassified,
            max(
                0,
                status.final_counter
                - (status.last_block_end_counter if previous else status.first_counter),
            )
            if source_span_attested
            else 0,
            denominator,
            duty,
            duty >= self.minimum_valid_duty_ppm,
            source_span_attested,
        )
        self._receipt = receipt
        self._segments.clear()
        return receipt, output

    def _require_open(self) -> None:
        if self._failed or self._receipt is not None:
            raise PersistentHopClientError("adaptive stream is failed or already finished")
