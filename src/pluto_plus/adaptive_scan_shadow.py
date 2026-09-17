"""Scanner adapter for feature-103 shadow and adaptive qualification."""

from __future__ import annotations

import dataclasses
import enum
import time
from collections.abc import Callable, Iterable
from typing import Protocol

from .adaptive_scan import (
    FeedbackResult,
    ScanAck,
    ScanFeedback,
    ScanOutcome,
    ScanSetup,
    ScanTerminal,
)
from .adaptive_scan_client import AdaptiveScanVisit
from .adaptive_scan_qualification import (
    AdaptiveScanAccumulator,
    AdaptiveScanGate,
    AdaptiveScanMetrics,
    primary_acceptance_gate,
)


class AdaptiveScanMode(enum.StrEnum):
    SHADOW = "shadow"
    ADAPTIVE = "adaptive"


Detector = Callable[[AdaptiveScanVisit], ScanOutcome]
ACK_DRAIN_WATERMARK = 32


class ScannerSession(Protocol):
    setup: ScanSetup
    terminal: ScanTerminal | None

    def visits(self) -> Iterable[AdaptiveScanVisit]: ...

    def submit_feedback(self, feedback: ScanFeedback) -> FeedbackResult: ...

    def take_ack(self) -> ScanAck: ...

    def try_take_ack(self) -> ScanAck | None: ...


@dataclasses.dataclass(frozen=True, slots=True)
class ScannerObservation:
    visit: int
    target: int
    outcome: ScanOutcome
    feedback: ScanFeedback | None
    receipt: FeedbackResult | None


@dataclasses.dataclass(frozen=True, slots=True)
class ScannerRunReport:
    mode: AdaptiveScanMode
    feedback_period_visits: int
    observations: tuple[ScannerObservation, ...]
    acknowledgements: tuple[ScanAck, ...]
    metrics: AdaptiveScanMetrics
    gate: AdaptiveScanGate


@dataclasses.dataclass(frozen=True, slots=True)
class WeightingEvidence:
    target: int
    application_visit: int
    before_visits: int
    after_visits: int
    before_share: float
    after_share: float

    @property
    def probability_increased(self) -> bool:
        return self.after_share > self.before_share


def weighting_evidence(report: ScannerRunReport, *, target: int) -> WeightingEvidence:
    """Measure selection share around the first applied active feedback boundary."""

    active_sequences = {
        item.feedback.sequence
        for item in report.observations
        if item.feedback is not None
        and item.feedback.target == target
        and item.feedback.outcome is ScanOutcome.ACTIVE
        and item.receipt is FeedbackResult.ACCEPTED
    }
    applied = next(
        (
            ack
            for ack in report.acknowledgements
            if ack.sequence in active_sequences and ack.result is FeedbackResult.APPLIED
        ),
        None,
    )
    if applied is None:
        raise ValueError("target has no applied active feedback")
    before = tuple(item for item in report.observations if item.visit < applied.first_visit)
    after = tuple(item for item in report.observations if item.visit >= applied.first_visit)
    if not before or not after:
        raise ValueError("weighting evidence requires visits on both sides of application")
    return WeightingEvidence(
        target=target,
        application_visit=applied.first_visit,
        before_visits=len(before),
        after_visits=len(after),
        before_share=sum(item.target == target for item in before) / len(before),
        after_share=sum(item.target == target for item in after) / len(after),
    )


def run_scanner_session(
    session: ScannerSession,
    detector: Detector,
    *,
    mode: AdaptiveScanMode,
    feedback_period_visits: int = 1,
    rejected_race_retries: int = 5,
    retry_delay_s: float = 0.001,
    sleeper: Callable[[float], None] = time.sleep,
) -> ScannerRunReport:
    """Run one stream; shadow mode constructs but never transmits feedback."""

    if (
        feedback_period_visits <= 0
        or rejected_race_retries < 0
        or not 0 <= retry_delay_s <= 0.1
    ):
        raise ValueError("feedback period or retry policy is invalid")
    accumulator = AdaptiveScanAccumulator(session.setup)
    observations: list[ScannerObservation] = []
    acknowledgements: list[ScanAck] = []
    accepted_count = 0

    def drain_ready_acknowledgements() -> None:
        while len(acknowledgements) < accepted_count:
            ack = session.try_take_ack()
            if ack is None:
                return
            acknowledgements.append(ack)

    sequence = 0
    complete_visits = 0
    for visit in session.visits():
        accumulator.add(visit)
        if accepted_count - len(acknowledgements) >= ACK_DRAIN_WATERMARK:
            drain_ready_acknowledgements()
        if not visit.iq:
            continue
        complete_visits += 1
        outcome = detector(visit)
        if not isinstance(outcome, ScanOutcome):
            raise TypeError("scanner detector must return ScanOutcome")
        feedback = None
        receipt = None
        if outcome is not ScanOutcome.UNKNOWN and complete_visits % feedback_period_visits == 0:
            sequence += 1
            feedback = ScanFeedback(
                session=session.setup.session,
                generation=session.setup.generation,
                sequence=sequence,
                visit=visit.record.visit,
                valid_start=visit.record.valid_start,
                valid_end=visit.record.valid_end,
                target=visit.record.target,
                outcome=outcome,
                analysis_digest=session.setup.analysis_digest,
            )
            if mode is AdaptiveScanMode.ADAPTIVE:
                receipt = session.submit_feedback(feedback)
                attempts = 0
                while receipt is FeedbackResult.REJECTED and attempts < rejected_race_retries:
                    sleeper(retry_delay_s)
                    receipt = session.submit_feedback(feedback)
                    attempts += 1
                if receipt is FeedbackResult.ACCEPTED:
                    accepted_count += 1
                    if accepted_count - len(acknowledgements) >= ACK_DRAIN_WATERMARK:
                        drain_ready_acknowledgements()
        observations.append(
            ScannerObservation(
                visit=visit.record.visit,
                target=visit.record.target,
                outcome=outcome,
                feedback=feedback,
                receipt=receipt,
            )
        )
    if session.terminal is None:
        raise RuntimeError("scanner stream ended without a terminal record")
    accepted = tuple(
        item
        for item in observations
        if item.feedback is not None and item.receipt is FeedbackResult.ACCEPTED
    )
    while len(acknowledgements) < len(accepted):
        acknowledgements.append(session.take_ack())
    expected = {
        item.feedback.sequence: (item.feedback.visit, item.feedback.target)
        for item in accepted
        if item.feedback is not None
    }
    observed = {
        ack.sequence: (ack.source_visit, ack.target) for ack in acknowledgements
    }
    if len(observed) != len(acknowledgements) or observed != expected:
        raise RuntimeError("feedback acknowledgements do not match accepted observations")
    metrics = accumulator.finish(session.terminal)
    return ScannerRunReport(
        mode=mode,
        feedback_period_visits=feedback_period_visits,
        observations=tuple(observations),
        acknowledgements=tuple(acknowledgements),
        metrics=metrics,
        gate=primary_acceptance_gate(metrics),
    )
