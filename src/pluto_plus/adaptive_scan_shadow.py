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


class ScannerSession(Protocol):
    setup: ScanSetup
    terminal: ScanTerminal | None

    def visits(self) -> Iterable[AdaptiveScanVisit]: ...

    def submit_feedback(self, feedback: ScanFeedback) -> FeedbackResult: ...

    def take_ack(self) -> ScanAck: ...


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
    sequence = 0
    complete_visits = 0
    for visit in session.visits():
        accumulator.add(visit)
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
    acknowledgements = tuple(session.take_ack() for _item in accepted)
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
        acknowledgements=acknowledgements,
        metrics=metrics,
        gate=primary_acceptance_gate(metrics),
    )
