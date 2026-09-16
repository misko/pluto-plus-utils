"""Scanner adapter for feature-103 shadow and adaptive qualification."""

from __future__ import annotations

import dataclasses
import enum
from collections.abc import Callable, Iterable
from typing import Protocol

from .adaptive_scan import FeedbackResult, ScanFeedback, ScanOutcome, ScanSetup, ScanTerminal
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
    metrics: AdaptiveScanMetrics
    gate: AdaptiveScanGate


def run_scanner_session(
    session: ScannerSession,
    detector: Detector,
    *,
    mode: AdaptiveScanMode,
    feedback_period_visits: int = 1,
) -> ScannerRunReport:
    """Run one stream; shadow mode constructs but never transmits feedback."""

    if feedback_period_visits <= 0:
        raise ValueError("feedback period must be positive")
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
    metrics = accumulator.finish(session.terminal)
    return ScannerRunReport(
        mode=mode,
        feedback_period_visits=feedback_period_visits,
        observations=tuple(observations),
        metrics=metrics,
        gate=primary_acceptance_gate(metrics),
    )
