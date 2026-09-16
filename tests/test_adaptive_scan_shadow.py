from __future__ import annotations

from dataclasses import replace

import pytest

from pluto_plus.adaptive_scan import (
    FeedbackResult,
    ScanAck,
    ScanOutcome,
    ScanSetup,
    ScanTarget,
    ScanTerminal,
    ScanVisit,
    TerminalState,
    VisitResult,
)
from pluto_plus.adaptive_scan_client import AdaptiveScanVisit
from pluto_plus.adaptive_scan_shadow import AdaptiveScanMode, run_scanner_session


def _setup() -> ScanSetup:
    return ScanSetup(
        session=10,
        generation=20,
        seed=30,
        source_rate_hz=10_000_000,
        analog_bandwidth_hz=8_000_000,
        duration_ms=1_000,
        dwell_ms=20,
        transition_budget_ms=1,
        maximum_revisit_ms=100,
        feedback_age_ms=100,
        application_delay_ms=100,
        decay_ms=500,
        maximum_boost=3,
        maximum_queue_bytes=10_000_000,
        maximum_queue_age_ms=500,
        maximum_queue_visits=8,
        analysis_digest=bytes(range(1, 33)),
        targets=(
            ScanTarget(1, 0, 2_400_000_000, 1, 0x11111111),
            ScanTarget(2, 1, 2_500_000_000, 1, 0x22222222),
        ),
    )


def _visits(setup: ScanSetup) -> list[AdaptiveScanVisit]:
    result = []
    cursor = 1_000
    samples = setup.source_rate_hz * setup.dwell_ms // 1_000
    for index in range(4):
        target = index % 2
        start = cursor + 10_000
        end = start + samples
        iq = bytes(samples * 4)
        item = setup.targets[target]
        record = ScanVisit(
            session=setup.session,
            generation=setup.generation,
            visit=index,
            selection_counter=cursor,
            transition_before=cursor,
            transition_after=start,
            valid_start=start,
            valid_end=end,
            frequency_hz=item.frequency_hz,
            iq_bytes=len(iq),
            missing_samples_before=0,
            analog_bandwidth_hz=setup.analog_bandwidth_hz,
            source_rate_hz=setup.source_rate_hz,
            target=target,
            profile=item.profile,
            result=VisitResult.COMPLETE,
            eligible_mask=3,
            effective_weight=65_536,
            profile_crc32=item.profile_crc32,
        )
        result.append(AdaptiveScanVisit(record, iq))
        cursor = end
    return result


class Session:
    def __init__(self, *, reject_first: bool = False) -> None:
        self.setup = _setup()
        self.items = _visits(self.setup)
        self.sent = []
        self.reject_first = reject_first
        self.attempts = {}
        self.terminal = None

    def visits(self):
        yield from self.items
        final = self.items[-1].record.valid_end
        self.terminal = ScanTerminal(
            session=self.setup.session,
            generation=self.setup.generation,
            final_counter=final,
            restore_before=final,
            restore_after=final + 1,
            planned=4,
            delivered=4,
            skipped=0,
            invalid=0,
            cancelled=0,
            iq_bytes=sum(len(item.iq) for item in self.items),
            state=TerminalState.COMPLETED,
            reason=1,
            error=0,
        )

    def submit_feedback(self, feedback):
        self.attempts[feedback.sequence] = self.attempts.get(feedback.sequence, 0) + 1
        if self.reject_first and self.attempts[feedback.sequence] == 1:
            return FeedbackResult.REJECTED
        self.sent.append(feedback)
        return FeedbackResult.ACCEPTED

    def take_ack(self):
        feedback = self.sent[len(getattr(self, "acks", []))]
        if not hasattr(self, "acks"):
            self.acks = []
        ack = ScanAck(
            sequence=feedback.sequence,
            source_visit=feedback.visit,
            first_visit=feedback.visit + 1,
            received_counter=feedback.valid_end + 1,
            application_counter=feedback.valid_end + 2,
            target=feedback.target,
            result=FeedbackResult.APPLIED,
            old_boost=65_536,
            new_boost=196_608,
        )
        self.acks.append(ack)
        return ack


def _detector(visit: AdaptiveScanVisit) -> ScanOutcome:
    return ScanOutcome.ACTIVE if visit.record.target == 1 else ScanOutcome.QUIET


def test_shadow_observes_identical_decisions_without_transmission() -> None:
    session = Session()
    report = run_scanner_session(
        session, _detector, mode=AdaptiveScanMode.SHADOW, feedback_period_visits=2
    )

    assert not session.sent
    assert [item.outcome for item in report.observations] == [
        ScanOutcome.QUIET,
        ScanOutcome.ACTIVE,
        ScanOutcome.QUIET,
        ScanOutcome.ACTIVE,
    ]
    assert [item.feedback.sequence for item in report.observations if item.feedback] == [1, 2]
    assert all(item.receipt is None for item in report.observations)


def test_adaptive_transmits_periodic_source_bound_feedback() -> None:
    session = Session()
    report = run_scanner_session(
        session, _detector, mode=AdaptiveScanMode.ADAPTIVE, feedback_period_visits=2
    )

    assert session.sent == [
        item.feedback for item in report.observations if item.feedback is not None
    ]
    assert all(
        item.receipt is FeedbackResult.ACCEPTED
        for item in report.observations
        if item.feedback
    )
    assert [ack.sequence for ack in report.acknowledgements] == [1, 2]


def test_adaptive_retries_narrow_post_delivery_completion_race() -> None:
    session = Session(reject_first=True)
    report = run_scanner_session(
        session,
        _detector,
        mode=AdaptiveScanMode.ADAPTIVE,
        feedback_period_visits=2,
        sleeper=lambda _delay: None,
    )
    assert session.attempts == {1: 2, 2: 2}
    assert [item.receipt for item in report.observations if item.feedback] == [
        FeedbackResult.ACCEPTED,
        FeedbackResult.ACCEPTED,
    ]
    assert all(
        feedback.analysis_digest == session.setup.analysis_digest
        and feedback.valid_start == session.items[feedback.visit].record.valid_start
        for feedback in session.sent
    )


def test_unknown_is_not_conflated_with_quiet_and_bad_detector_fails() -> None:
    session = Session()
    report = run_scanner_session(
        session,
        lambda _visit: ScanOutcome.UNKNOWN,
        mode=AdaptiveScanMode.ADAPTIVE,
    )
    assert not session.sent
    assert all(item.feedback is None for item in report.observations)

    bad = Session()
    with pytest.raises(TypeError, match="ScanOutcome"):
        run_scanner_session(bad, lambda _visit: 1, mode=AdaptiveScanMode.SHADOW)


def test_noncompleted_terminal_cannot_qualify() -> None:
    session = Session()
    original = session.visits

    def visits():
        yield from original()
        assert session.terminal is not None
        session.terminal = replace(
            session.terminal,
            state=TerminalState.FAILED,
            error=-5,
            restore_before=0,
            restore_after=0,
        )

    session.visits = visits
    with pytest.raises(ValueError, match="did not complete"):
        run_scanner_session(session, _detector, mode=AdaptiveScanMode.SHADOW)
