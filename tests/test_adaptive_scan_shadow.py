from __future__ import annotations

import struct
import threading
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
from pluto_plus.adaptive_scan_shadow import (
    AdaptiveScanMode,
    ScannerObservation,
    run_scanner_session,
    weighting_evidence,
)


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

    def try_take_ack(self):
        if len(getattr(self, "acks", [])) >= len(self.sent):
            return None
        return self.take_ack()


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
        item.receipt is FeedbackResult.ACCEPTED for item in report.observations if item.feedback
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


def test_long_adaptive_run_drains_bounded_ack_mailbox_during_stream() -> None:
    class LongSession(Session):
        def __init__(self) -> None:
            super().__init__()
            self.setup = replace(self.setup, duration_ms=3_000)
            template = _visits(self.setup)[0]
            samples = self.setup.source_rate_hz * self.setup.dwell_ms // 1_000
            iq = template.iq
            cursor = 1_000
            self.items = []
            for index in range(100):
                start = cursor + self.setup.source_rate_hz // 1_000
                end = start + samples
                record = replace(
                    template.record,
                    visit=index,
                    selection_counter=cursor,
                    transition_before=cursor,
                    transition_after=start,
                    valid_start=start,
                    valid_end=end,
                    iq_bytes=len(iq),
                )
                self.items.append(AdaptiveScanVisit(record, iq))
                cursor = end

        def visits(self):
            yield from self.items
            final = self.items[-1].record.valid_end
            self.terminal = ScanTerminal(
                session=self.setup.session,
                generation=self.setup.generation,
                final_counter=final,
                restore_before=final,
                restore_after=final + 1,
                planned=len(self.items),
                delivered=len(self.items),
                skipped=0,
                invalid=0,
                cancelled=0,
                iq_bytes=sum(len(item.iq) for item in self.items),
                state=TerminalState.COMPLETED,
                reason=1,
                error=0,
            )

        def submit_feedback(self, feedback):
            if len(self.sent) - len(getattr(self, "acks", [])) >= 64:
                return FeedbackResult.MAILBOX_FULL
            return super().submit_feedback(feedback)

    session = LongSession()
    report = run_scanner_session(
        session,
        lambda _visit: ScanOutcome.ACTIVE,
        mode=AdaptiveScanMode.ADAPTIVE,
        classifier_queue_visits=128,
    )

    assert len(session.sent) == 100
    assert len(report.acknowledgements) == 100
    assert all(item.receipt is FeedbackResult.ACCEPTED for item in report.observations)


def test_weighting_evidence_uses_firmware_application_boundary() -> None:
    session = Session()
    report = run_scanner_session(
        session, _detector, mode=AdaptiveScanMode.ADAPTIVE, feedback_period_visits=2
    )
    observations = report.observations + tuple(
        ScannerObservation(
            visit=visit,
            target=1,
            outcome=ScanOutcome.ACTIVE,
            feedback=None,
            receipt=None,
        )
        for visit in range(4, 10)
    )
    evidence = weighting_evidence(
        replace(report, observations=observations),
        target=1,
    )
    assert evidence.application_visit == 2
    assert evidence.before_share == 0.5
    assert evidence.after_share == 0.875
    assert evidence.probability_increased
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


def test_dual_rx_classifier_receives_only_receiver_id_one() -> None:
    session = Session()
    session.setup = replace(
        session.setup,
        source_rate_hz=2_500_000,
        analog_bandwidth_hz=2_500_000,
        rx_mask=3,
    )
    samples = session.setup.source_rate_hz * session.setup.dwell_ms // 1_000
    frame = struct.pack("<hhhh", 101, -102, 3001, -3002)
    iq = frame * samples
    session.items = [
        AdaptiveScanVisit(replace(item.record, iq_bytes=len(iq)), iq)
        for item in _visits(session.setup)
    ]

    def detector(visit: AdaptiveScanVisit) -> ScanOutcome:
        assert visit.record.iq_bytes == samples * 4
        assert len(visit.iq) == samples * 4
        assert visit.iq[:4] == struct.pack("<hh", 3001, -3002)
        assert struct.pack("<hh", 101, -102) not in visit.iq[:4]
        return ScanOutcome.ACTIVE

    report = run_scanner_session(session, detector, mode=AdaptiveScanMode.SHADOW)
    assert report.classification_dropped == 0


def test_blocked_classifier_does_not_block_iq_stream_drain() -> None:
    class DrainSession(Session):
        def __init__(self) -> None:
            super().__init__()
            self.setup = replace(
                self.setup,
                source_rate_hz=2_500_000,
                analog_bandwidth_hz=2_500_000,
                duration_ms=1_000,
            )
            template = _visits(self.setup)[0]
            samples = self.setup.source_rate_hz * self.setup.dwell_ms // 1_000
            cursor = 1_000
            self.items = []
            for index in range(20):
                start = cursor + self.setup.source_rate_hz // 1_000
                end = start + samples
                record = replace(
                    template.record,
                    visit=index,
                    selection_counter=cursor,
                    transition_before=cursor,
                    transition_after=start,
                    valid_start=start,
                    valid_end=end,
                )
                self.items.append(AdaptiveScanVisit(record, template.iq))
                cursor = end
            self.stream_drained = threading.Event()

        def visits(self):
            yield from self.items
            final = self.items[-1].record.valid_end
            self.terminal = ScanTerminal(
                session=self.setup.session,
                generation=self.setup.generation,
                final_counter=final,
                restore_before=final,
                restore_after=final + 1,
                planned=len(self.items),
                delivered=len(self.items),
                skipped=0,
                invalid=0,
                cancelled=0,
                iq_bytes=sum(len(item.iq) for item in self.items),
                state=TerminalState.COMPLETED,
                reason=1,
                error=0,
            )
            self.stream_drained.set()

    session = DrainSession()
    detector_started = threading.Event()
    release_detector = threading.Event()
    result = []
    errors = []

    def detector(_visit: AdaptiveScanVisit) -> ScanOutcome:
        detector_started.set()
        if not release_detector.wait(5):
            raise TimeoutError("test did not release classifier")
        return ScanOutcome.ACTIVE

    def run() -> None:
        try:
            result.append(
                run_scanner_session(
                    session,
                    detector,
                    mode=AdaptiveScanMode.SHADOW,
                    classifier_queue_visits=2,
                )
            )
        except BaseException as error:
            errors.append(error)

    thread = threading.Thread(target=run)
    thread.start()
    assert detector_started.wait(2)
    assert session.stream_drained.wait(2)
    release_detector.set()
    thread.join(5)

    assert not thread.is_alive() and not errors
    assert result[0].classification_dropped > 0
