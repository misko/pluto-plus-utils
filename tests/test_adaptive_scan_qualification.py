from __future__ import annotations

import pytest

from pluto_plus.adaptive_scan import (
    ScanSetup,
    ScanTarget,
    ScanTerminal,
    ScanVisit,
    TerminalState,
    VisitResult,
)
from pluto_plus.adaptive_scan_client import AdaptiveScanVisit
from pluto_plus.adaptive_scan_qualification import (
    AdaptiveScanAccumulator,
    AdaptiveScanQualificationError,
    primary_acceptance_gate,
)


def _setup(rate: int, dwell_ms: int = 240, rx_mask: int = 1) -> ScanSetup:
    return ScanSetup(
        session=1,
        generation=2,
        seed=3,
        source_rate_hz=rate,
        analog_bandwidth_hz=8_000_000,
        duration_ms=2_000,
        dwell_ms=dwell_ms,
        transition_budget_ms=10,
        maximum_revisit_ms=1_000,
        feedback_age_ms=1_000,
        application_delay_ms=1_000,
        decay_ms=5_000,
        maximum_boost=3,
        maximum_queue_bytes=200_000_000,
        maximum_queue_age_ms=5_000,
        maximum_queue_visits=50,
        analysis_digest=bytes(range(1, 33)),
        targets=(ScanTarget(1, 0, 2_400_000_000, 1, 0x12345678),),
        rx_mask=rx_mask,
    )


def _stream(
    setup: ScanSetup, *, visits: int, delivered: int, transition_samples: int
) -> tuple[list[ScanVisit], ScanTerminal]:
    cursor = 10_000
    records: list[ScanVisit] = []
    dwell_samples = setup.source_rate_hz * setup.dwell_ms // 1_000
    for index in range(visits):
        before = cursor
        start = before + transition_samples
        end = start + dwell_samples
        result = VisitResult.COMPLETE if index < delivered else VisitResult.SKIP_CAPACITY
        iq_bytes = (
            dwell_samples * 4 * setup.rx_mask.bit_count()
            if result is VisitResult.COMPLETE
            else 0
        )
        record = ScanVisit(
            session=setup.session,
            generation=setup.generation,
            visit=index,
            selection_counter=before,
            transition_before=before,
            transition_after=start,
            valid_start=start,
            valid_end=end,
            frequency_hz=setup.targets[0].frequency_hz,
            iq_bytes=iq_bytes,
            missing_samples_before=0,
            analog_bandwidth_hz=setup.analog_bandwidth_hz,
            source_rate_hz=setup.source_rate_hz,
            target=0,
            profile=0,
            result=result,
            eligible_mask=1,
            effective_weight=65_536,
            profile_crc32=setup.targets[0].profile_crc32,
        )
        records.append(record)
        cursor = end
    terminal = ScanTerminal(
        session=setup.session,
        generation=setup.generation,
        final_counter=cursor,
        restore_before=cursor,
        restore_after=cursor + 1,
        planned=visits,
        delivered=delivered,
        skipped=visits - delivered,
        invalid=0,
        cancelled=0,
        iq_bytes=delivered * dwell_samples * 4 * setup.rx_mask.bit_count(),
        state=TerminalState.COMPLETED,
        reason=1,
        error=0,
    )
    return records, terminal


@pytest.mark.parametrize(
    ("rate", "dwell_ms", "visits", "delivered", "transition_ms", "passed"),
    [
        (10_000_000, 240, 100, 100, 10, True),
        (10_000_000, 240, 100, 98, 5, True),
        (10_000_000, 240, 100, 97, 10, False),
        (10_000_000, 120, 101, 101, 10, True),
        (10_000_000, 120, 100, 99, 10, False),
        (15_000_000, 240, 100, 98, 10, True),
        (15_000_000, 240, 100, 93, 10, False),
        (20_000_000, 240, 100, 1, 10, True),
        (30_000_000, 240, 100, 1, 10, True),
    ],
)
def test_primary_acceptance_gates_are_exact(
    rate, dwell_ms, visits, delivered, transition_ms, passed
) -> None:
    setup = _setup(rate, dwell_ms)
    records, terminal = _stream(
        setup,
        visits=visits,
        delivered=delivered,
        transition_samples=rate * transition_ms // 1_000,
    )
    accumulator = AdaptiveScanAccumulator(setup)
    for record in records:
        accumulator.observe(record, record.iq_bytes)
    metrics = accumulator.finish(terminal)

    assert primary_acceptance_gate(metrics).passed is passed
    assert metrics.iq_bytes == metrics.delivered_valid_samples * 4
    assert sum(metrics.target_visits) == metrics.planned


def test_metrics_reject_terminal_or_iq_inconsistency() -> None:
    setup = _setup(10_000_000)
    records, terminal = _stream(setup, visits=2, delivered=2, transition_samples=100_000)
    accumulator = AdaptiveScanAccumulator(setup)
    accumulator.observe(records[0], records[0].iq_bytes)
    with pytest.raises(AdaptiveScanQualificationError, match="accounting"):
        accumulator.finish(terminal)

    accumulator = AdaptiveScanAccumulator(setup)
    with pytest.raises(AdaptiveScanQualificationError, match="IQ payload"):
        accumulator.add(AdaptiveScanVisit(records[0], b""))


def test_dual_rx_metrics_count_payload_twice_but_duty_once() -> None:
    setup = _setup(2_500_000, dwell_ms=120, rx_mask=3)
    records, terminal = _stream(
        setup, visits=4, delivered=4, transition_samples=50_000
    )
    accumulator = AdaptiveScanAccumulator(setup)
    for record in records:
        accumulator.observe(record, record.iq_bytes)
    metrics = accumulator.finish(terminal)

    assert metrics.iq_bytes == metrics.delivered_valid_samples * 8
    assert metrics.full_session_retained_duty == pytest.approx(120 / 140)


def test_zero_length_cancelled_cleanup_record_is_valid() -> None:
    setup = _setup(20_000_000, dwell_ms=120)
    records, _ = _stream(setup, visits=1, delivered=1, transition_samples=400_000)
    complete = records[0]
    cancelled = ScanVisit(
        session=setup.session,
        generation=setup.generation,
        visit=1,
        selection_counter=complete.valid_end,
        transition_before=complete.valid_end,
        transition_after=complete.valid_end,
        valid_start=complete.valid_end,
        valid_end=complete.valid_end,
        frequency_hz=setup.targets[0].frequency_hz,
        iq_bytes=0,
        missing_samples_before=0,
        analog_bandwidth_hz=setup.analog_bandwidth_hz,
        source_rate_hz=setup.source_rate_hz,
        target=0,
        profile=0,
        result=VisitResult.CANCELLED,
        eligible_mask=1,
        effective_weight=65_536,
        profile_crc32=setup.targets[0].profile_crc32,
    )
    terminal = ScanTerminal(
        session=setup.session,
        generation=setup.generation,
        final_counter=complete.valid_end + 1,
        restore_before=complete.valid_end,
        restore_after=complete.valid_end + 1,
        planned=2,
        delivered=1,
        skipped=0,
        invalid=0,
        cancelled=1,
        iq_bytes=complete.iq_bytes,
        state=TerminalState.COMPLETED,
        reason=1,
        error=0,
    )

    accumulator = AdaptiveScanAccumulator(setup)
    accumulator.observe(complete, complete.iq_bytes)
    accumulator.observe(cancelled, 0)
    metrics = accumulator.finish(terminal)

    assert metrics.planned_valid_samples == setup.source_rate_hz * setup.dwell_ms // 1_000
    assert metrics.cancelled == 1
