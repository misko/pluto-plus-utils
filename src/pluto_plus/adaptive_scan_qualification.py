"""Source-counter-derived qualification metrics for feature-request #103."""

from __future__ import annotations

import dataclasses
from collections import Counter

from .adaptive_scan import ScanSetup, ScanTerminal, ScanVisit, TerminalState, VisitResult
from .adaptive_scan_client import AdaptiveScanVisit


class AdaptiveScanQualificationError(ValueError):
    """A stream cannot support a trustworthy qualification result."""


@dataclasses.dataclass(frozen=True, slots=True)
class AdaptiveScanMetrics:
    source_rate_hz: int
    dwell_ms: int
    first_counter: int
    final_counter: int
    source_span_samples: int
    planned_valid_samples: int
    delivered_valid_samples: int
    iq_bytes: int
    planned: int
    delivered: int
    skipped: int
    invalid: int
    cancelled: int
    deadline_forced: int
    target_visits: tuple[int, ...]

    @property
    def full_session_retained_duty(self) -> float:
        return self.delivered_valid_samples / self.source_span_samples

    @property
    def planned_valid_delivery(self) -> float:
        return self.delivered_valid_samples / self.planned_valid_samples

    @property
    def payload_bytes_per_second(self) -> float:
        return self.iq_bytes * self.source_rate_hz / self.source_span_samples


@dataclasses.dataclass(frozen=True, slots=True)
class AdaptiveScanGate:
    name: str
    passed: bool
    observed: float
    threshold: float | None
    comparison: str


class AdaptiveScanAccumulator:
    """Accumulate records only; IQ contents never enter the metric arithmetic."""

    def __init__(self, setup: ScanSetup) -> None:
        setup.validate()
        self.setup = setup
        self._records: list[ScanVisit] = []
        self._iq_bytes = 0

    def add(self, visit: AdaptiveScanVisit) -> None:
        self.observe(visit.record, len(visit.iq))

    def observe(self, record: ScanVisit, iq_bytes: int) -> None:
        """Record validated stream geometry without retaining the IQ allocation."""

        if iq_bytes != record.iq_bytes:
            raise AdaptiveScanQualificationError("IQ payload length disagrees with visit")
        expected_samples = self.setup.source_rate_hz * self.setup.dwell_ms // 1_000
        valid_samples = record.valid_end - record.valid_start
        expected_intervals: tuple[int, ...]
        if record.result is VisitResult.CANCELLED:
            expected_intervals = (0, expected_samples)
        else:
            expected_intervals = (expected_samples,)
        if valid_samples not in expected_intervals:
            raise AdaptiveScanQualificationError("visit valid interval disagrees with dwell")
        self._records.append(record)
        self._iq_bytes += iq_bytes

    def finish(self, terminal: ScanTerminal) -> AdaptiveScanMetrics:
        if terminal.state is not TerminalState.COMPLETED:
            raise AdaptiveScanQualificationError(
                "qualification session did not complete: "
                f"state={terminal.state.name} reason={terminal.reason} error={terminal.error} "
                f"planned={terminal.planned} delivered={terminal.delivered} "
                f"skipped={terminal.skipped} invalid={terminal.invalid} "
                f"cancelled={terminal.cancelled}"
            )
        if not self._records:
            raise AdaptiveScanQualificationError("qualification session returned no visits")
        first = self._records[0].transition_before
        if terminal.final_counter <= first:
            raise AdaptiveScanQualificationError("qualification source span is empty")
        dwell_samples = self.setup.source_rate_hz * self.setup.dwell_ms // 1_000
        planned_valid = dwell_samples * sum(
            item.result is not VisitResult.CANCELLED for item in self._records
        )
        delivered_valid = sum(
            item.valid_end - item.valid_start
            for item in self._records
            if item.result is VisitResult.COMPLETE
        )
        if not planned_valid or not delivered_valid:
            raise AdaptiveScanQualificationError("qualification has no valid delivered samples")
        expected_iq_bytes = delivered_valid * 4 * self.setup.rx_mask.bit_count()
        if terminal.iq_bytes != self._iq_bytes or self._iq_bytes != expected_iq_bytes:
            raise AdaptiveScanQualificationError("IQ byte accounting is inconsistent")
        counts = Counter(item.result for item in self._records)
        expected = (
            counts[VisitResult.COMPLETE],
            counts[VisitResult.SKIP_CAPACITY] + counts[VisitResult.SKIP_AGE],
            counts[VisitResult.INVALID_GAP],
            counts[VisitResult.CANCELLED],
        )
        if expected != (
            terminal.delivered,
            terminal.skipped,
            terminal.invalid,
            terminal.cancelled,
        ) or terminal.planned != len(self._records):
            raise AdaptiveScanQualificationError("terminal visit accounting is inconsistent")
        target_counts = Counter(item.target for item in self._records)
        return AdaptiveScanMetrics(
            source_rate_hz=self.setup.source_rate_hz,
            dwell_ms=self.setup.dwell_ms,
            first_counter=first,
            final_counter=terminal.final_counter,
            source_span_samples=terminal.final_counter - first,
            planned_valid_samples=planned_valid,
            delivered_valid_samples=delivered_valid,
            iq_bytes=self._iq_bytes,
            planned=terminal.planned,
            delivered=terminal.delivered,
            skipped=terminal.skipped,
            invalid=terminal.invalid,
            cancelled=terminal.cancelled,
            deadline_forced=sum(bool(item.flags & 2) for item in self._records),
            target_visits=tuple(target_counts[index] for index in range(len(self.setup.targets))),
        )


def primary_acceptance_gate(metrics: AdaptiveScanMetrics) -> AdaptiveScanGate:
    """Evaluate the predeclared 10/15 MS/s acceptance gate without rounding."""

    if metrics.source_rate_hz == 10_000_000 and metrics.dwell_ms == 120:
        passed = metrics.delivered_valid_samples * 100 > metrics.planned_valid_samples * 99
        return AdaptiveScanGate(
            "10MSs-120ms-planned-valid-delivery",
            passed,
            metrics.planned_valid_delivery,
            0.99,
            ">",
        )
    if metrics.source_rate_hz == 10_000_000:
        passed = metrics.delivered_valid_samples * 100 > metrics.source_span_samples * 95
        return AdaptiveScanGate(
            "10MSs-full-session-duty",
            passed,
            metrics.full_session_retained_duty,
            0.95,
            ">",
        )
    if metrics.source_rate_hz == 15_000_000:
        passed = metrics.delivered_valid_samples * 10 >= metrics.source_span_samples * 9
        return AdaptiveScanGate(
            "15MSs-full-session-duty",
            passed,
            metrics.full_session_retained_duty,
            0.90,
            ">=",
        )
    return AdaptiveScanGate(
        "20-30MSs-integrity-only",
        True,
        metrics.full_session_retained_duty,
        None,
        "informational",
    )
