"""Counter-derived duty ladder for real adaptive-scan sessions."""

from __future__ import annotations

import time
from collections import Counter
from collections.abc import Callable, Sequence
from datetime import UTC, datetime
from typing import Any

from pydantic import Field

from .adaptive_scan import ScanVisit
from .adaptive_scan_campaign import build_adaptive_scan_setup, run_adaptive_scan_campaign
from .adaptive_scan_client import AdaptiveScanClient
from .adaptive_scan_detector import Ci16EnergyDetector, Ci16EnergyDetectorConfig
from .adaptive_scan_shadow import AdaptiveScanMode
from .models import ApiModel, GainMode

DEFAULT_ADAPTIVE_DUTY_RATES = "5M,10M,12.5M,15M"
DEFAULT_ADAPTIVE_DUTY_FREQUENCIES = (
    960_000_000,
    1_210_000_000,
    1_460_000_000,
    1_710_000_000,
)


class AdaptiveDutyCell(ApiModel):
    sample_rate_hz: int = Field(gt=0)
    actual_sample_rate_hz: int = Field(gt=0)
    protocol_version: int = Field(ge=1)
    requested_duration_seconds: int = Field(ge=1, le=300)
    dwell_ms: int = Field(ge=20, le=240)
    elapsed_seconds: float = Field(gt=0)
    source_span_samples: int = Field(gt=0)
    delivered_valid_samples: int = Field(gt=0)
    planned_valid_samples: int = Field(gt=0)
    full_session_retained_duty: float = Field(ge=0, le=1)
    planned_valid_delivery: float = Field(ge=0, le=1)
    planned_visits: int = Field(gt=0)
    delivered_visits: int = Field(ge=0)
    skipped_visits: int = Field(ge=0)
    invalid_visits: int = Field(ge=0)
    cancelled_visits: int = Field(ge=0)
    classification_dropped: int = Field(ge=0)
    iq_bytes: int = Field(gt=0)
    interval_samples: dict[str, int]
    receiver_restored: bool


class AdaptiveDutyLadderReport(ApiModel):
    schema_name: str = "org.openai.pluto-plus-utils.adaptive-duty-ladder.v1"
    created_at: datetime
    serial: str
    uri: str
    rx_mask: int
    gain_mode: GainMode
    manual_gain_db: float
    frequencies_hz: tuple[int, ...]
    cells: tuple[AdaptiveDutyCell, ...]
    continuity_claim: str = (
        "duty is complete adaptive-visit sample periods divided by the complete FPGA "
        "source-counter span; both-RX samples count once"
    )


def partition_source_span(records: Sequence[ScanVisit], final_counter: int) -> dict[str, int]:
    """Partition the observed counter span without using host-clock timing."""

    if not records:
        raise ValueError("adaptive duty cell returned no visits")
    buckets: Counter[str] = Counter()
    previous = records[0].transition_before
    for record in records:
        intervals = {
            "between_visits": record.transition_before - previous,
            "recall": record.transition_after - record.transition_before,
            "settle": record.valid_start - record.transition_after,
            record.result.name.lower(): record.valid_end - record.valid_start,
        }
        if any(value < 0 for value in intervals.values()):
            raise ValueError("adaptive duty source intervals overlap or run backwards")
        buckets.update(intervals)
        previous = record.valid_end
    buckets["terminal_tail"] = final_counter - previous
    span = final_counter - records[0].transition_before
    if buckets["terminal_tail"] < 0 or sum(buckets.values()) != span:
        raise ValueError("adaptive duty source-counter partition is inconsistent")
    return dict(sorted(buckets.items()))


def run_adaptive_duty_ladder(
    *,
    uri: str,
    serial: str,
    rates_hz: Sequence[int],
    duration_seconds: int,
    dwell_ms: int = 120,
    rx_mask: int = 3,
    manual_gain_db: float = 40.0,
    frequencies_hz: tuple[int, ...] = DEFAULT_ADAPTIVE_DUTY_FREQUENCIES,
    campaign_runner: Callable[..., Any] = run_adaptive_scan_campaign,
    monotonic_ns: Callable[[], int] = time.monotonic_ns,
    realtime_ns: Callable[[], int] = time.time_ns,
) -> AdaptiveDutyLadderReport:
    """Run one real adaptive session per rate and retain counter-derived duty."""

    selected_rates = tuple(rates_hz)
    if not selected_rates or len(selected_rates) > 8:
        raise ValueError("adaptive duty ladder requires between one and eight rates")
    if any(right <= left for left, right in zip(selected_rates, selected_rates[1:], strict=False)):
        raise ValueError("adaptive duty ladder rates must be strictly increasing")
    if not 1 <= duration_seconds <= 300:
        raise ValueError("adaptive duty duration must be between 1 and 300 seconds")
    if not 20 <= dwell_ms <= 240:
        raise ValueError("adaptive duty dwell must be between 20 and 240 milliseconds")
    if rx_mask not in (1, 3):
        raise ValueError("adaptive duty RX mask must be 1 or 3")

    detector = Ci16EnergyDetector(Ci16EnergyDetectorConfig(-38.0))
    cells: list[AdaptiveDutyCell] = []
    identity = realtime_ns() & ((1 << 63) - 1)
    for index, rate in enumerate(selected_rates):
        setup = build_adaptive_scan_setup(
            session=identity + index * 3 + 1,
            generation=identity + index * 3 + 2,
            seed=identity + index * 3 + 3,
            source_rate_hz=rate,
            analog_bandwidth_hz=min(rate, 56_000_000),
            duration_ms=duration_seconds * 1_000,
            dwell_ms=dwell_ms,
            frequencies_hz=frequencies_hz,
            baseline_weights=(1,) * len(frequencies_hz),
            analysis_digest=detector.config.analysis_digest,
            transition_budget_ms=20,
            maximum_revisit_ms=3_000,
            rx_mask=rx_mask,
        )
        records: list[ScanVisit] = []
        started = monotonic_ns()
        receipt = campaign_runner(
            uri,
            serial,
            setup,
            detector,
            mode=AdaptiveScanMode.ADAPTIVE,
            manual_gain_db=manual_gain_db,
            gain_mode=GainMode.MANUAL,
            samples_per_block=1_000_000,
            feedback_period_visits=8,
            visit_sink=lambda visit, records=records: records.append(visit.record),
            client_factory=lambda host: AdaptiveScanClient(
                host, timeout_s=duration_seconds + 180.0
            ),
        )
        elapsed = (monotonic_ns() - started) / 1_000_000_000
        metrics = receipt.run.metrics
        restoration = receipt.restoration
        restored = (
            restoration.expected_kernel_buffers == restoration.observed_kernel_buffers
            and restoration.fastlock_inactive
        )
        if not restored:
            raise RuntimeError("adaptive duty ladder receiver restoration was not exact")
        cells.append(
            AdaptiveDutyCell(
                sample_rate_hz=rate,
                actual_sample_rate_hz=round(receipt.preparation.configured.sample_rate_hz),
                protocol_version=receipt.preparation.setup.protocol_version,
                requested_duration_seconds=duration_seconds,
                dwell_ms=dwell_ms,
                elapsed_seconds=elapsed,
                source_span_samples=metrics.source_span_samples,
                delivered_valid_samples=metrics.delivered_valid_samples,
                planned_valid_samples=metrics.planned_valid_samples,
                full_session_retained_duty=metrics.full_session_retained_duty,
                planned_valid_delivery=metrics.planned_valid_delivery,
                planned_visits=metrics.planned,
                delivered_visits=metrics.delivered,
                skipped_visits=metrics.skipped,
                invalid_visits=metrics.invalid,
                cancelled_visits=metrics.cancelled,
                classification_dropped=receipt.run.classification_dropped,
                iq_bytes=metrics.iq_bytes,
                interval_samples=partition_source_span(records, receipt.terminal.final_counter),
                receiver_restored=restored,
            )
        )
    return AdaptiveDutyLadderReport(
        created_at=datetime.now(UTC),
        serial=serial,
        uri=uri,
        rx_mask=rx_mask,
        gain_mode=GainMode.MANUAL,
        manual_gain_db=manual_gain_db,
        frequencies_hz=frequencies_hz,
        cells=tuple(cells),
    )
