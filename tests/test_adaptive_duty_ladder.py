from __future__ import annotations

import json
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from typer.testing import CliRunner

from pluto_plus.adaptive_duty_ladder import (
    AdaptiveDutyCell,
    AdaptiveDutyLadderReport,
    partition_source_span,
    run_adaptive_duty_ladder,
)
from pluto_plus.adaptive_scan import ScanTerminal, ScanVisit, TerminalState, VisitResult
from pluto_plus.adaptive_scan_client import AdaptiveScanVisit
from pluto_plus.adaptive_scan_qualification import AdaptiveScanAccumulator
from pluto_plus.adaptive_scan_shadow import AdaptiveScanMode
from pluto_plus.cli import app
from pluto_plus.hardware.preflight import IioEnvironmentReport, IioEnvironmentStatus
from pluto_plus.models import GainMode


def _complete_visit(setup, *, visit: int, cursor: int) -> ScanVisit:
    recall = setup.source_rate_hz // 1_000
    settle = setup.source_rate_hz // 500
    samples = setup.source_rate_hz * setup.dwell_ms // 1_000
    return ScanVisit(
        session=setup.session,
        generation=setup.generation,
        visit=visit,
        selection_counter=cursor,
        transition_before=cursor,
        transition_after=cursor + recall,
        valid_start=cursor + recall + settle,
        valid_end=cursor + recall + settle + samples,
        frequency_hz=setup.targets[visit % len(setup.targets)].frequency_hz,
        iq_bytes=samples * 4 * setup.rx_mask.bit_count(),
        missing_samples_before=0,
        analog_bandwidth_hz=setup.analog_bandwidth_hz,
        source_rate_hz=setup.source_rate_hz,
        target=visit % len(setup.targets),
        profile=setup.targets[visit % len(setup.targets)].profile,
        result=VisitResult.COMPLETE,
        eligible_mask=(1 << len(setup.targets)) - 1,
        effective_weight=65_536,
        profile_crc32=1,
    )


def _runner(uri, serial, setup, detector, **kwargs):
    assert uri == "ip:192.168.1.20"
    assert serial == "SERIAL"
    assert kwargs["mode"] is AdaptiveScanMode.ADAPTIVE
    assert kwargs["gain_mode"] is GainMode.MANUAL
    assert "client_factory" not in kwargs
    assert kwargs["samples_per_block"] == 1_000_000
    assert setup.rx_mask == 3
    first = _complete_visit(setup, visit=0, cursor=10_000)
    second = _complete_visit(setup, visit=1, cursor=first.valid_end)
    records = (first, second)
    accumulator = AdaptiveScanAccumulator(setup)
    for record in records:
        visit = AdaptiveScanVisit(record, bytes(record.iq_bytes))
        kwargs["visit_sink"](visit)
        accumulator.add(visit)
    terminal = ScanTerminal(
        session=setup.session,
        generation=setup.generation,
        final_counter=second.valid_end,
        restore_before=second.valid_end,
        restore_after=second.valid_end + 1,
        planned=2,
        delivered=2,
        skipped=0,
        invalid=0,
        cancelled=0,
        iq_bytes=sum(record.iq_bytes for record in records),
        state=TerminalState.COMPLETED,
        reason=1,
        error=0,
    )
    metrics = accumulator.finish(terminal)
    original = SimpleNamespace(value="same")
    return SimpleNamespace(
        preparation=SimpleNamespace(
            configured=SimpleNamespace(sample_rate_hz=setup.source_rate_hz), setup=setup
        ),
        run=SimpleNamespace(metrics=metrics, classification_dropped=0),
        terminal=terminal,
        restoration=SimpleNamespace(
            expected=original,
            observed=original,
            expected_kernel_buffers=8,
            observed_kernel_buffers=8,
            fastlock_inactive=True,
        ),
    )


def test_adaptive_duty_ladder_runs_real_adaptive_geometry_and_counts_both_rx_once() -> None:
    ticks = iter((0, 2_000_000_000, 3_000_000_000, 6_000_000_000))
    report = run_adaptive_duty_ladder(
        uri="ip:192.168.1.20",
        serial="SERIAL",
        rates_hz=(5_000_000, 7_500_000),
        duration_seconds=100,
        campaign_runner=_runner,
        monotonic_ns=lambda: next(ticks),
        realtime_ns=lambda: 100,
    )

    assert [cell.protocol_version for cell in report.cells] == [3, 3]
    assert [cell.elapsed_seconds for cell in report.cells] == [2.0, 3.0]
    assert all(cell.full_session_retained_duty == pytest.approx(120 / 123) for cell in report.cells)
    assert all(cell.planned_valid_delivery == 1 for cell in report.cells)
    assert all(cell.receiver_restored for cell in report.cells)
    assert all(cell.iq_bytes == cell.delivered_valid_samples * 8 for cell in report.cells)


def test_partition_rejects_counter_tail_before_last_visit() -> None:
    class Record:
        transition_before = 10
        transition_after = 11
        valid_start = 12
        valid_end = 20
        result = VisitResult.COMPLETE

    with pytest.raises(ValueError, match="partition"):
        partition_source_span((Record(),), 19)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("rates", "duration", "message"),
    [
        ((10_000_000, 5_000_000), 100, "strictly increasing"),
        ((12_500_000,), 100, "variable-dwell v3"),
        ((5_000_000,), 301, "duration"),
    ],
)
def test_adaptive_duty_ladder_rejects_unbounded_or_ambiguous_shapes(
    rates, duration, message
) -> None:
    with pytest.raises(ValueError, match=message):
        run_adaptive_duty_ladder(
            uri="ip:192.168.1.20",
            serial="SERIAL",
            rates_hz=rates,
            duration_seconds=duration,
            campaign_runner=_runner,
        )


def test_adaptive_duty_cli_forwards_exact_matrix(monkeypatch: pytest.MonkeyPatch) -> None:
    calls = []
    report = AdaptiveDutyLadderReport(
        created_at=datetime.now(UTC),
        serial="SERIAL",
        uri="ip:192.168.1.20",
        rx_mask=3,
        gain_mode=GainMode.MANUAL,
        manual_gain_db=40.0,
        frequencies_hz=(960_000_000,),
        cells=(
            AdaptiveDutyCell(
                sample_rate_hz=5_000_000,
                actual_sample_rate_hz=5_000_000,
                protocol_version=2,
                requested_duration_seconds=100,
                dwell_ms=120,
                elapsed_seconds=100.1,
                source_span_samples=500_000_000,
                delivered_valid_samples=480_000_000,
                planned_valid_samples=480_000_000,
                full_session_retained_duty=0.96,
                planned_valid_delivery=1.0,
                planned_visits=800,
                delivered_visits=800,
                skipped_visits=0,
                invalid_visits=0,
                cancelled_visits=0,
                classification_dropped=0,
                iq_bytes=3_840_000_000,
                interval_samples={"complete": 480_000_000, "recall": 20_000_000},
                receiver_restored=True,
            ),
        ),
    )

    def run(**kwargs):
        calls.append(kwargs)
        return report

    monkeypatch.setattr("pluto_plus.cli.run_adaptive_duty_ladder", run)
    monkeypatch.setattr(
        "pluto_plus.cli.inspect_iio_environment",
        lambda **_kwargs: IioEnvironmentReport(
            healthy=True,
            status=IioEnvironmentStatus.READY,
            message="ready",
            python_executable="/venv/python",
            pyadi_path="/venv/adi/__init__.py",
            pylibiio_path="/venv/iio.py",
            native_libiio_candidate="libiio.so.0",
            native_libiio_path="/usr/lib/libiio.so.0",
            libiio_version="0.25",
            backends=("ip",),
        ),
    )
    result = CliRunner().invoke(
        app,
        [
            "radio",
            "adaptive-duty-ladder",
            "192.168.1.20",
            "--expect-serial",
            "SERIAL",
            "--rates",
            "5M,10M,12.5M,15M",
            "--duration-seconds",
            "100",
            "--dwell-ms",
            "120",
            "--format",
            "json",
        ],
    )

    assert result.exit_code == 0, result.output
    assert json.loads(result.stdout)["schema_name"].endswith(".v1")
    assert calls == [
        {
            "uri": "ip:192.168.1.20",
            "serial": "SERIAL",
            "rates_hz": (5_000_000, 10_000_000, 12_500_000, 15_000_000),
            "duration_seconds": 100,
            "dwell_ms": 120,
            "manual_gain_db": 40.0,
        }
    ]
