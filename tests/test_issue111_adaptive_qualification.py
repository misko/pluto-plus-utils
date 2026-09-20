from __future__ import annotations

import dataclasses
import runpy
from pathlib import Path
from types import SimpleNamespace

import pytest

from pluto_plus.adaptive_scan import ScanCapabilities, VisitResult

SCRIPT = Path(__file__).parents[1] / "scripts/issue111_adaptive_qualification.py"


def module():
    return runpy.run_path(str(SCRIPT))


def test_cells_bound_every_session_and_total_attempt_ledger(tmp_path):
    values = module()
    assert max(cell[2] for cell in values["CELLS"].values()) == 120_000
    ledger = tmp_path / "budget.jsonl"
    reserve = values["reserve_attempt"]
    for index in range(6):
        serial = tuple(values["RADIOS"])[index % 2]
        with reserve(ledger, "dual5", serial) as allowance:
            assert allowance == 180
    with pytest.raises(ValueError, match="budget exhausted"), reserve(ledger, "dual5"):
        pytest.fail("must refuse before radio access")
    assert len(ledger.read_text().splitlines()) == 6


def test_failed_attempt_is_charged_and_parallel_attempt_is_refused(tmp_path):
    reserve = module()["reserve_attempt"]
    ledger = tmp_path / "budget.jsonl"
    with pytest.raises(RuntimeError), reserve(ledger, "dual5"):
        with pytest.raises(BlockingIOError), reserve(ledger, "dual5"):
            pytest.fail("parallel radio use must fail")
        raise RuntimeError("interrupted")
    assert len(ledger.read_text().splitlines()) == 1


def test_accounting_partitions_skipped_and_complete_source_intervals():
    summarize = module()["summarize"]
    complete = SimpleNamespace(transition_before=0, transition_after=10,
                              valid_start=20, valid_end=120, target=0,
                              result=VisitResult.COMPLETE, iq_bytes=800)
    skipped = SimpleNamespace(transition_before=130, transition_after=135,
                             valid_start=140, valid_end=240, target=1,
                             result=VisitResult.SKIP_CAPACITY, iq_bytes=0)
    terminal = SimpleNamespace(final_counter=250, planned=2, delivered=1,
                               skipped=1, invalid=0, cancelled=0, iq_bytes=800)
    report = summarize([complete, skipped], terminal, 7_500_000, 3)
    assert sum(report["partition_samples"].values()) == 250
    assert report["full_session_retained_duty"] == 0.4
    assert report["visit_counts"] == {"complete": 1, "skip_capacity": 1}
    terminal.iq_bytes = 400
    with pytest.raises(ValueError, match="IQ byte"):
        summarize([complete, skipped], terminal, 7_500_000, 3)
    skipped.transition_before = 119
    with pytest.raises(ValueError, match="overlap"):
        summarize([complete, skipped], terminal, 7_500_000, 3)


def test_unusual_rejection_records_restoration_without_retry(monkeypatch):
    values = module()
    run = values["run_cell"]
    namespace = run.__globals__
    caps = ScanCapabilities(rate_mask=31, rx_mask=3, protocol_version=2,
                            rate_mode=1, minimum_rate_hz=520_833, maximum_rate_hz=61_440_000)
    monkeypatch.setitem(namespace, "AdaptiveScanClient",
                        lambda *_: SimpleNamespace(runtime_capabilities=lambda: caps))
    observations = []
    monkeypatch.setitem(namespace, "ordinary_settings",
                        lambda *_: observations.append("ordinary") or (15_000_000,))
    def reject(*_args, **kwargs):
        observations.append("attempt")
        raise ValueError("driver rejects exact integer rate")
    monkeypatch.setitem(namespace, "run_adaptive_scan_campaign", reject)
    report = run("unusual")
    assert report["status"] == "rejected_or_failed"
    assert report["restored_to_pre_attempt"]
    assert report["requested_setup"]["source_rate_hz"] == 12_345_679
    assert observations == ["ordinary", "attempt", "ordinary"]


def test_capabilities_only_has_no_radio_capture(monkeypatch, tmp_path):
    values = module()
    main = values["main"]
    caps = dataclasses.replace(ScanCapabilities(), rate_mask=31, rx_mask=3)
    monkeypatch.setitem(main.__globals__, "AdaptiveScanClient",
                        lambda *_: SimpleNamespace(runtime_capabilities=lambda: caps))
    output = tmp_path / "caps.json"
    ledger = tmp_path / "budget.jsonl"
    monkeypatch.setattr("sys.argv", [str(SCRIPT), "--cell", "caps", "--output", str(output),
                                    "--ledger", str(ledger)])
    assert main() == 0
    assert output.exists() and not ledger.exists()
