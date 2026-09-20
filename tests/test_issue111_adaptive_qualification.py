from __future__ import annotations

import dataclasses
import json
import runpy
from pathlib import Path
from types import SimpleNamespace

import pytest

from pluto_plus.adaptive_scan import ScanCapabilities, VisitResult
from pluto_plus.hardware.iio import IioReceiverSettingsReadback
from pluto_plus.models import GainMode

SCRIPT = Path(__file__).parents[1] / "scripts/issue111_adaptive_qualification.py"


def module():
    return runpy.run_path(str(SCRIPT))


def settings(mode=GainMode.SLOW_ATTACK, gains=(42.0, 40.0)):
    return IioReceiverSettingsReadback(
        center_frequency_hz=2_400_000_000, sample_rate_hz=30_720_000,
        bandwidth_hz=18_000_000, channels=(0, 1),
        gain_modes=(mode, mode), gain_db=gains,
    )


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


def test_target_smoke_cells_fit_remaining_aggregate_budget(tmp_path):
    values = module()
    cells = values["CELLS"]
    assert cells["smoke-dual7p5"] == (7_500_000, 3, 15_000)
    assert cells["smoke-dual8"] == (8_000_000, 3, 15_000)
    reserve = values["reserve_attempt"]
    ledger = tmp_path / "budget.jsonl"
    for cell in ("baseline-dual2p5", "baseline-dual2p5", "baseline-single15",
                 "dual5", "dual7p5", "dual8", "unusual",
                 "dual5", "smoke-dual7p5", "smoke-dual8"):
        with reserve(ledger, cell):
            pass
    used = sum(json.loads(line)["reserved_seconds"] for line in ledger.read_text().splitlines())
    assert used == 1160
    with pytest.raises(ValueError, match="budget exhausted"), reserve(ledger, "smoke-dual8"):
        pytest.fail("another attempt exceeds the shared budget")


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


def test_target_short_cells_preserve_shared_1199_second_limit(tmp_path):
    values = module()
    ledger = tmp_path / "budget.jsonl"
    reserve = values["reserve_attempt"]
    cells = ("baseline-dual2p5", "baseline-dual2p5", "baseline-single15",
             "dual5", "dual7p5", "dual8", "unusual", "dual5")
    for cell in cells:
        with reserve(ledger, cell):
            pass
    for suffix, rate in (("5", 5_000_000), ("7p5", 7_500_000), ("8", 8_000_000)):
        cell = f"target-short-dual{suffix}"
        assert values["CELLS"][cell] == (rate, 3, 3000)
        with reserve(ledger, cell) as allowance:
            assert allowance == 63
    assert sum(json.loads(row)["reserved_seconds"]
               for row in ledger.read_text().splitlines()) == 1199
    with pytest.raises(ValueError, match="budget exhausted"), reserve(ledger, cell):
        pytest.fail("no further capture attempt fits")


@pytest.mark.parametrize("mode, expected_status", [
    (GainMode.SLOW_ATTACK, "completed"), (GainMode.MANUAL, "rejected_or_failed"),
])
def test_restoration_handles_volatile_agc_and_preserves_receipt(monkeypatch, mode, expected_status):
    values = module()
    run = values["run_cell"]
    namespace = run.__globals__
    caps = ScanCapabilities(rate_mask=31, rx_mask=3, protocol_version=2,
                            rate_mode=1, minimum_rate_hz=520_833, maximum_rate_hz=61_440_000)
    monkeypatch.setitem(namespace, "AdaptiveScanClient",
                        lambda *_: SimpleNamespace(runtime_capabilities=lambda: caps))
    before, after = settings(mode), settings(mode, (43.0, 41.0))
    observations = iter((before, after))
    monkeypatch.setitem(namespace, "ordinary_settings", lambda *_: next(observations))
    receipt = SimpleNamespace(
        restoration=SimpleNamespace(expected=before, observed=after,
                                    expected_kernel_buffers=4, observed_kernel_buffers=4,
                                    fastlock_inactive=True),
        preparation=SimpleNamespace(configured=SimpleNamespace(sample_rate_hz=5_000_000)),
        terminal=SimpleNamespace(planned=1),
        run=SimpleNamespace(metrics=SimpleNamespace(planned_valid_delivery=1.0)),
    )
    monkeypatch.setitem(namespace, "run_adaptive_scan_campaign", lambda *_, **__: receipt)
    monkeypatch.setitem(namespace, "summarize", lambda *_: {"checked": True})
    report = run("target-short-dual5")
    assert report["status"] == expected_status
    assert report["restored_to_pre_attempt"] == (mode is GainMode.SLOW_ATTACK)
    assert report["ordinary_libiio_before"] == values["plain"](before)
    assert report["receipt"] is receipt
    assert report["receipt"].terminal.planned == 1


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
                        lambda *_: observations.append("ordinary") or settings())
    def reject(*_args, **kwargs):
        observations.append("attempt")
        raise ValueError("driver rejects exact integer rate")
    monkeypatch.setitem(namespace, "run_adaptive_scan_campaign", reject)
    report = run("unusual")
    assert report["status"] == "rate_rejected"
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
