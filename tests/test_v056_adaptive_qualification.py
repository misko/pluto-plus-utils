"""Offline contract tests for the v0.56 Issue 111 adaptive wrapper."""

import json
import runpy
from pathlib import Path
from types import SimpleNamespace

import pytest

from pluto_plus.adaptive_scan import VisitResult

SCRIPT = Path(__file__).parents[1] / "scripts/v056_adaptive_qualification.py"


def module():
    return runpy.run_path(str(SCRIPT))


def test_inventory_is_exact_two_radio_mapping_and_never_invents_uri(tmp_path):
    values = module()
    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        json.dumps(
            {
                "schema": "plutosdr-fw.v056-radio-inventory/v1",
                "radios": {
                    "1040007c4a94000211000b009186843ef2": "ip:192.168.1.18",
                    "104000b29905000e17000800065934759d": "ip:192.168.1.19",
                },
            }
        )
    )
    assert values["inventory_uri"](
        inventory, "1040007c4a94000211000b009186843ef2", "ip:192.168.1.18"
    )
    with pytest.raises(ValueError, match="exact"):
        values["inventory_uri"](inventory, "104000b29905000e17000800065934759d", "ip:192.168.1.15")


def test_fresh_append_only_ledger_charges_all_attempts_and_rejects_short_budget(tmp_path):
    reserve = module()["reserve_attempt"]
    ledger = tmp_path / "v056.jsonl"
    with pytest.raises(ValueError, match="11520"), reserve(
        ledger,
        campaign_id="v056",
        budget_seconds=1200,
        serial="1040007c4a94000211000b009186843ef2",
        cell="x",
        duration_seconds=300,
    ):
        pass
    for index in range(32):
        with reserve(
            ledger,
            campaign_id="v056",
            budget_seconds=11_520,
            serial="1040007c4a94000211000b009186843ef2",
            cell=str(index),
            duration_seconds=300,
        ):
            pass
    assert (
        sum(json.loads(row)["reserved_seconds"] for row in ledger.read_text().splitlines())
        == 32 * 360
    )
    with pytest.raises(ValueError, match="exhausted"), reserve(
        ledger,
        campaign_id="v056",
        budget_seconds=11_520,
        serial="1040007c4a94000211000b009186843ef2",
        cell="extra-final",
        duration_seconds=300,
    ):
        pass


@pytest.mark.parametrize(
    "rate,mask",
    [
        (2_500_000, 3),
        (5_000_000, 3),
        (7_500_000, 3),
        (8_000_000, 3),
        (10_000_000, 1),
        (15_000_000, 1),
        (20_000_000, 1),
    ],
)
def test_v056_campaign_geometries_are_bounded_and_supported(monkeypatch, rate, mask):
    values = module()
    run = values["run_cell"]
    namespace = run.__globals__
    monkeypatch.setitem(
        namespace,
        "AdaptiveScanClient",
        lambda *_: type(
            "Client",
            (),
            {"runtime_capabilities": lambda _: type("Caps", (), {"protocol_version": 2})()},
        )(),
    )
    monkeypatch.setitem(namespace, "ordinary_settings", lambda *_: object())
    monkeypatch.setitem(namespace, "_receiver_settings_restored", lambda *_: True)

    class Receipt:
        restoration = type(
            "Restore",
            (),
            {
                "expected": object(),
                "observed": object(),
                "expected_kernel_buffers": 1,
                "observed_kernel_buffers": 1,
                "fastlock_inactive": True,
            },
        )()
        preparation = type(
            "Prepare", (), {"configured": type("Config", (), {"sample_rate_hz": rate})()}
        )()
        terminal = object()
        run = type("Run", (), {"metrics": type("Metrics", (), {"planned_valid_delivery": 1})()})()

    monkeypatch.setitem(namespace, "run_adaptive_scan_campaign", lambda *_, **__: Receipt())
    monkeypatch.setitem(
        namespace,
        "summarize",
        lambda *_: {"counter_continuity_passed": True, "iq_geometry_passed": True},
    )
    report = run(
        cell="test",
        serial="1040007c4a94000211000b009186843ef2",
        uri="ip:192.168.1.18",
        rate_hz=rate,
        rx_mask=mask,
        duration_seconds=300,
    )
    assert report["status"] == "completed" and report["receiver_restored"] is True


def test_live_candidate_binding_requires_exact_serial_and_firmware(monkeypatch, tmp_path):
    values = module()
    candidate = tmp_path / "candidate.json"
    candidate.write_text(
        json.dumps(
            {
                "firmware": "v0.56-plutoplus-spf-adaptive-runtime-rates",
                "asset_sha256": "a" * 64,
                "firmware_source_commit": "b" * 40,
            }
        )
    )
    fn = values["candidate_binding"]
    monkeypatch.setitem(
        fn.__globals__,
        "discover_network_iio",
        lambda *_args, **_kwargs: [
            type("Radio", (), {"serial": "wrong", "firmware_version": "v0.56"})()
        ],
    )
    with pytest.raises(ValueError, match="does not attest"):
        fn(candidate, "1040007c4a94000211000b009186843ef2", "ip:192.168.1.18")


@pytest.mark.parametrize("change", [("error", 1), ("skipped", 1), ("state", 0)])
def test_terminal_errors_or_skips_fail_counter_and_iq_acceptance(change):
    summarize = module()["summarize"]
    record = SimpleNamespace(
        transition_before=0,
        transition_after=10,
        valid_start=20,
        valid_end=120,
        result=VisitResult.COMPLETE,
        iq_bytes=120 * 4,
    )
    terminal = SimpleNamespace(
        final_counter=130,
        planned=1,
        delivered=1,
        skipped=0,
        invalid=0,
        cancelled=0,
        state=1,
        error=0,
        iq_bytes=120 * 4,
    )
    setattr(terminal, *change)
    with pytest.raises(ValueError, match="terminal"):
        summarize([record], terminal, 10_000_000, 1)


@pytest.mark.parametrize(
    "candidate",
    [
        {"firmware": "v0.55", "asset_sha256": "a" * 64, "firmware_source_commit": "b" * 40},
        {
            "firmware": "v0.56-plutoplus-spf-adaptive-runtime-rates",
            "asset_sha256": "short",
            "firmware_source_commit": "b" * 40,
        },
    ],
)
def test_candidate_wrong_firmware_or_hash_fails_before_live_discovery(
    monkeypatch, tmp_path, candidate
):
    values = module()
    path = tmp_path / "candidate.json"
    path.write_text(json.dumps(candidate))
    fn = values["candidate_binding"]
    monkeypatch.setitem(
        fn.__globals__,
        "discover_network_iio",
        lambda *_args, **_kwargs: pytest.fail("must not discover"),
    )
    with pytest.raises(ValueError, match="exact v0.56"):
        fn(path, "1040007c4a94000211000b009186843ef2", "ip:192.168.1.18")
