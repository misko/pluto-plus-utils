from __future__ import annotations

import json
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from pluto_plus.adaptive_scan_evidence import (
    AUTHORIZED_FEATURE_103_SERIALS,
    FEATURE_103_RC4_DFU_SHA256,
    FEATURE_103_RC4_FIT_SHA256,
    AdaptiveScanEvidenceIdentity,
)
from pluto_plus.adaptive_scan_shadow import AdaptiveScanMode
from pluto_plus.feature103_qualification import (
    Feature103Detector,
    Feature103QualificationRequest,
    main,
    run_feature103_qualification,
)


def _boot_receipt(tmp_path: Path, *, serial: str = AUTHORIZED_FEATURE_103_SERIALS[0]) -> Path:
    receipt_id = "1" * 32
    path = tmp_path / f"{receipt_id}.json"
    path.write_text(
        json.dumps(
            {
                "receipt_id": receipt_id,
                "outcome": "success",
                "phases": ["return_attested", "tx_safe_attested"],
                "returned_serial": serial,
                "plan": {
                    "serial": serial,
                    "profile_id": "feature-103-rc4-ram",
                    "image_sha256": FEATURE_103_RC4_DFU_SHA256,
                    "fit_sha256": FEATURE_103_RC4_FIT_SHA256,
                    "fit_size": 13_188_343,
                    "usb_sysfs_path": "/sys/bus/usb/devices/3-11",
                },
            }
        )
    )
    path.chmod(0o600)
    return path


def _request(tmp_path: Path) -> Feature103QualificationRequest:
    return Feature103QualificationRequest(
        serial=AUTHORIZED_FEATURE_103_SERIALS[0],
        uri="ip:192.168.1.18",
        ram_receipt=_boot_receipt(tmp_path),
        evidence_path=tmp_path / "campaign.json",
        mode=AdaptiveScanMode.ADAPTIVE,
        detector=Feature103Detector.CONTROLLED,
        session=1,
        generation=2,
        seed=3,
        source_rate_hz=10_000_000,
        analog_bandwidth_hz=8_000_000,
        duration_ms=30_000,
        dwell_ms=240,
        frequencies_hz=(959_687_500, 1_190_312_500),
        baseline_weights=(1, 1),
        active_targets=(1,),
    )


def test_dry_run_is_rc4_receipt_gated_and_non_mutating(tmp_path: Path) -> None:
    request = _request(tmp_path)
    result = run_feature103_qualification(request, execute=False)

    assert result["mode"] == "dry_run"
    assert result["plan"]["ram_boot"]["dfu_sha256"] == FEATURE_103_RC4_DFU_SHA256
    assert result["plan"]["setup"]["source_rate_hz"] == 10_000_000
    assert result["plan"]["will_mutate_radio_settings"] is False
    assert result["plan"]["will_write_qspi"] is False


def test_execute_requires_confirmation_and_writes_gate_evidence(tmp_path: Path) -> None:
    request = _request(tmp_path)
    calls: list[object] = []

    def campaign_runner(*args, **kwargs):
        calls.append((args, kwargs))
        return SimpleNamespace(
            run=SimpleNamespace(
                gate=SimpleNamespace(
                    name="10MSs-full-session-duty",
                    passed=True,
                    observed=0.96,
                    threshold=0.95,
                    comparison=">",
                )
            ),
            restoration=SimpleNamespace(fastlock_inactive=True),
        )

    def evidence_writer(path, receipt, **kwargs):
        calls.append((path, receipt, kwargs))
        return AdaptiveScanEvidenceIdentity(path, "a" * 64, 123)

    with pytest.raises(ValueError, match="confirmation"):
        run_feature103_qualification(
            request,
            execute=True,
            confirmation="wrong",
            campaign_runner=campaign_runner,
            evidence_writer=evidence_writer,
        )
    assert calls == []

    result = run_feature103_qualification(
        request,
        execute=True,
        confirmation=request.confirmation_phrase,
        campaign_runner=campaign_runner,
        evidence_writer=evidence_writer,
    )
    assert result["passed"] is True
    assert result["will_write_qspi"] is False
    assert len(calls) == 2
    assert calls[1][2]["candidate_fit_sha256"] == FEATURE_103_RC4_FIT_SHA256


def test_rejects_unapproved_serial_before_campaign(tmp_path: Path) -> None:
    request = _request(tmp_path)
    with pytest.raises(ValueError, match="not authorized"):
        run_feature103_qualification(
            replace(request, serial="104000bac4950008230026001b440a003a"),
            execute=False,
        )


def test_cli_dry_run_prints_machine_readable_plan(tmp_path: Path, capsys) -> None:
    receipt = _boot_receipt(tmp_path)
    exit_code = main(
        (
            "--serial",
            AUTHORIZED_FEATURE_103_SERIALS[0],
            "--uri",
            "ip:192.168.1.18",
            "--ram-receipt",
            str(receipt),
            "--evidence",
            str(tmp_path / "evidence.json"),
            "--mode",
            "shadow",
            "--detector",
            "controlled",
            "--session",
            "1",
            "--generation",
            "2",
            "--seed",
            "3",
            "--rate",
            "10000000",
            "--bandwidth",
            "8000000",
            "--duration-ms",
            "30000",
            "--dwell-ms",
            "240",
            "--frequencies",
            "959687500,1190312500",
            "--weights",
            "1,1",
            "--active-targets",
            "1",
        )
    )

    payload = json.loads(capsys.readouterr().out)
    assert exit_code == 0
    assert payload["mode"] == "dry_run"
    assert payload["plan"]["mode"] == "shadow"
