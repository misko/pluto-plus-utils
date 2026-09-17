from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

import pytest

from pluto_plus.adaptive_scan_evidence import (
    AUTHORIZED_FEATURE_103_SERIALS,
    FEATURE_103_V1_DFU_SHA256,
    FEATURE_103_V1_FIT_SHA256,
    SCHEMA,
    AdaptiveScanEvidenceError,
)
from pluto_plus.feature103_verify import MATRIX_RATES, verify_feature103_matrix


def _canonical_write(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n")
    path.chmod(0o600)


def _boot_receipt(tmp_path: Path, serial: str, index: int) -> Path:
    receipt_id = str(index) * 32
    path = tmp_path / f"{receipt_id}.json"
    payload = {
        "receipt_id": receipt_id,
        "outcome": "success",
        "phases": ["return_attested", "tx_safe_attested"],
        "returned_serial": serial,
        "plan": {
            "serial": serial,
            "profile_id": "adaptive-scan-v1-release-ram",
            "image_sha256": FEATURE_103_V1_DFU_SHA256,
            "fit_sha256": FEATURE_103_V1_FIT_SHA256,
            "fit_size": 13_007_023,
            "usb_sysfs_path": f"/sys/bus/usb/devices/3-{index}",
        },
    }
    _canonical_write(path, payload)
    return path


def _campaign(serial: str, rate: int) -> dict[str, Any]:
    duration = 30_000 if rate <= 15_000_000 else 10_000
    bandwidth = {10_000_000: 8_000_000, 15_000_000: 12_000_000,
                 20_000_000: 18_000_000, 30_000_000: 18_000_000}[rate]
    planned = 119 if rate <= 15_000_000 else 39
    delivered = 119 if rate <= 15_000_000 else (26 if rate == 20_000_000 else 13)
    skipped = planned - delivered
    dwell_samples = rate * 240 // 1_000
    delivered_samples = delivered * dwell_samples
    source_span = delivered_samples * 25 // 24 if rate <= 15_000_000 else delivered_samples * 2
    duty = delivered_samples / source_span
    session = rate // 1_000
    digest = "a" * 64
    observations = []
    acknowledgements = []
    for visit in range(delivered):
        target = 0 if visit == 0 else 1
        sequence = visit + 1
        observations.append(
            {
                "visit": visit,
                "target": target,
                "outcome": 2 if target == 0 else 1,
                "feedback": {
                    "analysis_digest": digest,
                    "generation": 1,
                    "outcome": 2 if target == 0 else 1,
                    "sequence": sequence,
                    "session": session,
                    "target": target,
                    "valid_end": (visit + 1) * dwell_samples,
                    "valid_start": visit * dwell_samples,
                    "visit": visit,
                },
                "receipt": 0,
            }
        )
        acknowledgements.append(
            {
                "application_counter": (visit + 2) * dwell_samples,
                "received_counter": (visit + 1) * dwell_samples,
                "new_boost": 65_536,
                "old_boost": 65_536,
                "sequence": sequence,
                "result": 7,
                "source_visit": visit,
                "target": target,
                "first_visit": 2,
            }
        )
    original = {
        "bandwidth_hz": 18_000_000.0,
        "center_frequency_hz": 2_400_000_000.0,
        "channels": [0],
        "gain_db": [71.0],
        "gain_modes": ["slow_attack"],
        "sample_rate_hz": 30_720_000.0,
    }
    setup = {
        "source_rate_hz": rate,
        "analog_bandwidth_hz": bandwidth,
        "duration_ms": duration,
        "dwell_ms": 240,
        "seed": 103,
        "generation": 1,
        "session": session,
        "rx_mask": 1,
        "format": 1,
        "flags": 1,
        "analysis_digest": digest,
        "application_delay_ms": 1_000,
        "decay_ms": 5_000,
        "feedback_age_ms": 1_000,
        "maximum_boost": 3,
        "maximum_queue_age_ms": 5_000,
        "maximum_queue_bytes": 200_000_000,
        "maximum_queue_visits": 50,
        "maximum_revisit_ms": 3_000,
        "transition_budget_ms": 10,
        "targets": [
            {"channel": 0, "frequency_hz": 960_000_000, "profile": 1,
             "baseline_weight": 1, "profile_crc32": 1},
            {"channel": 1, "frequency_hz": 1_190_312_500, "profile": 2,
             "baseline_weight": 1, "profile_crc32": 2},
        ],
    }
    return {
        "schema": SCHEMA,
        "schema_version": 1,
        "created_at": "2026-09-16T00:00:00+00:00",
        "candidate": {"dfu_sha256": FEATURE_103_V1_DFU_SHA256,
                      "fit_sha256": FEATURE_103_V1_FIT_SHA256},
        "campaign": {
            "uri": "ip:192.0.2.1",
            "serial": serial,
            "preparation": {
                "setup": setup,
                "configured": {"sample_rate_hz": float(rate),
                               "bandwidth_hz": float(bandwidth), "channels": [0],
                               "center_frequency_hz": 2_400_000_000.0,
                               "gain_db": [40.0], "gain_modes": ["manual"]},
                "configured_kernel_buffers": 16,
                "original": original,
                "original_kernel_buffers": 4,
                "profile_words": [[0] * 16, [1] * 16],
                "serial": serial,
                "uri": "ip:192.0.2.1",
            },
            "run": {
                "mode": "adaptive",
                "feedback_period_visits": 1,
                "observations": observations,
                "acknowledgements": acknowledgements,
                "metrics": {
                    "source_rate_hz": rate,
                    "dwell_ms": 240,
                    "planned": planned,
                    "delivered": delivered,
                    "skipped": skipped,
                    "invalid": 0,
                    "cancelled": 0,
                    "planned_valid_samples": planned * dwell_samples,
                    "delivered_valid_samples": delivered_samples,
                    "iq_bytes": delivered_samples * 4,
                    "source_span_samples": source_span,
                    "first_counter": 1_000,
                    "final_counter": 1_000 + source_span,
                    "deadline_forced": 0,
                    "target_visits": [1, planned - 1],
                },
                "gate": {
                    "name": "10MSs-full-session-duty" if rate == 10_000_000 else (
                        "15MSs-full-session-duty" if rate == 15_000_000
                        else "20-30MSs-integrity-only"
                    ),
                    "passed": True,
                    "observed": duty,
                    "threshold": 0.95 if rate == 10_000_000 else (
                        0.90 if rate == 15_000_000 else None
                    ),
                    "comparison": ">" if rate == 10_000_000 else (
                        ">=" if rate == 15_000_000 else "informational"
                    ),
                },
            },
            "restoration": {
                "expected": original,
                "observed": original,
                "expected_kernel_buffers": 4,
                "observed_kernel_buffers": 4,
                "fastlock_inactive": True,
            },
        },
        "rf_observations": [],
    }


def _matrix(tmp_path: Path) -> tuple[dict[str, Path], list[Path], dict[tuple[str, int], str]]:
    receipts = {
        serial: _boot_receipt(tmp_path, serial, index)
        for index, serial in enumerate(AUTHORIZED_FEATURE_103_SERIALS, start=1)
    }
    paths = []
    identities = {}
    for serial_index, serial in enumerate(AUTHORIZED_FEATURE_103_SERIALS):
        for rate in MATRIX_RATES:
            path = tmp_path / f"cell-{serial_index}-{rate}.json"
            _canonical_write(path, _campaign(serial, rate))
            paths.append(path)
            identities[(serial, rate)] = hashlib.sha256(path.read_bytes()).hexdigest()
    return receipts, paths, identities


def test_complete_two_radio_matrix_passes_and_reconstructs_weighting(tmp_path: Path) -> None:
    receipts, paths, identities = _matrix(tmp_path)

    result = verify_feature103_matrix(
        receipts, tuple(reversed(paths)), expected_evidence_sha256=identities
    )

    assert result.passed is True
    assert len(result.cells) == 8
    assert all(cell.active_share_after > cell.active_share_before for cell in result.cells)
    assert tuple(cell.source_rate_hz for cell in result.cells[:4]) == MATRIX_RATES


@pytest.mark.parametrize(
    ("mutation", "message"),
    (
        (lambda root: root["campaign"]["restoration"].update(fastlock_inactive=False),
         "restore exact"),
        (lambda root: root["campaign"]["run"]["gate"].update(observed=0.1),
         "acceptance gate"),
        (lambda root: root["campaign"]["run"]["observations"][2].update(target=0),
         "controlled detector"),
        (lambda root: root["candidate"].update(dfu_sha256="0" * 64),
         "exact v0.52"),
    ),
)
def test_matrix_rejects_semantic_tampering(tmp_path: Path, mutation, message: str) -> None:
    receipts, paths, identities = _matrix(tmp_path)
    selected = paths[0]
    payload = json.loads(selected.read_bytes())
    mutation(payload)
    _canonical_write(selected, payload)

    with pytest.raises(AdaptiveScanEvidenceError, match=message):
        verify_feature103_matrix(receipts, paths, expected_evidence_sha256=identities)


def test_matrix_rejects_noncanonical_or_unpinned_evidence(tmp_path: Path) -> None:
    receipts, paths, identities = _matrix(tmp_path)
    selected = paths[0]
    selected.write_text(json.dumps(json.loads(selected.read_bytes()), indent=2))
    selected.chmod(0o600)
    with pytest.raises(AdaptiveScanEvidenceError, match="not canonical"):
        verify_feature103_matrix(receipts, paths, expected_evidence_sha256=identities)

    _canonical_write(selected, _campaign(AUTHORIZED_FEATURE_103_SERIALS[0], 10_000_000))
    identities[(AUTHORIZED_FEATURE_103_SERIALS[0], 10_000_000)] = "0" * 64
    with pytest.raises(AdaptiveScanEvidenceError, match="not the pinned"):
        verify_feature103_matrix(receipts, paths, expected_evidence_sha256=identities)


def test_matrix_rejects_missing_or_duplicate_cells(tmp_path: Path) -> None:
    receipts, paths, _identities = _matrix(tmp_path)
    with pytest.raises(AdaptiveScanEvidenceError, match="exactly eight"):
        verify_feature103_matrix(receipts, paths[:-1])
    with pytest.raises(AdaptiveScanEvidenceError, match="duplicate"):
        verify_feature103_matrix(receipts, [*paths[:-1], paths[0]])
