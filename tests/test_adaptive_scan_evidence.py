from __future__ import annotations

import hashlib
import json
import stat
from dataclasses import dataclass
from pathlib import Path

import pytest

from pluto_plus.adaptive_scan_evidence import (
    FEATURE_103_RC2_DFU_SHA256,
    FEATURE_103_RC2_FIT_SHA256,
    SCHEMA,
    AdaptiveScanEvidenceError,
    attest_feature103_ram_boot_receipt,
    write_adaptive_scan_evidence,
)


@dataclass
class _Receipt:
    uri: str = "ip:192.168.1.18"
    serial: str = "SERIAL_A"
    preparation: tuple[tuple[int, ...], ...] = ((1, 2, 3),)
    run: str = "shadow"
    restoration: bool = True


def _receipt() -> _Receipt:
    return _Receipt()


def test_evidence_is_private_atomic_canonical_and_exclusive(tmp_path: Path) -> None:
    path = tmp_path / "campaign.json"
    identity = write_adaptive_scan_evidence(
        path,
        _receipt(),  # type: ignore[arg-type]
        candidate_dfu_sha256="a" * 64,
        candidate_fit_sha256="b" * 64,
    )
    payload = json.loads(path.read_bytes())

    assert payload["schema"] == SCHEMA
    assert payload["candidate"] == {"dfu_sha256": "a" * 64, "fit_sha256": "b" * 64}
    assert payload["campaign"]["serial"] == "SERIAL_A"
    assert identity.bytes == path.stat().st_size
    assert identity.sha256 == hashlib.sha256(path.read_bytes()).hexdigest()
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert not tuple(tmp_path.glob(".feature-103-*"))

    with pytest.raises(AdaptiveScanEvidenceError, match="must not already exist"):
        write_adaptive_scan_evidence(
            path,
            _receipt(),  # type: ignore[arg-type]
            candidate_dfu_sha256="a" * 64,
            candidate_fit_sha256="b" * 64,
        )


def test_evidence_rejects_unpinned_candidate(tmp_path: Path) -> None:
    with pytest.raises(AdaptiveScanEvidenceError, match="lowercase SHA-256"):
        write_adaptive_scan_evidence(
            tmp_path / "bad.json",
            _receipt(),  # type: ignore[arg-type]
            candidate_dfu_sha256="A" * 64,
            candidate_fit_sha256="b" * 64,
        )


def test_exact_rc2_ram_receipt_is_required(tmp_path: Path) -> None:
    receipt_id = "1" * 32
    path = tmp_path / f"{receipt_id}.json"
    path.write_text(
        json.dumps(
            {
                "receipt_id": receipt_id,
                "outcome": "success",
                "phases": ["return_attested", "tx_safe_attested"],
                "returned_serial": "SERIAL_A",
                "plan": {
                    "serial": "SERIAL_A",
                    "profile_id": "feature-103-rc2-ram",
                    "image_sha256": FEATURE_103_RC2_DFU_SHA256,
                    "fit_sha256": FEATURE_103_RC2_FIT_SHA256,
                    "fit_size": 13_188_215,
                    "usb_sysfs_path": "/sys/bus/usb/devices/3-11",
                },
            }
        )
    )
    path.chmod(0o600)

    identity = attest_feature103_ram_boot_receipt(path, expected_serial="SERIAL_A")
    assert identity.receipt_id == receipt_id
    assert identity.dfu_sha256 == FEATURE_103_RC2_DFU_SHA256

    payload = json.loads(path.read_bytes())
    payload["plan"]["profile_id"] = "feature-103-rc1-ram"
    path.write_text(json.dumps(payload))
    with pytest.raises(AdaptiveScanEvidenceError, match="exact RC2"):
        attest_feature103_ram_boot_receipt(path, expected_serial="SERIAL_A")
