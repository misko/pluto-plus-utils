"""Durable, content-addressed evidence for feature-request #103 campaigns."""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
import os
import re
import tempfile
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from .adaptive_scan_campaign import AdaptiveScanCampaignReceipt
from .adaptive_scan_detector import Ci16EnergyObservation

SCHEMA = "pluto-plus-utils.feature-103-campaign-evidence.v1"
AUTHORIZED_FEATURE_103_SERIALS = (
    "1040007c4a94000211000b009186843ef2",
    "104000b29905000e17000800065934759d",
)
FEATURE_103_RC12_DFU_SHA256 = (
    "9f401b3b1309db28d67e6b5380e6872f310ed1e2c3d9f073ee6d8aad5ac9fa05"
)
FEATURE_103_RC12_FIT_SHA256 = (
    "71b397ae007013b3b8ac6a017a4897f617e7db8be097708f61ff6aa0b15feac7"
)
FEATURE_103_RC14_DFU_SHA256 = (
    "99ae82e5e6a5eb4f02394463112e9d41fd90ff8343cbfbf95a4ec15e97853db1"
)
FEATURE_103_RC14_FIT_SHA256 = (
    "26db9c700ad5b2cf01a3a9fc841f847bc0d06f7a1660cbbd3f181dcc4bdf048e"
)
FEATURE_103_V1_DFU_SHA256 = (
    "f88c5fe44160f0a09031fb8b68f92b2280022e0f38174845b7edc3a37c26eea2"
)
FEATURE_103_V1_FIT_SHA256 = (
    "1f3ec2b6937e09a349e952a7bcc499a2902043f09f35c51fb0a5d50eb34d5403"
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AdaptiveScanEvidenceError(ValueError):
    """Campaign evidence is incomplete, malformed, or cannot be stored safely."""


@dataclasses.dataclass(frozen=True, slots=True)
class AdaptiveScanEvidenceIdentity:
    path: Path
    sha256: str
    bytes: int


@dataclasses.dataclass(frozen=True, slots=True)
class Feature103RamBootIdentity:
    receipt_id: str
    receipt_path: Path
    serial: str
    usb_sysfs_path: str
    dfu_sha256: str
    fit_sha256: str


def _attest_feature103_ram_boot_receipt(
    path: Path,
    *,
    expected_serial: str,
    profile_id: str,
    dfu_sha256: str,
    fit_sha256: str,
    fit_size: int,
    candidate: str,
) -> Feature103RamBootIdentity:
    if expected_serial not in AUTHORIZED_FEATURE_103_SERIALS:
        raise AdaptiveScanEvidenceError("serial is not authorized for feature 103 qualification")

    selected = path.expanduser().absolute()
    try:
        stat_result = selected.lstat()
        raw = selected.read_bytes()
        payload = json.loads(raw)
        plan = payload["plan"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as error:
        raise AdaptiveScanEvidenceError("RAM-boot receipt is unreadable or malformed") from error
    phases = tuple(payload.get("phases", ()))
    receipt_id = str(payload.get("receipt_id", ""))
    if (
        selected.is_symlink()
        or not selected.is_file()
        or stat_result.st_mode & 0o077
        or not re.fullmatch(r"[0-9a-f]{32}", receipt_id)
        or selected.stem != receipt_id
    ):
        raise AdaptiveScanEvidenceError("RAM-boot receipt identity or permissions are unsafe")
    if (
        payload.get("outcome") != "success"
        or phases[-2:] != ("return_attested", "tx_safe_attested")
        or payload.get("returned_serial") != expected_serial
        or plan.get("serial") != expected_serial
        or plan.get("profile_id") != profile_id
        or plan.get("image_sha256") != dfu_sha256
        or plan.get("fit_sha256") != fit_sha256
        or plan.get("fit_size") != fit_size
    ):
        raise AdaptiveScanEvidenceError(
            f"RAM-boot receipt does not attest exact {candidate} return"
        )
    usb_path = str(plan.get("usb_sysfs_path", ""))
    if not usb_path.startswith("/sys/bus/usb/devices/") or ":" in Path(usb_path).name:
        raise AdaptiveScanEvidenceError("RAM-boot receipt USB identity is invalid")
    return Feature103RamBootIdentity(
        receipt_id=receipt_id,
        receipt_path=selected,
        serial=expected_serial,
        usb_sysfs_path=usb_path,
        dfu_sha256=dfu_sha256,
        fit_sha256=fit_sha256,
    )


def attest_feature103_ram_boot_receipt(
    path: Path, *, expected_serial: str
) -> Feature103RamBootIdentity:
    """Require a private successful RC12-full release receipt for this serial."""

    return _attest_feature103_ram_boot_receipt(
        path,
        expected_serial=expected_serial,
        profile_id="feature-103-rc12-full-ram",
        dfu_sha256=FEATURE_103_RC12_DFU_SHA256,
        fit_sha256=FEATURE_103_RC12_FIT_SHA256,
        fit_size=13_187_283,
        candidate="RC12-full",
    )


def attest_feature103_rc14_ram_boot_receipt(
    path: Path, *, expected_serial: str
) -> Feature103RamBootIdentity:
    """Require a private successful RC14-full campaign receipt for this serial."""

    return _attest_feature103_ram_boot_receipt(
        path,
        expected_serial=expected_serial,
        profile_id="feature-103-rc14-full-ram",
        dfu_sha256=FEATURE_103_RC14_DFU_SHA256,
        fit_sha256=FEATURE_103_RC14_FIT_SHA256,
        fit_size=13_200_115,
        candidate="RC14-full",
    )


def attest_feature103_v1_ram_boot_receipt(
    path: Path, *, expected_serial: str
) -> Feature103RamBootIdentity:
    """Require a private successful exact-v0.52 RAM return for this serial."""

    return _attest_feature103_ram_boot_receipt(
        path,
        expected_serial=expected_serial,
        profile_id="adaptive-scan-v1-release-ram",
        dfu_sha256=FEATURE_103_V1_DFU_SHA256,
        fit_sha256=FEATURE_103_V1_FIT_SHA256,
        fit_size=13_007_023,
        candidate="v0.52 adaptive-scan-v1",
    )


def attest_feature103_fleet_ram_boot_receipts(
    paths: Sequence[Path],
) -> tuple[Feature103RamBootIdentity, ...]:
    """Require one distinct successful RC12-full RAM return for each authorized radio."""

    if len(paths) != len(AUTHORIZED_FEATURE_103_SERIALS):
        raise AdaptiveScanEvidenceError("fleet qualification requires exactly two boot receipts")
    identities = tuple(
        attest_feature103_ram_boot_receipt(path, expected_serial=serial)
        for path, serial in zip(paths, AUTHORIZED_FEATURE_103_SERIALS, strict=True)
    )
    if len({item.receipt_id for item in identities}) != len(identities) or len(
        {item.usb_sysfs_path for item in identities}
    ) != len(identities):
        raise AdaptiveScanEvidenceError("fleet boot receipts are not distinct")
    return identities


def _json_value(value: Any) -> Any:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _json_value(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
    if isinstance(value, BaseModel):
        return _json_value(value.model_dump(mode="python"))
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_value(item) for key, item in value.items()}
    if isinstance(value, (tuple, list)):
        return [_json_value(item) for item in value]
    if isinstance(value, float) and not (-float("inf") < value < float("inf")):
        return None
    return value


def write_adaptive_scan_evidence(
    path: Path,
    receipt: AdaptiveScanCampaignReceipt,
    *,
    candidate_dfu_sha256: str,
    candidate_fit_sha256: str,
    rf_observations: Sequence[Ci16EnergyObservation] = (),
) -> AdaptiveScanEvidenceIdentity:
    """Atomically store one private report and return its exact identity."""

    if not _SHA256.fullmatch(candidate_dfu_sha256) or not _SHA256.fullmatch(
        candidate_fit_sha256
    ):
        raise AdaptiveScanEvidenceError("candidate hashes must be lowercase SHA-256")
    selected = path.expanduser().absolute()
    if selected.exists() or selected.is_symlink():
        raise AdaptiveScanEvidenceError("campaign evidence path must not already exist")
    if not selected.parent.is_dir():
        raise AdaptiveScanEvidenceError("campaign evidence parent does not exist")
    payload = {
        "schema": SCHEMA,
        "schema_version": 1,
        "created_at": datetime.now(UTC).isoformat(),
        "candidate": {
            "dfu_sha256": candidate_dfu_sha256,
            "fit_sha256": candidate_fit_sha256,
        },
        "campaign": _json_value(receipt),
        "rf_observations": _json_value(tuple(rf_observations)),
    }
    encoded = (json.dumps(payload, sort_keys=True, separators=(",", ":")) + "\n").encode()
    descriptor, temporary_name = tempfile.mkstemp(prefix=".feature-103-", dir=selected.parent)
    temporary = Path(temporary_name)
    opened = False
    try:
        os.fchmod(descriptor, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            opened = True
            stream.write(encoded)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, selected)
        temporary.unlink()
        directory_fd = os.open(selected.parent, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    except BaseException:
        if not opened:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
        raise
    return AdaptiveScanEvidenceIdentity(
        path=selected,
        sha256=hashlib.sha256(encoded).hexdigest(),
        bytes=len(encoded),
    )
