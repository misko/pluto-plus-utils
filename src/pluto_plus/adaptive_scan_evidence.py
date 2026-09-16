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
FEATURE_103_RC2_DFU_SHA256 = (
    "fbc591ecbbeac83f8b24fc169fd675a834aa5e00aa5b779e79c7c097d9c61c81"
)
FEATURE_103_RC2_FIT_SHA256 = (
    "6cf16e9884fc46a362f3fcc9b61ea752c4cac89e69a8b12b3da2dbbe9b602c0e"
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


def attest_feature103_ram_boot_receipt(
    path: Path, *, expected_serial: str
) -> Feature103RamBootIdentity:
    """Require a private successful RC2 volatile-return receipt for this serial."""

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
        or plan.get("profile_id") != "feature-103-rc2-ram"
        or plan.get("image_sha256") != FEATURE_103_RC2_DFU_SHA256
        or plan.get("fit_sha256") != FEATURE_103_RC2_FIT_SHA256
        or plan.get("fit_size") != 13_188_215
    ):
        raise AdaptiveScanEvidenceError("RAM-boot receipt does not attest exact RC2 return")
    usb_path = str(plan.get("usb_sysfs_path", ""))
    if not usb_path.startswith("/sys/bus/usb/devices/") or ":" in Path(usb_path).name:
        raise AdaptiveScanEvidenceError("RAM-boot receipt USB identity is invalid")
    return Feature103RamBootIdentity(
        receipt_id=receipt_id,
        receipt_path=selected,
        serial=expected_serial,
        usb_sysfs_path=usb_path,
        dfu_sha256=FEATURE_103_RC2_DFU_SHA256,
        fit_sha256=FEATURE_103_RC2_FIT_SHA256,
    )


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
