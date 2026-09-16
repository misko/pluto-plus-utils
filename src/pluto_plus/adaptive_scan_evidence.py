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
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class AdaptiveScanEvidenceError(ValueError):
    """Campaign evidence is incomplete, malformed, or cannot be stored safely."""


@dataclasses.dataclass(frozen=True, slots=True)
class AdaptiveScanEvidenceIdentity:
    path: Path
    sha256: str
    bytes: int


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
