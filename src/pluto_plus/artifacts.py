"""Atomic SigMF capture artifacts with exact CI16 provenance."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import uuid
from pathlib import Path
from typing import Any

import numpy as np

from pluto_plus.hardware.base import SampleBlock
from pluto_plus.models import ArtifactSummary, RadioIdentity, RadioSettings, utc_now


class CaptureWriter:
    def __init__(
        self,
        root: Path,
        *,
        radio: RadioIdentity,
        settings: RadioSettings,
        label: str | None,
        artifact_id: str | None = None,
    ) -> None:
        self.artifact_id = artifact_id or uuid.uuid4().hex
        self._radio = radio
        self._initial_settings = settings
        self._label = label
        self._created_at = utc_now()
        self._partial = root / ".partial" / self.artifact_id
        self._final = root / self.artifact_id
        if self._partial.exists() or self._final.exists():
            raise FileExistsError(f"artifact already exists: {self.artifact_id}")
        self._partial.mkdir(parents=True)
        self._data_path = self._partial / f"{self.artifact_id}.sigmf-data"
        self._stream = self._data_path.open("xb")
        self._sha256 = hashlib.sha256()
        self._sample_count = 0
        self._receiver_count = len(settings.channels)
        self._first_utc_ns: int | None = None
        self._last_utc_ns: int | None = None
        self._epochs: list[dict[str, Any]] = []
        self._last_revision: int | None = None
        self._closed = False

    def append(self, block: SampleBlock, settings: RadioSettings, revision: int) -> None:
        self._require_open()
        values = np.asarray(block.samples)
        if values.shape[0] != self._receiver_count:
            raise ValueError("receiver count changed during capture")
        encoded = complex_to_ci16(values)
        wire = encoded.tobytes(order="C")
        self._stream.write(wire)
        self._sha256.update(wire)
        if self._first_utc_ns is None:
            self._first_utc_ns = block.utc_ns
        self._last_utc_ns = block.utc_ns
        if revision != self._last_revision:
            self._epochs.append(
                {
                    "sample_start": self._sample_count,
                    "utc_ns": block.utc_ns,
                    "configuration_revision": revision,
                    "settings": settings.model_dump(mode="json"),
                }
            )
            self._last_revision = revision
        self._sample_count += values.shape[1]

    def finalize(self) -> ArtifactSummary:
        self._require_open()
        self._stream.flush()
        os.fsync(self._stream.fileno())
        self._stream.close()
        self._closed = True
        digest = self._sha256.hexdigest()
        metadata = {
            "global": {
                "core:datatype": "ci16_le",
                "core:sample_rate": self._initial_settings.sample_rate_hz,
                "core:num_channels": self._receiver_count,
                "core:description": self._label or "Pluto+ IQ capture",
                "pluto:artifact_id": self.artifact_id,
                "pluto:radio": self._radio.model_dump(mode="json"),
                "pluto:sha256": digest,
                "pluto:created_at": self._created_at.isoformat(),
            },
            "captures": self._epochs,
            "annotations": [],
            "pluto:capture": {
                "sample_count": self._sample_count,
                "receiver_count": self._receiver_count,
                "first_utc_ns": self._first_utc_ns,
                "last_utc_ns": self._last_utc_ns,
                "initial_settings": self._initial_settings.model_dump(mode="json"),
            },
        }
        meta_path = self._partial / f"{self.artifact_id}.sigmf-meta"
        with meta_path.open("x", encoding="utf-8") as stream:
            json.dump(metadata, stream, sort_keys=True, separators=(",", ":"))
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        self._final.parent.mkdir(parents=True, exist_ok=True)
        os.replace(self._partial, self._final)
        _fsync_directory(self._final.parent)
        return ArtifactSummary(
            artifact_id=self.artifact_id,
            radio_id=self._radio.radio_id,
            created_at=self._created_at,
            path=str(self._final),
            sample_count=self._sample_count,
            receiver_count=self._receiver_count,
            sample_rate_hz=self._initial_settings.sample_rate_hz,
            center_frequency_hz=self._initial_settings.center_frequency_hz,
            sha256=digest,
            label=self._label,
        )

    def fail(self, error: BaseException) -> Path:
        if not self._closed:
            self._stream.close()
            self._closed = True
        failed_root = self._partial.parent.parent / ".failed"
        failed_root.mkdir(parents=True, exist_ok=True)
        destination = failed_root / self.artifact_id
        if self._partial.exists():
            failure = self._partial / "failure.json"
            failure.write_text(
                json.dumps(
                    {"type": type(error).__name__, "message": str(error)},
                    sort_keys=True,
                )
                + "\n"
            )
            os.replace(self._partial, destination)
        return destination

    def _require_open(self) -> None:
        if self._closed:
            raise RuntimeError("capture writer is closed")


def complex_to_ci16(samples: np.ndarray) -> np.ndarray:
    values = np.asarray(samples)
    if values.ndim != 2 or not np.iscomplexobj(values):
        raise ValueError("samples must be receiver x sample complex values")
    clipped_real = np.clip(np.rint(values.real), -32768, 32767).astype("<i2")
    clipped_imag = np.clip(np.rint(values.imag), -32768, 32767).astype("<i2")
    output = np.empty((values.shape[1], values.shape[0], 2), dtype="<i2")
    output[:, :, 0] = clipped_real.T
    output[:, :, 1] = clipped_imag.T
    return output


def load_metadata(artifact: ArtifactSummary) -> dict[str, Any]:
    path = Path(artifact.path) / f"{artifact.artifact_id}.sigmf-meta"
    value = json.loads(path.read_text())
    if not isinstance(value, dict):
        raise ValueError("SigMF metadata root must be an object")
    return value


def data_path(artifact: ArtifactSummary) -> Path:
    return Path(artifact.path) / f"{artifact.artifact_id}.sigmf-data"


def verify_artifact(artifact: ArtifactSummary) -> bool:
    digest = hashlib.sha256()
    with data_path(artifact).open("rb") as stream:
        while chunk := stream.read(1024 * 1024):
            digest.update(chunk)
    return digest.hexdigest() == artifact.sha256


def remove_partial_tree(root: Path) -> None:
    """Test/maintenance helper; complete artifacts are never removed here."""

    partial = root / ".partial"
    if partial.exists():
        shutil.rmtree(partial)


def _fsync_directory(path: Path) -> None:
    descriptor = os.open(path, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
