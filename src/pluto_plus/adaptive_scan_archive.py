"""Crash-safe, immutable IQ archive for firmware adaptive scan streams."""

from __future__ import annotations

import dataclasses
import enum
import hashlib
import json
import os
import shutil
import time
from pathlib import Path

import zstandard as zstd

from .adaptive_scan import ScanSetup, ScanTerminal, VisitResult
from .adaptive_scan_client import AdaptiveScanVisit


def _json(value: object) -> object:
    if dataclasses.is_dataclass(value) and not isinstance(value, type):
        return {
            field.name: _json(getattr(value, field.name))
            for field in dataclasses.fields(value)
        }
    if isinstance(value, enum.Enum):
        return value.value
    if isinstance(value, bytes):
        return value.hex()
    if isinstance(value, (tuple, list)):
        return [_json(item) for item in value]
    return value


class AdaptiveScanArchive:
    """Stage complete visit IQ on one filesystem and seal it with one manifest."""

    def __init__(self, root: Path, session_id: str, setup: ScanSetup) -> None:
        self.root = root
        self.session_id = session_id
        self.setup = setup
        self.partial = root / f".{session_id}.partial"
        self.destination = root / session_id
        root.mkdir(parents=True, exist_ok=True)
        self.partial.mkdir(mode=0o750)
        self._visits: list[dict[str, object]] = []
        self._digest = hashlib.sha256()
        self._bytes = 0
        self._closed = False

    def append(self, visit: AdaptiveScanVisit) -> None:
        if self._closed:
            raise RuntimeError("adaptive archive is closed")
        record = visit.record
        entry = {"record": _json(record), "iq": None}
        if record.result is VisitResult.COMPLETE:
            if len(visit.iq) != record.iq_bytes or not visit.iq:
                raise ValueError("complete adaptive visit lacks exact IQ")
            name = f"visit-{record.visit:06d}.ci16.zst"
            temporary = self.partial / f".{name}.partial"
            payload = zstd.ZstdCompressor(level=1).compress(visit.iq)
            with temporary.open("xb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, self.partial / name)
            digest = hashlib.sha256(visit.iq).hexdigest()
            self._digest.update(visit.iq)
            self._bytes += len(visit.iq)
            entry["iq"] = {
                "relative_path": name,
                "uncompressed_bytes": len(visit.iq),
                "compressed_bytes": len(payload),
                "uncompressed_sha256": f"sha256:{digest}",
                "compressed_sha256": f"sha256:{hashlib.sha256(payload).hexdigest()}",
            }
        elif visit.iq:
            raise ValueError("non-complete adaptive visit unexpectedly has IQ")
        self._visits.append(entry)

    def finish(self, terminal: ScanTerminal, evidence: dict[str, object]) -> Path:
        if self._closed:
            raise RuntimeError("adaptive archive is closed")
        manifest = {
            "schema": "org.leo.firmware-adaptive-iq/v1",
            "session_id": self.session_id,
            "created_utc_ns": time.time_ns(),
            "sample_format": "ci16_le",
            "sample_layout": "sample_iq",
            "physical_receiver": 0,
            "setup": _json(self.setup),
            "terminal": _json(terminal),
            "visits": self._visits,
            "uncompressed_bytes": self._bytes,
            "uncompressed_sha256": f"sha256:{self._digest.hexdigest()}",
            "evidence": evidence,
        }
        payload = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode() + b"\n"
        temporary = self.partial / ".manifest.json.partial"
        with temporary.open("xb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, self.partial / "manifest.json")
        directory = os.open(self.partial, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
        os.rename(self.partial, self.destination)
        self._closed = True
        return self.destination

    def abort(self) -> None:
        if not self._closed:
            shutil.rmtree(self.partial, ignore_errors=True)
            self._closed = True
