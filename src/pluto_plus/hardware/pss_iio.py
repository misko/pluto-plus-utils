"""Native libiio transport for FPGA Starlink PSS acquisition and tracking results.

The FPGA keeps 60 MS/s receive samples on the radio.  The two IIO devices
transport only a 26-word fine-timing packet or losslessly chunked 20,000-bin
coarse phase maps.  Parsing is intentionally independent from pylibiio so the
wire ABI can be tested with golden byte strings.
"""

from __future__ import annotations

import importlib
import math
import re
import statistics
import struct
import threading
from collections.abc import Callable, Iterable, Iterator, Sequence
from contextlib import contextmanager, nullcontext
from dataclasses import dataclass, replace
from functools import partial, wraps
from pathlib import Path
from types import TracebackType
from typing import TYPE_CHECKING, Any, Concatenate, ParamSpec, Self, TypeVar
from uuid import uuid4

from pluto_plus.errors import RadioConfigurationError
from pluto_plus.hardware.pss_control import (
    CONTROL_FIELDS,
    PssFineStartError,
    PssFineStartReceipt,
    PssTrackerControlError,
    PssTrackerControlReceipt,
    _ControlJournal,
    _error_text,
    _start_control_errors,
)

if TYPE_CHECKING:
    from pluto_plus.hardware.fine_schedule import FineScheduleManifest
    from pluto_plus.hardware.source_support import ObservationIdentity

PSS_TRACK_DEVICE = "starlink-pss-track"
PSS_MAP_DEVICE = "starlink-pss-map"
PSS_TRACK_ID = 0x50535354
PSS_TRACK_VERSIONS = {15: 0x00010002, 30: 0x00010003, 60: 0x00010003}
PSS_TRACK_GEOMETRY = {15: 0x003D8242, 30: 0x0BCA0884, 60: 0x0F8C1108}
PSS_TRACK_CAPABILITIES = {15: 0x3D, 30: 0x1D, 60: 0x1D}
PSS_PACKET_MAGIC = 0x31535350
PSS_PACKET_HEADER = 0x1A010001
PSS_RESULT_WORDS = 26
PSS_PACKET_BYTES = PSS_RESULT_WORDS * 4
PSS_TRACK_SCAN_WORDS = 32
PSS_TRACK_SCAN_BYTES = PSS_TRACK_SCAN_WORDS * 4

PSS_MAP_ID = 0x50534D41
PSS_MAP_VERSIONS = {15: 0x00010001, 30: 0x00010002, 60: 0x00010004}
PSS_MAP_CAPABILITIES = {15: 0x3F, 30: 0x7F, 60: 0xFF}
PSS_MAP_SHARED_XFFT_VERSION = 0x00010005
PSS_MAP_SHARED_XFFT_CAPABILITIES = 0x13F
PSS_MAP_TILE_GEOMETRY = 0x00401002
PSS_MAP_PHASE_BINS = 20_000
PSS_MAP_CHUNK_MAGIC = 0x4B4E4843
PSS_MAP_CHUNK_BINS = 100
PSS_MAP_CHUNKS = PSS_MAP_PHASE_BINS // PSS_MAP_CHUNK_BINS
PSS_MAP_METADATA_WORDS = 9
PSS_MAP_CHUNK_WORDS = PSS_MAP_METADATA_WORDS + PSS_MAP_CHUNK_BINS // 2
PSS_MAP_CHUNK_BYTES = PSS_MAP_CHUNK_WORDS * 4
PSS_MAP_SCAN_WORDS = 64
PSS_MAP_SCAN_BYTES = PSS_MAP_SCAN_WORDS * 4
PSS_MAP_FRAMES = 64
PSS_MAP_WINDOW_MAPS = 3
PSS_MAP_CANONICAL_SPAN = PSS_MAP_PHASE_BINS * PSS_MAP_FRAMES
PSS_MAP_DEFAULT_DRIFT_BINS = (-12, -8, -4, 0, 4, 8, 12)
PSS_MAX_BATCH_SCANS = 4096
PSS_MAX_BATCH_BYTES = 1 << 20
PSS_HEALTH_WORDS = 46
_HEALTH_CONTRACTS = {
    # ABI: declared MSPS, DDC telemetry mode, known health bits, fatal bits.
    0x10001: (15, 0, 0x1FFF, 0x17FF),
    0x10002: (30, 1, 0x3FFF, 0x37FF),
    0x10003: (60, 1, 0x3FFF, 0x37FF),
    0x10004: (60, 2, 0x3FFF, 0x37FF),
    0x10005: (15, 0, 0x5FFF, 0x57FF),
}


@dataclass(frozen=True, slots=True)
class PssAcquisitionHealth:
    """PSMH v1 receipt: coherent snapshot plus separately labeled LIVE fields.

    Declared MSPS is not a measured PHY rate. DDC mode 1 contains low32-only
    observations, not 64-bit totals. Mode 2 reads each counter individually:
    accepted/emitted are not mutually atomic or tied to the snapshot instant.
    Serial, boot, source-interval binding, and RF claims belong to the caller.
    """

    raw: str
    words: tuple[int, ...]

    @classmethod
    def decode(cls, text: str) -> Self:
        if not isinstance(text, str) or not text.isascii() or len(text) > 2048:
            raise ValueError("PSMH requires bounded ASCII text")
        fields = text.split()
        if fields[:3] != ["PSMH", "1", str(PSS_HEALTH_WORDS)] or len(fields) != 49:
            raise ValueError("PSMH envelope/version/word count is invalid")
        if any(not re.fullmatch(r"[0-9a-f]{8}", field) for field in fields[3:]):
            raise ValueError("PSMH payload requires eight lowercase hexadecimal digits")
        words = tuple(int(field, 16) for field in fields[3:])
        contract = _HEALTH_CONTRACTS.get(words[0])
        if contract is None or (words[1], words[34]) != contract[:2]:
            raise ValueError("PSMH hardware ABI/declared rate/DDC mode mismatch")
        if not words[2] or words[3] & ~0x1FF or words[4] & ~0x1FF:
            raise ValueError("PSMH snapshot generation or reserved status bits are invalid")
        if words[5] & ~7 or words[6] & ~0x7F or words[10] & ~3:
            raise ValueError("PSMH reserved lifecycle/driver/ready bits are nonzero")
        if words[24] & ~contract[2] or words[45] & 0xFC00FC00:
            raise ValueError("PSMH reserved health/candidate-FIFO bits are nonzero")
        for packed in words[44:46]:
            if (packed & 0xFFFF) > (packed >> 16):
                raise ValueError("PSMH FIFO occupancy exceeds recorded high water")
        if any(words[10] & (1 << bank) and not words[11 + bank] for bank in range(2)):
            raise ValueError("PSMH ready bank lacks a map generation")
        if words[10] == 3 and words[11] == words[12]:
            raise ValueError("PSMH ready banks repeat a map generation")
        if (words[34] == 0 and any(words[35:41])) or (
            words[34] == 1 and (words[36] or words[38])
        ):
            raise ValueError("PSMH DDC telemetry mode has unavailable nonzero fields")
        return cls(text, words)

    @property
    def abi_version(self) -> int:
        return self.words[0]

    @property
    def declared_rate_msps(self) -> int:
        return self.words[1]

    @property
    def generation(self) -> int:
        return self.words[2]

    @property
    def coherent_fault_signature(self) -> tuple[int, ...]:
        return self.words[17:31]

    @property
    def ddc_telemetry_mode(self) -> int:
        return self.words[34]

    @property
    def ddc_accepted_observation(self) -> int | None:
        if not self.ddc_telemetry_mode:
            return None
        return self.words[35] | (self.words[36] << 32)

    @property
    def ddc_emitted_observation(self) -> int | None:
        if not self.ddc_telemetry_mode:
            return None
        return self.words[37] | (self.words[38] << 32)

    @property
    def acquisition_enabled(self) -> bool:
        return bool(self.words[5] & 2)

    def require_fault_free(self) -> None:
        mask = _HEALTH_CONTRACTS[self.abi_version][3]
        if not self.words[3] & 1 or not self.words[4] & 1:
            raise ValueError("PSMH hardware epoch is not live")
        if self.words[6] or self.words[9] or any(self.words[31:34]):
            raise ValueError("PSMH driver/bridge/snapshot fault is present")
        for index, value in enumerate(self.coherent_fault_signature):
            fatal_value = (value & mask) if index == 7 else value
            if fatal_value:
                raise ValueError("PSMH coherent acquisition hardware fault is present")
        if self.words[39] or self.words[40]:
            raise ValueError("PSMH live DDC discontinuity/clipping fault is present")


class PssAcquisitionHealthError(RadioConfigurationError):
    """Unavailable, invalid or unhealthy evidence, retaining the raw receipt."""

    def __init__(
        self, message: str, *, raw: str | None = None,
        receipt: PssAcquisitionHealth | None = None,
    ) -> None:
        super().__init__(message)
        self.raw = raw
        self.receipt = receipt


@dataclass(frozen=True, slots=True)
class PssGracefulCloseReceipt:
    health_before: PssAcquisitionHealth | None
    health_after: PssAcquisitionHealth | None
    errors: tuple[str, ...]
    health_before_raw: str | None = None
    health_after_raw: str | None = None
    native_cancel_used: bool = False
    reader_join_asserted: bool = True
    # These are cleanup observations, never a source-continuity or RF claim.


class PssGracefulCloseError(RadioConfigurationError):
    def __init__(self, receipt: PssGracefulCloseReceipt) -> None:
        super().__init__("PSS graceful close incomplete: " + "; ".join(receipt.errors))
        self.receipt = receipt


_Params = ParamSpec("_Params")
_Result = TypeVar("_Result")


def _client_operation(
    method: Callable[Concatenate[PssIioClient, _Params], _Result],
) -> Callable[Concatenate[PssIioClient, _Params], _Result]:
    """Count public operations without serializing independent legacy streams."""

    @wraps(method)
    def guarded(self: PssIioClient, /, *args: _Params.args, **kwargs: _Params.kwargs) -> _Result:
        with self._operation_lock:
            if self._batch_io_active:
                raise RadioConfigurationError("PSS bounded batch I/O is in flight")
            if self._batch_cleanup_errors:
                raise RadioConfigurationError(
                    "PSS failed-open cleanup is unverified; use joined graceful teardown"
                )
            if self._graceful_closing:
                raise RadioConfigurationError("PSS client is closing gracefully")
            if self._closed and method.__name__ not in {"close", "close_fine", "close_maps"}:
                raise RadioConfigurationError("PSS client is closed")
            self._active_operations += 1
        try:
            return method(self, *args, **kwargs)
        finally:
            with self._operation_lock:
                self._active_operations -= 1

    return guarded


def _map_contract(rate_msps: int, experimental_shared_xfft: bool) -> tuple[int, int]:
    """Select one exact contract; never reinterpret a legacy rate's default ABI."""

    if not isinstance(experimental_shared_xfft, bool):
        raise ValueError("experimental_shared_xfft must be a boolean")
    if rate_msps not in PSS_MAP_VERSIONS:
        raise ValueError("PSS map rate must be 15, 30, or 60 MS/s")
    if experimental_shared_xfft:
        if rate_msps != 15:
            raise ValueError("experimental shared-XFFT ABI 1.5 only supports 15 MS/s")
        return PSS_MAP_SHARED_XFFT_VERSION, PSS_MAP_SHARED_XFFT_CAPABILITIES
    return PSS_MAP_VERSIONS[rate_msps], PSS_MAP_CAPABILITIES[rate_msps]


def _signed_16(value: int) -> int:
    return value - (1 << 16) if value & (1 << 15) else value


def read_ci16_coefficients(path: Path, *, rate_msps: int) -> tuple[tuple[int, int], ...]:
    """Read the FPGA's strict one-packed-CI16-word-per-line coefficient format."""

    if rate_msps not in PSS_TRACK_VERSIONS:
        raise ValueError("PSS tracker rate must be 15, 30, or 60 MS/s")
    expected = 66 * (rate_msps // 15)
    coefficients: list[tuple[int, int]] = []
    for line_number, raw in enumerate(path.read_text(encoding="ascii").splitlines(), 1):
        word = raw.strip()
        if len(word) != 8 or any(character not in "0123456789abcdefABCDEF" for character in word):
            raise ValueError(f"PSS coefficient line {line_number} is not one packed CI16 word")
        packed = int(word, 16)
        # Generator/C-tool memory files encode I in 31:16 and Q in 15:0.
        # load_coefficients() repacks the tuple for the FPGA register, whose
        # coefficient I field is 15:0 and Q field is 31:16.
        coefficients.append((_signed_16(packed >> 16), _signed_16(packed & 0xFFFF)))
    if len(coefficients) != expected:
        raise ValueError(
            f"{rate_msps} MS/s coefficient file has {len(coefficients)} words, expected {expected}"
        )
    return tuple(coefficients)


def _s48(low: int, high: int) -> int:
    value = low | ((high & 0xFFFF) << 32)
    return value - (1 << 48) if value & (1 << 47) else value


def _u64(low: int, high: int) -> int:
    return low | (high << 32)


@dataclass(frozen=True, slots=True)
class PssFinePacket:
    """One exact, self-contained fine-timing result from the FPGA."""

    words: tuple[int, ...]
    request_id: int
    center_index: int
    center_timestamp: int
    lag: int
    winner_timestamp: int
    coefficient_generation: int
    correlation_real: int
    correlation_imag: int
    sample_energy: int
    coefficient_energy: int
    saturation_events: int

    @classmethod
    def decode(cls, payload: bytes, *, rate_msps: int) -> Self:
        if rate_msps not in PSS_TRACK_VERSIONS:
            raise ValueError("PSS tracker rate must be 15, 30, or 60 MS/s")
        if len(payload) != PSS_PACKET_BYTES:
            raise ValueError(f"fine packet is {len(payload)} bytes, expected 104")
        words = struct.unpack("<26I", payload)
        lag = struct.unpack("<i", payload[28:32])[0]
        center_index = _u64(words[3], words[4])
        center_timestamp = _u64(words[5], words[6])
        winner_timestamp = _u64(words[8], words[9])
        maximum_lag = 30 * (rate_msps // 15)
        if words[0] != PSS_PACKET_MAGIC or words[1] != PSS_PACKET_HEADER:
            raise ValueError("fine packet envelope does not match PSS ABI 1")
        if words[2] == 0 or words[10] == 0:
            raise ValueError("fine packet request and coefficient generations must be nonzero")
        if center_index != center_timestamp:
            raise ValueError("fine packet center index/timestamp disagree")
        if not -maximum_lag <= lag <= maximum_lag:
            raise ValueError("fine packet winning lag is outside the qualified aperture")
        if winner_timestamp != center_timestamp + lag:
            raise ValueError("fine packet winner timestamp is inconsistent")
        if words[19]:
            raise ValueError("fine packet reports arithmetic saturation")
        sample_energy = _s48(words[15], words[16])
        coefficient_energy = _s48(words[17], words[18])
        if sample_energy <= 0 or coefficient_energy <= 0:
            raise ValueError("fine packet energy must be positive")
        return cls(
            tuple(words),
            words[2],
            center_index,
            center_timestamp,
            lag,
            winner_timestamp,
            words[10],
            _s48(words[11], words[12]),
            _s48(words[13], words[14]),
            sample_energy,
            coefficient_energy,
            words[19],
        )


@dataclass(frozen=True, slots=True)
class PssMapChunk:
    abi_version: int
    generation: int
    chunk_index: int
    chunk_count: int
    start_index: int
    first_bin: int
    bins: tuple[int, ...]

    @classmethod
    def decode(cls, payload: bytes, *, allow_experimental_shared_xfft: bool = False) -> Self:
        if not isinstance(allow_experimental_shared_xfft, bool):
            raise ValueError("allow_experimental_shared_xfft must be a boolean")
        if len(payload) != PSS_MAP_CHUNK_BYTES:
            raise ValueError(
                f"phase-map chunk is {len(payload)} bytes, expected {PSS_MAP_CHUNK_BYTES}"
            )
        metadata = struct.unpack_from("<9I", payload)
        bins = struct.unpack_from("<100H", payload, PSS_MAP_METADATA_WORDS * 4)
        start_index = _u64(metadata[5], metadata[6])
        if metadata[0] != PSS_MAP_CHUNK_MAGIC:
            raise ValueError("phase-map chunk magic is invalid")
        if metadata[1] not in PSS_MAP_VERSIONS.values() and not (
            allow_experimental_shared_xfft and metadata[1] == PSS_MAP_SHARED_XFFT_VERSION
        ):
            raise ValueError("phase-map chunk ABI is unsupported")
        if metadata[2] == 0:
            raise ValueError("phase-map generation must be nonzero")
        if metadata[4] != PSS_MAP_CHUNKS or metadata[3] >= metadata[4]:
            raise ValueError("phase-map chunk geometry is invalid")
        if metadata[7] != metadata[3] * PSS_MAP_CHUNK_BINS or metadata[8] != len(bins):
            raise ValueError("phase-map chunk bin range is inconsistent")
        return cls(
            abi_version=metadata[1],
            generation=metadata[2],
            chunk_index=metadata[3],
            chunk_count=metadata[4],
            start_index=start_index,
            first_bin=metadata[7],
            bins=tuple(bins),
        )


@dataclass(frozen=True, slots=True)
class PssPhaseMap:
    """One phase map whose start index is always in canonical 15 MS/s samples."""

    abi_version: int
    generation: int
    start_index: int
    bins: tuple[int, ...]

    @property
    def canonical_start_index(self) -> int:
        return self.start_index

    def source_start_index(self, *, rate_msps: int) -> int:
        if rate_msps not in PSS_MAP_VERSIONS:
            raise ValueError("PSS map rate must be 15, 30, or 60 MS/s")
        return self.start_index * (rate_msps // 15)


@dataclass(frozen=True, slots=True)
class PssBatchAttributes:
    """Separately sampled attributes, NOT atomic health or an RF qualification.

    None is unavailable (or not applicable to maps), never an invented zero.
    Raw numeric attributes are bounded to 128 characters with explicit errors.
    """

    fault_flags: int | None
    coefficient_generation: int | None
    raw: tuple[tuple[str, str], ...]
    errors: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PssBatchScan:
    """One raw byte range; decoded values with errors are diagnostic only."""

    index: int
    byte_offset: int
    byte_count: int
    decoded: PssFinePacket | PssMapChunk | None
    errors: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PssBatchReceipt:
    """One bounded native refill attempt, retaining bytes BEFORE parsing.

    stream_id is host-generated, not a boot/serial/visit attestation. Native
    refill byte count may be unavailable in pylibiio; read() bytes are not proof
    of DMA/RF continuity or persistence. No batch joins native refill boundaries.
    """

    stream: str
    stream_id: str
    batch_index: int
    rate_msps: int
    abi_version: int
    requested_scans: int
    scan_bytes: int
    buffer_bytes: int | None
    buffer_step: int | None
    refill_started: bool
    refill_completed: bool
    native_refill_bytes: int | None
    observed_bytes: int | None
    raw: bytes | None
    attributes_before: PssBatchAttributes | None
    attributes_after: PssBatchAttributes | None
    expected_request_before: int | None
    remaining_results_before: int | None
    scans: tuple[PssBatchScan, ...]
    errors: tuple[str, ...]

    @property
    def raw_retention_complete(self) -> bool:
        return self.raw is not None and self.observed_bytes == len(self.raw)

    @property
    def complete_scans(self) -> int:
        return len(self.raw) // self.scan_bytes if self.raw is not None else 0

    @property
    def trailing_bytes(self) -> int:
        return len(self.raw) % self.scan_bytes if self.raw is not None else 0

    @property
    def complete(self) -> bool:
        return (not self.errors and self.refill_completed and self.raw_retention_complete and
                self.observed_bytes == self.requested_scans * self.scan_bytes and
                len(self.scans) == self.requested_scans and
                all(scan.index == index and scan.byte_offset == index * self.scan_bytes and
                    scan.byte_count == self.scan_bytes and scan.decoded is not None and
                    not scan.errors for index, scan in enumerate(self.scans)))


class PssBatchError(RadioConfigurationError):
    """Failed batch with retained raw/decoded diagnostics; stream cannot resume."""

    def __init__(self, receipt: PssBatchReceipt) -> None:
        super().__init__("PSS batch rejected: " + "; ".join(receipt.errors))
        self.receipt = receipt


@dataclass(slots=True)
class _BatchStream:
    requested_scans: int
    batch_mode: bool
    stream_id: str
    next_batch: int = 0
    failed: bool = False


@dataclass(frozen=True, slots=True)
class PssCoarseEstimate:
    """C-equivalent candidate extracted from exactly three canonical phase maps."""

    phase_bin: int
    drift_bins_per_64_frames: int
    combined_score: int
    combined_median: float
    median_absolute_deviation: float
    peak_to_median: float
    robust_z: float
    candidate_start_index_canonical: int
    candidate_start_index_source_center: int
    estimated_frame_period_canonical_samples: float
    estimated_frame_period_source_samples: float
    reference_generation: int
    newest_generation: int
    reference_start_index_canonical: int
    newest_start_index_canonical: int


def analyze_phase_maps(
    maps: Sequence[PssPhaseMap],
    *,
    rate_msps: int,
    drift_bins: Sequence[int] = PSS_MAP_DEFAULT_DRIFT_BINS,
    experimental_shared_xfft: bool = False,
) -> PssCoarseEstimate:
    """Extract one deterministic coarse candidate using the qualified C algorithm.

    Phase-map indexes and drift values are canonical 15 MS/s samples.  Source-rate
    indexes and periods are returned separately so 30/60 MS/s callers cannot
    accidentally schedule the full-rate tracker in canonical units.
    """

    expected_abi, _ = _map_contract(rate_msps, experimental_shared_xfft)
    if len(maps) != PSS_MAP_WINDOW_MAPS:
        raise ValueError("exactly three complete phase maps are required")
    hypotheses = tuple(drift_bins)
    if (
        not 1 <= len(hypotheses) <= len(PSS_MAP_DEFAULT_DRIFT_BINS)
        or any(isinstance(value, bool) or not isinstance(value, int) for value in hypotheses)
        or any(not -PSS_MAP_PHASE_BINS < value < PSS_MAP_PHASE_BINS for value in hypotheses)
        or any(right <= left for left, right in zip(hypotheses, hypotheses[1:], strict=False))
    ):
        raise ValueError(
            "drift bank must contain one through seven strictly increasing bounded integers"
        )
    for phase_map in maps:
        if phase_map.abi_version != expected_abi:
            raise ValueError("phase-map ABI does not match the selected sample rate")
        if len(phase_map.bins) != PSS_MAP_PHASE_BINS:
            raise ValueError("phase map must contain exactly 20,000 bins")
        if any(
            isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 0xFFFF
            for value in phase_map.bins
        ):
            raise ValueError("phase-map bins must be unsigned 16-bit integers")
    for previous, current in zip(maps, maps[1:], strict=False):
        if (
            previous.generation == 0
            or previous.generation == 0xFFFFFFFF
            or current.generation != previous.generation + 1
            or current.start_index != previous.start_index + PSS_MAP_CANONICAL_SPAN
        ):
            raise ValueError("phase-map generations or canonical start indexes are discontinuous")

    best_drift = hypotheses[0]
    best_phase = 0
    best_score = -1
    best_combined: list[int] | None = None
    for drift in hypotheses:
        combined = [
            sum(
                phase_map.bins[(phase + tile * drift) % PSS_MAP_PHASE_BINS]
                for tile, phase_map in enumerate(maps)
            )
            for phase in range(PSS_MAP_PHASE_BINS)
        ]
        phase = max(range(PSS_MAP_PHASE_BINS), key=combined.__getitem__)
        score = combined[phase]
        if score > best_score:
            best_drift = drift
            best_phase = phase
            best_score = score
            best_combined = combined

    assert best_combined is not None
    median = float(statistics.median(best_combined))
    median_absolute_deviation = float(
        statistics.median(abs(value - median) for value in best_combined)
    )
    robust_sigma = 1.4826 * median_absolute_deviation
    peak_to_median = best_score / median if median > 0.0 else (math.inf if best_score else 1.0)
    robust_z = (
        (best_score - median) / robust_sigma
        if robust_sigma > 0.0
        else (math.inf if best_score > median else 0.0)
    )
    decimation = rate_msps // 15
    candidate_canonical = maps[0].start_index + best_phase
    period_canonical = PSS_MAP_PHASE_BINS + best_drift / PSS_MAP_FRAMES
    return PssCoarseEstimate(
        phase_bin=best_phase,
        drift_bins_per_64_frames=best_drift,
        combined_score=best_score,
        combined_median=median,
        median_absolute_deviation=median_absolute_deviation,
        peak_to_median=float(peak_to_median),
        robust_z=float(robust_z),
        candidate_start_index_canonical=candidate_canonical,
        candidate_start_index_source_center=candidate_canonical * decimation,
        estimated_frame_period_canonical_samples=period_canonical,
        estimated_frame_period_source_samples=period_canonical * decimation,
        reference_generation=maps[0].generation,
        newest_generation=maps[-1].generation,
        reference_start_index_canonical=maps[0].start_index,
        newest_start_index_canonical=maps[-1].start_index,
    )


class PssMapReassembler:
    """Strictly reassemble one map; partial or interleaved generations fail closed."""

    def __init__(self) -> None:
        self._chunks: list[PssMapChunk] = []

    def reset(self) -> None:
        self._chunks.clear()

    def add(self, chunk: PssMapChunk) -> PssPhaseMap | None:
        if chunk.chunk_index == 0:
            if self._chunks:
                generation = self._chunks[0].generation
                self.reset()
                raise ValueError(
                    f"phase-map restart discarded incomplete generation {generation}"
                )
            self.reset()
        if chunk.chunk_index != len(self._chunks):
            self.reset()
            raise ValueError("phase-map chunks are missing, duplicated, or out of order")
        if self._chunks:
            first = self._chunks[0]
            if (
                chunk.abi_version != first.abi_version
                or chunk.generation != first.generation
                or chunk.start_index != first.start_index
                or chunk.chunk_count != first.chunk_count
            ):
                self.reset()
                raise ValueError("phase-map generation changed during reassembly")
        self._chunks.append(chunk)
        if len(self._chunks) != chunk.chunk_count:
            return None
        first = self._chunks[0]
        bins = tuple(value for item in self._chunks for value in item.bins)
        self.reset()
        if len(bins) != PSS_MAP_PHASE_BINS:
            raise ValueError("reassembled phase map has the wrong bin count")
        return PssPhaseMap(first.abi_version, first.generation, first.start_index, bins)


def _attr_value(device: Any, name: str) -> str:
    try:
        return str(device.attrs[name].value).strip()
    except (AttributeError, KeyError) as error:
        raise RadioConfigurationError(
            f"{device.name} lacks required IIO attribute {name}"
        ) from error


def _read_int_attr(device: Any, name: str) -> int:
    raw = _attr_value(device, name)
    try:
        value = int(raw, 0)
    except ValueError as error:
        raise RadioConfigurationError(
            f"{device.name} attribute {name} is not an integer"
        ) from error
    if value < 0:
        raise RadioConfigurationError(f"{device.name} attribute {name} is negative")
    return value


def _write_attr(device: Any, name: str, value: int | str) -> None:
    try:
        device.attrs[name].value = str(value)
    except (AttributeError, KeyError) as error:
        raise RadioConfigurationError(
            f"{device.name} lacks writable IIO attribute {name}"
        ) from error


def _find_scan_channel(device: Any, expected_repeat: int) -> Any:
    candidates = [channel for channel in device.channels if getattr(channel, "scan_element", False)]
    for channel in candidates:
        data_format = getattr(channel, "data_format", None)
        if getattr(data_format, "repeat", None) == expected_repeat:
            return channel
    # pylibiio 0.25 does not expose repeat on every build. Names are stable.
    names = {
        PSS_TRACK_SCAN_WORDS: "packet_words",
        PSS_MAP_SCAN_WORDS: "chunk_words",
    }
    wanted = names[expected_repeat]
    for channel in candidates:
        if wanted in {getattr(channel, "id", None), getattr(channel, "name", None)}:
            return channel
    raise RadioConfigurationError(
        f"{device.name} lacks the required repeat={expected_repeat} scan channel"
    )


def _disable_scan_channels(device: Any) -> None:
    for channel in device.channels:
        if getattr(channel, "scan_element", False):
            channel.enabled = False


def _split_scans(payload: bytes, scan_bytes: int) -> tuple[bytes, ...]:
    if not payload or len(payload) % scan_bytes:
        raise RadioConfigurationError(
            f"IIO refill returned {len(payload)} bytes, not whole {scan_bytes}-byte scans"
        )
    return tuple(
        payload[offset : offset + scan_bytes] for offset in range(0, len(payload), scan_bytes)
    )


def _unpadded_scan(scan: bytes, payload_bytes: int, *, label: str) -> bytes:
    if any(scan[payload_bytes:]):
        raise RadioConfigurationError(f"{label} IIO transport padding is nonzero")
    return scan[:payload_bytes]


def _close_iio_buffer(iio_module: Any, buffer: Any) -> None:
    """Cancel and destroy modern or legacy pylibiio buffers exactly once."""

    first_error: BaseException | None = None
    cancel = getattr(buffer, "cancel", None)
    if callable(cancel):
        try:
            cancel()
        except BaseException as error:
            first_error = error
    try:
        _destroy_iio_buffer(iio_module, buffer)
    except BaseException as error:
        if first_error is None:
            first_error = error
    if first_error is not None:
        raise first_error


def _destroy_iio_buffer(iio_module: Any, buffer: Any) -> None:
    """Destroy without native cancellation; caller must have joined all readers."""
    closer = getattr(buffer, "close", None) or getattr(buffer, "destroy", None)
    if callable(closer):
        closer()
        return
    native = getattr(buffer, "_buffer", None)
    destroy = getattr(iio_module, "_buffer_destroy", None)
    if native is None or not callable(destroy):
        raise RadioConfigurationError("pylibiio buffer exposes no deterministic destroy operation")
    buffer._buffer = None
    destroy(native)


def _close_iio_context(iio_module: Any, context: Any) -> None:
    """Destroy modern or legacy pylibiio contexts exactly once."""

    closer = getattr(context, "close", None) or getattr(context, "destroy", None)
    if callable(closer):
        closer()
        return
    native = getattr(context, "_context", None)
    destroy = getattr(iio_module, "_destroy", None)
    if native is None or not callable(destroy):
        raise RadioConfigurationError("pylibiio context exposes no deterministic close operation")
    context._context = None
    destroy(native)


class PssIioClient:
    """Capability-discovered, network-safe IIO client for the two PSS devices."""

    def __init__(
        self, context: Any, iio_module: Any, *, experimental_shared_xfft: bool = False
    ) -> None:
        self.context = context
        self._iio = iio_module
        self.experimental_shared_xfft = experimental_shared_xfft
        self.tracker = self._find_device(PSS_TRACK_DEVICE)
        self.phase_map = self._find_device(PSS_MAP_DEVICE)
        self.rate_msps = self._require_contracts()
        self.map_abi_version, _ = _map_contract(self.rate_msps, experimental_shared_xfft)
        self._fine_buffer: Any | None = None
        self._map_buffer: Any | None = None
        self._expected_request: int | None = None
        self._remaining_results: int | None = None
        self._map_session_consumed = False
        self._closed = False
        self._operation_lock = threading.Lock()
        self._active_operations = 0
        self._graceful_closing = False
        self._graceful_receipt: PssGracefulCloseReceipt | None = None
        self._last_health_generation: int | None = None
        self._batch_io_active = False
        self._batch_streams: dict[str, _BatchStream] = {}
        self._batch_cleanup_errors: tuple[str, ...] = ()

    @contextmanager
    def _exclusive_batch_io(self) -> Iterator[None]:
        """New mode only: do not race a shared timeout, buffer or control path."""
        with self._operation_lock:
            # A legacy close may have completed after the public wrapper entered
            # but before this guard. No mutable stream lookup precedes admission.
            if self._closed or self._graceful_closing:
                raise RadioConfigurationError("PSS client is closed or closing gracefully")
            if self._batch_cleanup_errors:
                raise RadioConfigurationError(
                    "PSS failed-open cleanup is unverified; use joined graceful teardown"
                )
            if self._active_operations != 1 or self._batch_io_active:
                raise RadioConfigurationError("join other PSS operations before bounded batch I/O")
            self._batch_io_active = True
        try:
            yield
        finally:
            with self._operation_lock:
                self._batch_io_active = False

    @staticmethod
    def _batch_geometry(count: int, scan_bytes: int, timeout_ms: int) -> None:
        if type(count) is not int or not 1 <= count <= PSS_MAX_BATCH_SCANS:
            raise ValueError("PSS batch must contain 1..4096 scans")
        if count * scan_bytes > PSS_MAX_BATCH_BYTES:
            raise ValueError("PSS batch exceeds the one-MiB byte cap")
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 60_000:
            raise ValueError("PSS batch timeout must be 1..60000 milliseconds")

    def _require_read_mode(self, stream: str, *, batch_mode: bool) -> _BatchStream:
        state = self._batch_streams.get(stream)
        if state is None or state.batch_mode != batch_mode:
            raise RadioConfigurationError(
                "PSS stream read mode does not match its explicit open mode"
            )
        if state.failed:
            raise RadioConfigurationError("PSS batch stream failed; join and clean up before reuse")
        return state

    def _close_failed_batch_open(
        self, stream: str, error: BaseException, journal: _ControlJournal | None = None,
    ) -> None:
        """No reader exists yet; disable/destroy without native network cancel."""
        device = self.tracker if stream == "fine" else self.phase_map
        field = "_fine_buffer" if stream == "fine" else "_map_buffer"
        enable = "schedule_enable" if stream == "fine" else "acquisition_enable"
        buffer = getattr(self, field)
        setattr(self, field, None)
        self._batch_streams.pop(stream, None)
        if stream == "fine":
            self._expected_request = self._remaining_results = None
        try:
            if journal is None:
                _write_attr(device, enable, 0)
            else:
                journal.call("cleanup", "write", enable,
                             lambda: _write_attr(device, enable, 0), requested="0")
        except BaseException as cleanup_error:
            self._batch_cleanup_errors += (f"{stream} failed-open disable: {cleanup_error}",)
            error.add_note(f"PSS failed-open disable: {cleanup_error}")
        if buffer is not None:
            try:
                if journal is None:
                    _destroy_iio_buffer(self._iio, buffer)
                else:
                    journal.call("cleanup", "destroy", "fine_buffer",
                                 lambda: _destroy_iio_buffer(self._iio, buffer))
            except BaseException as cleanup_error:
                if journal is not None and journal.steps and (
                    journal.steps[-1].phase == "cleanup"
                    and journal.steps[-1].action == "destroy"
                    and journal.steps[-1].attempted is False
                ):
                    # Timeout/deadline setup failed before destruction began.
                    # This handle is known live, unlike a possibly destroyed
                    # native pointer. Quarantine blocks reads/reopens; joined
                    # graceful teardown may still destroy this handle once.
                    setattr(self, field, buffer)
                self._batch_cleanup_errors += (f"{stream} failed-open destroy: {cleanup_error}",)
                error.add_note(f"PSS failed-open destroy: {cleanup_error}")

    @classmethod
    def connect(
        cls,
        uri: str,
        *,
        expected_serial: str | None = None,
        iio_module: Any | None = None,
        experimental_shared_xfft: bool = False,
    ) -> Self:
        if not isinstance(experimental_shared_xfft, bool):
            raise ValueError("experimental_shared_xfft must be a boolean")
        if experimental_shared_xfft and (expected_serial is None or not expected_serial.strip()):
            raise ValueError(
                "experimental shared-XFFT connection requires an exact expected serial"
            )
        module = iio_module or importlib.import_module("iio")
        context = module.Context(uri)
        try:
            if expected_serial is not None:
                normalized = expected_serial.strip()
                if not normalized:
                    raise ValueError("expected PSS radio serial must not be empty")
                try:
                    attrs = {str(key): str(value) for key, value in context.attrs.items()}
                except AttributeError as error:
                    raise RadioConfigurationError(
                        "IIO context cannot attest the expected PSS radio serial"
                    ) from error
                observed = attrs.get("hw_serial") or attrs.get("usb,serial") or attrs.get("serial")
                if observed != normalized:
                    raise RadioConfigurationError(
                        "IIO context serial does not match the expected PSS radio"
                    )
            return cls(context, module, experimental_shared_xfft=experimental_shared_xfft)
        except BaseException:
            _close_iio_context(module, context)
            raise

    def _find_device(self, name: str) -> Any:
        find_device = getattr(self.context, "find_device", None)
        device = find_device(name) if callable(find_device) else None
        if device is None:
            raise RadioConfigurationError(f"IIO context lacks required device {name}")
        return device

    def _require_contracts(self) -> int:
        tracker_id = _read_int_attr(self.tracker, "fpga_identity")
        map_id = _read_int_attr(self.phase_map, "fpga_identity")
        rate = _read_int_attr(self.tracker, "rate_msps")
        map_rate = _read_int_attr(self.phase_map, "input_rate_msps")
        if tracker_id != PSS_TRACK_ID or map_id != PSS_MAP_ID:
            raise RadioConfigurationError("PSS IIO FPGA identity mismatch")
        if rate not in PSS_TRACK_VERSIONS or map_rate != rate:
            raise RadioConfigurationError("PSS tracker/map sample rates disagree")
        try:
            map_version, map_capabilities = _map_contract(rate, self.experimental_shared_xfft)
        except ValueError as error:
            raise RadioConfigurationError(str(error)) from error
        expected = (
            (
                self.tracker,
                {
                    "abi_version": PSS_TRACK_VERSIONS[rate],
                    "geometry": PSS_TRACK_GEOMETRY[rate],
                    "capabilities": PSS_TRACK_CAPABILITIES[rate],
                },
            ),
            (
                self.phase_map,
                {
                    "abi_version": map_version,
                    "tile_geometry": PSS_MAP_TILE_GEOMETRY,
                    "capabilities": map_capabilities,
                    "phase_bins": PSS_MAP_PHASE_BINS,
                    "reassembly_chunks": PSS_MAP_CHUNKS,
                },
            ),
        )
        for device, attributes in expected:
            for name, value in attributes.items():
                if _read_int_attr(device, name) != value:
                    raise RadioConfigurationError(
                        f"{device.name} attribute {name} does not match the supported ABI"
                    )
            if _read_int_attr(device, "fault_flags"):
                raise RadioConfigurationError(f"{device.name} entered IIO with a latched fault")
        return rate

    @_client_operation
    def load_coefficients(self, coefficients: Sequence[tuple[int, int]], generation: int) -> None:
        expected = 66 * (self.rate_msps // 15)
        if len(coefficients) != expected or not 1 <= generation <= 0xFFFFFFFF:
            raise ValueError(f"{self.rate_msps} MS/s requires {expected} CI16 coefficients")
        words = []
        for i_value, q_value in coefficients:
            if not -32768 <= i_value <= 32767 or not -32768 <= q_value <= 32767:
                raise ValueError("PSS coefficient is outside signed CI16")
            words.append((i_value & 0xFFFF) | ((q_value & 0xFFFF) << 16))
        _write_attr(self.tracker, "coefficient_generation", generation)
        _write_attr(self.tracker, "coefficient_words", ",".join(f"0x{word:08x}" for word in words))
        _write_attr(self.tracker, "coefficient_commit", 1)
        if _read_int_attr(self.tracker, "active_coefficient_generation") != generation:
            raise RadioConfigurationError("PSS coefficient commit did not become active")

    @_client_operation
    def load_coefficient_file(self, path: Path, *, generation: int) -> None:
        self.load_coefficients(read_ci16_coefficients(path, rate_msps=self.rate_msps), generation)

    @_client_operation
    def open_fine(
        self,
        *,
        first_center: int,
        period_q32_32: int,
        request_base: int,
        count: int,
        queue_target: int = 7,
        refill_results: int = 16,
        batch_mode: bool = False,
        timeout_ms: int = 1000,
    ) -> None:
        if not batch_mode and self._fine_buffer is not None:
            raise RadioConfigurationError("PSS fine stream is already open")
        if min(first_center, period_q32_32, request_base, refill_results) <= 0:
            raise ValueError("PSS fine schedule values must be positive")
        if not 0 <= count <= 0xFFFFFFFF or not 1 <= queue_target <= 7:
            raise ValueError("PSS fine schedule count or queue target is invalid")
        if type(batch_mode) is not bool:
            raise ValueError("batch_mode must be a boolean")
        actual_refill = min(refill_results, count) if count else refill_results
        if batch_mode:
            self._batch_geometry(actual_refill, PSS_TRACK_SCAN_BYTES, timeout_ms)
            if count % actual_refill:
                raise ValueError("finite PSS batch schedule must fill whole native refills")
        with self._exclusive_batch_io() if batch_mode else nullcontext():
            self._open_fine_owned(first_center=first_center, period_q32_32=period_q32_32,
                                  request_base=request_base, count=count, queue_target=queue_target,
                                  actual_refill=actual_refill, batch_mode=batch_mode,
                                  timeout_ms=timeout_ms)

    def _open_fine_owned(
        self, *, first_center: int, period_q32_32: int, request_base: int, count: int,
        queue_target: int, actual_refill: int, batch_mode: bool, timeout_ms: int,
        journal: _ControlJournal | None = None,
    ) -> None:
        """Common owned open body; caller holds the required lifecycle admission."""
        if batch_mode:
            if self._fine_buffer is not None:
                raise RadioConfigurationError("PSS fine stream is already open")
            if journal is None:
                self._set_finite_timeout(timeout_ms)
        state = _BatchStream(actual_refill, batch_mode, str(uuid4()) if batch_mode else "")
        if journal is not None:
            journal.stream_id = state.stream_id

        def invoke(name: str, operation: Callable[[], Any], action: str = "prepare",
                   requested: str | None = None) -> Any:
            if journal is None:
                return operation()
            return journal.call("open", action, name, operation, requested=requested)

        def enable_scan() -> None:
            _find_scan_channel(self.tracker, PSS_TRACK_SCAN_WORDS).enabled = True

        invoke("disable_scan_channels", lambda: _disable_scan_channels(self.tracker))
        invoke("enable_packet_scan", enable_scan)
        if batch_mode and self.tracker.sample_size != PSS_TRACK_SCAN_BYTES:
            raise RadioConfigurationError("PSS fine batch scan stride is unsupported")
        for name, value in (("schedule_first_center", first_center),
                            ("schedule_period_q32_32", period_q32_32),
                            ("schedule_request_base", request_base), ("schedule_count", count),
                            ("schedule_queue_target", queue_target)):
            invoke(name, partial(_write_attr, self.tracker, name, value),
                   "write", str(value))

        def allocate() -> None:
            # Register ownership inside the allocation operation so an error
            # finalizing its receipt still leaves an owned buffer to clean up.
            self._fine_buffer = self._iio.Buffer(self.tracker, actual_refill, False)
            self._batch_streams["fine"] = state

        try:
            invoke("fine_buffer", allocate, "allocate", str(actual_refill))
            if batch_mode:
                invoke("fine_buffer_geometry", lambda: self._check_batch_buffer(
                    self._fine_buffer, actual_refill, PSS_TRACK_SCAN_BYTES), "validate")
            invoke("schedule_enable", lambda: _write_attr(self.tracker, "schedule_enable", 1),
                   "write", "1")
            self._expected_request = request_base
            self._remaining_results = count or None
        except BaseException as error:
            # The receipt path owns cleanup across both this body and its
            # subsequent readbacks; legacy callers preserve their old policy.
            if journal is None:
                if batch_mode:
                    self._close_failed_batch_open("fine", error)
                else:
                    self.close_fine()
            raise

    def _require_control_profile(self, observation: ObservationIdentity) -> None:
        from pluto_plus.hardware.source_support import ObservationIdentity, ProcessingProfile

        if (not isinstance(observation, ObservationIdentity)
                or observation.profile is not ProcessingProfile.PAIRED_15_SHARED_XFFT_512_447_V1
                or self.rate_msps != 15 or self.map_abi_version != PSS_MAP_SHARED_XFFT_VERSION
                or not self.experimental_shared_xfft):
            raise ValueError("control receipts require the explicit paired 15 MS/s shared profile")

    def _control_identity(
        self, observation: ObservationIdentity,
    ) -> tuple[tuple[tuple[str, str | None], ...], tuple[str, ...]]:
        raw: list[tuple[str, str | None]] = []
        errors: list[str] = []
        attrs = self.context.attrs
        for name in ("hw_serial", "usb,serial", "serial", "boot_id"):
            value = attrs.get(name)
            if value is not None and not isinstance(value, str):
                errors.append(f"context {name} is not text")
                value = None
            if value is not None and len(value) > 256:
                errors.append(f"context {name} exceeds its retained bound")
                value = value[:256]
            raw.append((name, value))
        serials = [value for name, value in raw if name != "boot_id" and value]
        if not serials or any(value != observation.serial for value in serials):
            errors.append("context serial aliases do not match the observation")
        boot = dict(raw)["boot_id"]
        if boot is not None and boot != observation.boot_id:
            errors.append("cached context boot identity differs from the observation")
        return tuple(raw), tuple(errors)

    def _read_control_owned(
        self, journal: _ControlJournal, phase: str, *, observation: ObservationIdentity,
        fields: tuple[str, ...], identity: tuple[tuple[str, str | None], ...],
        identity_errors: tuple[str, ...] = (),
    ) -> PssTrackerControlReceipt:
        for name in fields:
            def read(name: str = name) -> Any:
                return self.tracker.attrs[name].value

            try:
                journal.call(phase, "read", name, read)
            except Exception:
                # Preserve all independent observations, including known faults;
                # expired budgets record unattempted fields without more I/O.
                continue
        return journal.control_receipt(phase, observation=observation, fields=fields,
                                       identity=identity, errors=identity_errors)

    def _read_control_transaction(
        self, observation: ObservationIdentity, fields: tuple[str, ...], *,
        timeout_ms: int, budget_ms: int,
    ) -> PssTrackerControlReceipt:
        self._require_control_profile(observation)
        journal = _ControlJournal(timeout_ms=timeout_ms, budget_ms=budget_ms,
                                  setter=self._set_finite_timeout)
        with self._exclusive_batch_io():
            identity: tuple[tuple[str, str | None], ...] = ()
            identity_errors: tuple[str, ...] = ()
            try:
                identity, identity_errors = journal.call(
                    "identity", "metadata", "context_identity",
                    lambda: self._control_identity(observation))
                if identity_errors:
                    raise RadioConfigurationError("; ".join(identity_errors))
                receipt = self._read_control_owned(
                    journal, "control", observation=observation, fields=fields, identity=identity)
                if not receipt.complete:
                    raise PssTrackerControlError(receipt)
                return receipt
            except BaseException as error:
                if isinstance(error, PssTrackerControlError):
                    raise
                error.pss_control_steps = tuple(journal.steps)  # type: ignore[attr-defined]
                error.pss_control_identity = identity  # type: ignore[attr-defined]
                try:
                    receipt = journal.control_receipt(
                        "control", observation=observation, fields=fields, identity=identity,
                        errors=identity_errors + (_error_text(error),))
                except BaseException as receipt_error:
                    error.add_note("rich control receipt unavailable: " +
                                   _error_text(receipt_error))
                    raise error from receipt_error
                if not isinstance(error, Exception):
                    error.pss_control_receipt = receipt  # type: ignore[attr-defined]
                    raise
                raise PssTrackerControlError(receipt) from error

    @_client_operation
    def read_current_index(
        self, observation: ObservationIdentity, *, timeout_ms: int = 1000, budget_ms: int = 5000,
    ) -> PssTrackerControlReceipt:
        """Retain one coherent u64 read, not a multi-field/PHY/boot snapshot.

        The supplied identity is externally owned. Exact cached context serials
        are checked; absent context boot metadata remains explicitly unavailable.
        No counter freshness, minimum lead time, RF health or frame lock is inferred.
        """
        return self._read_control_transaction(observation, ("current_index",),
                                               timeout_ms=timeout_ms, budget_ms=budget_ms)

    @_client_operation
    def read_tracker_control(
        self, observation: ObservationIdentity, *, timeout_ms: int = 1000, budget_ms: int = 5000,
    ) -> PssTrackerControlReceipt:
        """Read bounded, separately sampled controls; nonzero faults remain observations."""
        return self._read_control_transaction(observation, CONTROL_FIELDS,
                                               timeout_ms=timeout_ms, budget_ms=budget_ms)

    @_client_operation
    def open_fine_receipted(
        self, manifest: FineScheduleManifest, *, queue_target: int = 7, refill_results: int = 16,
        timeout_ms: int = 1000, budget_ms: int = 10_000,
    ) -> PssFineStartReceipt:
        """Open finite raw-batch fine capture with write and later-readback evidence.

        This is not a radio lease or a paired recorder. The caller owns the
        observation, coefficient content and external lifecycle. No reads may be
        in flight on this context. Rejected starts retain cleanup evidence; an
        uncertain write is never interpreted as driver rejection or acceptance.
        """
        from pluto_plus.hardware.fine_schedule import FineScheduleManifest

        if not isinstance(manifest, FineScheduleManifest):
            raise ValueError("an explicit finite FineScheduleManifest is required")
        self._require_control_profile(manifest.observation)
        if type(queue_target) is not int or not 1 <= queue_target <= 7:
            raise ValueError("queue_target must be 1..7")
        if type(refill_results) is not int or not 1 <= refill_results <= PSS_MAX_BATCH_SCANS:
            raise ValueError("refill_results must be 1..4096")
        actual_refill = min(refill_results, manifest.count)
        self._batch_geometry(actual_refill, PSS_TRACK_SCAN_BYTES, timeout_ms)
        if manifest.count % actual_refill:
            raise ValueError("finite PSS batch schedule must fill whole native refills")
        journal = _ControlJournal(timeout_ms=timeout_ms, budget_ms=budget_ms,
                                  setter=self._set_finite_timeout)
        with self._exclusive_batch_io():
            if self._fine_buffer is not None:
                raise RadioConfigurationError("PSS fine stream is already open")
            identity: tuple[tuple[str, str | None], ...] = ()
            before: PssTrackerControlReceipt | None = None
            after: PssTrackerControlReceipt | None = None
            errors: list[str] = []
            try:
                identity, identity_errors = journal.call(
                    "identity", "metadata", "context_identity",
                    lambda: self._control_identity(manifest.observation))
                if identity_errors:
                    errors.extend(identity_errors)
                    raise RadioConfigurationError("observation identity was not admitted")
                before = self._read_control_owned(
                    journal, "before", observation=manifest.observation, fields=CONTROL_FIELDS,
                    identity=identity)
                errors.extend(_start_control_errors(before, manifest, after=False,
                                                     queue_target=queue_target))
                if errors:
                    raise RadioConfigurationError("fine start preflight evidence failed")
                self._open_fine_owned(
                    first_center=manifest.first_center, period_q32_32=manifest.period_q32_32,
                    request_base=manifest.request_base, count=manifest.count,
                    queue_target=queue_target, actual_refill=actual_refill, batch_mode=True,
                    timeout_ms=timeout_ms, journal=journal)
                after = self._read_control_owned(
                    journal, "after", observation=manifest.observation, fields=CONTROL_FIELDS,
                    identity=identity)
                errors.extend(_start_control_errors(after, manifest, after=True,
                                                     queue_target=queue_target))
                current_before, current_after = before.current_index, after.current_index
                if (current_before is not None and current_after is not None
                        and current_after < current_before):
                    errors.append("source index regressed across fine startup")
                if errors:
                    raise RadioConfigurationError("fine start later-readback evidence failed")
                receipt = PssFineStartReceipt(
                    manifest, queue_target, actual_refill, journal.stream_id,
                    before, after, tuple(journal.steps), ())
                if not receipt.complete:
                    raise RadioConfigurationError("fine start receipt is incomplete")
                return receipt
            except BaseException as error:
                # Cleanup must not depend on reconstructing a rich receipt:
                # that constructor may be the operation which just failed.
                if self._fine_buffer is not None or any(
                    step.phase == "open" and step.attempted
                    and step.action in {"write", "allocate"} for step in journal.steps
                ):
                    missing_handle = self._fine_buffer is None and any(
                        step.phase == "open" and step.action == "allocate"
                        and step.attempted and not step.returned for step in journal.steps)
                    try:
                        journal.begin_cleanup()
                        self._close_failed_batch_open("fine", error, journal)
                    except BaseException as cleanup_error:
                        self._batch_cleanup_errors += (
                            f"fine cleanup could not be completed: {_error_text(cleanup_error)}",)
                    if missing_handle:
                        self._batch_cleanup_errors += (
                            "fine allocation outcome unverified; native handle unavailable",)
                    errors.extend(self._batch_cleanup_errors)
                error.pss_control_steps = tuple(journal.steps)  # type: ignore[attr-defined]
                error.pss_control_identity = identity  # type: ignore[attr-defined]
                error.pss_fine_manifest = manifest  # type: ignore[attr-defined]
                try:
                    errors.append(_error_text(error))
                    if before is None:
                        before = journal.control_receipt(
                            "before", observation=manifest.observation,
                            fields=CONTROL_FIELDS, identity=identity)
                    if after is None and any(step.phase == "after" for step in journal.steps):
                        after = journal.control_receipt(
                            "after", observation=manifest.observation,
                            fields=CONTROL_FIELDS, identity=identity)
                    receipt = PssFineStartReceipt(
                        manifest, queue_target, actual_refill, journal.stream_id, before, after,
                        tuple(journal.steps), tuple(errors), journal.cleanup_attempted,
                        not self._batch_cleanup_errors if journal.cleanup_attempted else None)
                except BaseException as receipt_error:
                    error.add_note("rich fine start receipt unavailable: " +
                                   _error_text(receipt_error))
                    raise error from receipt_error
                if not isinstance(error, Exception):
                    error.pss_fine_start_receipt = receipt  # type: ignore[attr-defined]
                    raise
                raise PssFineStartError(receipt) from error

    @_client_operation
    def read_fine(self) -> tuple[PssFinePacket, ...]:
        if self._fine_buffer is None:
            raise RadioConfigurationError("PSS fine stream is not open")
        self._require_read_mode("fine", batch_mode=False)
        self._fine_buffer.refill()
        scans = _split_scans(bytes(self._fine_buffer.read()), PSS_TRACK_SCAN_BYTES)
        packets = tuple(
            PssFinePacket.decode(
                _unpadded_scan(scan, PSS_PACKET_BYTES, label="PSS fine packet"),
                rate_msps=self.rate_msps,
            )
            for scan in scans
        )
        active_generation = _read_int_attr(self.tracker, "active_coefficient_generation")
        for packet in packets:
            if packet.coefficient_generation != active_generation:
                raise RadioConfigurationError("PSS fine packet coefficient generation changed")
            if self._expected_request is None or packet.request_id != self._expected_request:
                raise RadioConfigurationError("PSS fine packet request sequence is discontinuous")
            self._expected_request = (self._expected_request + 1) & 0xFFFFFFFF
            if self._expected_request == 0 and (
                self._remaining_results is None or self._remaining_results > 1
            ):
                raise RadioConfigurationError("PSS fine request sequence would wrap through zero")
            if self._remaining_results is not None:
                self._remaining_results -= 1
        if _read_int_attr(self.tracker, "fault_flags"):
            raise RadioConfigurationError("PSS fine driver latched a stream fault")
        return packets

    @_client_operation
    def open_maps(
        self, *, refill_chunks: int = 400, batch_mode: bool = False, timeout_ms: int = 1000,
    ) -> None:
        """Open the one continuous coarse-map session for this FPGA reset epoch.

        Keep this stream open and refill it continuously.  Stopping and restarting
        the producer can turn a rate-change discontinuity into a latched hardware
        fault, so a second session is rejected until the FPGA has been reset.
        """

        if not batch_mode and self._map_buffer is not None:
            raise RadioConfigurationError("PSS phase-map stream is already open")
        if type(batch_mode) is not bool:
            raise ValueError("batch_mode must be a boolean")
        if batch_mode:
            self._batch_geometry(refill_chunks, PSS_MAP_SCAN_BYTES, timeout_ms)
        with self._exclusive_batch_io() if batch_mode else nullcontext():
            if batch_mode:
                if self._map_buffer is not None:
                    raise RadioConfigurationError("PSS phase-map stream is already open")
                self._set_finite_timeout(timeout_ms)
            if self._map_session_consumed or _read_int_attr(self.phase_map, "maps_delivered"):
                raise RadioConfigurationError(
                    "PSS phase-map acquisition is one continuous session per FPGA reset epoch"
                )
            if refill_chunks < PSS_MAP_CHUNKS:
                raise ValueError(f"phase-map refill must hold at least {PSS_MAP_CHUNKS} chunks")
            state = _BatchStream(refill_chunks, batch_mode, str(uuid4()) if batch_mode else "")
            self._map_session_consumed = True
            _write_attr(self.phase_map, "acquisition_flush", 1)
            _disable_scan_channels(self.phase_map)
            _find_scan_channel(self.phase_map, PSS_MAP_SCAN_WORDS).enabled = True
            if batch_mode and self.phase_map.sample_size != PSS_MAP_SCAN_BYTES:
                raise RadioConfigurationError("PSS map batch scan stride is unsupported")
            try:
                self._map_buffer = self._iio.Buffer(self.phase_map, refill_chunks, False)
                self._batch_streams["map"] = state
                if batch_mode:
                    self._check_batch_buffer(self._map_buffer, refill_chunks, PSS_MAP_SCAN_BYTES)
                _write_attr(self.phase_map, "acquisition_enable", 1)
            except BaseException as error:
                if batch_mode:
                    self._close_failed_batch_open("map", error)
                else:
                    self.close_maps()
                raise

    @_client_operation
    def read_map_chunks(self) -> tuple[PssMapChunk, ...]:
        if self._map_buffer is None:
            raise RadioConfigurationError("PSS phase-map stream is not open")
        self._require_read_mode("map", batch_mode=False)
        self._map_buffer.refill()
        scans = _split_scans(bytes(self._map_buffer.read()), PSS_MAP_SCAN_BYTES)
        chunks = tuple(
            PssMapChunk.decode(
                _unpadded_scan(scan, PSS_MAP_CHUNK_BYTES, label="PSS phase-map chunk"),
                allow_experimental_shared_xfft=self.experimental_shared_xfft,
            )
            for scan in scans
        )
        if any(chunk.abi_version != self.map_abi_version for chunk in chunks):
            raise RadioConfigurationError(
                "PSS phase-map stream ABI differs from its attested context"
            )
        if _read_int_attr(self.phase_map, "fault_flags"):
            raise RadioConfigurationError("PSS phase-map driver latched a stream fault")
        return chunks

    @staticmethod
    def _check_batch_buffer(buffer: Any, count: int, stride: int) -> tuple[int, int]:
        length, step = len(buffer), buffer.step
        if type(step) is not int or step != stride or length != count * stride:
            raise RadioConfigurationError("PSS batch native buffer length/step mismatch")
        binding_count = getattr(buffer, "sample_count", getattr(buffer, "_samples_count", None))
        if binding_count is not None and (type(binding_count) is not int or binding_count != count):
            raise RadioConfigurationError("PSS batch native sample count mismatch")
        return length, step

    @staticmethod
    def _batch_attributes(device: Any, *, fine: bool) -> PssBatchAttributes:
        names = ("fault_flags", "active_coefficient_generation") if fine else ("fault_flags",)
        raw: list[tuple[str, str]] = []
        values: dict[str, int] = {}
        errors: list[str] = []
        for name in names:
            try:
                text = _attr_value(device, name)
                raw.append((name, text[:128]))
                if len(text) > 128:
                    raise ValueError("numeric attribute exceeds 128 characters; raw text truncated")
                value = int(text, 0)
                if not 0 <= value <= 0xFFFFFFFF or (
                    name == "active_coefficient_generation" and not value
                ):
                    raise ValueError("attribute is outside its nonnegative/nonzero u32 contract")
                values[name] = value
            except Exception as error:
                errors.append(f"{name}: {error}")
        if values.get("fault_flags"):
            errors.append("driver latched a stream fault")
        return PssBatchAttributes(values.get("fault_flags"),
                                  values.get("active_coefficient_generation"),
                                  tuple(raw), tuple(errors))

    def _decode_batch_scans(
        self, raw: bytes, *, fine: bool, before: PssBatchAttributes,
        expected_request: int | None, remaining: int | None,
    ) -> tuple[tuple[PssBatchScan, ...], BaseException | None]:
        stride = PSS_TRACK_SCAN_BYTES if fine else PSS_MAP_SCAN_BYTES
        payload_bytes = PSS_PACKET_BYTES if fine else PSS_MAP_CHUNK_BYTES
        observations = []
        for index, offset in enumerate(range(0, len(raw), stride)):
            scan = raw[offset:offset + stride]
            errors: list[str] = []
            decoded: PssFinePacket | PssMapChunk | None = None
            try:
                if len(scan) != stride:
                    raise ValueError("truncated trailing scan")
                payload = _unpadded_scan(scan, payload_bytes, label="PSS batch scan")
                if fine:
                    packet = PssFinePacket.decode(payload, rate_msps=self.rate_msps)
                    decoded = packet
                    if packet.coefficient_generation != before.coefficient_generation:
                        errors.append("fine packet coefficient generation differs from before read")
                    if expected_request is None or packet.request_id != expected_request + index:
                        errors.append("fine packet request sequence is discontinuous or wraps")
                    if remaining is not None and index >= remaining:
                        errors.append("fine packet exceeds the finite schedule")
                else:
                    decoded = PssMapChunk.decode(
                        payload, allow_experimental_shared_xfft=self.experimental_shared_xfft,
                    )
                    if decoded.abi_version != self.map_abi_version:
                        errors.append("map chunk ABI differs from the admitted context")
            except BaseException as error:
                errors.append(f"decode: {error}")
                if not isinstance(error, Exception):
                    observations.append(
                        PssBatchScan(index, offset, len(scan), decoded, tuple(errors))
                    )
                    return tuple(observations), error
            observations.append(PssBatchScan(index, offset, len(scan), decoded, tuple(errors)))
        return tuple(observations), None

    def _read_batch(self, stream: str, *, timeout_ms: int) -> PssBatchReceipt:
        fine = stream == "fine"
        stride = PSS_TRACK_SCAN_BYTES if fine else PSS_MAP_SCAN_BYTES
        with self._exclusive_batch_io():
            buffer = self._fine_buffer if fine else self._map_buffer
            if buffer is None:
                raise RadioConfigurationError(f"PSS {stream} stream is not open")
            state = self._require_read_mode(stream, batch_mode=True)
            self._batch_geometry(state.requested_scans, stride, timeout_ms)
            ordinal = state.next_batch
            state.next_batch += 1
            device = self.tracker if fine else self.phase_map
            buffer_bytes: int | None = None
            buffer_step: int | None = None
            native_count: int | None = None
            observed_bytes: int | None = None
            raw: bytes | None = None
            before: PssBatchAttributes | None = None
            after: PssBatchAttributes | None = None
            scans: tuple[PssBatchScan, ...] = ()
            errors: list[str] = []
            refill_started = refill_completed = False
            expected = self._expected_request if fine else None
            remaining = self._remaining_results if fine else None
            interrupt: BaseException | None = None
            phase = "timeout"
            try:
                self._set_finite_timeout(timeout_ms)
                phase = "buffer geometry"
                # Capture reported geometry even when a mismatched value fails admission.
                buffer_bytes = len(buffer)
                reported_step = buffer.step
                buffer_step = reported_step if type(reported_step) is int else None
                self._check_batch_buffer(buffer, state.requested_scans, stride)
                if fine and remaining == 0:
                    raise ValueError("fine schedule is already completely received")
                phase = "attributes before"
                before = self._batch_attributes(device, fine=fine)
                if before.errors:
                    raise ValueError("; ".join(before.errors))
                phase = "refill"
                refill_started = True
                returned = buffer.refill()
                refill_completed = True
                if returned is not None:
                    if type(returned) is int:
                        native_count = returned
                        if returned < 0:
                            refill_completed = False
                            raise OSError("native refill returned a negative byte count")
                    else:
                        errors.append("native refill returned an unsupported byte-count type")
                phase = "read"
                payload = buffer.read()
                if type(payload) not in (bytes, bytearray):
                    raise ValueError("PSS batch read requires binding bytes or bytearray")
                observed_bytes = len(payload)
                # A broken binding can already have allocated more. Retain no
                # more than the admitted per-stream cap and explicitly reject it.
                cap = min(PSS_MAX_BATCH_BYTES, PSS_MAX_BATCH_SCANS * stride)
                raw = bytes(payload[:cap])
                if observed_bytes > cap:
                    errors.append("raw retention truncated at the bounded byte cap")
                if observed_bytes != state.requested_scans * stride:
                    errors.append("raw refill byte count differs from the requested native batch")
                if native_count is not None and native_count != observed_bytes:
                    errors.append("native refill byte count differs from bytes returned by read")
            except BaseException as error:
                errors.append(f"{phase}: {error}")
                if not isinstance(error, Exception):
                    interrupt = error
            if refill_started:
                try:
                    after = self._batch_attributes(device, fine=fine)
                    errors.extend(f"attributes after: {error}" for error in after.errors)
                    if fine and before is not None and (
                        after.coefficient_generation != before.coefficient_generation
                    ):
                        errors.append("fine coefficient generation changed across the refill")
                except BaseException as error:
                    errors.append(f"attributes after: {error}")
                    if not isinstance(error, Exception) and interrupt is None:
                        interrupt = error
            try:
                raw_receipt = PssBatchReceipt(
                    stream=stream, stream_id=state.stream_id, batch_index=ordinal,
                    rate_msps=self.rate_msps,
                    abi_version=(PSS_TRACK_VERSIONS[self.rate_msps]
                                 if fine else self.map_abi_version),
                    requested_scans=state.requested_scans, scan_bytes=stride,
                    buffer_bytes=buffer_bytes, buffer_step=buffer_step,
                    refill_started=refill_started, refill_completed=refill_completed,
                    native_refill_bytes=native_count, observed_bytes=observed_bytes, raw=raw,
                    attributes_before=before, attributes_after=after,
                    expected_request_before=expected, remaining_results_before=remaining,
                    scans=(), errors=tuple(errors),
                )
            except BaseException as error:
                state.failed = True
                # Even receipt construction failure must not erase the payload.
                # This fallback is explicitly NOT a complete structured receipt.
                error.pss_batch_raw = raw  # type: ignore[attr-defined]
                error.add_note("PSS raw receipt construction failed; pss_batch_raw retains bytes")
                raise
            try:
                if raw is not None and before is not None and interrupt is None:
                    scans, interrupt = self._decode_batch_scans(
                        raw, fine=fine, before=before, expected_request=expected,
                        remaining=remaining,
                    )
                    errors.extend(
                        f"scan {scan.index}: {error}" for scan in scans for error in scan.errors
                    )
                    if fine and expected is not None and expected + len(scans) > 0xFFFFFFFF and (
                        remaining is None or remaining > len(scans)
                    ):
                        errors.append("fine request sequence would wrap through zero")
                receipt = replace(raw_receipt, scans=scans, errors=tuple(errors))
            except BaseException as error:
                state.failed = True
                error.pss_batch_receipt = raw_receipt  # type: ignore[attr-defined]
                error.pss_batch_scans = scans  # type: ignore[attr-defined]
                error.add_note("PSS decode/receipt finalization failed; raw receipt retained")
                raise
            try:
                if not receipt.complete:
                    state.failed = True
                    if interrupt is not None:
                        interrupt.add_note(str(PssBatchError(receipt)))
                        # Preserve process-control semantics AND the raw observation.
                        raise interrupt
                    raise PssBatchError(receipt)
                if fine:
                    assert expected is not None
                    self._expected_request = (expected + len(scans)) & 0xFFFFFFFF
                    if remaining is not None:
                        self._remaining_results = remaining - len(scans)
                return receipt
            except PssBatchError:
                raise
            except BaseException as error:
                # Completeness traversal and ledger writes can be interrupted
                # too. Never resume a possibly partly advanced host ledger.
                state.failed = True
                # Start with a definitely incomplete fallback before attempting
                # to construct the richer failed, fully decoded receipt.
                error.pss_batch_receipt = raw_receipt  # type: ignore[attr-defined]
                error.pss_batch_scans = scans  # type: ignore[attr-defined]
                try:
                    error.pss_batch_receipt = replace(  # type: ignore[attr-defined]
                        receipt, errors=receipt.errors + (f"final decision/accounting: {error}",),
                    )
                except BaseException as receipt_error:
                    error.add_note(f"PSS failed-decision receipt unavailable: {receipt_error}")
                error.add_note("PSS final decision/accounting failed; decoded receipt retained")
                raise

    @_client_operation
    def read_map_batch(self, *, timeout_ms: int = 1000) -> PssBatchReceipt:
        """Retain one raw native batch before parsing; never reassemble or drop negatives.

        Requires open_maps(batch_mode=True). Persist this receipt/raw or the
        PssBatchError receipt before feeding decoded chunks to a reassembler.
        The caller binds owner, boot, visit and actual source support separately.
        """
        return self._read_batch("map", timeout_ms=timeout_ms)

    @_client_operation
    def read_fine_batch(self, *, timeout_ms: int = 1000) -> PssBatchReceipt:
        """Retain one bounded raw batch; commit fine request accounting only on success."""
        return self._read_batch("fine", timeout_ms=timeout_ms)

    @_client_operation
    def read_maps(self, reassembler: PssMapReassembler) -> tuple[PssPhaseMap, ...]:
        maps: list[PssPhaseMap] = []
        for chunk in self.read_map_chunks():
            completed = reassembler.add(chunk)
            if completed is not None:
                maps.append(completed)
        return tuple(maps)

    def _read_acquisition_health(self, *, require_fault_free: bool) -> PssAcquisitionHealth:
        raw: str | None = None
        receipt: PssAcquisitionHealth | None = None
        try:
            raw = str(self.phase_map.attrs["acquisition_health"].value)
            receipt = PssAcquisitionHealth.decode(raw)
            if receipt.abi_version != self.map_abi_version or (
                receipt.declared_rate_msps != self.rate_msps
            ):
                raise ValueError("acquisition health differs from the admitted context ABI/rate")
            with self._operation_lock:
                if (self._last_health_generation is not None and
                        receipt.generation <= self._last_health_generation):
                    raise ValueError("acquisition health snapshot generation is stale or reset")
                self._last_health_generation = receipt.generation
            if require_fault_free:
                receipt.require_fault_free()
            return receipt
        except (AttributeError, KeyError) as error:
            raise PssAcquisitionHealthError(
                "fresh acquisition_health evidence is unavailable", raw=raw, receipt=receipt,
            ) from error
        except (ValueError, OSError) as error:
            raise PssAcquisitionHealthError(
                f"acquisition_health evidence rejected: {error}", raw=raw, receipt=receipt,
            ) from error

    @_client_operation
    def read_acquisition_health(
        self, *, require_fault_free: bool = True, timeout_ms: int = 1000,
    ) -> PssAcquisitionHealth:
        """Read fresh driver-serialized health, never substitute fault_flags alone.

        Diagnostic callers may explicitly retain known faults, but cannot opt
        out of envelope, context-binding, or freshness checks. Applies a finite
        context timeout; the caller binds the receipt to its observation.
        """
        if not isinstance(require_fault_free, bool):
            raise ValueError("require_fault_free must be a boolean")
        self._set_finite_timeout(timeout_ms)
        return self._read_acquisition_health(require_fault_free=require_fault_free)

    def _set_finite_timeout(self, timeout_ms: int) -> None:
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 60_000:
            raise ValueError("PSS context timeout must be 1..60000 milliseconds")
        setter = getattr(self.context, "set_timeout", None)
        if not callable(setter):
            raise RadioConfigurationError("PSS operation requires a bounded context timeout")
        setter(timeout_ms)

    def close_gracefully(
        self, *, readers_joined: bool, timeout_ms: int = 1000,
    ) -> PssGracefulCloseReceipt:
        """Explicit joined-reader close without native cancellation.

        The caller stops and joins bounded readers first, retaining all partial
        data. This guard rejects concurrent public operations without waiting or
        destroying a buffer being read. It cannot attest threads using private
        buffer/context objects. Incomplete fine work is an evidence failure, NOT
        a reason to leave the producer alive. Teardown is still attempted.

        Only owned producers are disabled. This method closes its context; RF
        restoration through the caller's owner/control context remains external.
        Legacy close()/context-manager defaults retain their cancellation policy.
        """
        if readers_joined is not True:
            raise ValueError("graceful close requires the caller to stop and join all readers")
        if type(timeout_ms) is not int or not 1 <= timeout_ms <= 60_000:
            raise ValueError("graceful close timeout must be 1..60000 milliseconds")
        with self._operation_lock:
            if self._graceful_receipt is not None:
                if self._graceful_receipt.errors:
                    raise PssGracefulCloseError(self._graceful_receipt)
                return self._graceful_receipt
            if self._closed:
                raise RadioConfigurationError(
                    "context was already closed without a graceful receipt"
                )
            if self._graceful_closing or self._active_operations:
                raise RadioConfigurationError("join in-flight PSS operations before graceful close")
            self._graceful_closing = True
        errors: list[str] = []
        health: list[PssAcquisitionHealth | None] = [None, None]
        raw_health: list[str | None] = [None, None]
        owned_map = self._map_buffer is not None

        def read_health(ordinal: int) -> None:
            try:
                observed = self._read_acquisition_health(require_fault_free=True)
                health[ordinal], raw_health[ordinal] = observed, observed.raw
            except PssAcquisitionHealthError as error:
                health[ordinal], raw_health[ordinal] = error.receipt, error.raw
                errors.append(f"health {'before' if ordinal == 0 else 'after'}: {error}")
            except BaseException as error:
                errors.append(f"health read: {error}")

        # No remote operation is safe to begin if a finite timeout cannot be set.
        try:
            self._set_finite_timeout(timeout_ms)
        except BaseException:
            with self._operation_lock:
                self._graceful_closing = False
            raise

        try:
            errors.extend(f"unverified {error}" for error in self._batch_cleanup_errors)
            read_health(0)
            for stream, state in self._batch_streams.items():
                if state.failed:
                    errors.append(f"{stream} batch failed; retain its separate error receipt")
            if self._fine_buffer is not None and self._remaining_results != 0:
                errors.append(
                    "fine schedule is unbounded or incomplete; queued work is unqualified"
                )
            for field, device, enable_attr in (
                ("_fine_buffer", self.tracker, "schedule_enable"),
                ("_map_buffer", self.phase_map, "acquisition_enable"),
            ):
                buffer = getattr(self, field)
                if buffer is None:
                    continue
                try:
                    _write_attr(device, enable_attr, 0)
                    if _read_int_attr(device, enable_attr):
                        raise RadioConfigurationError("producer disable readback is not zero")
                except BaseException as error:
                    errors.append(f"{enable_attr} disable: {error}")
                # Clear ownership even when destroy raises, avoiding double free.
                setattr(self, field, None)
                try:
                    _destroy_iio_buffer(self._iio, buffer)
                except BaseException as error:
                    errors.append(f"{device.name} destroy: {error}")
            self._expected_request = None
            self._remaining_results = None
            self._batch_streams.clear()
            read_health(1)
            after = health[1]
            if owned_map and after is not None and (after.words[5] or after.words[4] & 2):
                errors.append("map producer/IRQ lifecycle remains active after destruction")
            try:
                if _read_int_attr(self.tracker, "fault_flags"):
                    errors.append("tracker driver reports a terminal fault")
            except BaseException as error:
                errors.append(f"tracker terminal fault read: {error}")
        finally:
            try:
                _close_iio_context(self._iio, self.context)
            except BaseException as error:
                errors.append(f"context close: {error}")
            receipt = PssGracefulCloseReceipt(
                health_before=health[0], health_after=health[1], errors=tuple(errors),
                health_before_raw=raw_health[0], health_after_raw=raw_health[1],
            )
            with self._operation_lock:
                self._closed = True
                self._graceful_closing = False
                self._graceful_receipt = receipt
        if receipt.errors:
            raise PssGracefulCloseError(receipt)
        return receipt

    @_client_operation
    def close_fine(self) -> None:
        buffer = self._fine_buffer
        if buffer is None:
            return
        self._fine_buffer = None
        self._batch_streams.pop("fine", None)
        try:
            _write_attr(self.tracker, "schedule_enable", 0)
        finally:
            self._expected_request = None
            self._remaining_results = None
            _close_iio_buffer(self._iio, buffer)

    @_client_operation
    def close_maps(self) -> None:
        buffer = self._map_buffer
        if buffer is None:
            return
        self._map_buffer = None
        self._batch_streams.pop("map", None)
        try:
            _write_attr(self.phase_map, "acquisition_enable", 0)
        finally:
            _close_iio_buffer(self._iio, buffer)

    @_client_operation
    def close(self) -> None:
        if self._closed:
            return
        first_error: BaseException | None = None
        for close_resource in (self.close_fine, self.close_maps):
            try:
                close_resource()
            except BaseException as error:
                if first_error is None:
                    first_error = error
        self._closed = True
        try:
            _close_iio_context(self._iio, self.context)
        except BaseException as error:
            if first_error is None:
                first_error = error
        if first_error is not None:
            raise first_error

    def __enter__(self) -> Self:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc_value: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


def reassemble_maps(chunks: Iterable[PssMapChunk]) -> tuple[PssPhaseMap, ...]:
    reassembler = PssMapReassembler()
    maps: list[PssPhaseMap] = []
    for chunk in chunks:
        completed = reassembler.add(chunk)
        if completed is not None:
            maps.append(completed)
    if reassembler._chunks:
        raise ValueError("phase-map stream ended with an incomplete map")
    return tuple(maps)
