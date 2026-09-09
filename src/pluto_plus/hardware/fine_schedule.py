"""Pure finite fine-result accounting; no IIO, RF policy or detector seeding.

The owner must persist each batch result and adopt its immutable successor.
Historical ledger values can deliberately be forked; this module cannot revoke
them. Complete means a validated finite result sequence, not continuous IQ or
one second of timing lock. Only the explicit paired-15/shared profile is admitted.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum

from pluto_plus.hardware.pss_iio import (
    PssBatchAttributes,
    PssBatchReceipt,
    PssBatchScan,
    PssFinePacket,
)
from pluto_plus.hardware.source_support import (
    DetectionState,
    FineSearchSupport,
    ObservationIdentity,
    ProcessingProfile,
    RecordKind,
    RecordState,
    SourceInterval,
    SourceRecord,
    fine_support,
)

_U32_MAX = (1 << 32) - 1
_U64_MAX = (1 << 64) - 1
_MAX_SCANS = 4096
_SCAN_BYTES = 128
_PAYLOAD_BYTES = 104


def _integer(value: int, name: str, maximum: int = _U64_MAX) -> None:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"{name} must be an unsigned integer <= {maximum}")


def _identifier(value: str, name: str, maximum: int = 128) -> None:
    if (not isinstance(value, str) or not value.isascii() or not 1 <= len(value) <= maximum
            or any(ord(character) < 33 or character.isspace() for character in value)):
        raise ValueError(f"{name} must be a nonempty bounded ASCII identifier")


def _observation(value: ObservationIdentity) -> None:
    if not isinstance(value, ObservationIdentity):
        raise ValueError("an explicit ObservationIdentity is required")
    # The fine ABI alone cannot distinguish the legacy and shared 15 MS/s paths.
    if (value.profile is not ProcessingProfile.PAIRED_15_SHARED_XFFT_512_447_V1
            or type(value.source_rate_hz) is not int or value.source_rate_hz != 15_000_000):
        raise ValueError("only the explicit paired 15 MS/s shared-XFFT profile is supported")


@dataclass(frozen=True, slots=True)
class FineScheduleManifest:
    """Finite plan, not evidence of driver acceptance, lead time or RF state.

    The kernel initializes next_fraction=0 and advances it using u32 carry.
    center(n) = first_center + floor(n * period_q32_32 / 2**32).
    Its unused post-last advance is checked too: even that state must not wrap.
    Count may be large; construction/indexing never allocate the schedule.
    """

    observation: ObservationIdentity
    schedule_id: str
    first_center: int
    period_q32_32: int
    request_base: int
    count: int
    coefficient_generation: int

    def __post_init__(self) -> None:
        _observation(self.observation)
        _identifier(self.schedule_id, "schedule_id")
        _integer(self.first_center, "first_center")
        _integer(self.period_q32_32, "period_q32_32")
        for name in ("request_base", "count", "coefficient_generation"):
            value = getattr(self, name)
            _integer(value, name, _U32_MAX)
            if not value:
                raise ValueError(f"{name} must be nonzero")
        if not self.period_q32_32 >> 32:
            raise ValueError("period must have a nonzero integer part, as required by the driver")
        _integer(self.request_base + self.count - 1, "last request ID", _U32_MAX)
        # SourceInterval also rejects a negative full-capture history bound.
        self.capture_at(0)
        self.capture_at(self.count - 1)
        _integer(self.first_center + ((self.count * self.period_q32_32) >> 32),
                 "kernel post-last center")

    def _index(self, index: int) -> None:
        _integer(index, "schedule index", _U32_MAX)
        if index >= self.count:
            raise ValueError("schedule index lies outside the finite manifest")

    def center_at(self, index: int) -> int:
        self._index(index)
        return self.first_center + ((index * self.period_q32_32) >> 32)

    def request_at(self, index: int) -> int:
        self._index(index)
        return self.request_base + index

    def capture_at(self, index: int) -> SourceInterval:
        """Full 130-sample search input, not the eventual winning 66-sample tap span."""
        center = self.center_at(index)
        return SourceInterval(center - 32, center + 98)

    @property
    def planned_anchor_separation(self) -> int:
        """Last minus first scheduled center; NOT count*period or continuous support."""
        return self.center_at(self.count - 1) - self.first_center


class FineLedgerState(StrEnum):
    ACTIVE = "active"
    COMPLETE = "complete"
    FAILED = "failed"


@dataclass(frozen=True, slots=True)
class FineScheduleLedger:
    """Constant-size accepted prefix; failed/completed successors refuse admission.

    No batch history is owned here. The durable recorder must adopt the returned
    successor exactly once. These pure values are neither locks nor attestations.
    """

    manifest: FineScheduleManifest
    accepted_count: int = 0
    next_batch_index: int = 0
    stream_id: str | None = None
    state: FineLedgerState = FineLedgerState.ACTIVE
    failure: str | None = None

    def __post_init__(self) -> None:
        if not isinstance(self.manifest, FineScheduleManifest):
            raise ValueError("a validated finite manifest is required")
        _integer(self.accepted_count, "accepted_count", self.manifest.count)
        _integer(self.next_batch_index, "next_batch_index", self.manifest.count)
        if not isinstance(self.state, FineLedgerState):
            raise ValueError("ledger state must use FineLedgerState")
        if self.stream_id is not None:
            _identifier(self.stream_id, "stream_id", 256)
        if bool(self.accepted_count) != bool(self.next_batch_index):
            raise ValueError("accepted results and accepted batches must start together")
        if self.next_batch_index > self.accepted_count:
            raise ValueError("accepted batch count exceeds accepted result count")
        if self.accepted_count and self.stream_id is None:
            raise ValueError("an accepted prefix requires a bound stream identity")
        if self.state is FineLedgerState.FAILED:
            if not isinstance(self.failure, str) or not 1 <= len(self.failure) <= 256:
                raise ValueError("failed ledger requires a bounded explicit failure reason")
        elif self.failure is not None:
            raise ValueError("only failed ledgers have a failure reason")
        if self.state is FineLedgerState.COMPLETE:
            if self.accepted_count != self.manifest.count:
                raise ValueError("complete ledger must account for the entire finite schedule")
        elif self.accepted_count == self.manifest.count:
            raise ValueError("a full accepted prefix must be complete")

    @property
    def remaining_results(self) -> int:
        return self.manifest.count - self.accepted_count

    @property
    def validated_anchor_separation(self) -> int | None:
        """Accepted last-minus-first center, or None with no accepted result."""
        if not self.accepted_count:
            return None
        return self.manifest.center_at(self.accepted_count - 1) - self.manifest.first_center


@dataclass(frozen=True, slots=True)
class FineScheduledScan:
    """One observed or missing native slot; expected coordinates never replace raw ones."""

    scan_index: int | None
    schedule_index: int | None
    expected_request: int | None
    expected_center: int | None
    packet: PssFinePacket | None
    record: SourceRecord
    errors: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class FineScheduleBatchResult:
    """Retains the original raw receipt by reference, including error/negative evidence.

    All records in a rejected batch are INCOMPLETE, including otherwise valid
    diagnostic packets. Error strings here are bounded summaries; the original
    receipt remains authoritative for its raw bytes and detailed native errors.
    """

    before: FineScheduleLedger
    after: FineScheduleLedger
    batch: PssBatchReceipt
    observation: ObservationIdentity
    detections: tuple[DetectionState, ...] | None
    scans: tuple[FineScheduledScan, ...]
    errors: tuple[str, ...]

    @property
    def accepted(self) -> bool:
        return self.after.state is not FineLedgerState.FAILED

    @property
    def source_records(self) -> tuple[SourceRecord, ...]:
        """For trigger-independent join_source_interval; not an IQ-selection policy."""
        return tuple(scan.record for scan in self.scans)


def _attribute_errors(
    attributes: PssBatchAttributes | None, generation: int,
) -> tuple[str, ...]:
    if not isinstance(attributes, PssBatchAttributes):
        return ("attributes unavailable",)
    errors: list[str] = []
    if not isinstance(attributes.errors, tuple) or attributes.errors:
        errors.append("attribute read error tuple is malformed or reports errors; see receipt")
    if type(attributes.fault_flags) is not int or attributes.fault_flags != 0:
        errors.append("driver fault flags are unavailable or nonzero")
    if (type(attributes.coefficient_generation) is not int
            or attributes.coefficient_generation != generation):
        errors.append("active coefficient generation is unavailable or mismatched")
    expected = {"fault_flags": 0, "active_coefficient_generation": generation}
    if not isinstance(attributes.raw, tuple) or len(attributes.raw) != 2:
        errors.append("raw attribute pair is unavailable or malformed")
        return tuple(errors)
    seen: set[str] = set()
    for item in attributes.raw:
        if (not isinstance(item, tuple) or len(item) != 2
                or not isinstance(item[0], str) or item[0] not in expected
                or item[0] in seen or not isinstance(item[1], str) or len(item[1]) > 128):
            errors.append("raw attribute pair has invalid names, bounds or duplicates")
            continue
        name, raw = item
        seen.add(name)
        try:
            value = int(raw, 0)
        except ValueError:
            errors.append("raw attribute is not a numeric value")
            continue
        if value != expected[name]:
            errors.append("raw attribute contradicts the required health/generation")
    if seen != set(expected):
        errors.append("raw attributes do not include both required fields")
    return tuple(errors)


def _batch_errors(ledger: FineScheduleLedger, batch: PssBatchReceipt) -> tuple[list[str], bool]:
    """Check bounded shape before traversal; false means do not expand any scan rows."""
    errors: list[str] = []
    bounded = (type(batch.requested_scans) is int and 1 <= batch.requested_scans <= _MAX_SCANS
               and isinstance(batch.scans, tuple) and len(batch.scans) <= _MAX_SCANS
               and (batch.raw is None or (type(batch.raw) is bytes
                    and len(batch.raw) <= _MAX_SCANS * _SCAN_BYTES)))
    if not bounded:
        errors.append("batch exceeds the bounded fine receipt shape; scan traversal omitted")
    if batch.stream != "fine" or type(batch.rate_msps) is not int or batch.rate_msps != 15:
        errors.append("batch is not a fine 15 MS/s observation")
    if type(batch.abi_version) is not int or batch.abi_version != 0x10002:
        errors.append("batch ABI does not match the admitted fine tracker")
    try:
        _identifier(batch.stream_id, "stream_id", 256)
    except ValueError:
        errors.append("batch stream identity is invalid")
    if ledger.stream_id is not None and batch.stream_id != ledger.stream_id:
        errors.append("batch stream identity changed")
    if type(batch.batch_index) is not int or batch.batch_index != ledger.next_batch_index:
        errors.append("batch ordinal is duplicate, missing or out of order")
    if (type(batch.expected_request_before) is not int
            or batch.expected_request_before != ledger.manifest.request_at(ledger.accepted_count)):
        errors.append("native expected request differs from the finite ledger")
    if (type(batch.remaining_results_before) is not int
            or batch.remaining_results_before != ledger.remaining_results):
        errors.append("native remaining count differs from the finite ledger")
    if batch.refill_started is not True or batch.refill_completed is not True:
        errors.append("native refill did not start and complete")
    if not isinstance(batch.errors, tuple) or batch.errors:
        errors.append("native batch error tuple is malformed or reports errors; see receipt")
    if (type(batch.scan_bytes) is not int or batch.scan_bytes != _SCAN_BYTES
            or type(batch.buffer_step) is not int or batch.buffer_step != _SCAN_BYTES):
        errors.append("fine scan stride or native step is invalid")
    if not bounded:
        return errors, False
    size = batch.requested_scans * _SCAN_BYTES
    if batch.requested_scans > ledger.remaining_results:
        errors.append("batch exceeds the finite schedule remainder")
    if type(batch.buffer_bytes) is not int or batch.buffer_bytes != size:
        errors.append("native buffer byte length is unavailable or mismatched")
    if batch.native_refill_bytes is not None and (
        type(batch.native_refill_bytes) is not int or batch.native_refill_bytes != size
    ):
        errors.append("available native refill byte count is invalid")
    if (batch.raw is None or type(batch.observed_bytes) is not int
            or batch.observed_bytes != size or len(batch.raw) != size):
        errors.append("retained raw payload is missing, truncated or not the complete native batch")
    if len(batch.scans) != batch.requested_scans:
        errors.append("native decoded scan coverage is incomplete or oversized")
    return errors, True


def validate_fine_batch(
    ledger: FineScheduleLedger, batch: PssBatchReceipt, *, observation: ObservationIdentity,
    detections: tuple[DetectionState, ...] | None = None,
) -> FineScheduleBatchResult:
    """Validate one native boundary, returning a whole-batch successor and evidence.

    Each call expands at most 4096 slots / 512 KiB of existing fine raw bytes.
    No complete property or unbounded caller collection is traversed implicitly.
    Unknown native refill byte counts remain unknown; read bytes are not RF truth.
    The caller binds observation identity independently of the untagged packet.
    """
    if not isinstance(ledger, FineScheduleLedger) or not isinstance(batch, PssBatchReceipt):
        raise ValueError("a finite ledger and retained PssBatchReceipt are required")
    if ledger.state is not FineLedgerState.ACTIVE:
        raise ValueError("failed or completed fine ledger cannot accept another batch")
    _observation(observation)
    if detections is not None and (
        not isinstance(detections, tuple) or len(detections) > _MAX_SCANS
        or any(not isinstance(value, DetectionState) for value in detections)
    ):
        raise ValueError("detections must be a bounded tuple of explicit DetectionState values")
    manifest = ledger.manifest
    errors, bounded = _batch_errors(ledger, batch)
    if observation != manifest.observation:
        errors.append("observation identity differs from the schedule manifest")
    for name, attributes in (("before", batch.attributes_before),
                             ("after", batch.attributes_after)):
        errors.extend(f"attributes {name}: {error}" for error in
                      _attribute_errors(attributes, manifest.coefficient_generation))
    if detections is not None and len(detections) != batch.requested_scans:
        errors.append("detection labels do not cover exactly the requested native slots")

    # Raw bytes, original errors and caller labels stay in the result even if a
    # malformed/unbounded envelope prevents safe per-slot expansion.
    rows: list[tuple[int, int, int | None, int | None, PssFinePacket | None,
                     FineSearchSupport | None, DetectionState, tuple[str, ...]]] = []
    if bounded:
        raw = batch.raw or b""
        count = max(batch.requested_scans, len(batch.scans),
                    (len(raw) + _SCAN_BYTES - 1) // _SCAN_BYTES)
        for index in range(count):
            ordinal = ledger.accepted_count + index
            expected_request = manifest.request_at(ordinal) if ordinal < manifest.count else None
            expected_center = manifest.center_at(ordinal) if ordinal < manifest.count else None
            local: list[str] = []
            packet = None
            support = None
            offset = index * _SCAN_BYTES
            chunk = raw[offset:offset + _SCAN_BYTES]
            if len(chunk) != _SCAN_BYTES:
                local.append("raw scan is missing or truncated")
            elif any(chunk[_PAYLOAD_BYTES:]):
                local.append("raw scan has nonzero IIO padding")
            else:
                try:
                    packet = PssFinePacket.decode(chunk[:_PAYLOAD_BYTES], rate_msps=15)
                    # Retain ACTUAL support even if schedule matching fails later.
                    support = fine_support(packet, observation=observation,
                                           coefficient_generation=packet.coefficient_generation)
                except ValueError as error:
                    local.append(f"raw scan decode/support: {error}")
            supplied = batch.scans[index] if index < len(batch.scans) else None
            if not isinstance(supplied, PssBatchScan):
                local.append("native scan diagnostic is missing or malformed")
            else:
                if (type(supplied.index) is not int or supplied.index != index
                        or type(supplied.byte_offset) is not int or supplied.byte_offset != offset
                        or type(supplied.byte_count) is not int
                        or supplied.byte_count != len(chunk)):
                    local.append("native scan byte range contradicts its retained raw slot")
                if not isinstance(supplied.errors, tuple) or supplied.errors:
                    local.append("native scan error tuple is malformed or nonempty; see receipt")
                if supplied.decoded != packet or packet is None:
                    local.append("native decoded packet is absent or contradicts retained raw")
            if packet is not None:
                if packet.request_id != expected_request:
                    local.append("packet request ID differs from its scheduled ordinal")
                if packet.center_index != expected_center:
                    local.append("packet center differs from the exact Q32 scheduled center")
                if packet.coefficient_generation != manifest.coefficient_generation:
                    local.append("packet coefficient generation differs from the manifest")
            label = (detections[index] if detections is not None and index < len(detections)
                     else DetectionState.NOT_EVALUATED)
            rows.append((index, ordinal, expected_request, expected_center, packet, support,
                         label, tuple(local)))
    if any(row[-1] for row in rows):
        errors.append("one or more native slots failed exact fine-schedule validation")
    failed = bool(errors)
    after = FineScheduleLedger(
        manifest, ledger.accepted_count if failed else ledger.accepted_count + len(rows),
        ledger.next_batch_index if failed else ledger.next_batch_index + 1,
        ledger.stream_id if failed else batch.stream_id,
        FineLedgerState.FAILED if failed else (
            FineLedgerState.COMPLETE if len(rows) == ledger.remaining_results
            else FineLedgerState.ACTIVE),
        "fine batch validation failed; retain its batch result" if failed else None,
    )
    scans: list[FineScheduledScan] = []
    for index, ordinal, request, center, packet, support, label, local_errors in rows:
        record = SourceRecord(
            observation, f"{manifest.schedule_id}:batch{ledger.next_batch_index}:scan{index}",
            RecordKind.FINE, RecordState.INCOMPLETE if failed else RecordState.COMPLETE,
            support, label, "whole native batch failed; see retained result" if failed else None,
        )
        scans.append(FineScheduledScan(index, ordinal, request, center, packet, record,
                                       local_errors))
    if not scans:
        record = SourceRecord(
            observation, f"{manifest.schedule_id}:batch{ledger.next_batch_index}:unexpanded",
            RecordKind.FINE, RecordState.INCOMPLETE,
            reason="invalid bounded envelope; per-slot observations unavailable",
        )
        scans.append(FineScheduledScan(None, None, None, None, None, record, tuple(errors)))
    return FineScheduleBatchResult(ledger, after, batch, observation, detections,
                                   tuple(scans), tuple(errors))
