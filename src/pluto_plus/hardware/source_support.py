"""Pure, explicitly profiled source-coordinate joins; no IIO or detection policy.

Intervals are half-open in original ADC sample coordinates. A lattice's bounds
do not imply that every intervening full-rate sample was exported. Geometry
checks are not identity attestation, RF settling, continuity or detection proof.
"""

from __future__ import annotations

import re
import struct
from collections.abc import Sequence
from dataclasses import dataclass
from enum import StrEnum

from pluto_plus.hardware.pilot_iio import PilotSnapshot
from pluto_plus.hardware.pss_iio import PssFinePacket, PssPhaseMap

_U64_LIMIT = 1 << 64
_MAP_SAMPLES = 20_000 * 64
_FFT_SAMPLES = 512
_FFT_STRIDE = 447
_PILOT_RADIUS = 269


def _integer(value: int, name: str, *, maximum: int = _U64_LIMIT - 1) -> None:
    if type(value) is not int or not 0 <= value <= maximum:
        raise ValueError(f"{name} must be an unsigned integer <= {maximum}")


def _identifier(value: str, name: str) -> None:
    if (not isinstance(value, str) or not value.isascii() or not 1 <= len(value) <= 256
            or any(character.isspace() or ord(character) < 33 for character in value)):
        raise ValueError(f"{name} must be a nonempty bounded ASCII identifier")


class ProcessingProfile(StrEnum):
    """Only this explicitly admitted processing geometry is currently supported."""

    PAIRED_15_SHARED_XFFT_512_447_V1 = "paired-15-shared-xfft-512-447-v1"


@dataclass(frozen=True, slots=True)
class ObservationIdentity:
    """Required caller-owned binding, not information invented from a packet.

    processing_fingerprint names a manifest containing filter/coefficient and
    firmware identities. Its content and the serial/boot/RF state must be
    attested by the external owner; this library only checks exact agreement.
    """

    serial: str
    boot_id: str
    session_id: str
    visit_id: int
    source_rate_hz: int
    profile: ProcessingProfile
    frequency_plan_id: str
    processing_fingerprint: str

    def __post_init__(self) -> None:
        for field in ("serial", "boot_id", "session_id", "frequency_plan_id"):
            _identifier(getattr(self, field), field)
        _integer(self.visit_id, "visit_id", maximum=0xffffffff)
        if not self.visit_id:
            raise ValueError("visit_id must be nonzero")
        if (self.profile is not ProcessingProfile.PAIRED_15_SHARED_XFFT_512_447_V1
                or type(self.source_rate_hz) is not int or self.source_rate_hz != 15_000_000):
            raise ValueError("only the explicit paired 15 MS/s shared-XFFT profile is supported")
        if (not isinstance(self.processing_fingerprint, str)
                or not re.fullmatch(r"[0-9a-f]{64}", self.processing_fingerprint)):
            raise ValueError("processing_fingerprint must be a lowercase SHA256")


def _observation(value: ObservationIdentity) -> None:
    if not isinstance(value, ObservationIdentity):
        raise ValueError("an explicit ObservationIdentity is required")


@dataclass(frozen=True, slots=True)
class SourceInterval:
    """Nonempty half-open u64 sample interval; exclusive stop may equal 2**64."""

    start: int
    stop: int

    def __post_init__(self) -> None:
        _integer(self.start, "interval start")
        _integer(self.stop, "interval stop", maximum=_U64_LIMIT)
        if self.start >= self.stop:
            raise ValueError("source interval must be nonempty and increasing")

    @property
    def samples(self) -> int:
        return self.stop - self.start

    def contains(self, other: SourceInterval) -> bool:
        return self.start <= other.start and other.stop <= self.stop

    def intersection(self, other: SourceInterval) -> SourceInterval | None:
        start, stop = max(self.start, other.start), min(self.stop, other.stop)
        return SourceInterval(start, stop) if start < stop else None


@dataclass(frozen=True, slots=True)
class SourceLattice:
    """Observed sample centers, NOT a contiguous full-rate IQ recording."""

    first: int
    step: int
    count: int

    def __post_init__(self) -> None:
        for name in ("first", "step", "count"):
            _integer(getattr(self, name), name)
        if not self.step or not self.count:
            raise ValueError("lattice step/count must be positive")
        _integer(self.last, "last lattice center")

    @property
    def last(self) -> int:
        return self.first + (self.count - 1) * self.step

    @property
    def bounds(self) -> SourceInterval:
        """First through last center inclusive, not the count*step nominal dwell."""
        return SourceInterval(self.first, self.last + 1)


@dataclass(frozen=True, slots=True)
class PilotSliceSupport:
    observation: ObservationIdentity
    output_start: int
    centers: SourceLattice
    raw_inputs: SourceInterval

    def __post_init__(self) -> None:
        _observation(self.observation)
        _integer(self.output_start, "pilot output start")
        _integer(self.output_start + self.centers.count, "pilot output stop", maximum=_U64_LIMIT)
        newest = self.centers.first + _PILOT_RADIUS
        if self.centers.step != 6 or newest < 538 or newest % 6:
            raise ValueError(
                "pilot center lattice violates the supported absolute decimation phase"
            )
        if self.raw_inputs != SourceInterval(self.centers.first - _PILOT_RADIUS,
                                             self.centers.last + _PILOT_RADIUS + 1):
            raise ValueError("pilot raw-input support disagrees with its center lattice")


class EnvelopeKind(StrEnum):
    EXACT_BLOCK_ENVELOPE = "exact_block_envelope"
    CONSERVATIVE_BLOCK_ENVELOPE = "conservative_block_envelope"


@dataclass(frozen=True, slots=True)
class PhaseMapSupport:
    observation: ObservationIdentity
    generation: int
    candidate_starts: SourceInterval
    ideal_template_inputs: SourceInterval
    processing_inputs: SourceInterval
    envelope_kind: EnvelopeKind
    fft_origin: int | None

    def __post_init__(self) -> None:
        _observation(self.observation)
        _integer(self.generation, "map generation", maximum=0xffffffff)
        if not self.generation or self.candidate_starts.samples != _MAP_SAMPLES:
            raise ValueError("phase map generation or complete candidate span is invalid")
        expected, kind = _map_envelope(self.candidate_starts, self.fft_origin)
        if (self.processing_inputs != expected or self.envelope_kind is not kind
                or self.ideal_template_inputs != SourceInterval(
                    self.candidate_starts.start, self.candidate_starts.stop + 65)):
            raise ValueError("phase map support differs from its explicit processing geometry")


def _map_envelope(
    starts: SourceInterval, origin: int | None,
) -> tuple[SourceInterval, EnvelopeKind]:
    if origin is None:
        return (SourceInterval(starts.start - 446, starts.stop + 511),
                EnvelopeKind.CONSERVATIVE_BLOCK_ENVELOPE)
    _integer(origin, "FFT origin")
    if origin > starts.start or (starts.start - origin) % 20_000:
        raise ValueError("map start is inconsistent with the epoch-relative phase origin")
    first_block = origin + ((starts.start - origin) // _FFT_STRIDE) * _FFT_STRIDE
    last_block = origin + ((starts.stop - 1 - origin) // _FFT_STRIDE) * _FFT_STRIDE
    return SourceInterval(first_block, last_block + _FFT_SAMPLES), EnvelopeKind.EXACT_BLOCK_ENVELOPE


@dataclass(frozen=True, slots=True)
class FineSearchSupport:
    observation: ObservationIdentity
    request_id: int
    coefficient_generation: int
    center: int
    winner: int
    winner_inputs: SourceInterval
    capture_inputs: SourceInterval

    def __post_init__(self) -> None:
        _observation(self.observation)
        for name in ("request_id", "coefficient_generation"):
            _integer(getattr(self, name), name, maximum=0xffffffff)
            if not getattr(self, name):
                raise ValueError(f"{name} must be nonzero")
        _integer(self.center, "fine center")
        _integer(self.winner, "fine winner")
        if (abs(self.winner - self.center) > 30
                or self.winner_inputs != SourceInterval(self.winner, self.winner + 66)
                or self.capture_inputs != SourceInterval(self.center - 32, self.center + 98)):
            raise ValueError("fine search support differs from the admitted 15 MS/s geometry")


def pilot_slice_support(
    snapshot: PilotSnapshot, *, observation: ObservationIdentity,
    expected_samples: int, received_bytes: int, start: int, stop: int,
) -> PilotSliceSupport:
    """Map a slice of a complete received PIL1 capture; never invent byte counts.

    Incomplete captures belong in an INCOMPLETE SourceRecord, not in this
    complete-support path. Whole-path/RF health remains an external prerequisite.
    """
    _observation(observation)
    if PilotSnapshot.decode(snapshot.raw) != snapshot:
        raise ValueError("pilot snapshot fields differ from its raw receipt")
    snapshot.require_complete_prefix(
        expected_visit_id=observation.visit_id,
        expected_source_rate_hz=observation.source_rate_hz,
        expected_samples=expected_samples, received_bytes=received_bytes,
    )
    _integer(start, "pilot slice start")
    _integer(stop, "pilot slice stop")
    if not start < stop <= snapshot.axis_delivered_samples:
        raise ValueError("pilot slice is outside the complete received prefix")
    centers = SourceLattice(snapshot.source_center(start), 6, stop - start)
    return PilotSliceSupport(
        observation, start, centers,
        SourceInterval(centers.first - _PILOT_RADIUS, centers.last + _PILOT_RADIUS + 1),
    )


def map_support(
    phase_map: PssPhaseMap, *, observation: ObservationIdentity, fft_origin: int | None = None,
) -> PhaseMapSupport:
    """Map PSMA1.5 starts into ideal and full-transform processing envelopes.

    The explicit profile fixes 66 template samples, 512 FFT inputs and 447
    outputs/block. With no attested scheduler origin, [a-446,b+511) is a
    conservative dependency bound, not a claim that every sample contributes
    equally. Metadata start a is never silently treated as the FFT origin.
    """
    if phase_map.abi_version != 0x10005:
        raise ValueError("phase map does not match the explicit shared-XFFT ABI1.5 profile")
    _integer(phase_map.generation, "map generation", maximum=0xffffffff)
    if not phase_map.generation or len(phase_map.bins) != 20_000:
        raise ValueError("phase map must have a generation and 20000 complete bins")
    for value in phase_map.bins:
        _integer(value, "map bin", maximum=0xffff)
    starts = SourceInterval(phase_map.start_index, phase_map.start_index + _MAP_SAMPLES)
    ideal = SourceInterval(starts.start, starts.stop + 65)
    processing, kind = _map_envelope(starts, fft_origin)
    return PhaseMapSupport(observation, phase_map.generation, starts, ideal,
                           processing, kind, fft_origin)


def fine_support(
    packet: PssFinePacket, *, observation: ObservationIdentity, coefficient_generation: int,
) -> FineSearchSupport:
    """The winner is a first-tap timestamp; the full search consumes 130 samples."""
    if len(packet.words) != 26:
        raise ValueError("fine packet must contain exactly 26 words")
    _integer(coefficient_generation, "coefficient generation", maximum=0xffffffff)
    for word in packet.words:
        _integer(word, "fine packet word", maximum=0xffffffff)
    decoded = PssFinePacket.decode(struct.pack(f"<{len(packet.words)}I", *packet.words),
                                   rate_msps=15)
    if decoded != packet or decoded.coefficient_generation != coefficient_generation:
        raise ValueError(
            "fine packet differs from its raw words or expected coefficient generation"
        )
    return FineSearchSupport(
        observation, packet.request_id, packet.coefficient_generation,
        packet.center_index, packet.winner_timestamp,
        SourceInterval(packet.winner_timestamp, packet.winner_timestamp + 66),
        SourceInterval(packet.center_index - 32, packet.center_index + 98),
    )


class RecordKind(StrEnum):
    PILOT = "pilot"
    MAP = "map"
    FINE = "fine"


class RecordState(StrEnum):
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    UNOBSERVABLE = "unobservable"


class DetectionState(StrEnum):
    NOT_EVALUATED = "not_evaluated"
    TRIGGER = "trigger"
    NO_TRIGGER = "no_trigger"


Support = PilotSliceSupport | PhaseMapSupport | FineSearchSupport
_SUPPORT_TYPES = {RecordKind.PILOT: PilotSliceSupport, RecordKind.MAP: PhaseMapSupport,
                  RecordKind.FINE: FineSearchSupport}


@dataclass(frozen=True, slots=True)
class SourceRecord:
    """Caller-owned evidence ledger; absent/incomplete records are never erased."""

    observation: ObservationIdentity
    record_id: str
    kind: RecordKind
    state: RecordState
    support: Support | None = None
    detection: DetectionState = DetectionState.NOT_EVALUATED
    reason: str | None = None

    def __post_init__(self) -> None:
        _observation(self.observation)
        _identifier(self.record_id, "record_id")
        if (not isinstance(self.kind, RecordKind) or not isinstance(self.state, RecordState)
                or not isinstance(self.detection, DetectionState)):
            raise ValueError("record kind/state/detection must use their explicit enums")
        if self.support is not None and (
            not isinstance(self.support, _SUPPORT_TYPES[self.kind])
            or self.support.observation != self.observation
        ):
            raise ValueError("record support kind/observation identity disagrees")
        if self.state is RecordState.COMPLETE:
            if self.support is None or self.reason is not None:
                raise ValueError("complete record requires support and no missing-evidence reason")
        elif not isinstance(self.reason, str) or not self.reason.strip():
            raise ValueError("incomplete/unobservable record requires an explicit reason")


class JoinState(StrEnum):
    INCLUDED = "included"
    INCOMPLETE = "incomplete"
    UNOBSERVABLE = "unobservable"


@dataclass(frozen=True, slots=True)
class RecordJoin:
    record: SourceRecord
    state: JoinState
    reason: str | None
    pilot_selection: PilotSliceSupport | None = None


def join_source_interval(
    records: Sequence[SourceRecord], *, observation: ObservationIdentity,
    comparison: SourceInterval, available_inputs: SourceInterval,
) -> tuple[RecordJoin, ...]:
    """Classify every record against caller-chosen, trigger-independent bounds.

    comparison is the anchor/center domain; available_inputs is the externally
    declared common raw-input support, including boundary history/halo. Neither
    is selected using detections. A map cannot be cropped. Pilot selections are
    integer output slices, not host arrival times or GLRT search seeds.

    INCLUDED means per-record geometric containment only. It does not establish
    one-second map coverage, continuity between maps, a complete request ledger,
    GLRT consumed-symbol support, RF health, or agreement between detectors.
    """
    _observation(observation)
    if not available_inputs.contains(comparison):
        raise ValueError("comparison interval must lie within declared available inputs")
    if not 1 <= len(records) <= 4096:
        raise ValueError("join requires a bounded nonempty record ledger")
    if len({record.record_id for record in records}) != len(records):
        raise ValueError("record IDs must be unique")
    results: list[RecordJoin] = []
    for record in records:
        if record.observation != observation:
            raise ValueError("cannot join different observation identities")
        if record.state is not RecordState.COMPLETE:
            state = (JoinState.INCOMPLETE if record.state is RecordState.INCOMPLETE
                     else JoinState.UNOBSERVABLE)
            results.append(RecordJoin(record, state, record.reason))
            continue
        support = record.support
        selection = None
        if isinstance(support, PilotSliceSupport):
            if not support.centers.bounds.contains(comparison):
                results.append(RecordJoin(record, JoinState.UNOBSERVABLE,
                                          "pilot center lattice does not bound comparison"))
                continue
            first = (comparison.start - support.centers.first + 5) // 6
            stop = (comparison.stop - support.centers.first + 5) // 6
            if first >= stop:
                results.append(RecordJoin(record, JoinState.UNOBSERVABLE,
                                          "comparison contains no exported sample center"))
                continue
            centers = SourceLattice(support.centers.first + first * 6, 6, stop - first)
            inputs = SourceInterval(centers.first - _PILOT_RADIUS,
                                    centers.last + _PILOT_RADIUS + 1)
            selection = PilotSliceSupport(
                observation, support.output_start + first, centers, inputs
            )
            anchors_inside = True
        elif isinstance(support, PhaseMapSupport):
            anchors_inside = comparison.contains(support.candidate_starts)
            inputs = support.processing_inputs
        elif isinstance(support, FineSearchSupport):
            anchors_inside = comparison.start <= support.winner < comparison.stop
            inputs = support.capture_inputs
        else:
            raise ValueError("complete record lacks recognized support")
        if not anchors_inside or not available_inputs.contains(inputs):
            results.append(RecordJoin(record, JoinState.UNOBSERVABLE,
                                      "complete anchors or processing support lie outside bounds"))
        else:
            results.append(RecordJoin(record, JoinState.INCLUDED, None, selection))
    return tuple(results)
