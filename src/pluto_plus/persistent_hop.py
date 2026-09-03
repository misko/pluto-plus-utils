"""Strict host contract for device-timed persistent eight-profile hopping.

The current metadata ABI remains version 3.  A firmware build which provides
persistent hopping advertises four independent context attributes and accepts a
frozen ``HOPR`` suffix after the existing tandem-v1 request.  Each metadata
record then carries one ``HOPS`` evidence record, while ``READBUFMSTAT`` exposes
``HOPT`` status for the active session.

This module deliberately contains no socket or IIO implementation.  Callers
must inject a backend, which keeps unit tests offline and makes serial and
capability attestation happen before any capture request is submitted.
"""

from __future__ import annotations

import dataclasses
import enum
import ipaddress
import math
import struct
from collections import deque
from collections.abc import Callable, Iterator, Mapping
from typing import Final, Protocol

import numpy as np
import numpy.typing as npt

from pluto_plus.direct_radio.samples import ci16_dual_rx
from pluto_plus.tandem import TandemSessionRequestV1

PERSISTENT_HOP_PROTOCOL_VERSION: Final = 1
PERSISTENT_HOP_REQUEST_BYTES: Final = 288
PERSISTENT_HOP_EVIDENCE_HEADER_BYTES: Final = 64
PERSISTENT_HOP_EVENT_BYTES: Final = 80
PERSISTENT_HOP_STATUS_BYTES: Final = 160
PERSISTENT_HOP_PROFILE_COUNT: Final = 8
PERSISTENT_HOP_EVENT_CAPACITY: Final = 8
PERSISTENT_HOP_REQUIRED_FEATURES: Final = 0x1F
PERSISTENT_HOP_REQUIRED_FLAGS: Final = 0x03
PERSISTENT_HOP_NONE_PROFILE: Final = 0xFF
PERSISTENT_HOP_DUAL_RX_SCAN_MASK: Final = 0x0F
PERSISTENT_HOP_METADATA_ABI: Final = "3"
PERSISTENT_HOP_EXCLUDED_SERIAL: Final = "104000bac4950008230026001b440a003a"
PERSISTENT_HOP_CAPABILITIES: Final = (
    "iio,buffer-persistent-hop",
    "iio,buffer-persistent-hop-request",
    "iio,buffer-persistent-hop-event",
    "iio,buffer-persistent-hop-status",
    "iio,buffer-persistent-hop-cancel",
)

_REQUEST_MAGIC: Final = 0x52504F48  # b"HOPR"
_EVIDENCE_MAGIC: Final = 0x53504F48  # b"HOPS"
_STATUS_MAGIC: Final = 0x54504F48  # b"HOPT"
_REQUEST_HEADER = struct.Struct("<IHHIIQQQqQQQHBBHH8sQ")
_PROFILE = struct.Struct("<BBHQQI")
_EVIDENCE_HEADER = struct.Struct("<IHHIIIHHQQQQHHi")
_EVENT = struct.Struct("<QQQQQQBBBBHHQqQ")
_STATUS = struct.Struct("<IHHIHHiI" + "Q" * 12 + "iBBH" + "Q" * 4)

if _REQUEST_HEADER.size != 96 or _PROFILE.size != 24:  # pragma: no cover
    raise RuntimeError("persistent-hop request wire layout changed")
if _EVIDENCE_HEADER.size != PERSISTENT_HOP_EVIDENCE_HEADER_BYTES:  # pragma: no cover
    raise RuntimeError("persistent-hop evidence header wire layout changed")
if _EVENT.size != PERSISTENT_HOP_EVENT_BYTES:  # pragma: no cover
    raise RuntimeError("persistent-hop event wire layout changed")
if _STATUS.size != PERSISTENT_HOP_STATUS_BYTES:  # pragma: no cover
    raise RuntimeError("persistent-hop status wire layout changed")


class PersistentHopProtocolError(ValueError):
    """A persistent-hop record violates the frozen v1 wire contract."""


class PersistentHopClientError(RuntimeError):
    """A persistent-hop session failed identity, continuity, or cleanup checks."""


class PersistentHopTarget(enum.IntEnum):
    CH1L = 0
    CH2L = 1
    CH3L = 2
    CH4L = 3
    CH1U = 4
    CH2U = 5
    CH3U = 6
    CH4U = 7


class PersistentHopFeature(enum.IntFlag):
    DEVICE_COUNTER_BOUNDS = 0x01
    ORDERED_EVENTS = 0x02
    EXPLICIT_INVALID_SPANS = 0x04
    FAIL_CLOSED_RESTORE = 0x08
    SETTINGS_ATTESTED = 0x10


class PersistentHopRequestFlag(enum.IntFlag):
    FINITE = 0x01
    RESTORE_REQUIRED = 0x02


class PersistentHopStatusFlag(enum.IntFlag):
    TERMINAL = 0x01
    DEVICE_EVENT_OVERFLOW = 0x02
    CONTINUITY_FAULT = 0x04
    RESTORE_ATTEMPTED = 0x08
    RESTORE_SUCCEEDED = 0x10
    RESTORE_REQUIRED = 0x20


class PersistentHopEventFlag(enum.IntFlag):
    COUNTER_BOUNDS_ATTESTED = 0x01
    LO_ATTESTED = 0x02


class PersistentHopEventKind(enum.IntEnum):
    STARTUP = 1
    RETUNE = 2


class PersistentHopSessionState(enum.IntEnum):
    IDLE = 0
    ARMED = 1
    RUNNING = 2
    COMPLETED = 3
    CANCELLED = 4
    FAILED = 5


class PersistentHopTerminalReason(enum.IntEnum):
    NONE = 0
    PLAN_COMPLETE = 1
    CLIENT_CLOSE = 2
    CLIENT_DISCONNECT = 3
    DEVICE_ERROR = 4
    EVENT_OVERFLOW = 5
    EVENT_SEQUENCE = 6
    COUNTER_DISCONTINUITY = 7
    PROTOCOL_ERROR = 8
    RESTORE_ERROR = 9


_KNOWN_STATUS_FLAGS = PersistentHopStatusFlag(0x3F)
_REQUIRED_EVENT_FLAGS = PersistentHopEventFlag(0x03)
_TERMINAL_STATES = {
    PersistentHopSessionState.COMPLETED,
    PersistentHopSessionState.CANCELLED,
    PersistentHopSessionState.FAILED,
}


def require_physical_lan_uri(uri: str) -> str:
    """Require one canonical literal ``ip:192.168.1.1..254`` endpoint."""

    if not isinstance(uri, str) or uri != uri.strip() or not uri.startswith("ip:"):
        raise ValueError("persistent hopping requires a literal ip:192.168.1.* URI")
    literal = uri.removeprefix("ip:")
    try:
        address = ipaddress.IPv4Address(literal)
    except ipaddress.AddressValueError as error:
        raise ValueError("persistent hopping requires a literal ip:192.168.1.* URI") from error
    if str(address) != literal or address not in ipaddress.IPv4Network("192.168.1.0/24"):
        raise ValueError("persistent hopping requires a canonical ip:192.168.1.* URI")
    if int(address) & 0xFF in {0, 255}:
        raise ValueError("persistent hopping cannot target a network or broadcast address")
    return uri


def require_allowed_serial(serial: str) -> str:
    if not isinstance(serial, str) or not serial or serial != serial.strip():
        raise ValueError("persistent-hop serial must be one trimmed nonempty value")
    if serial == PERSISTENT_HOP_EXCLUDED_SERIAL:
        raise ValueError(f"persistent hopping is forbidden on excluded serial {serial}")
    return serial


def _uint(name: str, value: int, bits: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 1 << bits:
        raise PersistentHopProtocolError(f"{name} is outside uint{bits}: {value!r}")


def _int64(name: str, value: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not -(1 << 63) <= value < 1 << 63:
        raise PersistentHopProtocolError(f"{name} is outside int64: {value!r}")


def _checked_add_u64(name: str, left: int, right: int) -> int:
    _uint(f"{name} left", left, 64)
    _uint(f"{name} right", right, 64)
    result = left + right
    if result >= 1 << 64:
        raise PersistentHopProtocolError(f"{name} overflows uint64")
    return result


@dataclasses.dataclass(frozen=True, slots=True)
class PersistentHopProfileV1:
    target_index: int
    fastlock_profile_index: int
    center_hz: int
    lo_hz: int
    profile_crc32: int

    @property
    def target(self) -> PersistentHopTarget:
        return PersistentHopTarget(self.target_index)

    def _validate(self, if_offset_hz: int) -> None:
        _uint("profile target_index", self.target_index, 8)
        _uint("profile fastlock_profile_index", self.fastlock_profile_index, 8)
        _uint("profile center_hz", self.center_hz, 64)
        _uint("profile lo_hz", self.lo_hz, 64)
        _uint("profile profile_crc32", self.profile_crc32, 32)
        if self.target_index >= PERSISTENT_HOP_PROFILE_COUNT:
            raise PersistentHopProtocolError("persistent-hop target index is outside 0..7")
        if self.fastlock_profile_index >= PERSISTENT_HOP_PROFILE_COUNT:
            raise PersistentHopProtocolError("Fast Lock profile is outside 0..7")
        if not self.center_hz or not self.lo_hz or not self.profile_crc32:
            raise PersistentHopProtocolError("profile frequencies and CRC must be non-zero")
        if self.lo_hz + if_offset_hz != self.center_hz:
            raise PersistentHopProtocolError("profile center_hz does not equal lo_hz + IF offset")

    def _pack(self, if_offset_hz: int) -> bytes:
        self._validate(if_offset_hz)
        return _PROFILE.pack(
            self.target_index,
            self.fastlock_profile_index,
            0,
            self.center_hz,
            self.lo_hz,
            self.profile_crc32,
        )


@dataclasses.dataclass(frozen=True, slots=True)
class PersistentHopRequestV1:
    session_id: int
    sample_rate_hz: int
    rf_bandwidth_hz: int
    if_offset_hz: int
    dwell_samples: int
    transition_guard_samples: int
    dwell_count: int
    capture_span_samples: int
    profiles: tuple[PersistentHopProfileV1, ...]

    def _validate(self) -> None:
        for name, value in (
            ("session_id", self.session_id),
            ("sample_rate_hz", self.sample_rate_hz),
            ("rf_bandwidth_hz", self.rf_bandwidth_hz),
            ("dwell_samples", self.dwell_samples),
            ("transition_guard_samples", self.transition_guard_samples),
            ("dwell_count", self.dwell_count),
            ("capture_span_samples", self.capture_span_samples),
        ):
            _uint(name, value, 64)
        _int64("if_offset_hz", self.if_offset_hz)
        if not all((self.session_id, self.sample_rate_hz, self.rf_bandwidth_hz)):
            raise PersistentHopProtocolError("persistent-hop identity and rates must be non-zero")
        if not self.dwell_samples or not self.dwell_count:
            raise PersistentHopProtocolError("persistent-hop dwell size and count must be non-zero")
        if not self.dwell_samples <= self.capture_span_samples:
            raise PersistentHopProtocolError(
                "capture span must contain at least one complete dwell"
            )
        if self.dwell_count > ((1 << 64) - 1) // self.dwell_samples:
            raise PersistentHopProtocolError("persistent-hop dwell safety bound overflows uint64")
        if self.capture_span_samples > self.dwell_count * self.dwell_samples:
            raise PersistentHopProtocolError("capture span exceeds the dwell safety bound")
        if self.rf_bandwidth_hz > self.sample_rate_hz:
            raise PersistentHopProtocolError("RF bandwidth cannot exceed sample rate")
        if self.transition_guard_samples >= self.dwell_samples:
            raise PersistentHopProtocolError("transition guard must be shorter than one dwell")
        if len(self.profiles) != PERSISTENT_HOP_PROFILE_COUNT:
            raise PersistentHopProtocolError("persistent hopping requires exactly eight profiles")
        slots: set[int] = set()
        for index, profile in enumerate(self.profiles):
            if profile.target_index != index:
                raise PersistentHopProtocolError("profiles must be ordered CH1L..CH4U at 0..7")
            profile._validate(self.if_offset_hz)
            if profile.fastlock_profile_index in slots:
                raise PersistentHopProtocolError("Fast Lock profile slots must be unique")
            slots.add(profile.fastlock_profile_index)

    def pack(self) -> bytes:
        self._validate()
        header = _REQUEST_HEADER.pack(
            _REQUEST_MAGIC,
            PERSISTENT_HOP_PROTOCOL_VERSION,
            PERSISTENT_HOP_REQUEST_BYTES,
            PERSISTENT_HOP_REQUIRED_FEATURES,
            PERSISTENT_HOP_REQUIRED_FLAGS,
            self.session_id,
            self.sample_rate_hz,
            self.rf_bandwidth_hz,
            self.if_offset_hz,
            self.dwell_samples,
            self.transition_guard_samples,
            self.dwell_count,
            PERSISTENT_HOP_PROFILE_COUNT,
            0,
            0,
            PERSISTENT_HOP_EVENT_BYTES,
            PERSISTENT_HOP_STATUS_BYTES,
            bytes(8),
            self.capture_span_samples,
        )
        payload = header + b"".join(profile._pack(self.if_offset_hz) for profile in self.profiles)
        if len(payload) != PERSISTENT_HOP_REQUEST_BYTES:  # pragma: no cover
            raise RuntimeError("persistent-hop request packer emitted the wrong size")
        return payload

    @classmethod
    def unpack(cls, payload: bytes | bytearray | memoryview) -> PersistentHopRequestV1:
        if len(payload) != PERSISTENT_HOP_REQUEST_BYTES:
            raise PersistentHopProtocolError("HOPR request size mismatch")
        values = _REQUEST_HEADER.unpack(payload[: _REQUEST_HEADER.size])
        if values[:3] != (
            _REQUEST_MAGIC,
            PERSISTENT_HOP_PROTOCOL_VERSION,
            PERSISTENT_HOP_REQUEST_BYTES,
        ):
            raise PersistentHopProtocolError("bad HOPR magic, version, or size")
        if values[3] != PERSISTENT_HOP_REQUIRED_FEATURES:
            raise PersistentHopProtocolError("HOPR required feature mask is not exact v1")
        if values[4] != PERSISTENT_HOP_REQUIRED_FLAGS:
            raise PersistentHopProtocolError("HOPR flags are not exact finite/restore-required v1")
        if values[12:17] != (
            PERSISTENT_HOP_PROFILE_COUNT,
            0,
            0,
            PERSISTENT_HOP_EVENT_BYTES,
            PERSISTENT_HOP_STATUS_BYTES,
        ) or any(values[17]):
            raise PersistentHopProtocolError(
                "HOPR fixed counts, sizes, or reserved bytes are invalid"
            )
        profiles: list[PersistentHopProfileV1] = []
        offset = _REQUEST_HEADER.size
        for _index in range(PERSISTENT_HOP_PROFILE_COUNT):
            target, slot, reserved, center, lo, crc = _PROFILE.unpack(
                payload[offset : offset + _PROFILE.size]
            )
            if reserved:
                raise PersistentHopProtocolError("HOPR profile reserved field must be zero")
            profiles.append(PersistentHopProfileV1(target, slot, center, lo, crc))
            offset += _PROFILE.size
        result = cls(
            session_id=values[5],
            sample_rate_hz=values[6],
            rf_bandwidth_hz=values[7],
            if_offset_hz=values[8],
            dwell_samples=values[9],
            transition_guard_samples=values[10],
            dwell_count=values[11],
            capture_span_samples=values[18],
            profiles=tuple(profiles),
        )
        result._validate()
        return result

    def append_to_tandem_request(
        self,
        tandem_request: TandemSessionRequestV1,
        samples_per_block: int,
        *,
        retention_frames: int,
    ) -> bytes:
        """Return the exact tandem-v1 prefix followed by the HOPR suffix."""

        prefix = tandem_request.pack(samples_per_block, retention_frames=retention_frames)
        return prefix + self.pack()


@dataclasses.dataclass(frozen=True, slots=True)
class PersistentHopPlanV1:
    """Host-only bounded plan which deterministically produces one HOPR request."""

    nominal_duration_seconds: int
    valid_visit_ms: int
    sample_rate_hz: int
    rf_bandwidth_hz: int
    transition_guard_samples: int
    samples_per_block: int
    kernel_buffers: int
    minimum_valid_duty_ppm: int
    manual_gain_db: float
    profiles: tuple[PersistentHopProfileV1, ...]

    def __post_init__(self) -> None:
        if self.nominal_duration_seconds != 300 or self.valid_visit_ms != 120:
            raise ValueError("persistent-hop scanner plan must be exactly 300 seconds / 120 ms")
        if self.sample_rate_hz not in {2_500_000, 5_000_000}:
            raise ValueError("persistent-hop scanner rate must be 2.5 or 5 MS/s")
        if self.rf_bandwidth_hz != self.sample_rate_hz:
            raise ValueError("persistent-hop RF bandwidth must equal sample rate")
        if not 2 <= self.kernel_buffers <= 64:
            raise ValueError("persistent-hop kernel buffer count must be within 2..64")
        if not 1 <= self.samples_per_block <= 0xFFFFFFFF:
            raise ValueError("persistent-hop samples_per_block is outside uint32")
        if not 0 <= self.transition_guard_samples < self.dwell_samples:
            raise ValueError("persistent-hop transition guard is outside the visit")
        if not 1 <= self.minimum_valid_duty_ppm <= 1_000_000:
            raise ValueError("minimum persistent-hop duty must be within 1..1,000,000 ppm")
        if (
            isinstance(self.manual_gain_db, bool)
            or not isinstance(self.manual_gain_db, (int, float))
            or not math.isfinite(self.manual_gain_db)
            or not -3 <= self.manual_gain_db <= 73
        ):
            raise ValueError("persistent-hop manual gain must be finite and within -3..73 dB")
        profile_crcs = tuple(profile.profile_crc32 for profile in self.profiles)
        if any(profile_crcs) and not all(profile_crcs):
            raise ValueError(
                "persistent-hop plan profile CRCs must be all hardware-compiled or all zero"
            )
        # A host-only plan may carry all-zero CRC placeholders until a concrete
        # bufferless hardware preparer saves the volatile Fast Lock words. The
        # HOPR request itself remains strict and never permits a zero CRC.
        validation_request = self.request(session_id=1)
        if not any(profile_crcs):
            validation_request = dataclasses.replace(
                validation_request,
                profiles=tuple(
                    dataclasses.replace(profile, profile_crc32=1)
                    for profile in validation_request.profiles
                ),
            )
        validation_request._validate()
        if self.planned_valid_duty_ppm < self.minimum_valid_duty_ppm:
            raise ValueError("persistent-hop plan cannot meet its minimum valid duty")

    @property
    def dwell_samples(self) -> int:
        numerator = self.sample_rate_hz * self.valid_visit_ms
        if numerator % 1000:
            raise ValueError("visit duration does not produce an integral sample count")
        return numerator // 1000

    @property
    def dwell_count(self) -> int:
        available = self.capture_span_samples
        return (available + self.dwell_samples - 1) // self.dwell_samples

    @property
    def maximum_visit_count(self) -> int:
        return self.dwell_count

    @property
    def capture_span_samples(self) -> int:
        return self.sample_rate_hz * self.nominal_duration_seconds

    @property
    def planned_valid_sample_count(self) -> int:
        return self.dwell_count * self.dwell_samples

    @property
    def planned_valid_duty_ppm(self) -> int:
        return (
            self.dwell_samples * 1_000_000 // (self.dwell_samples + self.transition_guard_samples)
        )

    def request(self, *, session_id: int) -> PersistentHopRequestV1:
        if_offset = 0 if not self.profiles else self.profiles[0].center_hz - self.profiles[0].lo_hz
        return PersistentHopRequestV1(
            session_id=session_id,
            sample_rate_hz=self.sample_rate_hz,
            rf_bandwidth_hz=self.rf_bandwidth_hz,
            if_offset_hz=if_offset,
            dwell_samples=self.dwell_samples,
            transition_guard_samples=self.transition_guard_samples,
            dwell_count=self.dwell_count,
            capture_span_samples=self.capture_span_samples,
            profiles=self.profiles,
        )


@dataclasses.dataclass(frozen=True, slots=True)
class PersistentHopEventV1:
    event_sequence: int
    dwell_index: int
    transition_before_counter: int
    transition_after_counter: int
    invalid_start_counter: int
    invalid_end_counter_exclusive: int
    from_profile_index: int
    to_profile_index: int
    kind: PersistentHopEventKind
    flags: PersistentHopEventFlag
    fastlock_slot: int
    actual_lo_frequency_hz: int
    actual_if_offset_hz: int
    device_event_id: int

    def _validate(self) -> None:
        for name, value, bits in (
            ("event_sequence", self.event_sequence, 64),
            ("dwell_index", self.dwell_index, 64),
            ("transition_before_counter", self.transition_before_counter, 64),
            ("transition_after_counter", self.transition_after_counter, 64),
            ("invalid_start_counter", self.invalid_start_counter, 64),
            ("invalid_end_counter_exclusive", self.invalid_end_counter_exclusive, 64),
            ("from_profile_index", self.from_profile_index, 8),
            ("to_profile_index", self.to_profile_index, 8),
            ("fastlock_slot", self.fastlock_slot, 16),
            ("actual_lo_frequency_hz", self.actual_lo_frequency_hz, 64),
            ("device_event_id", self.device_event_id, 64),
        ):
            _uint(name, value, bits)
        _int64("actual_if_offset_hz", self.actual_if_offset_hz)
        if self.flags != _REQUIRED_EVENT_FLAGS:
            raise PersistentHopProtocolError("hop event lacks exact counter and LO attestations")
        if self.to_profile_index >= PERSISTENT_HOP_PROFILE_COUNT:
            raise PersistentHopProtocolError("hop event target profile is outside 0..7")
        if self.from_profile_index not in range(PERSISTENT_HOP_PROFILE_COUNT) and (
            self.from_profile_index != PERSISTENT_HOP_NONE_PROFILE
        ):
            raise PersistentHopProtocolError("hop event source profile is invalid")
        if self.fastlock_slot >= PERSISTENT_HOP_PROFILE_COUNT:
            raise PersistentHopProtocolError("hop event Fast Lock slot is outside 0..7")
        if not self.actual_lo_frequency_hz or not self.device_event_id:
            raise PersistentHopProtocolError(
                "hop event tuning and device identity must be non-zero"
            )
        if self.transition_after_counter < self.transition_before_counter:
            raise PersistentHopProtocolError("hop transition counter interval regressed")
        if self.invalid_start_counter > self.transition_before_counter:
            raise PersistentHopProtocolError(
                "hop invalid span does not include scheduler lead time"
            )
        if (
            self.invalid_end_counter_exclusive < self.transition_after_counter
            or self.invalid_end_counter_exclusive <= self.invalid_start_counter
        ):
            raise PersistentHopProtocolError("hop invalid span does not cover the transition")

    def pack(self) -> bytes:
        self._validate()
        return _EVENT.pack(
            self.event_sequence,
            self.dwell_index,
            self.transition_before_counter,
            self.transition_after_counter,
            self.invalid_start_counter,
            self.invalid_end_counter_exclusive,
            self.from_profile_index,
            self.to_profile_index,
            int(self.kind),
            int(self.flags),
            self.fastlock_slot,
            0,
            self.actual_lo_frequency_hz,
            self.actual_if_offset_hz,
            self.device_event_id,
        )

    @classmethod
    def unpack(cls, payload: bytes | bytearray | memoryview) -> PersistentHopEventV1:
        if len(payload) != PERSISTENT_HOP_EVENT_BYTES:
            raise PersistentHopProtocolError("hop event record has the wrong size")
        values = _EVENT.unpack(payload)
        if values[11]:
            raise PersistentHopProtocolError("hop event reserved field must be zero")
        try:
            kind = PersistentHopEventKind(values[8])
        except ValueError as error:
            raise PersistentHopProtocolError("hop event kind is unknown") from error
        result = cls(
            event_sequence=values[0],
            dwell_index=values[1],
            transition_before_counter=values[2],
            transition_after_counter=values[3],
            invalid_start_counter=values[4],
            invalid_end_counter_exclusive=values[5],
            from_profile_index=values[6],
            to_profile_index=values[7],
            kind=kind,
            flags=PersistentHopEventFlag(values[9]),
            fastlock_slot=values[10],
            actual_lo_frequency_hz=values[12],
            actual_if_offset_hz=values[13],
            device_event_id=values[14],
        )
        result._validate()
        return result


@dataclasses.dataclass(frozen=True, slots=True)
class PersistentHopEvidenceV1:
    flags: PersistentHopStatusFlag
    session_id: int
    buffer_sequence: int
    block_first_counter: int
    block_end_counter_exclusive: int
    state: PersistentHopSessionState
    reason: PersistentHopTerminalReason
    error_code: int
    events: tuple[PersistentHopEventV1, ...] = ()

    def _validate(self) -> None:
        if self.flags & ~_KNOWN_STATUS_FLAGS:
            raise PersistentHopProtocolError("HOPS contains unknown status flags")
        for name, value in (
            ("session_id", self.session_id),
            ("buffer_sequence", self.buffer_sequence),
            ("block_first_counter", self.block_first_counter),
            ("block_end_counter_exclusive", self.block_end_counter_exclusive),
        ):
            _uint(name, value, 64)
        if not self.session_id or self.block_end_counter_exclusive <= self.block_first_counter:
            raise PersistentHopProtocolError("HOPS session or block counter interval is invalid")
        if len(self.events) > PERSISTENT_HOP_EVENT_CAPACITY:
            raise PersistentHopProtocolError("HOPS event count exceeds its fixed capacity")
        if not -(1 << 31) <= self.error_code < 1 << 31:
            raise PersistentHopProtocolError("HOPS error code is outside int32")
        _validate_state_reason_flags(self.state, self.reason, self.error_code, self.flags)
        previous: PersistentHopEventV1 | None = None
        for event in self.events:
            event._validate()
            if previous is not None and (
                event.event_sequence != previous.event_sequence + 1
                or event.dwell_index != previous.dwell_index + 1
                or event.invalid_start_counter < previous.invalid_end_counter_exclusive
            ):
                raise PersistentHopProtocolError("HOPS events are out of order or overlap")
            previous = event

    def pack(self) -> bytes:
        self._validate()
        record_bytes = PERSISTENT_HOP_EVIDENCE_HEADER_BYTES + len(self.events) * _EVENT.size
        header = _EVIDENCE_HEADER.pack(
            _EVIDENCE_MAGIC,
            PERSISTENT_HOP_PROTOCOL_VERSION,
            PERSISTENT_HOP_EVIDENCE_HEADER_BYTES,
            record_bytes,
            PERSISTENT_HOP_REQUIRED_FEATURES,
            int(self.flags),
            len(self.events),
            PERSISTENT_HOP_EVENT_CAPACITY,
            self.session_id,
            self.buffer_sequence,
            self.block_first_counter,
            self.block_end_counter_exclusive,
            int(self.state),
            int(self.reason),
            self.error_code,
        )
        return header + b"".join(event.pack() for event in self.events)

    @classmethod
    def unpack(cls, payload: bytes | bytearray | memoryview) -> PersistentHopEvidenceV1:
        if len(payload) < PERSISTENT_HOP_EVIDENCE_HEADER_BYTES:
            raise PersistentHopProtocolError("HOPS record is shorter than its header")
        values = _EVIDENCE_HEADER.unpack(payload[:PERSISTENT_HOP_EVIDENCE_HEADER_BYTES])
        if values[:3] != (
            _EVIDENCE_MAGIC,
            PERSISTENT_HOP_PROTOCOL_VERSION,
            PERSISTENT_HOP_EVIDENCE_HEADER_BYTES,
        ):
            raise PersistentHopProtocolError("bad HOPS magic, version, or header size")
        record_bytes, features, raw_flags, count, capacity = values[3:8]
        if record_bytes != len(payload):
            raise PersistentHopProtocolError("HOPS declared record size does not match payload")
        if record_bytes != PERSISTENT_HOP_EVIDENCE_HEADER_BYTES + count * _EVENT.size:
            raise PersistentHopProtocolError("HOPS event count does not match record size")
        if (
            features != PERSISTENT_HOP_REQUIRED_FEATURES
            or capacity != PERSISTENT_HOP_EVENT_CAPACITY
        ):
            raise PersistentHopProtocolError("HOPS features or event capacity are not exact v1")
        try:
            state = PersistentHopSessionState(values[12])
            reason = PersistentHopTerminalReason(values[13])
        except ValueError as error:
            raise PersistentHopProtocolError("HOPS state or terminal reason is unknown") from error
        events = tuple(
            PersistentHopEventV1.unpack(
                payload[
                    PERSISTENT_HOP_EVIDENCE_HEADER_BYTES
                    + index * _EVENT.size : PERSISTENT_HOP_EVIDENCE_HEADER_BYTES
                    + (index + 1) * _EVENT.size
                ]
            )
            for index in range(count)
        )
        result = cls(
            flags=PersistentHopStatusFlag(raw_flags),
            session_id=values[8],
            buffer_sequence=values[9],
            block_first_counter=values[10],
            block_end_counter_exclusive=values[11],
            state=state,
            reason=reason,
            error_code=values[14],
            events=events,
        )
        result._validate()
        return result


@dataclasses.dataclass(frozen=True, slots=True)
class PersistentHopStatusV1:
    state: PersistentHopSessionState
    reason: PersistentHopTerminalReason
    error_code: int
    flags: PersistentHopStatusFlag
    session_id: int
    planned_dwells: int
    visits_started: int
    events_emitted: int
    next_event_sequence: int
    last_block_sequence: int
    last_block_end_counter: int
    first_counter: int
    final_counter: int
    restore_before_counter: int
    restore_after_counter: int
    restored_lo_frequency_hz: int
    restore_error_code: int
    active_profile_index: int
    restored_profile_index: int
    startup_invalid_start_counter: int
    startup_invalid_end_counter_exclusive: int
    device_dropped_events: int

    def _validate(self) -> None:
        if self.flags & ~_KNOWN_STATUS_FLAGS:
            raise PersistentHopProtocolError("HOPT contains unknown status flags")
        if not -(1 << 31) <= self.error_code < 1 << 31:
            raise PersistentHopProtocolError("HOPT error code is outside int32")
        if not -(1 << 31) <= self.restore_error_code < 1 << 31:
            raise PersistentHopProtocolError("HOPT restore error code is outside int32")
        for name, value in (
            ("session_id", self.session_id),
            ("planned_dwells", self.planned_dwells),
            ("visits_started", self.visits_started),
            ("events_emitted", self.events_emitted),
            ("next_event_sequence", self.next_event_sequence),
            ("last_block_sequence", self.last_block_sequence),
            ("last_block_end_counter", self.last_block_end_counter),
            ("first_counter", self.first_counter),
            ("final_counter", self.final_counter),
            ("restore_before_counter", self.restore_before_counter),
            ("restore_after_counter", self.restore_after_counter),
            ("restored_lo_frequency_hz", self.restored_lo_frequency_hz),
            ("startup_invalid_start_counter", self.startup_invalid_start_counter),
            ("startup_invalid_end_counter_exclusive", self.startup_invalid_end_counter_exclusive),
            ("device_dropped_events", self.device_dropped_events),
        ):
            _uint(name, value, 64)
        if not self.session_id or not self.planned_dwells:
            raise PersistentHopProtocolError(
                "HOPT session and planned dwell count must be non-zero"
            )
        if self.visits_started > self.planned_dwells or self.events_emitted > self.visits_started:
            raise PersistentHopProtocolError("HOPT visit/event counts exceed the plan")
        if self.next_event_sequence != self.events_emitted:
            raise PersistentHopProtocolError(
                "HOPT next event sequence disagrees with emitted count"
            )
        for name, value in (
            ("active_profile_index", self.active_profile_index),
            ("restored_profile_index", self.restored_profile_index),
        ):
            if (
                value not in range(PERSISTENT_HOP_PROFILE_COUNT)
                and value != PERSISTENT_HOP_NONE_PROFILE
            ):
                raise PersistentHopProtocolError(f"HOPT {name} is invalid")
        if self.startup_invalid_end_counter_exclusive < self.startup_invalid_start_counter:
            raise PersistentHopProtocolError("HOPT startup invalid counter interval regressed")
        _validate_state_reason_flags(self.state, self.reason, self.error_code, self.flags)
        attempted = bool(self.flags & PersistentHopStatusFlag.RESTORE_ATTEMPTED)
        succeeded = bool(self.flags & PersistentHopStatusFlag.RESTORE_SUCCEEDED)
        if succeeded and not attempted:
            raise PersistentHopProtocolError("HOPT restore succeeded without being attempted")
        if attempted:
            if self.restore_after_counter < self.restore_before_counter:
                raise PersistentHopProtocolError("HOPT restoration counter interval regressed")
            if succeeded != (self.restore_error_code == 0):
                raise PersistentHopProtocolError("HOPT restore result disagrees with error code")
            if not succeeded and self.restore_error_code >= 0:
                raise PersistentHopProtocolError(
                    "HOPT failed restoration requires a negative error"
                )
            if succeeded and not self.restored_lo_frequency_hz:
                raise PersistentHopProtocolError("HOPT successful restore lacks LO readback")
        elif any(
            (
                self.restore_before_counter,
                self.restore_after_counter,
                self.restored_lo_frequency_hz,
                self.restore_error_code,
            )
        ):
            raise PersistentHopProtocolError("HOPT has restoration fields without an attempt")
        if bool(self.flags & PersistentHopStatusFlag.DEVICE_EVENT_OVERFLOW) != bool(
            self.device_dropped_events
        ):
            raise PersistentHopProtocolError("HOPT event-overflow flag disagrees with drop count")
        if self.flags & PersistentHopStatusFlag.TERMINAL:
            if self.final_counter < self.first_counter:
                raise PersistentHopProtocolError("HOPT terminal counter interval regressed")
            if self.last_block_end_counter > self.final_counter:
                raise PersistentHopProtocolError("HOPT final counter precedes the last block")
            if attempted and self.restore_before_counter < self.final_counter:
                raise PersistentHopProtocolError(
                    "HOPT restoration begins before the terminal counter"
                )
        elif self.final_counter:
            raise PersistentHopProtocolError("non-terminal HOPT status has a final counter")

    def pack(self) -> bytes:
        self._validate()
        return _STATUS.pack(
            _STATUS_MAGIC,
            PERSISTENT_HOP_PROTOCOL_VERSION,
            PERSISTENT_HOP_STATUS_BYTES,
            PERSISTENT_HOP_REQUIRED_FEATURES,
            int(self.state),
            int(self.reason),
            self.error_code,
            int(self.flags),
            self.session_id,
            self.planned_dwells,
            self.visits_started,
            self.events_emitted,
            self.next_event_sequence,
            self.last_block_sequence,
            self.last_block_end_counter,
            self.first_counter,
            self.final_counter,
            self.restore_before_counter,
            self.restore_after_counter,
            self.restored_lo_frequency_hz,
            self.restore_error_code,
            self.active_profile_index,
            self.restored_profile_index,
            0,
            self.startup_invalid_start_counter,
            self.startup_invalid_end_counter_exclusive,
            self.device_dropped_events,
            0,
        )

    @classmethod
    def unpack(cls, payload: bytes | bytearray | memoryview) -> PersistentHopStatusV1:
        if len(payload) != PERSISTENT_HOP_STATUS_BYTES:
            raise PersistentHopProtocolError("HOPT status size mismatch")
        values = _STATUS.unpack(payload)
        if values[:3] != (
            _STATUS_MAGIC,
            PERSISTENT_HOP_PROTOCOL_VERSION,
            PERSISTENT_HOP_STATUS_BYTES,
        ):
            raise PersistentHopProtocolError("bad HOPT magic, version, or size")
        if values[3] != PERSISTENT_HOP_REQUIRED_FEATURES:
            raise PersistentHopProtocolError("HOPT feature mask is not exact v1")
        if values[23] or values[27]:
            raise PersistentHopProtocolError("HOPT reserved fields must be zero")
        try:
            state = PersistentHopSessionState(values[4])
            reason = PersistentHopTerminalReason(values[5])
        except ValueError as error:
            raise PersistentHopProtocolError("HOPT state or terminal reason is unknown") from error
        result = cls(
            state=state,
            reason=reason,
            error_code=values[6],
            flags=PersistentHopStatusFlag(values[7]),
            session_id=values[8],
            planned_dwells=values[9],
            visits_started=values[10],
            events_emitted=values[11],
            next_event_sequence=values[12],
            last_block_sequence=values[13],
            last_block_end_counter=values[14],
            first_counter=values[15],
            final_counter=values[16],
            restore_before_counter=values[17],
            restore_after_counter=values[18],
            restored_lo_frequency_hz=values[19],
            restore_error_code=values[20],
            active_profile_index=values[21],
            restored_profile_index=values[22],
            startup_invalid_start_counter=values[24],
            startup_invalid_end_counter_exclusive=values[25],
            device_dropped_events=values[26],
        )
        result._validate()
        return result


def _validate_state_reason_flags(
    state: PersistentHopSessionState,
    reason: PersistentHopTerminalReason,
    error_code: int,
    flags: PersistentHopStatusFlag,
) -> None:
    terminal = state in _TERMINAL_STATES
    if bool(flags & PersistentHopStatusFlag.TERMINAL) != terminal:
        raise PersistentHopProtocolError("persistent-hop terminal flag disagrees with state")
    if not flags & PersistentHopStatusFlag.RESTORE_REQUIRED:
        raise PersistentHopProtocolError("persistent-hop record lost restore-required evidence")
    active = state in {
        PersistentHopSessionState.IDLE,
        PersistentHopSessionState.ARMED,
        PersistentHopSessionState.RUNNING,
    }
    if active and flags != PersistentHopStatusFlag.RESTORE_REQUIRED:
        raise PersistentHopProtocolError("active persistent-hop flags are not exact v1")
    if terminal and not flags & PersistentHopStatusFlag.RESTORE_ATTEMPTED:
        raise PersistentHopProtocolError("terminal persistent-hop status lacks a restore attempt")
    if active:
        if reason is not PersistentHopTerminalReason.NONE or error_code:
            raise PersistentHopProtocolError("active persistent-hop state has a terminal result")
    elif state is PersistentHopSessionState.COMPLETED:
        if reason is not PersistentHopTerminalReason.PLAN_COMPLETE or error_code:
            raise PersistentHopProtocolError("completed persistent-hop result is inconsistent")
    elif state is PersistentHopSessionState.CANCELLED:
        if (
            reason
            not in {
                PersistentHopTerminalReason.CLIENT_CLOSE,
                PersistentHopTerminalReason.CLIENT_DISCONNECT,
            }
            or error_code
        ):
            raise PersistentHopProtocolError("cancelled persistent-hop result is inconsistent")
    elif (
        reason
        in {
            PersistentHopTerminalReason.NONE,
            PersistentHopTerminalReason.PLAN_COMPLETE,
            PersistentHopTerminalReason.CLIENT_CLOSE,
            PersistentHopTerminalReason.CLIENT_DISCONNECT,
        }
        or error_code >= 0
    ):
        raise PersistentHopProtocolError("failed persistent-hop result is inconsistent")


@dataclasses.dataclass(frozen=True, slots=True)
class PersistentHopWireBlock:
    evidence: bytes
    iq_payload: bytes
    stream_generation: int | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class PersistentHopDecodedBlockV1:
    evidence: PersistentHopEvidenceV1
    samples: npt.NDArray[np.complex64]
    stream_generation: int | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class PersistentHopSampledVisitV1:
    """One device-attested valid dwell and only its dual-RX IQ samples."""

    visit: PersistentHopVisitV1
    samples: npt.NDArray[np.complex64]

    def __post_init__(self) -> None:
        if (
            self.samples.dtype != np.complex64
            or self.samples.ndim != 2
            or self.samples.shape != (2, self.visit.valid_sample_count)
        ):
            raise ValueError("persistent-hop visit IQ does not match its attested span")


@dataclasses.dataclass(frozen=True, slots=True)
class PersistentHopInvalidSpanV1:
    visit_index: int
    from_profile_index: int
    to_profile_index: int
    transition_before_counter: int
    transition_after_counter: int
    device_sample_counter: int
    device_sample_counter_end_exclusive: int


@dataclasses.dataclass(frozen=True, slots=True)
class PersistentHopVisitV1:
    visit_index: int
    sweep_index: int
    target_index: int
    fastlock_slot: int
    event_sequence: int
    device_event_id: int
    device_event_flags: int
    target: PersistentHopTarget
    requested_center_hz: int
    requested_lo_hz: int
    requested_if_offset_hz: int
    actual_lo_frequency_hz: int
    actual_if_offset_hz: int
    transition_invalid_before: PersistentHopInvalidSpanV1
    valid_device_sample_counter: int
    valid_device_sample_counter_end_exclusive: int

    @property
    def valid_sample_count(self) -> int:
        return self.valid_device_sample_counter_end_exclusive - self.valid_device_sample_counter

    @property
    def fastlock_profile_index(self) -> int:
        return self.fastlock_slot

    @property
    def hop_event_sequence(self) -> int:
        return self.event_sequence


@dataclasses.dataclass(frozen=True, slots=True)
class PersistentHopRestorationReceiptV1:
    status: str
    restore_before_counter: int
    restore_after_counter: int
    restored_lo_frequency_hz: int
    restored_profile_index: int
    active_profile_index: int
    error_code: int


@dataclasses.dataclass(frozen=True, slots=True)
class PersistentHopReceiverSettingsV1:
    center_frequency_hz: float
    sample_rate_hz: float
    bandwidth_hz: float
    channels: tuple[int, ...]
    gain_modes: tuple[str, ...]
    gain_db: tuple[float, ...]


@dataclasses.dataclass(frozen=True, slots=True)
class PersistentHopHostLifecycleReceiptV1:
    original_settings: PersistentHopReceiverSettingsV1
    restored_settings: PersistentHopReceiverSettingsV1
    receive_buffer_closed: bool
    fastlock_inactive: bool


@dataclasses.dataclass(frozen=True, slots=True)
class PersistentHopCancellationReceiptV1:
    session_id: int
    reason: PersistentHopTerminalReason
    visits_started: int
    events_emitted: int
    final_counter: int
    restoration: PersistentHopRestorationReceiptV1
    host_lifecycle: PersistentHopHostLifecycleReceiptV1 | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class PersistentHopSessionReceiptV1:
    session_id: int
    radio_serial: str
    radio_uri: str
    status: PersistentHopStatusV1
    visits: tuple[PersistentHopVisitV1, ...]
    target_coverage: tuple[PersistentHopTargetCoverageV1, ...]
    capture_outcome: str
    valid_sample_count: int
    transition_invalid_sample_count: int
    missing_sample_count: int
    overflow_count: int
    hop_event_sequence_gap_count: int
    duty_denominator_sample_count: int
    valid_duty_ppm: int
    continuity_attested: bool
    duty_target_met: bool
    restoration: PersistentHopRestorationReceiptV1
    incomplete_visit_sample_count: int = 0
    incomplete_visit_device_sample_counter: int | None = None
    incomplete_visit_device_sample_counter_end_exclusive: int | None = None
    host_lifecycle: PersistentHopHostLifecycleReceiptV1 | None = None
    radio_id: str | None = None
    metadata_abi_version: int = 3
    stream_generation: int | None = None
    kernel_buffers_requested: int | None = None
    kernel_buffers_readback: int | None = None


@dataclasses.dataclass(frozen=True, slots=True)
class PersistentHopTargetCoverageV1:
    target_index: int
    target: PersistentHopTarget
    visit_count: int
    valid_sample_count: int


@dataclasses.dataclass(frozen=True, slots=True)
class _PersistentHopBackendReceiptFacts:
    radio_id: str | None
    stream_generation: int | None
    kernel_buffers_requested: int
    kernel_buffers_readback: int | None


class PersistentHopBackend(Protocol):
    """Injected IIO/provider adapter; implementations own all actual I/O."""

    @property
    def uri(self) -> str: ...

    def open(self) -> None: ...

    def context_attributes(self) -> Mapping[str, str]: ...

    def start(
        self,
        request: bytes,
        *,
        samples_per_block: int,
        kernel_buffers: int,
    ) -> None: ...

    def blocks(self) -> Iterator[PersistentHopWireBlock]: ...

    def cancel(self) -> None: ...

    def read_status(self) -> bytes: ...

    def close(self) -> PersistentHopHostLifecycleReceiptV1 | None: ...


class PersistentHopPlanPreparer(Protocol):
    """Optional bufferless hardware compiler for volatile Fast Lock profiles."""

    def prepare_plan(self, plan: PersistentHopPlanV1) -> PersistentHopPlanV1: ...


class PersistentHopClient:
    """Serial-attested, exact-capability entry point for persistent hopping."""

    def __init__(
        self,
        uri: str,
        *,
        expected_serial: str,
        backend_factory: Callable[[str], PersistentHopBackend],
    ) -> None:
        self.uri = require_physical_lan_uri(uri)
        self.expected_serial = require_allowed_serial(expected_serial)
        self._backend_factory = backend_factory
        self._active = False

    def start(
        self,
        plan: PersistentHopPlanV1,
        *,
        session_id: int,
        tandem_request: TandemSessionRequestV1,
    ) -> PersistentHopSession:
        if self._active:
            raise PersistentHopClientError("persistent-hop client already owns a session")
        backend = self._backend_factory(self.uri)
        if backend.uri != self.uri:
            raise PersistentHopClientError("persistent-hop backend URI does not match the client")
        opened = False
        try:
            backend.open()
            opened = True
            attributes = dict(backend.context_attributes())
            observed_serial = attributes.get("hw_serial")
            if observed_serial == PERSISTENT_HOP_EXCLUDED_SERIAL:
                raise PersistentHopClientError(
                    f"persistent hopping is forbidden on excluded serial {observed_serial}"
                )
            if observed_serial != self.expected_serial:
                raise PersistentHopClientError(
                    f"persistent-hop serial readback {observed_serial!r} does not match "
                    f"expected {self.expected_serial!r}"
                )
            if attributes.get("iio,buffer-metadata") != PERSISTENT_HOP_METADATA_ABI:
                raise PersistentHopClientError("persistent hopping requires exact metadata ABI 3")
            missing = tuple(
                name for name in PERSISTENT_HOP_CAPABILITIES if attributes.get(name) != "1"
            )
            if missing:
                raise PersistentHopClientError(
                    "persistent-hop exact capability negotiation failed: " + ", ".join(missing)
                )
            prepare_plan = getattr(backend, "prepare_plan", None)
            if callable(prepare_plan):
                prepared_plan = prepare_plan(plan)
                _require_same_plan_except_profile_crcs(plan, prepared_plan)
                plan = prepared_plan
            if any(not profile.profile_crc32 for profile in plan.profiles):
                raise PersistentHopClientError(
                    "persistent-hop plan requires hardware-compiled Fast Lock CRCs"
                )
            request = plan.request(session_id=session_id)
            payload = request.append_to_tandem_request(
                tandem_request,
                plan.samples_per_block,
                retention_frames=plan.kernel_buffers + 1,
            )
            backend.start(
                payload,
                samples_per_block=plan.samples_per_block,
                kernel_buffers=plan.kernel_buffers,
            )
            initial_status = PersistentHopStatusV1.unpack(backend.read_status())
            if initial_status.session_id != session_id or initial_status.state not in {
                PersistentHopSessionState.ARMED,
                PersistentHopSessionState.RUNNING,
            }:
                raise PersistentHopClientError(
                    "persistent-hop backend did not arm the exact session"
                )
            if initial_status.planned_dwells != request.dwell_count:
                raise PersistentHopClientError(
                    "persistent-hop backend changed the planned dwell count"
                )
        except BaseException:
            if opened:
                backend.close()
            raise
        self._active = True
        return PersistentHopSession(self, backend, plan, request, initial_status)

    def _released(self) -> None:
        self._active = False


class PersistentHopSession:
    """One continuous dual-RX iterator with strict counter/event continuity."""

    def __init__(
        self,
        owner: PersistentHopClient,
        backend: PersistentHopBackend,
        plan: PersistentHopPlanV1,
        request: PersistentHopRequestV1,
        initial_status: PersistentHopStatusV1,
    ) -> None:
        self._owner = owner
        self._backend = backend
        self.plan = plan
        self.request = request
        self._closed = False
        self._iterated = False
        self._previous_block_sequence: int | None = None
        self._previous_block_end: int | None = None
        self._previous_event: PersistentHopEventV1 | None = None
        self._stream_generation: int | None = None
        self._visits: list[PersistentHopVisitV1] = []
        self._receipt: PersistentHopSessionReceiptV1 | None = None
        self._initial_status = initial_status

    @property
    def completed_visits(self) -> tuple[PersistentHopVisitV1, ...]:
        return tuple(self._visits)

    @property
    def receipt(self) -> PersistentHopSessionReceiptV1:
        if self._receipt is None:
            raise PersistentHopClientError("persistent-hop session has no terminal receipt yet")
        return self._receipt

    def blocks(self) -> Iterator[PersistentHopDecodedBlockV1]:
        self._claim_iterator()
        yield from self._decoded_blocks()

    def visits(self) -> Iterator[PersistentHopSampledVisitV1]:
        """Yield valid per-target IQ, excluding every attested transition span.

        Device events may cross arbitrary refill boundaries. The assembler
        therefore retains the current not-yet-attested visit, emits only after
        its closing counter is proven, and fails closed if event delivery would
        require retaining more than one dwell plus one boundary refill.
        """

        self._claim_iterator()
        segments: deque[tuple[int, int, npt.NDArray[np.complex64]]] = deque()
        emitted = 0
        for block in self._decoded_blocks():
            segments.append(
                (
                    block.evidence.block_first_counter,
                    block.evidence.block_end_counter_exclusive,
                    block.samples,
                )
            )
            while emitted < len(self._visits):
                visit = self._visits[emitted]
                if (
                    not segments
                    or segments[-1][1]
                    < visit.valid_device_sample_counter_end_exclusive
                ):
                    break
                sampled = _sampled_visit_from_segments(visit, segments)
                emitted += 1
                _trim_sample_segments(
                    segments, visit.valid_device_sample_counter_end_exclusive
                )
                yield sampled
            retain_from = (
                self._visits[emitted].valid_device_sample_counter
                if emitted < len(self._visits)
                else (
                    self._previous_event.invalid_end_counter_exclusive
                    if self._previous_event is not None
                    else self._initial_status.first_counter
                )
            )
            _trim_sample_segments(segments, retain_from)
            retained = sum(end - start for start, end, _samples in segments)
            if retained > self.request.dwell_samples + self.plan.samples_per_block:
                raise PersistentHopClientError(
                    "persistent-hop event delivery exceeded the bounded visit IQ window"
                )
        while emitted < len(self._visits):
            visit = self._visits[emitted]
            sampled = _sampled_visit_from_segments(visit, segments)
            emitted += 1
            _trim_sample_segments(segments, visit.valid_device_sample_counter_end_exclusive)
            yield sampled
        if emitted != len(self._visits):  # pragma: no cover - loop invariant
            raise PersistentHopClientError("persistent-hop visit IQ assembly was incomplete")

    def _claim_iterator(self) -> None:
        if self._closed:
            raise PersistentHopClientError("persistent-hop session is closed")
        if self._iterated:
            raise PersistentHopClientError("persistent-hop IQ iterator is single-use")
        self._iterated = True

    def _decoded_blocks(self) -> Iterator[PersistentHopDecodedBlockV1]:
        try:
            for wire in self._backend.blocks():
                evidence = PersistentHopEvidenceV1.unpack(wire.evidence)
                self._validate_evidence(evidence)
                self._accept_stream_generation(wire.stream_generation)
                expected_bytes = (
                    evidence.block_end_counter_exclusive - evidence.block_first_counter
                ) * 8
                if len(wire.iq_payload) != expected_bytes:
                    raise PersistentHopClientError(
                        "persistent-hop dual-RX payload length disagrees with device counters"
                    )
                try:
                    samples = ci16_dual_rx(wire.iq_payload)
                except ValueError as error:
                    raise PersistentHopClientError(str(error)) from error
                yield PersistentHopDecodedBlockV1(
                    evidence=evidence,
                    samples=samples,
                    stream_generation=wire.stream_generation,
                )
            self._finish_completed()
        except BaseException as error:
            cleanup_error = self._cancel_after_failure()
            if cleanup_error is not None:
                error.add_note(f"persistent-hop cleanup also failed: {cleanup_error!r}")
            raise

    def cancel(self) -> PersistentHopCancellationReceiptV1:
        if self._closed:
            raise PersistentHopClientError("persistent-hop session is already closed")
        receipt: PersistentHopCancellationReceiptV1 | None = None
        full_receipt: PersistentHopSessionReceiptV1 | None = None
        host_lifecycle: PersistentHopHostLifecycleReceiptV1 | None = None
        try:
            self._backend.cancel()
            status = PersistentHopStatusV1.unpack(self._backend.read_status())
            self._require_terminal_status(status, PersistentHopSessionState.CANCELLED)
            receipt = PersistentHopCancellationReceiptV1(
                session_id=status.session_id,
                reason=status.reason,
                visits_started=status.visits_started,
                events_emitted=status.events_emitted,
                final_counter=status.final_counter,
                restoration=_restoration_receipt(status),
            )
            full_receipt = self._cancelled_full_receipt(status)
        finally:
            host_lifecycle = self._release()
        assert receipt is not None and full_receipt is not None
        self._receipt = dataclasses.replace(
            full_receipt,
            host_lifecycle=host_lifecycle,
        )
        return dataclasses.replace(receipt, host_lifecycle=host_lifecycle)

    def close(self) -> PersistentHopCancellationReceiptV1 | None:
        if self._closed:
            return None
        return self.cancel()

    def __enter__(self) -> PersistentHopSession:
        if self._closed:
            raise PersistentHopClientError("persistent-hop session is closed")
        return self

    def __exit__(self, exc_type: object, exc: object, traceback: object) -> None:
        del exc_type, exc, traceback
        self.close()

    def _validate_evidence(self, evidence: PersistentHopEvidenceV1) -> None:
        if evidence.session_id != self.request.session_id:
            raise PersistentHopClientError("HOPS evidence belongs to a different session")
        if evidence.flags & (
            PersistentHopStatusFlag.DEVICE_EVENT_OVERFLOW | PersistentHopStatusFlag.CONTINUITY_FAULT
        ):
            raise PersistentHopClientError(
                "persistent-hop device reported overflow or continuity loss"
            )
        expected_sequence = (
            0 if self._previous_block_sequence is None else self._previous_block_sequence + 1
        )
        if evidence.buffer_sequence != expected_sequence:
            raise PersistentHopClientError("persistent-hop buffer sequence is not contiguous")
        expected_first = (
            self._initial_status.first_counter
            if self._previous_block_end is None
            else self._previous_block_end
        )
        if evidence.block_first_counter != expected_first:
            raise PersistentHopClientError("persistent-hop device sample counter has a gap")
        self._previous_block_sequence = evidence.buffer_sequence
        self._previous_block_end = evidence.block_end_counter_exclusive
        for event in evidence.events:
            self._accept_event(event)

    def _accept_event(self, event: PersistentHopEventV1) -> None:
        expected_index = (
            0 if self._previous_event is None else self._previous_event.event_sequence + 1
        )
        expected_dwell = 0 if self._previous_event is None else self._previous_event.dwell_index + 1
        if event.event_sequence != expected_index or event.dwell_index != expected_dwell:
            raise PersistentHopClientError("persistent-hop event sequence or dwell index has a gap")
        expected_target = event.dwell_index % PERSISTENT_HOP_PROFILE_COUNT
        expected_from = (
            PERSISTENT_HOP_NONE_PROFILE
            if event.dwell_index == 0
            else (expected_target - 1) % PERSISTENT_HOP_PROFILE_COUNT
        )
        expected_kind = (
            PersistentHopEventKind.STARTUP
            if event.dwell_index == 0
            else PersistentHopEventKind.RETUNE
        )
        if (
            event.to_profile_index != expected_target
            or event.from_profile_index != expected_from
            or event.kind is not expected_kind
        ):
            raise PersistentHopClientError("persistent-hop event does not follow CH1L..CH4U order")
        profile = self.request.profiles[expected_target]
        if event.fastlock_slot != profile.fastlock_profile_index:
            raise PersistentHopClientError("persistent-hop event Fast Lock slot changed")
        if event.invalid_end_counter_exclusive != _checked_add_u64(
            "hop invalid end",
            event.transition_after_counter,
            self.request.transition_guard_samples,
        ):
            raise PersistentHopClientError("persistent-hop event guard does not match the request")
        if (
            event.actual_lo_frequency_hz != profile.lo_hz
            or event.actual_if_offset_hz != self.request.if_offset_hz
        ):
            raise PersistentHopClientError(
                "persistent-hop event actual LO or IF differs from the request"
            )
        if self._previous_event is not None:
            self._visits.append(self._visit_from(self._previous_event, event.invalid_start_counter))
        self._previous_event = event

    def _visit_from(self, event: PersistentHopEventV1, valid_end: int) -> PersistentHopVisitV1:
        valid_start = event.invalid_end_counter_exclusive
        if valid_end <= valid_start or valid_end - valid_start != self.request.dwell_samples:
            raise PersistentHopClientError("persistent-hop valid visit is not the requested dwell")
        profile = self.request.profiles[event.to_profile_index]
        invalid = PersistentHopInvalidSpanV1(
            visit_index=event.dwell_index,
            from_profile_index=event.from_profile_index,
            to_profile_index=event.to_profile_index,
            transition_before_counter=event.transition_before_counter,
            transition_after_counter=event.transition_after_counter,
            device_sample_counter=event.invalid_start_counter,
            device_sample_counter_end_exclusive=event.invalid_end_counter_exclusive,
        )
        return PersistentHopVisitV1(
            visit_index=event.dwell_index,
            sweep_index=event.dwell_index // PERSISTENT_HOP_PROFILE_COUNT,
            target_index=event.to_profile_index,
            fastlock_slot=event.fastlock_slot,
            event_sequence=event.event_sequence,
            device_event_id=event.device_event_id,
            device_event_flags=int(event.flags),
            target=profile.target,
            requested_center_hz=profile.center_hz,
            requested_lo_hz=profile.lo_hz,
            requested_if_offset_hz=self.request.if_offset_hz,
            actual_lo_frequency_hz=event.actual_lo_frequency_hz,
            actual_if_offset_hz=event.actual_if_offset_hz,
            transition_invalid_before=invalid,
            valid_device_sample_counter=valid_start,
            valid_device_sample_counter_end_exclusive=valid_end,
        )

    def _finish_completed(self) -> None:
        status = PersistentHopStatusV1.unpack(self._backend.read_status())
        self._require_terminal_status(status, PersistentHopSessionState.COMPLETED)
        if not 1 <= status.visits_started <= self.request.dwell_count:
            raise PersistentHopClientError("persistent-hop completion has an invalid visit count")
        if status.events_emitted != status.visits_started:
            raise PersistentHopClientError("persistent-hop completion omitted device hop events")
        if self._previous_event is None:
            raise PersistentHopClientError("persistent-hop completion has no device hop events")
        self._visits.append(self._visit_from(self._previous_event, status.final_counter))
        if len(self._visits) != status.visits_started:
            raise PersistentHopClientError("persistent-hop completed visit count is inconsistent")
        valid_samples = sum(visit.valid_sample_count for visit in self._visits)
        invalid_samples = sum(
            visit.transition_invalid_before.device_sample_counter_end_exclusive
            - visit.transition_invalid_before.device_sample_counter
            for visit in self._visits
        )
        denominator = status.final_counter - status.first_counter
        if denominator <= 0 or valid_samples + invalid_samples != denominator:
            raise PersistentHopClientError(
                "persistent-hop visit spans do not partition the session"
            )
        if denominator < self.request.capture_span_samples:
            raise PersistentHopClientError("persistent-hop session ended before its capture span")
        final_transition_invalid_samples = (
            self._previous_event.invalid_end_counter_exclusive
            - self._previous_event.invalid_start_counter
        )
        maximum_overshoot = self.request.dwell_samples + final_transition_invalid_samples
        if denominator - self.request.capture_span_samples > maximum_overshoot:
            raise PersistentHopClientError("persistent-hop session exceeded its bounded overshoot")
        if status.last_block_end_counter != status.final_counter:
            raise PersistentHopClientError("persistent-hop completion did not deliver final IQ")
        startup = self._visits[0].transition_invalid_before
        if (
            status.first_counter != startup.device_sample_counter
            or status.startup_invalid_start_counter != startup.device_sample_counter
            or status.startup_invalid_end_counter_exclusive
            != startup.device_sample_counter_end_exclusive
        ):
            raise PersistentHopClientError("persistent-hop startup invalid span is inconsistent")
        duty = valid_samples * 1_000_000 // denominator
        restoration = _restoration_receipt(status)
        coverage = tuple(
            PersistentHopTargetCoverageV1(
                target_index=index,
                target=PersistentHopTarget(index),
                visit_count=sum(visit.target_index == index for visit in self._visits),
                valid_sample_count=sum(
                    visit.valid_sample_count
                    for visit in self._visits
                    if visit.target_index == index
                ),
            )
            for index in range(PERSISTENT_HOP_PROFILE_COUNT)
        )
        backend_facts = self._backend_receipt_facts()
        receipt = PersistentHopSessionReceiptV1(
            session_id=status.session_id,
            radio_serial=self._owner.expected_serial,
            radio_uri=self._owner.uri,
            status=status,
            visits=tuple(self._visits),
            target_coverage=coverage,
            capture_outcome="complete",
            valid_sample_count=valid_samples,
            transition_invalid_sample_count=invalid_samples,
            missing_sample_count=0,
            overflow_count=0,
            hop_event_sequence_gap_count=0,
            duty_denominator_sample_count=denominator,
            valid_duty_ppm=duty,
            continuity_attested=True,
            duty_target_met=duty >= self.plan.minimum_valid_duty_ppm,
            restoration=restoration,
            incomplete_visit_sample_count=0,
            incomplete_visit_device_sample_counter=None,
            incomplete_visit_device_sample_counter_end_exclusive=None,
            radio_id=backend_facts.radio_id,
            metadata_abi_version=3,
            stream_generation=backend_facts.stream_generation,
            kernel_buffers_requested=backend_facts.kernel_buffers_requested,
            kernel_buffers_readback=backend_facts.kernel_buffers_readback,
        )
        if not receipt.duty_target_met:
            raise PersistentHopClientError("persistent-hop session missed its minimum valid duty")
        self._receipt = dataclasses.replace(
            receipt,
            host_lifecycle=self._release(),
        )

    def _cancelled_full_receipt(
        self,
        status: PersistentHopStatusV1,
    ) -> PersistentHopSessionReceiptV1:
        accepted_events = (
            0 if self._previous_event is None else self._previous_event.event_sequence + 1
        )
        if (
            status.events_emitted != accepted_events
            or status.visits_started != accepted_events
        ):
            raise PersistentHopClientError(
                "persistent-hop cancellation has undelivered device events"
            )
        if self._previous_block_sequence is not None and (
            status.last_block_sequence != self._previous_block_sequence
            or status.last_block_end_counter != self._previous_block_end
        ):
            raise PersistentHopClientError(
                "persistent-hop cancellation status disagrees with delivered IQ"
            )
        first = status.first_counter
        final = status.final_counter
        if final < first or (
            self._previous_block_end is not None and final < self._previous_block_end
        ):
            raise PersistentHopClientError(
                "persistent-hop cancellation counter envelope regressed"
            )
        valid_samples = sum(visit.valid_sample_count for visit in self._visits)
        invalid_intervals = [
            (
                visit.transition_invalid_before.device_sample_counter,
                visit.transition_invalid_before.device_sample_counter_end_exclusive,
            )
            for visit in self._visits
        ]
        if self._previous_event is not None:
            invalid_intervals.append(
                (
                    self._previous_event.invalid_start_counter,
                    self._previous_event.invalid_end_counter_exclusive,
                )
            )
        invalid_samples = sum(
            max(0, min(final, end) - max(first, start))
            for start, end in invalid_intervals
        )
        incomplete_start = (
            first
            if self._previous_event is None
            else max(first, min(final, self._previous_event.invalid_end_counter_exclusive))
        )
        incomplete_samples = final - incomplete_start
        denominator = final - first
        if valid_samples + invalid_samples + incomplete_samples != denominator:
            raise PersistentHopClientError(
                "persistent-hop cancellation spans do not partition the session"
            )
        coverage = tuple(
            PersistentHopTargetCoverageV1(
                target_index=index,
                target=PersistentHopTarget(index),
                visit_count=sum(visit.target_index == index for visit in self._visits),
                valid_sample_count=sum(
                    visit.valid_sample_count
                    for visit in self._visits
                    if visit.target_index == index
                ),
            )
            for index in range(PERSISTENT_HOP_PROFILE_COUNT)
        )
        backend_facts = self._backend_receipt_facts()
        return PersistentHopSessionReceiptV1(
            session_id=status.session_id,
            radio_serial=self._owner.expected_serial,
            radio_uri=self._owner.uri,
            status=status,
            visits=tuple(self._visits),
            target_coverage=coverage,
            capture_outcome="cancelled",
            valid_sample_count=valid_samples,
            transition_invalid_sample_count=invalid_samples,
            missing_sample_count=0,
            overflow_count=0,
            hop_event_sequence_gap_count=0,
            duty_denominator_sample_count=denominator,
            valid_duty_ppm=(
                0 if denominator == 0 else valid_samples * 1_000_000 // denominator
            ),
            continuity_attested=True,
            duty_target_met=False,
            restoration=_restoration_receipt(status),
            incomplete_visit_sample_count=incomplete_samples,
            incomplete_visit_device_sample_counter=(
                incomplete_start if incomplete_samples else None
            ),
            incomplete_visit_device_sample_counter_end_exclusive=(
                final if incomplete_samples else None
            ),
            radio_id=backend_facts.radio_id,
            metadata_abi_version=3,
            stream_generation=backend_facts.stream_generation,
            kernel_buffers_requested=backend_facts.kernel_buffers_requested,
            kernel_buffers_readback=backend_facts.kernel_buffers_readback,
        )

    def _accept_stream_generation(self, generation: int | None) -> None:
        if generation is None:
            if self._stream_generation is not None:
                raise PersistentHopClientError(
                    "persistent-hop ABI-3 stream generation disappeared"
                )
            return
        if isinstance(generation, bool) or not isinstance(generation, int) or generation <= 0:
            raise PersistentHopClientError(
                "persistent-hop ABI-3 stream generation is invalid"
            )
        if self._stream_generation is None:
            self._stream_generation = generation
        elif generation != self._stream_generation:
            raise PersistentHopClientError(
                "persistent-hop ABI-3 stream generation changed"
            )

    def _backend_receipt_facts(self) -> _PersistentHopBackendReceiptFacts:
        requested = getattr(self._backend, "kernel_buffers_requested", None)
        readback = getattr(self._backend, "kernel_buffers_readback", None)
        radio_id = getattr(self._backend, "radio_id", None)
        if requested is not None and requested != self.plan.kernel_buffers:
            raise PersistentHopClientError(
                "persistent-hop kernel-buffer request changed"
            )
        if readback is not None and readback != self.plan.kernel_buffers:
            raise PersistentHopClientError(
                "persistent-hop kernel-buffer readback changed"
            )
        return _PersistentHopBackendReceiptFacts(
            radio_id=radio_id if isinstance(radio_id, str) and radio_id else None,
            stream_generation=self._stream_generation,
            kernel_buffers_requested=(
                requested if isinstance(requested, int) else self.plan.kernel_buffers
            ),
            kernel_buffers_readback=(readback if isinstance(readback, int) else None),
        )

    def _require_terminal_status(
        self,
        status: PersistentHopStatusV1,
        expected_state: PersistentHopSessionState,
    ) -> None:
        if status.session_id != self.request.session_id or status.state is not expected_state:
            raise PersistentHopClientError(
                "persistent-hop terminal status does not match the session"
            )
        if status.flags & (
            PersistentHopStatusFlag.DEVICE_EVENT_OVERFLOW | PersistentHopStatusFlag.CONTINUITY_FAULT
        ):
            raise PersistentHopClientError("persistent-hop terminal status reports lost evidence")
        restoration = _restoration_receipt(status)
        if restoration.status != "restored":
            raise PersistentHopClientError("persistent-hop settings restoration was not attested")

    def _cancel_after_failure(self) -> BaseException | None:
        if self._closed:
            return None
        try:
            self._backend.cancel()
            status = PersistentHopStatusV1.unpack(self._backend.read_status())
            if status.session_id != self.request.session_id:
                raise PersistentHopClientError("cleanup status belongs to a different session")
            if _restoration_receipt(status).status != "restored":
                raise PersistentHopClientError("cleanup did not attest exact settings restoration")
        except BaseException as error:
            return error
        finally:
            self._release()
        return None

    def _release(self) -> PersistentHopHostLifecycleReceiptV1 | None:
        if not self._closed:
            try:
                return self._backend.close()
            finally:
                self._closed = True
                self._owner._released()
        return None


def _restoration_receipt(status: PersistentHopStatusV1) -> PersistentHopRestorationReceiptV1:
    attempted = bool(status.flags & PersistentHopStatusFlag.RESTORE_ATTEMPTED)
    succeeded = bool(status.flags & PersistentHopStatusFlag.RESTORE_SUCCEEDED)
    result = "restored" if succeeded else "failed" if attempted else "not_attempted"
    return PersistentHopRestorationReceiptV1(
        status=result,
        restore_before_counter=status.restore_before_counter,
        restore_after_counter=status.restore_after_counter,
        restored_lo_frequency_hz=status.restored_lo_frequency_hz,
        restored_profile_index=status.restored_profile_index,
        active_profile_index=status.active_profile_index,
        error_code=status.restore_error_code,
    )


def _sampled_visit_from_segments(
    visit: PersistentHopVisitV1,
    segments: deque[tuple[int, int, npt.NDArray[np.complex64]]],
) -> PersistentHopSampledVisitV1:
    start = visit.valid_device_sample_counter
    end = visit.valid_device_sample_counter_end_exclusive
    pieces = tuple(
        samples[
            :,
            max(start, segment_start) - segment_start : min(end, segment_end)
            - segment_start,
        ]
        for segment_start, segment_end, samples in segments
        if segment_end > start and segment_start < end
    )
    covered = sum(piece.shape[1] for piece in pieces)
    if covered != visit.valid_sample_count:
        raise PersistentHopClientError(
            "persistent-hop IQ blocks do not cover the attested valid visit"
        )
    output = (
        pieces[0].copy()
        if len(pieces) == 1
        else np.concatenate(pieces, axis=1, dtype=np.complex64)
    )
    return PersistentHopSampledVisitV1(visit=visit, samples=output)


def _trim_sample_segments(
    segments: deque[tuple[int, int, npt.NDArray[np.complex64]]],
    retain_from: int,
) -> None:
    while segments and segments[0][1] <= retain_from:
        segments.popleft()
    if segments and segments[0][0] < retain_from:
        start, end, samples = segments[0]
        segments[0] = (retain_from, end, samples[:, retain_from - start :])


def _require_same_plan_except_profile_crcs(
    requested: PersistentHopPlanV1,
    prepared: PersistentHopPlanV1,
) -> None:
    """Prevent a hardware compiler from silently changing the requested scan."""

    requested_without_crcs = dataclasses.replace(
        requested,
        profiles=tuple(
            dataclasses.replace(profile, profile_crc32=1) for profile in requested.profiles
        ),
    )
    prepared_without_crcs = dataclasses.replace(
        prepared,
        profiles=tuple(
            dataclasses.replace(profile, profile_crc32=1) for profile in prepared.profiles
        ),
    )
    if prepared_without_crcs != requested_without_crcs:
        raise PersistentHopClientError(
            "persistent-hop hardware preparation changed the requested plan"
        )
