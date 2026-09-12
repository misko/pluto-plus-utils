"""Explicit HOPR/HOPS/HOPT major-2 codecs; no IIO or radio access.

V1 objects below describe shared numeric geometry only. Adaptive recordings
must retain their V2 wrapper and must never enter the fixed-order V1 session.
Streaming continuity/visit reconstruction belongs to a stateful capture adapter.
"""

from __future__ import annotations

import dataclasses
import enum
import struct
from collections.abc import Mapping

from .persistent_hop import (
    PersistentHopClientError,
    PersistentHopEventV1,
    PersistentHopEvidenceV1,
    PersistentHopProtocolError,
    PersistentHopRequestV1,
    PersistentHopStatusV1,
)
from .tandem import TandemSessionRequestV1

ADAPTIVE_HOP_REQUEST_BYTES = 352
ADAPTIVE_HOP_EVENT_BYTES = 144
ADAPTIVE_HOP_EVIDENCE_MAX_BYTES = 1216
ADAPTIVE_HOP_POLICY_ID = "three-miss-two-second-v1"
_POLICY = struct.Struct("<Q10I16s")
_CHOICE = struct.Struct("<4Q6I8s")
_NO_VISIT = (1 << 64) - 1


class AdaptiveHopMode(enum.IntEnum):
    SHADOW = 1
    ADAPTIVE = 2


def require_adaptive_capabilities(
    attributes: Mapping[str, str], policy: AdaptiveHopPolicyV2
) -> None:
    """Check before profile preparation; unsupported peers are not downgraded."""
    policy.require_pinned_policy()
    required = {
        "iio,buffer-adaptive-hop-request": "2",
        "iio,buffer-adaptive-hop-event": "2",
        "iio,buffer-adaptive-hop-status": "2",
        "iio,buffer-adaptive-hop-modes": "shadow,adaptive",
        "iio,buffer-adaptive-hop-policy": ADAPTIVE_HOP_POLICY_ID,
        "iio,buffer-scanner-glrt-mode": "positive-only-v1",
    }
    if any(attributes.get(key) != value for key, value in required.items()):
        raise PersistentHopClientError("adaptive peer capabilities/policy are incompatible")


def _uint(value: int, bits: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 1 << bits:
        raise PersistentHopProtocolError(f"adaptive value outside uint{bits}")


def _header(payload: bytes, magic: bytes, size: int, *, exact: bool = True) -> bytearray:
    if len(payload) != size if exact else len(payload) < size:
        raise PersistentHopProtocolError("adaptive record size mismatch")
    if payload[:4] != magic or struct.unpack_from("<HH", payload, 4) != (2, size):
        raise PersistentHopProtocolError("adaptive record magic/version/header mismatch")
    return bytearray(payload)


@dataclasses.dataclass(frozen=True, slots=True)
class AdaptiveHopPolicyV2:
    generation: int
    mode: AdaptiveHopMode = AdaptiveHopMode.ADAPTIVE
    warmup_visits: int = 3
    missed_dwells: int = 3
    active_weight: int = 3
    quiet_weight: int = 1
    cooldown_ms: int = 2000
    maximum_revisit_ms: int = 3000
    hop_budget_ms: int = 160
    maximum_result_age_ms: int = 1000
    unhealthy_limit: int = 3

    def _validate(self) -> None:
        _uint(self.generation, 64)
        for value in dataclasses.astuple(self)[1:]:
            _uint(value, 32)
        if (
            not self.generation
            or self.mode not in (1, 2)
            or not 1 <= self.warmup_visits <= 16
            or not 1 <= self.missed_dwells <= 32
            or not 1 <= self.quiet_weight <= self.active_weight <= 16
            or not 1 <= self.cooldown_ms <= 30000
            or not 120 <= self.hop_budget_ms <= 1000
            or not self.hop_budget_ms * 8 <= self.maximum_revisit_ms <= 30000
            or not 1 <= self.maximum_result_age_ms <= 10000
            or not 1 <= self.unhealthy_limit <= 32
        ):
            raise PersistentHopProtocolError("unsupported adaptive policy bounds")

    def pack(self) -> bytes:
        self._validate()
        return _POLICY.pack(*dataclasses.astuple(self), bytes(16))

    @classmethod
    def unpack(cls, payload: bytes) -> AdaptiveHopPolicyV2:
        if len(payload) != 64:
            raise PersistentHopProtocolError("adaptive policy size mismatch")
        values = _POLICY.unpack(payload)
        if values[-1] != bytes(16):
            raise PersistentHopProtocolError("adaptive policy reserved bytes are nonzero")
        try:
            result = cls(values[0], AdaptiveHopMode(values[1]), *values[2:-1])
        except ValueError as error:
            raise PersistentHopProtocolError("unknown adaptive policy mode") from error
        result._validate()
        return result

    def require_pinned_policy(self) -> None:
        """Provider currently advertises only this exact, versioned policy."""
        self._validate()
        if self != AdaptiveHopPolicyV2(self.generation, self.mode):
            raise PersistentHopProtocolError("policy differs from three-miss-two-second-v1")


@dataclasses.dataclass(frozen=True, slots=True)
class AdaptiveHopRequestV2:
    geometry: PersistentHopRequestV1
    policy: AdaptiveHopPolicyV2

    def pack(self) -> bytes:
        geometry = bytearray(self.geometry.pack())
        policy = self.policy.pack()
        if (
            self.geometry.sample_rate_hz not in (2500000, 5000000)
            or self.geometry.dwell_samples != self.geometry.sample_rate_hz * 120 // 1000
            or not self.policy.warmup_visits * 8 <= self.geometry.dwell_count <= 2500
        ):
            raise PersistentHopProtocolError("unsupported adaptive capture geometry")
        struct.pack_into("<HHI", geometry, 4, 2, ADAPTIVE_HOP_REQUEST_BYTES, 0x3F)
        struct.pack_into("<H", geometry, 76, ADAPTIVE_HOP_EVENT_BYTES)
        return bytes(geometry) + policy

    @classmethod
    def unpack(cls, payload: bytes | bytearray | memoryview) -> AdaptiveHopRequestV2:
        raw = bytes(payload)
        geometry = _header(raw, b"HOPR", ADAPTIVE_HOP_REQUEST_BYTES)[:288]
        if (
            struct.unpack_from("<I", raw, 8)[0] != 0x3F
            or struct.unpack_from("<H", raw, 76)[0] != 144
        ):
            raise PersistentHopProtocolError("adaptive request features/event size mismatch")
        # Private numeric-geometry validation, never a persisted V1 capture.
        struct.pack_into("<HHI", geometry, 4, 1, 288, 0x1F)
        struct.pack_into("<H", geometry, 76, 80)
        result = cls(PersistentHopRequestV1.unpack(geometry), AdaptiveHopPolicyV2.unpack(raw[288:]))
        result.pack()
        return result

    def append_to_tandem_request(
        self,
        tandem_request: TandemSessionRequestV1,
        samples_per_block: int,
        *,
        retention_frames: int = 3,
    ) -> bytes:
        packet = self.geometry.append_to_tandem_request(
            tandem_request, samples_per_block, retention_frames=retention_frames
        )
        return packet[:-288] + self.pack()


@dataclasses.dataclass(frozen=True, slots=True)
class AdaptiveHopChoiceV2:
    decision_counter: int
    basis_visit: int
    cooldown_remaining_samples: int
    generation: int
    proposed_target: int
    reason: int
    active_mask: int
    quiet_mask: int
    consecutive_misses: int
    mode: AdaptiveHopMode

    def _validate(self, event: PersistentHopEventV1) -> None:
        values = dataclasses.astuple(self)
        for value in values[:4]:
            _uint(value, 64)
        for value in values[4:]:
            _uint(value, 32)
        if (
            not self.generation
            or self.proposed_target >= 8
            or self.reason > 4
            or (self.active_mask | self.quiet_mask) > 255
            or self.active_mask & self.quiet_mask
            or self.consecutive_misses > 32
            or self.cooldown_remaining_samples > 150000000
            or (self.basis_visit != _NO_VISIT and self.basis_visit >= event.dwell_index)
            or self.decision_counter > event.transition_before_counter
            or self.mode not in (1, 2)
            or (self.mode == 2 and self.proposed_target != event.to_profile_index)
            or (self.mode == 1 and event.to_profile_index != event.dwell_index % 8)
        ):
            raise PersistentHopProtocolError("adaptive decision/actual-event mismatch")

    def pack(self, event: PersistentHopEventV1) -> bytes:
        self._validate(event)
        return _CHOICE.pack(*dataclasses.astuple(self), bytes(8))

    @classmethod
    def unpack(cls, payload: bytes, event: PersistentHopEventV1) -> AdaptiveHopChoiceV2:
        if len(payload) != 64:
            raise PersistentHopProtocolError("adaptive decision size mismatch")
        values = _CHOICE.unpack(payload)
        if values[-1] != bytes(8):
            raise PersistentHopProtocolError("adaptive decision reserved bytes are nonzero")
        try:
            result = cls(
                values[0],
                values[1],
                values[2],
                values[3],
                values[4],
                values[5],
                values[6],
                values[7],
                values[8],
                AdaptiveHopMode(values[9]),
            )
        except ValueError as error:
            raise PersistentHopProtocolError("unknown adaptive decision mode") from error
        result._validate(event)
        return result


@dataclasses.dataclass(frozen=True, slots=True)
class AdaptiveHopEvidenceV2:
    geometry: PersistentHopEvidenceV1
    choices: tuple[AdaptiveHopChoiceV2, ...]

    def pack(self) -> bytes:
        if len(self.geometry.events) != len(self.choices):
            raise PersistentHopProtocolError("adaptive choices/events cardinality mismatch")
        base = self.geometry.pack()
        header = bytearray(base[:64])
        struct.pack_into("<H", header, 4, 2)
        struct.pack_into("<II", header, 8, 64 + len(self.choices) * 144, 0x3F)
        events = b"".join(
            event.pack() + choice.pack(event)
            for event, choice in zip(self.geometry.events, self.choices, strict=True)
        )
        return bytes(header) + events

    @classmethod
    def unpack(cls, payload: bytes | bytearray | memoryview) -> AdaptiveHopEvidenceV2:
        raw = bytes(payload)
        header = _header(raw, b"HOPS", 64, exact=False)[:64]
        size, features = struct.unpack_from("<II", raw, 8)
        count, capacity = struct.unpack_from("<HH", raw, 20)
        if (
            count > 8
            or capacity != 8
            or features != 0x3F
            or size != len(raw)
            or size != 64 + count * 144
        ):
            raise PersistentHopProtocolError("adaptive evidence size/features mismatch")
        struct.pack_into("<H", header, 4, 1)
        struct.pack_into("<II", header, 8, 64 + count * 80, 0x1F)
        event_bytes = b"".join(raw[64 + i * 144 : 144 + i * 144] for i in range(count))
        geometry = PersistentHopEvidenceV1.unpack(bytes(header) + event_bytes)
        choices = tuple(
            AdaptiveHopChoiceV2.unpack(raw[144 + i * 144 : 208 + i * 144], event)
            for i, event in enumerate(geometry.events)
        )
        return cls(geometry, choices)

    def validate_binding(self, request: AdaptiveHopRequestV2) -> None:
        """Per-record binding only; does not assert cross-frame continuity."""
        request.pack()
        self.pack()
        if self.geometry.session_id != request.geometry.session_id:
            raise PersistentHopProtocolError("adaptive session identity mismatch")
        previous = None
        for event, choice in zip(self.geometry.events, self.choices, strict=True):
            profile = request.geometry.profiles[event.to_profile_index]
            if (
                choice.generation != request.policy.generation
                or choice.mode != request.policy.mode
                or choice.consecutive_misses > request.policy.missed_dwells
                or choice.cooldown_remaining_samples
                > request.geometry.sample_rate_hz * request.policy.cooldown_ms // 1000
                or event.actual_lo_frequency_hz != profile.lo_hz
                or event.actual_if_offset_hz != request.geometry.if_offset_hz
                or event.fastlock_slot != profile.fastlock_profile_index
                or event.invalid_end_counter_exclusive
                != event.transition_after_counter + request.geometry.transition_guard_samples
                or (
                    previous is not None
                    and (
                        event.from_profile_index != previous.to_profile_index
                        or event.invalid_start_counter
                        != previous.invalid_end_counter_exclusive + request.geometry.dwell_samples
                        or choice.decision_counter < event.invalid_start_counter
                    )
                )
            ):
                raise PersistentHopProtocolError("adaptive event/request binding mismatch")
            previous = event


@dataclasses.dataclass(frozen=True, slots=True)
class AdaptiveHopStatusV2:
    geometry: PersistentHopStatusV1

    def pack(self) -> bytes:
        packet = bytearray(self.geometry.pack())
        struct.pack_into("<H", packet, 4, 2)
        struct.pack_into("<I", packet, 8, 0x3F)
        return bytes(packet)

    @classmethod
    def unpack(cls, payload: bytes | bytearray | memoryview) -> AdaptiveHopStatusV2:
        packet = _header(bytes(payload), b"HOPT", 160)
        if struct.unpack_from("<I", packet, 8)[0] != 0x3F:
            raise PersistentHopProtocolError("adaptive status features mismatch")
        struct.pack_into("<H", packet, 4, 1)
        struct.pack_into("<I", packet, 8, 0x1F)
        return cls(PersistentHopStatusV1.unpack(packet))
