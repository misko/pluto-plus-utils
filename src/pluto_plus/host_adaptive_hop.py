"""Major-3 single-RX adaptive wire contracts and source-bound host feedback.

Only the decision copy is decimated. Capture geometry remains native 10 MS/s.
No radio, socket, storage, or detector implementation belongs in this codec.
"""

from __future__ import annotations

import dataclasses
import enum
import struct
from collections.abc import Mapping

from .adaptive_hop import (
    ADAPTIVE_HOP_POLICY_ID,
    AdaptiveHopChoiceV2,
    AdaptiveHopEvidenceV2,
    AdaptiveHopPolicyV2,
    AdaptiveHopStatusV2,
    _validate_event_binding,
)
from .persistent_hop import (
    PersistentHopClientError,
    PersistentHopEvidenceV1,
    PersistentHopProtocolError,
    PersistentHopRequestV1,
)
from .tandem import TandemSessionRequestV1

HOST_ADAPTIVE_REQUEST_BYTES = 416
HOST_FEEDBACK_BYTES = 160
_CONFIGURATION = struct.Struct("<8I32s")
_FEEDBACK = struct.Struct("<4sHH7Q14I32sQ")


def _uint(value: int, bits: int) -> None:
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value < 1 << bits:
        raise PersistentHopProtocolError(f"host-adaptive value outside uint{bits}")


def _digest(value: bytes) -> None:
    if not isinstance(value, bytes) or len(value) != 32 or not any(value):
        raise PersistentHopProtocolError("host decision identity requires a nonzero SHA-256")


@dataclasses.dataclass(frozen=True, slots=True)
class HostDecisionConfigurationV1:
    receiver_id: int
    configuration_sha256: bytes

    def pack(self) -> bytes:
        _uint(self.receiver_id, 32)
        _digest(self.configuration_sha256)
        if self.receiver_id not in (0, 1):
            raise PersistentHopProtocolError("host decision requires physical RX0 or RX1")
        return _CONFIGURATION.pack(
            1,
            self.receiver_id,
            2_500_000,
            4,
            0,
            80,
            40,
            300_000,
            self.configuration_sha256,
        )

    @classmethod
    def unpack(cls, payload: bytes) -> HostDecisionConfigurationV1:
        if len(payload) != _CONFIGURATION.size:
            raise PersistentHopProtocolError("host decision configuration size mismatch")
        values = _CONFIGURATION.unpack(payload)
        result = cls(values[1], values[8])
        if result.pack() != payload:
            raise PersistentHopProtocolError("unqualified host decimation geometry")
        return result


def require_host_adaptive_capabilities(
    attributes: Mapping[str, str],
    policy: AdaptiveHopPolicyV2,
    decision: HostDecisionConfigurationV1 | None = None,
) -> None:
    policy.require_pinned_policy()
    required = {
        "iio,buffer-host-adaptive-hop-event": "3",
        "iio,buffer-host-adaptive-hop-status": "3",
        "iio,buffer-metadata-feedback": "1",
        "iio,buffer-adaptive-hop-modes": "shadow,adaptive",
        "iio,buffer-adaptive-hop-policy": ADAPTIVE_HOP_POLICY_ID,
    }
    multirate = isinstance(decision, HostDecisionConfigurationV2)
    request_versions = attributes.get("iio,buffer-host-adaptive-hop-request")
    feedback_versions = attributes.get("iio,buffer-host-adaptive-hop-feedback")
    if (
        any(attributes.get(key) != value for key, value in required.items())
        or request_versions not in (("3,4",) if multirate else ("3", "3,4"))
        or feedback_versions not in (("1,2",) if multirate else ("1", "1,2"))
    ):
        raise PersistentHopClientError("host-adaptive peer capabilities/policy are incompatible")


@dataclasses.dataclass(frozen=True, slots=True)
class HostAdaptiveHopRequestV3:
    geometry: PersistentHopRequestV1
    policy: AdaptiveHopPolicyV2
    decision: HostDecisionConfigurationV1

    def pack(self) -> bytes:
        packet = bytearray(self.geometry.pack())
        self.policy.require_pinned_policy()
        if (
            self.geometry.sample_rate_hz != 10_000_000
            or self.geometry.rf_bandwidth_hz != 10_000_000
            or self.geometry.dwell_samples != 1_200_000
            or not self.policy.warmup_visits * 8 <= self.geometry.dwell_count <= 2500
        ):
            raise PersistentHopProtocolError("host adaptive capture requires native 10 MS/s")
        struct.pack_into("<HHI", packet, 4, 3, HOST_ADAPTIVE_REQUEST_BYTES, 0x7F)
        struct.pack_into("<H", packet, 76, 144)
        return bytes(packet) + self.policy.pack() + self.decision.pack()

    @classmethod
    def unpack(cls, payload: bytes | bytearray | memoryview) -> HostAdaptiveHopRequestV3:
        raw = bytes(payload)
        if (
            len(raw) != HOST_ADAPTIVE_REQUEST_BYTES
            or raw[:4] != b"HOPR"
            or struct.unpack_from("<HHI", raw, 4) != (3, HOST_ADAPTIVE_REQUEST_BYTES, 0x7F)
            or struct.unpack_from("<H", raw, 76)[0] != 144
        ):
            raise PersistentHopProtocolError("host adaptive request header mismatch")
        geometry = bytearray(raw[:288])
        struct.pack_into("<HHI", geometry, 4, 1, 288, 0x1F)
        struct.pack_into("<H", geometry, 76, 80)
        result = cls(
            PersistentHopRequestV1.unpack(geometry),
            AdaptiveHopPolicyV2.unpack(raw[288:352]),
            HostDecisionConfigurationV1.unpack(raw[352:]),
        )
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
class HostDecisionConfigurationV2(HostDecisionConfigurationV1):
    source_rate_hz: int

    def pack(self) -> bytes:
        _uint(self.receiver_id, 32)
        _digest(self.configuration_sha256)
        geometry = {
            15_000_000: (6, 100, 34),
            20_000_000: (8, 128, 32),
        }
        if self.receiver_id != 0 or self.source_rate_hz not in geometry:
            raise PersistentHopProtocolError("multirate host decision requires RX0 at 15/20 MS/s")
        factor, delay, supported_start = geometry[self.source_rate_hz]
        return _CONFIGURATION.pack(
            2,
            0,
            2_500_000,
            factor,
            0,
            delay,
            supported_start,
            300_000,
            self.configuration_sha256,
        )

    @classmethod
    def unpack(cls, payload: bytes) -> HostDecisionConfigurationV2:
        if len(payload) != _CONFIGURATION.size:
            raise PersistentHopProtocolError("host decision configuration size mismatch")
        values = _CONFIGURATION.unpack(payload)
        source_rate = {6: 15_000_000, 8: 20_000_000}.get(values[3], 0)
        result = cls(values[1], values[8], source_rate)
        if result.pack() != payload:
            raise PersistentHopProtocolError("unqualified multirate host decimation geometry")
        return result


@dataclasses.dataclass(frozen=True, slots=True)
class HostAdaptiveHopRequestV4(HostAdaptiveHopRequestV3):
    decision: HostDecisionConfigurationV2

    def pack(self) -> bytes:
        packet = bytearray(self.geometry.pack())
        self.policy.require_pinned_policy()
        if (
            self.geometry.sample_rate_hz != self.decision.source_rate_hz
            or self.geometry.rf_bandwidth_hz != self.decision.source_rate_hz
            or self.geometry.dwell_samples != self.decision.source_rate_hz * 120 // 1000
            or not self.policy.warmup_visits * 8 <= self.geometry.dwell_count <= 2500
        ):
            raise PersistentHopProtocolError("host adaptive capture changed multirate geometry")
        struct.pack_into("<HHI", packet, 4, 4, HOST_ADAPTIVE_REQUEST_BYTES, 0xFF)
        struct.pack_into("<H", packet, 76, 144)
        return bytes(packet) + self.policy.pack() + self.decision.pack()

    @classmethod
    def unpack(cls, payload: bytes | bytearray | memoryview) -> HostAdaptiveHopRequestV4:
        raw = bytes(payload)
        if (
            len(raw) != HOST_ADAPTIVE_REQUEST_BYTES
            or raw[:4] != b"HOPR"
            or struct.unpack_from("<HHI", raw, 4) != (4, HOST_ADAPTIVE_REQUEST_BYTES, 0xFF)
            or struct.unpack_from("<H", raw, 76)[0] != 144
        ):
            raise PersistentHopProtocolError("multirate host adaptive request header mismatch")
        geometry = bytearray(raw[:288])
        struct.pack_into("<HHI", geometry, 4, 1, 288, 0x1F)
        struct.pack_into("<H", geometry, 76, 80)
        result = cls(
            PersistentHopRequestV1.unpack(geometry),
            AdaptiveHopPolicyV2.unpack(raw[288:352]),
            HostDecisionConfigurationV2.unpack(raw[352:]),
        )
        result.pack()
        return result


def _major3_numeric_packet(payload: bytes, magic: bytes, feature_offset: int) -> bytes:
    """Validate the new discriminator before reusing the shared numeric codec."""
    raw = bytearray(payload)
    if (
        len(raw) < feature_offset + 4
        or raw[:4] != magic
        or struct.unpack_from("<H", raw, 4)[0] != 3
        or struct.unpack_from("<I", raw, feature_offset)[0] != 0x7F
    ):
        raise PersistentHopProtocolError("host adaptive evidence/status version mismatch")
    struct.pack_into("<H", raw, 4, 2)
    struct.pack_into("<I", raw, feature_offset, 0x3F)
    return bytes(raw)


@dataclasses.dataclass(frozen=True, slots=True)
class HostAdaptiveHopEvidenceV3:
    geometry: PersistentHopEvidenceV1
    choices: tuple[AdaptiveHopChoiceV2, ...]

    def pack(self) -> bytes:
        packet = bytearray(AdaptiveHopEvidenceV2(self.geometry, self.choices).pack())
        struct.pack_into("<H", packet, 4, 3)
        struct.pack_into("<I", packet, 12, 0x7F)
        return bytes(packet)

    @classmethod
    def unpack(cls, payload: bytes | bytearray | memoryview) -> HostAdaptiveHopEvidenceV3:
        value = AdaptiveHopEvidenceV2.unpack(_major3_numeric_packet(bytes(payload), b"HOPS", 12))
        return cls(value.geometry, value.choices)

    def validate_binding(self, request: HostAdaptiveHopRequestV3) -> None:
        if not isinstance(request, HostAdaptiveHopRequestV3):
            raise PersistentHopProtocolError("host evidence requires a major-3 request")
        request.pack()
        self.pack()
        _validate_event_binding(self.geometry, self.choices, request.geometry, request.policy)


@dataclasses.dataclass(frozen=True, slots=True)
class HostAdaptiveHopStatusV3(AdaptiveHopStatusV2):
    def pack(self) -> bytes:
        packet = bytearray(AdaptiveHopStatusV2.pack(self))
        struct.pack_into("<H", packet, 4, 3)
        struct.pack_into("<I", packet, 8, 0x7F)
        return bytes(packet)

    @classmethod
    def unpack(cls, payload: bytes | bytearray | memoryview) -> HostAdaptiveHopStatusV3:
        value = AdaptiveHopStatusV2.unpack(_major3_numeric_packet(bytes(payload), b"HOPT", 8))
        return cls(value.geometry)


class HostDecisionOutcome(enum.IntEnum):
    UNKNOWN = 0
    DETECTED = 1
    NOT_DETECTED = 2


@dataclasses.dataclass(frozen=True, slots=True)
class HostFeedbackV1:
    session_id: int
    generation: int
    stream_id: int
    visit: int
    event_sequence: int
    valid_start: int
    valid_end: int
    receiver_id: int
    target_index: int
    outcome: HostDecisionOutcome
    healthy: int
    screen_mask: int
    confirmation_mask: int
    configuration_sha256: bytes

    def pack(self) -> bytes:
        counters = (
            self.session_id,
            self.generation,
            self.stream_id,
            self.visit,
            self.event_sequence,
            self.valid_start,
            self.valid_end,
        )
        values = (
            self.receiver_id,
            self.target_index,
            self.outcome,
            self.healthy,
            self.screen_mask,
            self.confirmation_mask,
        )
        for value in counters:
            _uint(value, 64)
        for value in values:
            _uint(value, 32)
        _digest(self.configuration_sha256)
        if (
            not all(counters[:3])
            or self.visit >= 2500
            or self.event_sequence != self.visit
            or self.valid_end - self.valid_start != 1_200_000
            or self.receiver_id > 1
            or self.target_index >= 8
            or self.outcome not in (0, 1, 2)
            or self.healthy not in (0, 1)
            or self.screen_mask > 63
            or self.confirmation_mask > 63
            or self.confirmation_mask & (self.confirmation_mask - 1)
            or (self.healthy and self.screen_mask != 63)
            or (not self.healthy and self.outcome != HostDecisionOutcome.UNKNOWN)
            or (self.outcome == HostDecisionOutcome.DETECTED and not self.confirmation_mask)
        ):
            raise PersistentHopProtocolError("host feedback lacks complete bound decision evidence")
        return _FEEDBACK.pack(
            b"HFB1",
            1,
            HOST_FEEDBACK_BYTES,
            *counters,
            10_000_000,
            2_500_000,
            *values,
            40,
            300_000,
            4,
            0,
            80,
            0,
            self.configuration_sha256,
            0,
        )

    @classmethod
    def unpack(cls, payload: bytes | bytearray | memoryview) -> HostFeedbackV1:
        raw = bytes(payload)
        if len(raw) != HOST_FEEDBACK_BYTES:
            raise PersistentHopProtocolError("host feedback size mismatch")
        values = _FEEDBACK.unpack(raw)
        if values[:3] != (b"HFB1", 1, HOST_FEEDBACK_BYTES):
            raise PersistentHopProtocolError("host feedback version mismatch")
        try:
            result = cls(
                values[3],
                values[4],
                values[5],
                values[6],
                values[7],
                values[8],
                values[9],
                values[12],
                values[13],
                HostDecisionOutcome(values[14]),
                values[15],
                values[16],
                values[17],
                values[24],
            )
        except ValueError as error:
            raise PersistentHopProtocolError("unknown host feedback outcome") from error
        if result.pack() != raw:
            raise PersistentHopProtocolError("host feedback geometry/reserved bytes mismatch")
        return result


@dataclasses.dataclass(frozen=True, slots=True)
class HostFeedbackV2(HostFeedbackV1):
    source_rate_hz: int

    def pack(self) -> bytes:
        geometry = {
            15_000_000: (6, 100, 34),
            20_000_000: (8, 128, 32),
        }
        factor, delay, supported_start = geometry.get(self.source_rate_hz, (0, 0, 0))
        counters = (
            self.session_id,
            self.generation,
            self.stream_id,
            self.visit,
            self.event_sequence,
            self.valid_start,
            self.valid_end,
        )
        values = (
            self.receiver_id,
            self.target_index,
            self.outcome,
            self.healthy,
            self.screen_mask,
            self.confirmation_mask,
        )
        for value in counters:
            _uint(value, 64)
        for value in values:
            _uint(value, 32)
        _digest(self.configuration_sha256)
        if (
            not factor
            or not all(counters[:3])
            or self.visit >= 2500
            or self.event_sequence != self.visit
            or self.valid_end - self.valid_start != self.source_rate_hz * 120 // 1000
            or self.receiver_id != 0
            or self.target_index >= 8
            or self.outcome not in (0, 1, 2)
            or self.healthy not in (0, 1)
            or self.screen_mask > 63
            or self.confirmation_mask > 63
            or self.confirmation_mask & (self.confirmation_mask - 1)
            or (self.healthy and self.screen_mask != 63)
            or (not self.healthy and self.outcome != HostDecisionOutcome.UNKNOWN)
            or (self.outcome == HostDecisionOutcome.DETECTED and not self.confirmation_mask)
        ):
            raise PersistentHopProtocolError("multirate feedback lacks complete bound evidence")
        return _FEEDBACK.pack(
            b"HFB2",
            2,
            HOST_FEEDBACK_BYTES,
            *counters,
            self.source_rate_hz,
            2_500_000,
            *values,
            supported_start,
            300_000,
            factor,
            0,
            delay,
            0,
            self.configuration_sha256,
            0,
        )

    @classmethod
    def unpack(cls, payload: bytes | bytearray | memoryview) -> HostFeedbackV2:
        raw = bytes(payload)
        if len(raw) != HOST_FEEDBACK_BYTES:
            raise PersistentHopProtocolError("host feedback size mismatch")
        values = _FEEDBACK.unpack(raw)
        if values[:3] != (b"HFB2", 2, HOST_FEEDBACK_BYTES):
            raise PersistentHopProtocolError("host feedback version mismatch")
        try:
            result = cls(
                values[3], values[4], values[5], values[6], values[7], values[8], values[9],
                values[12], values[13], HostDecisionOutcome(values[14]), values[15], values[16],
                values[17], values[24], values[10],
            )
        except ValueError as error:
            raise PersistentHopProtocolError("unknown host feedback outcome") from error
        if result.pack() != raw:
            raise PersistentHopProtocolError("host feedback geometry/reserved bytes mismatch")
        return result
