"""Reliable direct-IP v1 control and UDP frame reassembly.

The wire layout is compatible with ``spf.direct_radio.ip_protocol`` (reviewed
2026-08-15), but this implementation has no SPF or socket dependency.
"""

from __future__ import annotations

import dataclasses
import enum
import math
import struct
import time
import zlib
from collections.abc import Hashable, Iterable
from typing import Final

from .usb import (
    KNOWN_FEATURES,
    MAX_FINITE_FRAMES,
    MAX_GAIN_EVENTS,
    MAX_GAIN_OBSERVATIONS,
    MAX_SAMPLES_PER_CHANNEL,
    MetadataFeatures,
    ProtocolError,
)

IP_CONTROL_MAGIC: Final = 0x31434953  # b"SIC1"
IP_CONTROL_VERSION: Final = 1
IP_FRAGMENT_MAGIC: Final = 0x31504953  # b"SIP1"
IP_FRAGMENT_VERSION: Final = 1
MAX_UDP_DATAGRAM_BYTES: Final = 65_507
DEFAULT_UDP_DATAGRAM_BYTES: Final = 1_472
MAX_IP_FRAME_BYTES: Final = 16 * 1024 * 1024
MAX_IP_FRAGMENT_COUNT: Final = 65_536


class IpControlType(enum.IntEnum):
    QUERY_CAPABILITIES = 1
    CAPABILITIES = 2
    START_RX = 3
    STARTED = 4
    STOP_RX = 5
    STOPPED = 6
    ERROR = 7


class IpControlFlags(enum.IntFlag):
    FINITE_RX = 1 << 0
    IDEMPOTENT_REQUESTS = 1 << 1
    TIME_ANCHOR = 1 << 2
    QUERY_TRANSPORT_CAPABILITIES = 1 << 3
    BUFFERED_FINITE_RX = 1 << 4
    USB_CLASS_PACING = 1 << 5
    TCP_DATA_TRANSPORT = 1 << 6
    DROP_STALE_FRAMES = 1 << 7


KNOWN_IP_CONTROL_FLAGS = IpControlFlags(0xFF)
QUERY_PROBE_FLAGS = IpControlFlags.QUERY_TRANSPORT_CAPABILITIES | IpControlFlags.TCP_DATA_TRANSPORT
START_TRANSPORT_FLAGS = (
    IpControlFlags.BUFFERED_FINITE_RX
    | IpControlFlags.USB_CLASS_PACING
    | IpControlFlags.TCP_DATA_TRANSPORT
    | IpControlFlags.DROP_STALE_FRAMES
)
NO_IP_CONTROL_FLAGS = IpControlFlags(0)
_CONTROL = struct.Struct("<IHHIQiIHHQIIIIIIHHHHQ")
IP_CONTROL_BYTES: Final = _CONTROL.size


def _uint(name: str, value: int, bits: int) -> None:
    if not isinstance(value, int) or isinstance(value, bool) or not 0 <= value < 1 << bits:
        raise ProtocolError(f"{name} is outside uint{bits}: {value!r}")


@dataclasses.dataclass(frozen=True, slots=True)
class IpControlMessageV1:
    message_type: IpControlType
    request_id: int
    status: int = 0
    flags: IpControlFlags = IpControlFlags(0)
    protocol_min: int = 0
    protocol_max: int = 0
    features: MetadataFeatures = MetadataFeatures(0)
    max_samples_per_channel: int = 0
    max_finite_frames: int = 0
    enabled_scan_mask: int = 0
    samples_per_channel: int = 0
    frame_count: int = 0
    gain_observation_interval_samples: int = 0
    gain_observation_capacity: int = 0
    gain_event_capacity: int = 0
    data_port: int = 0
    max_datagram_bytes: int = 0
    stream_id: int = 0

    def pack(self) -> bytes:
        _validate_control(self)
        return _CONTROL.pack(
            IP_CONTROL_MAGIC,
            1,
            int(self.message_type),
            IP_CONTROL_BYTES,
            self.request_id,
            self.status,
            int(self.flags),
            self.protocol_min,
            self.protocol_max,
            int(self.features),
            self.max_samples_per_channel,
            self.max_finite_frames,
            self.enabled_scan_mask,
            self.samples_per_channel,
            self.frame_count,
            self.gain_observation_interval_samples,
            self.gain_observation_capacity,
            self.gain_event_capacity,
            self.data_port,
            self.max_datagram_bytes,
            self.stream_id,
        )

    @classmethod
    def unpack(cls, payload: bytes | bytearray | memoryview) -> IpControlMessageV1:
        if len(payload) != IP_CONTROL_BYTES:
            raise ProtocolError("direct-IP control size mismatch")
        values = _CONTROL.unpack(payload)
        if values[0] != IP_CONTROL_MAGIC or values[1] != 1 or values[3] != IP_CONTROL_BYTES:
            raise ProtocolError("bad direct-IP control magic, version, or size")
        try:
            message_type = IpControlType(values[2])
        except ValueError as exc:
            raise ProtocolError("unknown direct-IP control message type") from exc
        result = cls(
            message_type,
            values[4],
            values[5],
            IpControlFlags(values[6]),
            values[7],
            values[8],
            MetadataFeatures(values[9]),
            *values[10:],
        )
        _validate_control(result, strict_flags=False)
        return result


def make_ip_capability_query(
    *, request_id: int, transport_capabilities: bool = False, tcp_transport: bool = False
) -> IpControlMessageV1:
    flags = IpControlFlags(0)
    if transport_capabilities:
        flags |= IpControlFlags.QUERY_TRANSPORT_CAPABILITIES
    if tcp_transport:
        flags |= IpControlFlags.TCP_DATA_TRANSPORT
    return IpControlMessageV1(IpControlType.QUERY_CAPABILITIES, request_id, flags=flags)


def make_ip_start_request(
    *,
    request_id: int,
    protocol_version: int,
    features: MetadataFeatures,
    enabled_scan_mask: int,
    samples_per_channel: int,
    frame_count: int,
    data_port: int,
    max_datagram_bytes: int = DEFAULT_UDP_DATAGRAM_BYTES,
    gain_observation_interval_samples: int = 0,
    gain_observation_capacity: int = 0,
    gain_event_capacity: int = 0,
    transport_flags: IpControlFlags = NO_IP_CONTROL_FLAGS,
) -> IpControlMessageV1:
    return IpControlMessageV1(
        IpControlType.START_RX,
        request_id,
        flags=transport_flags,
        protocol_min=protocol_version,
        protocol_max=protocol_version,
        features=features,
        enabled_scan_mask=enabled_scan_mask,
        samples_per_channel=samples_per_channel,
        frame_count=frame_count,
        gain_observation_interval_samples=gain_observation_interval_samples,
        gain_observation_capacity=gain_observation_capacity,
        gain_event_capacity=gain_event_capacity,
        data_port=data_port,
        max_datagram_bytes=max_datagram_bytes,
    )


def make_ip_stop_request(*, request_id: int, stream_id: int) -> IpControlMessageV1:
    return IpControlMessageV1(IpControlType.STOP_RX, request_id, stream_id=stream_id)


def _validate_control(message: IpControlMessageV1, *, strict_flags: bool = True) -> None:
    _uint("request_id", message.request_id, 64)
    if not -(1 << 31) <= message.status < 1 << 31:
        raise ProtocolError("direct-IP control status is outside int32")
    unknown_flags = int(message.flags) & ~int(KNOWN_IP_CONTROL_FLAGS)
    if unknown_flags and (strict_flags or message.message_type != IpControlType.CAPABILITIES):
        raise ProtocolError("unknown direct-IP control flags")
    if int(message.features) & ~int(KNOWN_FEATURES):
        raise ProtocolError("unknown direct-IP metadata features")
    numeric = (
        ("protocol_min", message.protocol_min, 16),
        ("protocol_max", message.protocol_max, 16),
        ("features", int(message.features), 64),
        ("max_samples_per_channel", message.max_samples_per_channel, 32),
        ("max_finite_frames", message.max_finite_frames, 32),
        ("enabled_scan_mask", message.enabled_scan_mask, 32),
        ("samples_per_channel", message.samples_per_channel, 32),
        ("frame_count", message.frame_count, 32),
        ("gain_observation_interval_samples", message.gain_observation_interval_samples, 32),
        ("gain_observation_capacity", message.gain_observation_capacity, 16),
        ("gain_event_capacity", message.gain_event_capacity, 16),
        ("data_port", message.data_port, 16),
        ("max_datagram_bytes", message.max_datagram_bytes, 16),
        ("stream_id", message.stream_id, 64),
    )
    for entry in numeric:
        _uint(*entry)
    kind = message.message_type
    if kind != IpControlType.ERROR and message.status:
        raise ProtocolError("successful direct-IP control message has non-zero status")
    if kind == IpControlType.ERROR:
        if not message.status:
            raise ProtocolError("direct-IP ERROR message requires non-zero status")
        return
    remaining = tuple(entry[1] for entry in numeric[2:])
    if kind == IpControlType.QUERY_CAPABILITIES:
        if int(message.flags) & ~int(QUERY_PROBE_FLAGS) or any(
            numeric_value
            for numeric_value in (message.protocol_min, message.protocol_max, *remaining)
        ):
            raise ProtocolError("direct-IP capability query has non-zero fields")
        return
    if kind == IpControlType.CAPABILITIES:
        if not message.flags & IpControlFlags.FINITE_RX:
            raise ProtocolError("direct-IP gadget does not advertise finite RX")
        if message.flags & IpControlFlags.QUERY_TRANSPORT_CAPABILITIES:
            raise ProtocolError("capability response retained query flags")
        if not 1 <= message.protocol_min <= message.protocol_max <= 3:
            raise ProtocolError("direct-IP capability protocol range is invalid")
        if (
            not 1 <= message.max_samples_per_channel <= MAX_SAMPLES_PER_CHANNEL
            or not 1 <= message.max_finite_frames <= MAX_FINITE_FRAMES
        ):
            raise ProtocolError("direct-IP capability limits are invalid")
        irrelevant = (
            message.enabled_scan_mask,
            message.samples_per_channel,
            message.frame_count,
            message.gain_observation_interval_samples,
            message.gain_observation_capacity,
            message.gain_event_capacity,
            message.data_port,
            message.max_datagram_bytes,
            message.stream_id,
        )
        if any(irrelevant):
            raise ProtocolError("direct-IP capability response has request fields")
        return
    if kind in (IpControlType.START_RX, IpControlType.STARTED):
        if int(message.flags) & ~int(START_TRANSPORT_FLAGS):
            raise ProtocolError("direct-IP START has capability-only flags")
        if (
            message.flags & IpControlFlags.USB_CLASS_PACING
            and not message.flags & IpControlFlags.BUFFERED_FINITE_RX
        ):
            raise ProtocolError("direct-IP pacing requires buffered finite RX")
        if (
            message.flags & IpControlFlags.DROP_STALE_FRAMES
            and not message.flags & IpControlFlags.TCP_DATA_TRANSPORT
        ):
            raise ProtocolError("direct-IP frame drop requires TCP transport")
        if message.protocol_min != message.protocol_max or message.protocol_min not in (1, 2, 3):
            raise ProtocolError("direct-IP START protocol selection is invalid")
        if message.max_samples_per_channel or message.max_finite_frames:
            raise ProtocolError("direct-IP START has capability-only limits")
        if (
            message.enabled_scan_mask != 0x0F
            or not 1 <= message.samples_per_channel <= MAX_SAMPLES_PER_CHANNEL
            or not 1 <= message.frame_count <= MAX_FINITE_FRAMES
        ):
            raise ProtocolError("direct-IP START scan/sample/frame fields are invalid")
        if (
            not message.data_port
            or not IP_FRAGMENT_HEADER_BYTES < message.max_datagram_bytes <= MAX_UDP_DATAGRAM_BYTES
        ):
            raise ProtocolError("direct-IP START data port or datagram size is invalid")
        if message.protocol_min == 3:
            required = (
                MetadataFeatures.GAIN_OBSERVATION_SERIES | MetadataFeatures.HARDWARE_SAMPLE_COUNTER
            )
            if message.features & required != required:
                raise ProtocolError("direct-IP v3 START lacks gain-series features")
            if (
                not 1 <= message.gain_observation_interval_samples <= message.samples_per_channel
                or not 1 <= message.gain_observation_capacity <= MAX_GAIN_OBSERVATIONS
                or not 0 <= message.gain_event_capacity <= MAX_GAIN_EVENTS
            ):
                raise ProtocolError("direct-IP v3 observation/event fields are invalid")
        elif any(
            (
                message.gain_observation_interval_samples,
                message.gain_observation_capacity,
                message.gain_event_capacity,
            )
        ):
            raise ProtocolError("direct-IP v1/v2 START has v3-only fields")
        if (
            kind == IpControlType.START_RX
            and message.stream_id
            or kind == IpControlType.STARTED
            and not message.stream_id
        ):
            raise ProtocolError("direct-IP START stream ID is invalid")
        return
    if kind in (IpControlType.STOP_RX, IpControlType.STOPPED):
        if not message.stream_id or message.flags or any(entry[1] for entry in numeric[:-1]):
            raise ProtocolError("direct-IP STOP has missing stream ID or unrelated fields")
        return
    raise ProtocolError("unsupported direct-IP control message")


class IpFragmentFlags(enum.IntFlag):
    FIRST = 1 << 0
    LAST = 1 << 1


_FRAGMENT = struct.Struct("<IHHIQQIIIIII")
IP_FRAGMENT_HEADER_BYTES: Final = _FRAGMENT.size


@dataclasses.dataclass(frozen=True, slots=True)
class IpFragmentV1:
    flags: IpFragmentFlags
    stream_id: int
    frame_sequence: int
    frame_bytes: int
    frame_crc32: int
    fragment_index: int
    fragment_count: int
    fragment_offset: int
    payload: bytes

    def pack(self) -> bytes:
        _validate_fragment(self)
        return (
            _FRAGMENT.pack(
                IP_FRAGMENT_MAGIC,
                1,
                IP_FRAGMENT_HEADER_BYTES,
                int(self.flags),
                self.stream_id,
                self.frame_sequence,
                self.frame_bytes,
                self.frame_crc32,
                self.fragment_index,
                self.fragment_count,
                self.fragment_offset,
                len(self.payload),
            )
            + self.payload
        )

    @classmethod
    def unpack(cls, datagram: bytes | bytearray | memoryview) -> IpFragmentV1:
        values, payload = _unpack_fragment(datagram)
        return cls(
            flags=IpFragmentFlags(values[0]),
            stream_id=values[1],
            frame_sequence=values[2],
            frame_bytes=values[3],
            frame_crc32=values[4],
            fragment_index=values[5],
            fragment_count=values[6],
            fragment_offset=values[7],
            payload=bytes(payload),
        )


def _validate_fragment(fragment: IpFragmentV1) -> None:
    if int(fragment.flags) & ~3:
        raise ProtocolError("unknown direct-IP fragment flags")
    if (
        not 1 <= fragment.frame_bytes <= MAX_IP_FRAME_BYTES
        or not 1 <= fragment.fragment_count <= MAX_IP_FRAGMENT_COUNT
    ):
        raise ProtocolError("direct-IP frame/fragment count is outside the supported range")
    if (
        fragment.fragment_index >= fragment.fragment_count
        or not fragment.payload
        or fragment.fragment_offset + len(fragment.payload) > fragment.frame_bytes
    ):
        raise ProtocolError("direct-IP fragment range is outside the frame")
    if bool(fragment.flags & IpFragmentFlags.FIRST) != (fragment.fragment_index == 0) or bool(
        fragment.flags & IpFragmentFlags.LAST
    ) != (fragment.fragment_index == fragment.fragment_count - 1):
        raise ProtocolError("direct-IP FIRST/LAST flags disagree with fragment index")


def _unpack_fragment(
    datagram: bytes | bytearray | memoryview,
) -> tuple[tuple[int, ...], memoryview]:
    if not IP_FRAGMENT_HEADER_BYTES < len(datagram) <= MAX_UDP_DATAGRAM_BYTES:
        raise ProtocolError("direct-IP datagram size is outside the supported range")
    raw = _FRAGMENT.unpack_from(datagram)
    if raw[:3] != (IP_FRAGMENT_MAGIC, 1, IP_FRAGMENT_HEADER_BYTES):
        raise ProtocolError("bad direct-IP fragment magic, version, or header size")
    flags, stream_id, sequence, frame_bytes, crc, index, count, offset, payload_bytes = raw[3:]
    if len(datagram) != IP_FRAGMENT_HEADER_BYTES + payload_bytes:
        raise ProtocolError("direct-IP fragment length mismatch")
    result = (flags, stream_id, sequence, frame_bytes, crc, index, count, offset)
    payload = memoryview(datagram)[IP_FRAGMENT_HEADER_BYTES:]
    _validate_fragment(IpFragmentV1(IpFragmentFlags(flags), *result[1:], bytes(payload)))
    return result, payload


def fragment_ip_frame(
    frame: bytes | bytearray | memoryview,
    *,
    stream_id: int,
    frame_sequence: int,
    max_datagram_bytes: int = DEFAULT_UDP_DATAGRAM_BYTES,
) -> tuple[bytes, ...]:
    view = memoryview(frame)
    if not 1 <= len(view) <= MAX_IP_FRAME_BYTES:
        raise ProtocolError("direct-IP frame size is outside the supported range")
    if not IP_FRAGMENT_HEADER_BYTES < max_datagram_bytes <= MAX_UDP_DATAGRAM_BYTES:
        raise ProtocolError("direct-IP datagram limit is outside the UDP range")
    capacity = max_datagram_bytes - IP_FRAGMENT_HEADER_BYTES
    count = math.ceil(len(view) / capacity)
    if count > MAX_IP_FRAGMENT_COUNT:
        raise ProtocolError("direct-IP frame requires too many fragments")
    crc = zlib.crc32(view) & 0xFFFFFFFF
    return tuple(
        IpFragmentV1(
            (IpFragmentFlags.FIRST if index == 0 else IpFragmentFlags(0))
            | (IpFragmentFlags.LAST if index == count - 1 else IpFragmentFlags(0)),
            stream_id,
            frame_sequence,
            len(view),
            crc,
            index,
            count,
            index * capacity,
            bytes(view[index * capacity : (index + 1) * capacity]),
        ).pack()
        for index in range(count)
    )


@dataclasses.dataclass(slots=True)
class _Partial:
    frame_bytes: int
    crc: int
    count: int
    first_seen: float
    pieces: dict[int, tuple[int, bytes]]


@dataclasses.dataclass(frozen=True, slots=True)
class ReassembledIpFrame:
    stream_id: int
    frame_sequence: int
    frame: bytes


class IpFrameReassembler:
    """Bounded, expiring reassembler; partial or corrupt IQ is never returned."""

    def __init__(
        self,
        *,
        frame_timeout_seconds: float = 2.0,
        max_pending_frames: int = 8,
        max_pending_bytes: int = 32 * 1024 * 1024,
    ) -> None:
        if frame_timeout_seconds <= 0 or max_pending_frames <= 0 or max_pending_bytes <= 0:
            raise ValueError("reassembly bounds must be positive")
        self.frame_timeout_seconds = frame_timeout_seconds
        self.max_pending_frames = max_pending_frames
        self.max_pending_bytes = max_pending_bytes
        self._pending: dict[tuple[Hashable | None, int, int], _Partial] = {}
        self._completed: dict[tuple[Hashable | None, int, int], tuple[int, int, float]] = {}
        self.pending_declared_bytes = 0
        self.completed_frame_count = self.expired_frame_count = 0
        self.rejected_frame_count = self.duplicate_fragment_count = 0

    @property
    def pending_frame_count(self) -> int:
        return len(self._pending)

    def reset(self) -> None:
        self._pending.clear()
        self._completed.clear()
        self.pending_declared_bytes = 0

    def expire(self, *, now: float | None = None) -> int:
        current = time.monotonic() if now is None else now
        expired = [
            key
            for key, value in self._pending.items()
            if current - value.first_seen >= self.frame_timeout_seconds
        ]
        for key in expired:
            self._remove(key)
        self._completed = {
            key: value
            for key, value in self._completed.items()
            if current - value[2] < self.frame_timeout_seconds
        }
        self.expired_frame_count += len(expired)
        return len(expired)

    def feed(
        self,
        datagram: bytes | bytearray | memoryview,
        *,
        peer: Hashable | None = None,
        now: float | None = None,
    ) -> list[ReassembledIpFrame]:
        current = time.monotonic() if now is None else now
        self.expire(now=current)
        values, payload_view = _unpack_fragment(datagram)
        _, stream, sequence, frame_bytes, crc, index, count, offset = values
        payload = bytes(payload_view)
        key = (peer, stream, sequence)
        completed = self._completed.get(key)
        if completed:
            if completed[:2] != (crc, count):
                self.rejected_frame_count += 1
                raise ProtocolError("conflicting late direct-IP fragment")
            self.duplicate_fragment_count += 1
            return []
        partial = self._pending.get(key)
        if partial is None:
            if (
                len(self._pending) >= self.max_pending_frames
                or self.pending_declared_bytes + frame_bytes > self.max_pending_bytes
            ):
                self.rejected_frame_count += 1
                raise ProtocolError("direct-IP pending reassembly limit exceeded")
            partial = _Partial(frame_bytes, crc, count, current, {})
            self._pending[key] = partial
            self.pending_declared_bytes += frame_bytes
        elif (partial.frame_bytes, partial.crc, partial.count) != (frame_bytes, crc, count):
            self._remove(key)
            self.rejected_frame_count += 1
            raise ProtocolError("conflicting direct-IP frame description")
        existing = partial.pieces.get(index)
        if existing is not None:
            if existing != (offset, payload):
                self._remove(key)
                self.rejected_frame_count += 1
                raise ProtocolError("conflicting duplicate direct-IP fragment")
            self.duplicate_fragment_count += 1
            return []
        partial.pieces[index] = (offset, payload)
        if len(partial.pieces) != count:
            return []
        expected = 0
        chunks = []
        try:
            for item_index in range(count):
                item_offset, item_payload = partial.pieces[item_index]
                if item_offset != expected:
                    raise ProtocolError("direct-IP frame has a fragment overlap or gap")
                expected += len(item_payload)
                chunks.append(item_payload)
            frame = b"".join(chunks)
            if len(frame) != frame_bytes or zlib.crc32(frame) & 0xFFFFFFFF != crc:
                raise ProtocolError("direct-IP frame length or CRC mismatch")
        except ProtocolError:
            self.rejected_frame_count += 1
            raise
        finally:
            self._remove(key)
        self.completed_frame_count += 1
        self._completed[key] = (crc, count, current)
        return [ReassembledIpFrame(stream, sequence, frame)]

    def _remove(self, key: tuple[Hashable | None, int, int]) -> None:
        self.pending_declared_bytes -= self._pending.pop(key).frame_bytes


def reassemble_ip_datagrams(datagrams: Iterable[bytes], *, peer: Hashable | None = None) -> bytes:
    reassembler = IpFrameReassembler()
    frames: list[ReassembledIpFrame] = []
    for datagram in datagrams:
        frames.extend(reassembler.feed(datagram, peer=peer))
    if reassembler.pending_frame_count or len(frames) != 1:
        raise ProtocolError("direct-IP datagram collection is incomplete or not singular")
    return frames[0].frame
