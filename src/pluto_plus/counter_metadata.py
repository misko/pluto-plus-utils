"""SPFC1 counter-only request and SPC1 frame, independent of paired metadata."""

from __future__ import annotations

import struct
import zlib
from dataclasses import dataclass

REQUEST = struct.Struct("<IHHIIIIII")
FRAME = struct.Struct("<IHHIIQQQQIIIIIIII")
REQUEST_MAGIC = 0x43465053
FRAME_MAGIC = 0x31435053
FEATURES = 7
VALID_FLAGS = (1 << 4) | (1 << 21)
GAP_FLAGS = (1 << 11) | (1 << 23)
CAPABILITY = "iio,buffer-counter-metadata"
PROFILE = "ad9361:1r1t:rx0:manual:decimation1:spfc1"


def pack_counter_request(samples: int, rate: int) -> bytes:
    if (
        isinstance(samples, bool)
        or not isinstance(samples, int)
        or samples <= 0
        or samples & 1
        or samples > 0xFFFFFFFF // 4
    ):
        raise ValueError("counter capture requires an even positive CI16 sample count")
    if isinstance(rate, bool) or not isinstance(rate, int) or not 0 < rate <= 61_440_000:
        raise ValueError("counter capture rate must be within 1..61440000")
    return REQUEST.pack(REQUEST_MAGIC, 1, REQUEST.size, FEATURES, 3, rate, samples, 0, 0)


@dataclass(frozen=True, slots=True)
class CounterMetadataV1:
    flags: int
    stream_id: int
    buffer_sequence: int
    first_sample_sequence: int
    missing_samples_before: int
    samples_per_channel: int
    iq_payload_bytes: int
    enabled_scan_mask: int
    sample_rate_hz: int
    channel_count: int = 1
    source_counter_offset_samples: int = 2

    @classmethod
    def unpack(cls, wire: bytes) -> CounterMetadataV1:
        if len(wire) != FRAME.size:
            raise ValueError("counter metadata frame must be exactly 80 bytes")
        (
            magic,
            version,
            size,
            features,
            flags,
            stream,
            sequence,
            first,
            missing,
            samples,
            iq_bytes,
            mask,
            rate,
            r0,
            r1,
            r2,
            crc,
        ) = FRAME.unpack(wire)
        if (
            magic != FRAME_MAGIC
            or version != 1
            or size != FRAME.size
            or features != FEATURES
            or r0 != 2
            or r1
            or r2
            or crc != zlib.crc32(wire[:76])
        ):
            raise ValueError("invalid counter metadata identity, features, reserved fields or CRC")
        pack_counter_request(samples, rate)
        if (
            not stream
            or mask != 3
            or iq_bytes != samples * 4
            or first + samples > 0xFFFFFFFFFFFFFFFF
            or missing > first
            or flags != VALID_FLAGS | (GAP_FLAGS if missing else 0)
        ):
            raise ValueError("invalid counter metadata interval, layout or flags")
        return cls(flags, stream, sequence, first, missing, samples, iq_bytes, mask, rate)
