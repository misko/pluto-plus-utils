from __future__ import annotations

import dataclasses
import random
import struct

import pytest

from pluto_plus.direct_radio.ip import (
    IP_CONTROL_BYTES,
    IP_FRAGMENT_HEADER_BYTES,
    IpControlFlags,
    IpControlMessageV1,
    IpControlType,
    IpFragmentV1,
    IpFrameReassembler,
    fragment_ip_frame,
    make_ip_capability_query,
    make_ip_start_request,
    make_ip_stop_request,
    reassemble_ip_datagrams,
)
from pluto_plus.direct_radio.usb import MetadataFeatures, ProtocolError

FEATURES = MetadataFeatures(0xF7)


def test_ip_control_golden_query_and_v3_lifecycle() -> None:
    query = make_ip_capability_query(request_id=0x0102030405060708)
    assert IP_CONTROL_BYTES == 80
    assert query.pack().hex() == (
        "5349433101000100500000000807060504030201000000000000000000000000"
        "0000000000000000000000000000000000000000000000000000000000000000"
        "00000000000000000000000000000000"
    )
    assert IpControlMessageV1.unpack(query.pack()) == query

    start = make_ip_start_request(
        request_id=2,
        protocol_version=3,
        features=FEATURES,
        enabled_scan_mask=0x0F,
        samples_per_channel=1024,
        frame_count=2,
        data_port=30_433,
        gain_observation_interval_samples=256,
        gain_observation_capacity=4,
    )
    assert IpControlMessageV1.unpack(start.pack()) == start
    started = dataclasses.replace(start, message_type=IpControlType.STARTED, stream_id=9)
    assert IpControlMessageV1.unpack(started.pack()) == started
    assert (
        IpControlMessageV1.unpack(make_ip_stop_request(request_id=3, stream_id=9).pack()).stream_id
        == 9
    )


def test_ip_control_rejects_bad_identity_flags_and_start_semantics() -> None:
    raw = bytearray(make_ip_capability_query(request_id=1).pack())
    raw[0:4] = bytes(4)
    with pytest.raises(ProtocolError, match="magic"):
        IpControlMessageV1.unpack(raw)
    with pytest.raises(ProtocolError, match="pacing"):
        make_ip_start_request(
            request_id=1,
            protocol_version=3,
            features=FEATURES,
            enabled_scan_mask=0x0F,
            samples_per_channel=8,
            frame_count=1,
            data_port=1234,
            gain_observation_interval_samples=8,
            gain_observation_capacity=1,
            transport_flags=IpControlFlags.USB_CLASS_PACING,
        ).pack()


def test_fragments_reassemble_out_of_order_with_duplicates() -> None:
    frame = bytes(range(251)) * 31
    datagrams = list(
        fragment_ip_frame(frame, stream_id=7, frame_sequence=11, max_datagram_bytes=200)
    )
    assert IP_FRAGMENT_HEADER_BYTES == 52
    assert IpFragmentV1.unpack(datagrams[0]).fragment_index == 0
    shuffled = datagrams + [datagrams[2], datagrams[0]]
    random.Random(4).shuffle(shuffled)
    reassembler = IpFrameReassembler()
    output = []
    for datagram in shuffled:
        output.extend(reassembler.feed(datagram, peer=("radio", 1), now=1.0))
    assert len(output) == 1
    assert output[0].frame == frame
    assert reassembler.duplicate_fragment_count == 2
    assert reassemble_ip_datagrams(datagrams[::-1]) == frame


def test_fragment_conflicts_crc_bounds_and_expiry_fail_closed() -> None:
    frame = b"reference payload" * 50
    datagrams = list(
        fragment_ip_frame(frame, stream_id=7, frame_sequence=12, max_datagram_bytes=128)
    )
    reassembler = IpFrameReassembler(
        frame_timeout_seconds=1, max_pending_frames=1, max_pending_bytes=4096
    )
    assert reassembler.feed(datagrams[0], now=1.0) == []
    assert reassembler.expire(now=2.0) == 1
    assert reassembler.pending_declared_bytes == 0

    corrupt = bytearray(datagrams[-1])
    corrupt[-1] ^= 1
    with pytest.raises(ProtocolError, match="CRC"):
        for datagram in [*datagrams[:-1], bytes(corrupt)]:
            reassembler.feed(datagram, now=3.0)
    assert reassembler.pending_declared_bytes == 0

    conflict = bytearray(datagrams[0])
    # Preserve a valid fragment header but make its frame CRC conflict.
    struct.pack_into("<I", conflict, 32, 123)
    reassembler.feed(datagrams[0], now=4.0)
    with pytest.raises(ProtocolError, match="conflicting"):
        reassembler.feed(conflict, now=4.1)


def test_fragment_header_rejects_flags_lengths_and_duplicate_conflict() -> None:
    datagram = bytearray(fragment_ip_frame(b"abc", stream_id=1, frame_sequence=1)[0])
    struct.pack_into("<I", datagram, 8, 4)
    with pytest.raises(ProtocolError, match="flags"):
        IpFragmentV1.unpack(datagram)
    short = fragment_ip_frame(b"abc", stream_id=1, frame_sequence=1)[0][:-1]
    with pytest.raises(ProtocolError, match="length"):
        IpFragmentV1.unpack(short)
