from __future__ import annotations

import struct
import zlib
from types import SimpleNamespace

import pytest
from test_iio_metadata_capture import _open_radio

from pluto_plus.counter_metadata import (
    CAPABILITY,
    FEATURES,
    FRAME,
    FRAME_MAGIC,
    GAP_FLAGS,
    PROFILE,
    VALID_FLAGS,
    CounterMetadataV1,
    pack_counter_request,
)
from pluto_plus.errors import RadioConfigurationError


def frame(first: int = 0x1FFFFFFFE, *, sequence: int = 0, missing: int = 0) -> bytes:
    wire = FRAME.pack(
        FRAME_MAGIC,
        1,
        80,
        FEATURES,
        VALID_FLAGS | (GAP_FLAGS if missing else 0),
        1,
        sequence,
        first,
        missing,
        4,
        16,
        3,
        5_000_000,
        2,
        0,
        0,
        0,
    )
    return wire[:76] + struct.pack("<I", zlib.crc32(wire[:76]))


def test_request_golden() -> None:
    assert pack_counter_request(4, 60_000_000).hex() == (
        "5350464301002000070000000300000000879303040000000000000000000000"
    )


@pytest.mark.parametrize("samples", [True, 0, -2, 3, 0xFFFFFFFF, 4.0])
def test_reject_sample_geometry(samples: int) -> None:
    with pytest.raises(ValueError):
        pack_counter_request(samples, 60_000_000)


@pytest.mark.parametrize("rate", [True, 0, -1, 61_440_001, 60_000_000.0])
def test_reject_rate(rate: int) -> None:
    with pytest.raises(ValueError):
        pack_counter_request(4, rate)


def test_counter_high_word_and_corruption() -> None:
    wire = frame()
    assert CounterMetadataV1.unpack(wire).first_sample_sequence == 0x1FFFFFFFE
    for index in range(80):
        corrupt = bytearray(wire)
        corrupt[index] ^= 1
        with pytest.raises(ValueError):
            CounterMetadataV1.unpack(corrupt)
    for bad in [wire[:-1], wire + b"\0"]:
        with pytest.raises(ValueError):
            CounterMetadataV1.unpack(bad)


def counter_radio(headers: list[bytes]):
    radio, adi, factory = _open_radio(headers, metadata_abi=3, channels=(0,))
    assert adi.device is not None
    adi.device.ctx.attrs.update({CAPABILITY: "1", "iio,buffer-counter-metadata-profile": PROFILE})
    adi.device._rxadc.channels = [
        SimpleNamespace(id=f"voltage{i}", scan_element=True, output=False) for i in range(2)
    ]
    adi.device.gain_control_mode_chan0 = "manual"
    adi.device.sample_rate = 5_000_000
    return radio, adi, factory


def test_public_counter_capture_exact_gaps_without_tandem() -> None:
    radio, adi, factory = counter_radio([frame(), frame(0x200000007, sequence=2, missing=5)])
    try:
        with radio.begin_metadata_capture(4, kernel_buffers=4, counter_only=True) as capture:
            first = capture.read_block()
            second = capture.read_block()
            assert first.tandem_metadata is None and second.tandem_metadata is None
            assert first.first_sample_sequence == 0x1FFFFFFFE
            assert second.missing_samples_before == 5
            assert capture._tandem_request is None
            assert capture._buffer.signature[1] == pack_counter_request(4, 5_000_000)
    finally:
        radio.close()


def test_counter_mode_rejects_paired_topology_before_open() -> None:
    radio, adi, factory = counter_radio([])
    assert adi.device is not None
    adi.device._rxadc.channels.append(
        SimpleNamespace(id="voltage2", scan_element=True, output=False)
    )
    try:
        with pytest.raises(RadioConfigurationError, match="physical 1R1T"):
            radio.begin_metadata_capture(4, kernel_buffers=4, counter_only=True)
    finally:
        radio.close()


def test_counter_mode_rejects_absent_capability() -> None:
    radio, adi, factory = counter_radio([])
    del adi.device.ctx.attrs[CAPABILITY]
    try:
        with pytest.raises(RadioConfigurationError, match="SPFC1"):
            radio.begin_metadata_capture(4, kernel_buffers=4, counter_only=True)
    finally:
        radio.close()


def test_corrupt_counter_frame_closes_capture() -> None:
    wire = bytearray(frame())
    wire[76] ^= 1
    radio, adi, factory = counter_radio([bytes(wire)])
    try:
        capture = radio.begin_metadata_capture(4, kernel_buffers=4, counter_only=True)
        buf = capture._buffer
        with pytest.raises(ValueError, match="CRC"):
            capture.read_block()
        assert buf.closed and capture._buffer is None
    finally:
        radio.close()
