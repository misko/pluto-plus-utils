"""Opt-in vectorized decoding for the attested Pluto interleaved RX layout."""

from __future__ import annotations

from typing import Any, Literal

import numpy as np
from numpy.typing import NDArray

IioIqDecoder = Literal["pyadi", "raw-complex64"]


def validate_iq_decoder(decoder: str) -> None:
    if decoder not in {"pyadi", "raw-complex64"}:
        raise ValueError("IIO IQ decoder must be pyadi or raw-complex64")


def decode_interleaved_complex64(
    payload: bytes | bytearray | memoryview,
    *,
    samples_per_channel: int,
    receiver_count: int,
) -> NDArray[np.complex64]:
    """Copy signed LE16 I/Q into one owned complex64 array, without complex128."""

    if samples_per_channel <= 0 or receiver_count not in {1, 2}:
        raise ValueError("raw IIO decode requires a positive sample count and one or two RX")
    payload_view = memoryview(payload)
    if payload_view.nbytes != samples_per_channel * receiver_count * 4:
        raise RuntimeError("raw IIO payload length does not match the selected RX geometry")
    components = np.frombuffer(payload_view, dtype="<i2").reshape(
        samples_per_channel, receiver_count * 2
    )
    result = np.empty((receiver_count, samples_per_channel), dtype=np.complex64)
    result.real[:] = components[:, 0::2].T
    result.imag[:] = components[:, 1::2].T
    return result


def read_interleaved_complex64(
    sdr: Any,
    *,
    samples_per_channel: int,
    channels: tuple[int, ...],
) -> NDArray[np.complex64]:
    """Refill once and decode only a proven packed, fully-defined Pluto RX scan.

    This is deliberately fail-closed, not an implicit replacement for PyADI's
    generic channel conversion. MetadataBuffer inherits the same refill/read
    contract, so metadata remains attached to the exact buffer generation.
    """

    if channels not in {(0,), (1,), (0, 1)}:
        raise ValueError("raw IIO decoder requires canonical RX0, RX1, or dual selection")
    if tuple(sdr.rx_enabled_channels) != channels:
        raise RuntimeError("RX selection changed before raw IIO decode")
    device = sdr._rxadc
    if device.name != "cf-ad9361-lpc":
        raise RuntimeError("raw IIO decoder requires the Pluto RX capture device")
    if sdr._rxbuf is None:
        sdr._rx_init_channels()
    buffer = sdr._rxbuf
    expected_indexes = tuple(index for rx in channels for index in (2 * rx, 2 * rx + 1))
    enabled = sorted(
        (channel for channel in device.channels if channel.scan_element and channel.enabled),
        key=lambda channel: channel.index,
    )
    if tuple(channel.index for channel in enabled) != expected_indexes:
        raise RuntimeError("raw IIO scan indexes do not match the selected RX layout")
    for channel, index in zip(enabled, expected_indexes, strict=True):
        data_format = channel.data_format
        if (
            channel.id != f"voltage{index}"
            or channel.output
            or data_format.length != 16
            or data_format.bits not in {12, 16}
            or data_format.shift != 0
            or data_format.repeat != 1
            or not data_format.is_signed
            or data_format.is_be
            or not data_format.is_fully_defined
        ):
            raise RuntimeError("raw IIO decoder requires fully-defined signed LE16 I/Q")
    stride = 4 * len(channels)
    if device.sample_size != stride or buffer.step != stride:
        raise RuntimeError("raw IIO scan stride contains padding or unexpected channels")
    buffer.refill()
    return decode_interleaved_complex64(
        buffer.read(),
        samples_per_channel=samples_per_channel,
        receiver_count=len(channels),
    )
