from __future__ import annotations

from types import SimpleNamespace

import numpy as np
import pytest

from pluto_plus.hardware.iio_iq_decode import (
    decode_interleaved_complex64,
    read_interleaved_complex64,
    validate_iq_decoder,
)


@pytest.mark.parametrize("receivers", (1, 2))
def test_vector_decode_matches_generic_conversion_for_every_int16_value(receivers: int) -> None:
    components = np.arange(-32768, 32768, dtype=np.int16).reshape(-1, receivers * 2)
    payload = bytearray(components.astype("<i2").tobytes())
    expected = (
        components[:, 0::2].T.astype(np.float64)
        + 1j * components[:, 1::2].T.astype(np.float64)
    ).astype(np.complex64)

    actual = decode_interleaved_complex64(
        payload, samples_per_channel=len(components), receiver_count=receivers
    )

    assert actual.dtype == np.complex64
    assert actual.flags.owndata and actual.flags.c_contiguous
    np.testing.assert_array_equal(actual, expected)
    payload[:] = bytes(len(payload))
    np.testing.assert_array_equal(actual, expected)


@pytest.mark.parametrize("payload", (b"", bytes(7), bytes(9)))
def test_vector_decode_rejects_nonexact_payload_geometry(payload: bytes) -> None:
    with pytest.raises(RuntimeError, match="payload length"):
        decode_interleaved_complex64(payload, samples_per_channel=2, receiver_count=1)


def test_vector_decode_uses_memoryview_byte_length() -> None:
    payload = np.array([1, -2, 3, -4], dtype="<i2")

    decoded = decode_interleaved_complex64(
        memoryview(payload),
        samples_per_channel=2,
        receiver_count=1,
    )

    np.testing.assert_array_equal(decoded, np.array([[1 - 2j, 3 - 4j]], np.complex64))


class FakeBuffer:
    def __init__(self, receivers: int) -> None:
        self.step = 4 * receivers
        self.payload = np.arange(8 * receivers, dtype="<i2").tobytes()
        self.refills = 0
        self.metadata: bytes | None = None

    def refill(self) -> None:
        self.refills += 1
        self.metadata = b"this-exact-refill"

    def read(self) -> bytes:
        return self.payload


def fake_sdr(channels: tuple[int, ...]) -> SimpleNamespace:
    indexes = tuple(index for rx in channels for index in (rx * 2, rx * 2 + 1))
    scan = [
        SimpleNamespace(
            id=f"voltage{index}",
            index=index,
            output=False,
            scan_element=True,
            enabled=index in indexes,
            data_format=SimpleNamespace(
                length=16,
                bits=12,
                shift=0,
                repeat=1,
                is_signed=True,
                is_be=False,
                is_fully_defined=True,
            ),
        )
        for index in reversed(range(4))
    ]
    return SimpleNamespace(
        rx_enabled_channels=list(channels),
        _rxadc=SimpleNamespace(
            name="cf-ad9361-lpc", channels=scan, sample_size=4 * len(channels)
        ),
        _rxbuf=FakeBuffer(len(channels)),
    )


@pytest.mark.parametrize("channels", ((0,), (1,), (0, 1)))
def test_raw_refill_uses_scan_indexes_and_preserves_metadata(channels: tuple[int, ...]) -> None:
    sdr = fake_sdr(channels)

    actual = read_interleaved_complex64(sdr, samples_per_channel=4, channels=channels)

    assert sdr._rxbuf.refills == 1
    assert sdr._rxbuf.metadata == b"this-exact-refill"
    expected = decode_interleaved_complex64(
        sdr._rxbuf.payload, samples_per_channel=4, receiver_count=len(channels)
    )
    np.testing.assert_array_equal(actual, expected)


def test_raw_refill_initializes_an_ordinary_buffer_once() -> None:
    sdr = fake_sdr((0,))
    buffer = sdr._rxbuf
    sdr._rxbuf = None
    initialized: list[bool] = []

    def initialize() -> None:
        initialized.append(True)
        sdr._rxbuf = buffer

    sdr._rx_init_channels = initialize
    for _ in range(2):
        read_interleaved_complex64(sdr, samples_per_channel=4, channels=(0,))

    assert initialized == [True]
    assert buffer.refills == 2


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("length", 32),
        ("bits", 8),
        ("shift", 4),
        ("repeat", 2),
        ("is_signed", False),
        ("is_be", True),
        ("is_fully_defined", False),
    ],
)
def test_raw_refill_rejects_formats_requiring_generic_conversion(field: str, value: object) -> None:
    sdr = fake_sdr((0,))
    channel = next(channel for channel in sdr._rxadc.channels if channel.id == "voltage0")
    setattr(channel.data_format, field, value)

    with pytest.raises(RuntimeError, match="fully-defined signed LE16"):
        read_interleaved_complex64(sdr, samples_per_channel=4, channels=(0,))
    assert sdr._rxbuf.refills == 0


@pytest.mark.parametrize("mismatch", ("selection", "device", "extra", "index", "stride", "step"))
def test_raw_refill_rejects_unproven_scan_geometry(mismatch: str) -> None:
    sdr = fake_sdr((0,))
    if mismatch == "selection":
        sdr.rx_enabled_channels = [1]
    elif mismatch == "device":
        sdr._rxadc.name = "other-device"
    elif mismatch == "extra":
        sdr._rxadc.channels[0].enabled = True
    elif mismatch == "index":
        sdr._rxadc.channels[-1].index = 8
    elif mismatch == "stride":
        sdr._rxadc.sample_size = 8
    else:
        sdr._rxbuf.step = 8

    with pytest.raises(RuntimeError):
        read_interleaved_complex64(sdr, samples_per_channel=4, channels=(0,))
    assert sdr._rxbuf.refills == 0


def test_raw_decoder_is_an_explicit_choice_without_silent_fallback() -> None:
    for decoder in ("pyadi", "raw-complex64"):
        validate_iq_decoder(decoder)
    with pytest.raises(ValueError, match="decoder"):
        validate_iq_decoder("auto")
