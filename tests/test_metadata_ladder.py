from __future__ import annotations

from collections.abc import Iterator
from types import TracebackType

import numpy as np
import pytest

from pluto_plus.hardware.base import SampleBlockV2
from pluto_plus.metadata_ladder import (
    MINIMUM_OBSERVED_FRACTION,
    parse_metadata_sample_ladder,
    run_metadata_continuity_ladder,
)
from pluto_plus.models import RadioCapabilities, RadioIdentity, RadioSettings, Transport


class _Capture:
    def __init__(self, samples: int, sequences: tuple[int, ...], kernel_buffers: int) -> None:
        self.samples = samples
        self.sequences: Iterator[int] = iter(sequences)
        self.kernel_buffers = kernel_buffers
        self.closed = False
        self.previous_sequence: int | None = None

    def read_block(self) -> SampleBlockV2:
        sequence = next(self.sequences)
        missing = (
            0
            if self.previous_sequence is None
            else (sequence - self.previous_sequence - 1) * self.samples
        )
        self.previous_sequence = sequence
        return SampleBlockV2(
            utc_ns=1,
            samples=np.ones((2, self.samples), dtype=np.complex64),
            stream_id=1,
            buffer_sequence=sequence,
            first_sample_sequence=1_000 + sequence * self.samples,
            metadata_flags=(1 << 2),
            metadata_abi=1,
            missing_samples_before=missing,
        )

    def close(self) -> None:
        self.closed = True

    def __enter__(self) -> _Capture:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: TracebackType | None,
    ) -> None:
        self.close()


class _Radio:
    def __init__(self, sequences: dict[int, tuple[int, ...]]) -> None:
        self.sequences = sequences
        self.original = RadioSettings()
        self.settings = self.original
        self.identity = RadioIdentity(
            radio_id="radio-a",
            serial="SERIAL_A",
            uri="ip:192.0.2.1",
            transport=Transport.IIO_IP,
        )
        self.capabilities = RadioCapabilities(receiver_channels=(0, 1))
        self.opened = False

    def open(self) -> None:
        self.opened = True

    def close(self) -> None:
        self.opened = False

    def read_settings(self) -> RadioSettings:
        return self.settings

    def apply_settings(self, settings: RadioSettings) -> RadioSettings:
        self.settings = settings
        return settings

    def begin_metadata_capture(self, sample_count: int, *, kernel_buffers: int) -> _Capture:
        return _Capture(sample_count, self.sequences[sample_count], kernel_buffers)


def test_parse_metadata_sample_ladder_is_strictly_descending() -> None:
    assert parse_metadata_sample_ladder("4194304, 1048576,262144") == (
        4_194_304,
        1_048_576,
        262_144,
    )
    for value in ("", "262144,262144", "262144,524288", "text"):
        with pytest.raises(ValueError):
            parse_metadata_sample_ladder(value)


def test_metadata_ladder_selects_largest_counter_continuous_refill_and_restores() -> None:
    radio = _Radio(
        {
            1_048_576: (0, 3, 6, 9, 12, 15),
            262_144: (0, 1, 2, 3, 4, 5),
        }
    )
    ticks = iter((0, 1_000_000_000, 2_000_000_000, 3_000_000_000))
    report = run_metadata_continuity_ladder(
        uri="ip:192.0.2.1",
        serial="SERIAL_A",
        sample_rate_hz=5_000_000,
        rf_bandwidth_hz=5_000_000,
        samples_per_channel=(1_048_576, 262_144),
        frames=6,
        kernel_buffers=4,
        radio_factory=lambda _uri, _serial, _abi: radio,
        clock_ns=lambda: next(ticks),
    )

    assert report.minimum_observed_fraction == MINIMUM_OBSERVED_FRACTION
    assert report.largest_passing_samples_per_channel == 262_144
    assert report.cells[0].observed_fraction == pytest.approx(6 / 16)
    assert report.cells[0].gap_count == 5
    assert not report.cells[0].passed
    assert report.cells[1].observed_fraction == 1.0
    assert report.cells[1].passed
    assert report.failures == ()
    assert report.original_settings_restored
    assert radio.settings == radio.original
    assert not radio.opened


def test_metadata_ladder_requires_native_bandwidth_and_four_kernel_buffers() -> None:
    radio = _Radio({262_144: (0, 1)})
    for bandwidth, kernel_buffers in ((5_000_001, 4), (5_000_000, 3)):
        with pytest.raises(ValueError):
            run_metadata_continuity_ladder(
                uri="ip:192.0.2.1",
                serial="SERIAL_A",
                sample_rate_hz=5_000_000,
                rf_bandwidth_hz=bandwidth,
                samples_per_channel=(262_144,),
                frames=2,
                kernel_buffers=kernel_buffers,
                radio_factory=lambda _uri, _serial, _abi: radio,
            )
