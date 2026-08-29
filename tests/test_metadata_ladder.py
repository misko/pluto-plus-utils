from __future__ import annotations

from collections.abc import Iterator
from types import TracebackType

import numpy as np
import pytest

from pluto_plus.hardware.base import SampleBlockV2
from pluto_plus.metadata_ladder import (
    DDR_BURST_MIN_FRAME_DURATION_US,
    MAX_METADATA_FRAMES,
    MINIMUM_OBSERVED_FRACTION,
    parse_metadata_sample_ladder,
    run_metadata_continuity_ladder,
)
from pluto_plus.models import RadioCapabilities, RadioIdentity, RadioSettings, Transport


class _Capture:
    def __init__(
        self,
        samples: int,
        sequences: tuple[int, ...],
        kernel_buffers: int,
        receiver_count: int,
    ) -> None:
        self.samples = samples
        self.sequences: Iterator[int] = iter(sequences)
        self.kernel_buffers = kernel_buffers
        self.receiver_count = receiver_count
        self.ddr_burst_requested_bytes = 0
        self.ddr_burst_admitted_bytes = 0
        self.ddr_burst_frames = 0
        self.ddr_burst_enabled = False
        self.ddr_ring_requested_bytes = 0
        self.ddr_ring_admitted_bytes = 0
        self.ddr_ring_capacity_frames = 0
        self.ddr_ring_capture_frames = 0
        self.ddr_ring_continuous = False
        self.ddr_ring_enabled = False
        self.closed = False
        self.previous_sequence: int | None = None

    def ddr_ring_status(self) -> dict[str, object]:
        if not self.ddr_ring_enabled or self.previous_sequence is None:
            raise RuntimeError("DDR ring has not completed")
        target = self.ddr_ring_capture_frames
        capacity = self.ddr_ring_capacity_frames
        return {
            "state": "complete",
            "terminal_reason": "target_complete",
            "error_code": 0,
            "requested_capacity_iq_bytes": self.ddr_ring_requested_bytes,
            "admitted_capacity_iq_bytes": self.ddr_ring_admitted_bytes,
            "target_frames": target,
            "produced_frames": target,
            "consumed_frames": target,
            "high_water_frames": min(target, capacity),
            "wrap_count": target // capacity,
            "producer_position": target % capacity,
            "consumer_position": target % capacity,
            "last_contiguous_sample_sequence": (
                1_000 + (self.previous_sequence + 1) * self.samples
            ),
            "first_unavailable_sample_sequence": None,
        }

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
            samples=np.ones((self.receiver_count, self.samples), dtype=np.complex64),
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
        self.capture_requests: list[int] = []

    def open(self) -> None:
        self.opened = True

    def close(self) -> None:
        self.opened = False

    def read_settings(self) -> RadioSettings:
        return self.settings

    def apply_settings(self, settings: RadioSettings) -> RadioSettings:
        self.settings = settings
        return settings

    def begin_metadata_capture(
        self,
        sample_count: int,
        *,
        kernel_buffers: int,
        ddr_burst_bytes: int = 0,
        ddr_ring_bytes: int = 0,
        ddr_ring_frames: int = 0,
        ddr_ring_continuous: bool = False,
    ) -> _Capture:
        self.capture_requests.append(sample_count)
        capture = _Capture(
            sample_count,
            self.sequences[sample_count],
            kernel_buffers,
            len(self.settings.channels),
        )
        capture.ddr_burst_requested_bytes = ddr_burst_bytes
        capture.ddr_burst_admitted_bytes = ddr_burst_bytes
        capture.ddr_burst_frames = ddr_burst_bytes // (sample_count * 4)
        capture.ddr_burst_enabled = bool(ddr_burst_bytes)
        frame_bytes = sample_count * len(self.settings.channels) * 4
        capture.ddr_ring_requested_bytes = ddr_ring_bytes
        capture.ddr_ring_capacity_frames = (
            0 if not ddr_ring_bytes else ddr_ring_bytes // frame_bytes
        )
        capture.ddr_ring_admitted_bytes = capture.ddr_ring_capacity_frames * frame_bytes
        capture.ddr_ring_capture_frames = ddr_ring_frames
        capture.ddr_ring_continuous = ddr_ring_continuous
        capture.ddr_ring_enabled = bool(ddr_ring_bytes)
        return capture


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


@pytest.mark.parametrize("channels", ((0,), (1,), (0, 1)))
def test_metadata_ladder_supports_every_abi3_layout(channels: tuple[int, ...]) -> None:
    radio = _Radio({262_144: (0, 1)})
    ticks = iter((0, 1_000_000_000))
    report = run_metadata_continuity_ladder(
        uri="ip:192.0.2.1",
        serial="SERIAL_A",
        sample_rate_hz=5_000_000,
        rf_bandwidth_hz=5_000_000,
        metadata_abi=3,
        channels=channels,
        samples_per_channel=(262_144,),
        frames=2,
        kernel_buffers=4,
        radio_factory=lambda _uri, _serial, _abi: radio,
        clock_ns=lambda: next(ticks),
    )
    assert report.channels == channels
    assert report.cells[0].passed


def test_metadata_ladder_rejects_single_rx_before_abi3_and_odd_abi3_counts() -> None:
    radio = _Radio({262_144: (0, 1)})
    with pytest.raises(ValueError, match="require dual RX"):
        run_metadata_continuity_ladder(
            uri="ip:192.0.2.1",
            serial="SERIAL_A",
            sample_rate_hz=5_000_000,
            rf_bandwidth_hz=5_000_000,
            metadata_abi=2,
            channels=(0,),
            samples_per_channel=(262_144,),
            frames=2,
            radio_factory=lambda _uri, _serial, _abi: radio,
        )


def test_metadata_ladder_qualifies_exact_single_rx_ddr_burst() -> None:
    radio = _Radio({300_000: (0, 1, 2, 3)})
    ticks = iter((0, 1_000_000_000))
    report = run_metadata_continuity_ladder(
        uri="ip:192.0.2.1",
        serial="SERIAL_A",
        sample_rate_hz=25_000_000,
        rf_bandwidth_hz=20_000_000,
        metadata_abi=3,
        channels=(0,),
        samples_per_channel=(300_000,),
        frames=4,
        kernel_buffers=4,
        ddr_burst=True,
        radio_factory=lambda _uri, _serial, _abi: radio,
        clock_ns=lambda: next(ticks),
    )

    assert report.ddr_burst_enabled
    assert report.cells[0].ddr_burst_requested_iq_bytes == 4_800_000
    assert report.cells[0].ddr_burst_admitted_iq_bytes == 4_800_000
    assert report.cells[0].ddr_burst_frames == 4
    assert report.cells[0].passed


def test_metadata_ladder_rejects_short_ddr_frames_before_capture() -> None:
    radio = _Radio({300_000: (0, 1), 299_998: (0, 1), 250_000: (0, 1)})
    ticks = iter((0, 1_000_000_000))

    report = run_metadata_continuity_ladder(
        uri="ip:192.0.2.1",
        serial="SERIAL_A",
        sample_rate_hz=25_000_000,
        rf_bandwidth_hz=20_000_000,
        metadata_abi=3,
        channels=(0,),
        samples_per_channel=(300_000, 299_998, 250_000),
        frames=2,
        kernel_buffers=4,
        ddr_burst=True,
        radio_factory=lambda _uri, _serial, _abi: radio,
        clock_ns=lambda: next(ticks),
    )

    assert DDR_BURST_MIN_FRAME_DURATION_US == 12_000
    assert [cell.samples_per_channel for cell in report.cells] == [300_000]
    assert radio.capture_requests == [300_000]
    assert [failure.samples_per_channel for failure in report.failures] == [299_998, 250_000]
    assert all(failure.error_type == "ValueError" for failure in report.failures)
    assert all(
        "at least a 12 ms frame period" in failure.message for failure in report.failures
    )
    assert "duration_us=11999.920" in report.failures[0].message
    assert "duration_us=10000.000" in report.failures[1].message
    assert report.original_settings_restored


def test_metadata_ladder_allows_short_frames_without_ddr_burst() -> None:
    radio = _Radio({125_000: (0, 1)})
    ticks = iter((0, 1_000_000_000))

    report = run_metadata_continuity_ladder(
        uri="ip:192.0.2.1",
        serial="SERIAL_A",
        sample_rate_hz=25_000_000,
        rf_bandwidth_hz=20_000_000,
        metadata_abi=3,
        channels=(0,),
        samples_per_channel=(125_000,),
        frames=2,
        kernel_buffers=4,
        ddr_burst=False,
        radio_factory=lambda _uri, _serial, _abi: radio,
        clock_ns=lambda: next(ticks),
    )

    assert report.failures == ()
    assert report.cells[0].passed
    assert radio.capture_requests == [125_000]


def test_metadata_ladder_qualifies_exact_200_mb_release_burst_geometry() -> None:
    samples = 1_000_000
    release_frames = 50
    radio = _Radio({samples: tuple(range(release_frames))})
    ticks = iter((0, 1_000_000_000))

    report = run_metadata_continuity_ladder(
        uri="ip:192.0.2.1",
        serial="SERIAL_A",
        sample_rate_hz=25_000_000,
        rf_bandwidth_hz=20_000_000,
        metadata_abi=3,
        channels=(0,),
        samples_per_channel=(samples,),
        frames=release_frames,
        kernel_buffers=4,
        ddr_burst=True,
        radio_factory=lambda _uri, _serial, _abi: radio,
        clock_ns=lambda: next(ticks),
    )

    assert release_frames <= MAX_METADATA_FRAMES
    assert report.cells[0].ddr_burst_requested_iq_bytes == 200_000_000
    assert report.cells[0].ddr_burst_admitted_iq_bytes == 200_000_000
    assert report.cells[0].ddr_burst_frames == release_frames
    assert report.cells[0].passed


def test_metadata_ladder_rejects_ddr_burst_outside_abi3_single_rx() -> None:
    radio = _Radio({262_144: (0, 1)})
    with pytest.raises(ValueError, match="ABI 3 and one receiver"):
        run_metadata_continuity_ladder(
            uri="ip:192.0.2.1",
            serial="SERIAL_A",
            sample_rate_hz=5_000_000,
            rf_bandwidth_hz=5_000_000,
            metadata_abi=3,
            channels=(0, 1),
            samples_per_channel=(262_144,),
            frames=2,
            ddr_burst=True,
            radio_factory=lambda _uri, _serial, _abi: radio,
        )


@pytest.mark.parametrize("channels", ((0,), (0, 1)))
def test_metadata_ladder_qualifies_finite_ddr_ring_with_exact_status(
    channels: tuple[int, ...],
) -> None:
    samples = 262_144
    frames = 6
    frame_bytes = samples * len(channels) * 4
    requested_ring_bytes = frame_bytes * 2 + 1
    radio = _Radio({samples: tuple(range(frames))})
    ticks = iter((0, 1_000_000_000))

    report = run_metadata_continuity_ladder(
        uri="ip:192.0.2.1",
        serial="SERIAL_A",
        sample_rate_hz=5_000_000,
        rf_bandwidth_hz=5_000_000,
        metadata_abi=3,
        channels=channels,
        samples_per_channel=(samples,),
        frames=frames,
        kernel_buffers=4,
        ddr_ring_bytes=requested_ring_bytes,
        radio_factory=lambda _uri, _serial, _abi: radio,
        clock_ns=lambda: next(ticks),
    )

    status = report.cells[0].ddr_ring_status
    assert report.ddr_ring_requested_iq_bytes == requested_ring_bytes
    assert status is not None
    assert status.admitted_capacity_iq_bytes == frame_bytes * 2
    assert status.produced_frames == status.consumed_frames == frames
    assert status.high_water_frames == 2
    assert report.cells[0].passed


def test_metadata_ladder_rejects_ambiguous_or_incompatible_ddr_ring() -> None:
    radio = _Radio({262_144: (0, 1)})
    arguments = {
        "uri": "ip:192.0.2.1",
        "serial": "SERIAL_A",
        "sample_rate_hz": 5_000_000,
        "rf_bandwidth_hz": 5_000_000,
        "samples_per_channel": (262_144,),
        "frames": 2,
        "radio_factory": lambda _uri, _serial, _abi: radio,
    }
    with pytest.raises(ValueError, match="mutually exclusive"):
        run_metadata_continuity_ladder(
            **arguments,
            metadata_abi=3,
            channels=(0,),
            ddr_burst=True,
            ddr_ring_bytes=2_097_152,
        )
    with pytest.raises(ValueError, match="requires metadata ABI 3"):
        run_metadata_continuity_ladder(
            **arguments,
            metadata_abi=2,
            channels=(0, 1),
            ddr_ring_bytes=2_097_152,
        )
    with pytest.raises(ValueError, match="must be even"):
        run_metadata_continuity_ladder(
            uri="ip:192.0.2.1",
            serial="SERIAL_A",
            sample_rate_hz=5_000_000,
            rf_bandwidth_hz=5_000_000,
            metadata_abi=3,
            channels=(1,),
            samples_per_channel=(262_145,),
            frames=2,
            radio_factory=lambda _uri, _serial, _abi: radio,
        )
