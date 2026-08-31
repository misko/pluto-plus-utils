from __future__ import annotations

import numpy as np
import pytest

from pluto_plus.direct_async_ladder import (
    DirectAsyncLadderReport,
    parse_duration_ladder,
    run_direct_async_ladder,
)
from pluto_plus.hardware.base import MetadataCapture, SampleBlock, SampleBlockV2
from pluto_plus.models import RadioCapabilities, RadioIdentity, RadioSettings, Transport
from pluto_plus.tandem import TandemSessionRequestV1


class _Clock:
    def __init__(self, step_ns: int = 100_000_000) -> None:
        self.value = 0
        self.step_ns = step_ns

    def __call__(self) -> int:
        self.value += self.step_ns
        return self.value


class _Capture:
    def __init__(
        self,
        radio: _Radio,
        *,
        samples: int,
        kernel_buffers: int,
        ring_bytes: int,
        direct_frames: int,
    ) -> None:
        self.radio = radio
        self.samples = samples
        self.kernel_buffers = kernel_buffers
        self.direct_async_frames = direct_frames
        self.direct_async_ring_extension = bool(ring_bytes)
        self.ddr_burst_enabled = False
        self.ddr_burst_requested_bytes = 0
        self.ddr_burst_admitted_bytes = 0
        self.ddr_burst_frames = 0
        self.ddr_ring_enabled = bool(ring_bytes)
        self.ddr_ring_requested_bytes = ring_bytes
        self.ddr_ring_admitted_bytes = ring_bytes
        self.ddr_ring_capacity_frames = 0 if not ring_bytes else ring_bytes // (samples * 4)
        self.ddr_ring_capture_frames = 0
        self.ddr_ring_continuous = False
        self.reads = 0

    def read_block(self) -> SampleBlockV2:
        sequence = self.radio.sequence
        missing = self.samples if sequence == self.radio.gap_at_sequence else 0
        first_sample = self.radio.first_sample + missing
        self.radio.first_sample = first_sample + self.samples
        self.radio.sequence += 1
        self.reads += 1
        return SampleBlockV2(
            utc_ns=1,
            samples=np.ones((1, self.samples), dtype=np.complex64),
            stream_id=self.radio.stream_id,
            buffer_sequence=sequence,
            first_sample_sequence=first_sample,
            metadata_flags=(1 << 11) if missing else 0,
            metadata_abi=3,
            missing_samples_before=missing,
        )

    def ddr_ring_status(self) -> dict[str, object]:
        produced = min(self.reads, self.ddr_ring_capacity_frames)
        return {
            "version": 1,
            "state": "complete",
            "terminal_reason": "target_complete",
            "error_code": 0,
            "requested_capacity_iq_bytes": self.ddr_ring_requested_bytes,
            "admitted_capacity_iq_bytes": self.ddr_ring_admitted_bytes,
            "target_frames": 0,
            "produced_frames": produced,
            "consumed_frames": produced,
            "high_water_frames": produced,
            "wrap_count": 0,
            "producer_position": 0,
            "consumer_position": 0,
            "last_contiguous_sample_sequence": self.radio.first_sample,
            "first_unavailable_sample_sequence": None,
            "failure_frame_index": None,
            "failure_sample_sequence": None,
        }

    def close(self) -> None:
        pass

    def __enter__(self) -> _Capture:
        return self

    def __exit__(
        self,
        exc_type: object,
        exc: object,
        traceback: object,
    ) -> None:
        del exc_type, exc, traceback
        self.close()


class _Radio:
    def __init__(
        self,
        *,
        gap_at_sequence: int = -1,
        rejected_rate: int | None = None,
    ) -> None:
        self.identity = RadioIdentity(
            radio_id="SERIAL_A",
            serial="SERIAL_A",
            uri="ip:192.168.1.15",
            transport=Transport.IIO_IP,
            model="Pluto+ Test",
            firmware_version="direct-v1",
        )
        self.capabilities = RadioCapabilities(
            receiver_channels=(0, 1),
            minimum_sample_rate_hz=520_833,
            maximum_sample_rate_hz=30_720_000,
        )
        self.original = RadioSettings()
        self.settings = self.original
        self.sequence = 0
        self.stream_id = 1
        self.first_sample = 1_000
        self.gap_at_sequence = gap_at_sequence
        self.rejected_rate = rejected_rate
        self.opened = False
        self.closed = False
        self.capture_targets: list[int] = []

    def open(self) -> None:
        self.opened = True

    def close(self) -> None:
        self.closed = True

    def read_settings(self) -> RadioSettings:
        return self.settings

    def apply_settings(self, settings: RadioSettings) -> RadioSettings:
        if settings.sample_rate_hz == self.rejected_rate:
            raise RuntimeError("planted rate rejection")
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
        direct_async_frames: int = 0,
        tandem_request: TandemSessionRequestV1 | None = None,
    ) -> MetadataCapture:
        del ddr_burst_bytes, ddr_ring_frames, ddr_ring_continuous, tandem_request
        self.capture_targets.append(direct_async_frames)
        self.stream_id += 1
        return _Capture(
            self,
            samples=sample_count,
            kernel_buffers=kernel_buffers,
            ring_bytes=ddr_ring_bytes,
            direct_frames=direct_async_frames,
        )

    def read_block(self, sample_count: int) -> SampleBlock:
        raise AssertionError(sample_count)


def test_duration_ladder_parser_accepts_matrix_and_rejects_ambiguity() -> None:
    assert parse_duration_ladder("3,10") == (3.0, 10.0)
    for invalid in ("", "0", "10,3", "3,3", "nan", "61"):
        with pytest.raises(ValueError):
            parse_duration_ladder(invalid)


def test_direct_ladder_runs_rate_duration_matrix_in_bounded_segments() -> None:
    radio = _Radio()
    report = run_direct_async_ladder(
        uri="ip:192.168.1.15",
        serial="SERIAL_A",
        rates_hz=(1_000_000, 2_000_000),
        durations_seconds=(0.032768, 0.54),
        channels=(0,),
        samples_per_frame=16_384,
        kernel_buffers=4,
        radio_factory=lambda _uri, _serial, _decoder: radio,
        clock_ns=_Clock(),
    )

    assert isinstance(report, DirectAsyncLadderReport)
    assert radio.opened and radio.closed
    assert radio.settings == radio.original
    assert report.original_settings_restored
    assert report.mode == "direct"
    assert report.failures == ()
    assert [(cell.sample_rate_hz, cell.requested_duration_seconds) for cell in report.cells] == [
        (1_000_000, 0.032768),
        (1_000_000, 0.54),
        (2_000_000, 0.032768),
        (2_000_000, 0.54),
    ]
    assert all(cell.passed for cell in report.cells)
    assert all(cell.observed_frames == cell.requested_frames for cell in report.cells)
    assert any(cell.capture_segments > 1 for cell in report.cells)
    assert max(radio.capture_targets) == 64


def test_direct_ram_ladder_requires_and_accounts_real_spill_status() -> None:
    radio = _Radio()
    report = run_direct_async_ladder(
        uri="ip:192.168.1.15",
        serial="SERIAL_A",
        rates_hz=(1_000_000,),
        durations_seconds=(0.05,),
        channels=(0,),
        samples_per_frame=16_384,
        kernel_buffers=3,
        ram_ring_slots=2,
        radio_factory=lambda _uri, _serial, _decoder: radio,
        clock_ns=_Clock(),
    )

    assert report.mode == "direct-ram"
    assert report.ram_ring_slots == 2
    assert report.cells[0].ram_spilled_frames == 2
    assert report.cells[0].ram_drained_frames == 2
    assert report.cells[0].ram_high_water_frames == 2


def test_direct_ladder_reports_counter_proven_gap_without_aborting_matrix() -> None:
    radio = _Radio(gap_at_sequence=1)
    report = run_direct_async_ladder(
        uri="ip:192.168.1.15",
        serial="SERIAL_A",
        rates_hz=(1_000_000,),
        durations_seconds=(0.05,),
        channels=(0,),
        samples_per_frame=16_384,
        kernel_buffers=4,
        radio_factory=lambda _uri, _serial, _decoder: radio,
        clock_ns=_Clock(),
    )

    cell = report.cells[0]
    assert not cell.passed
    assert cell.gap_frames == 1
    assert cell.missing_sample_count == 16_384
    assert cell.overflow_frames == 1
    assert report.failures == ()


def test_direct_ladder_accounts_failed_rate_and_continues_matrix() -> None:
    radio = _Radio(rejected_rate=1_000_000)
    report = run_direct_async_ladder(
        uri="ip:192.168.1.15",
        serial="SERIAL_A",
        rates_hz=(1_000_000, 2_000_000),
        durations_seconds=(0.05, 0.1),
        channels=(0,),
        samples_per_frame=16_384,
        kernel_buffers=4,
        radio_factory=lambda _uri, _serial, _decoder: radio,
        clock_ns=_Clock(),
    )

    assert [
        (failure.sample_rate_hz, failure.requested_duration_seconds) for failure in report.failures
    ] == [
        (1_000_000, 0.05),
        (1_000_000, 0.1),
    ]
    assert [cell.sample_rate_hz for cell in report.cells] == [2_000_000, 2_000_000]
    assert report.original_settings_restored


def test_direct_ladder_rejects_oversized_dma_queue_before_open() -> None:
    radio = _Radio()
    with pytest.raises(ValueError, match="DMA request"):
        run_direct_async_ladder(
            uri="ip:192.168.1.15",
            serial="SERIAL_A",
            rates_hz=(5_000_000,),
            durations_seconds=(3,),
            channels=(0,),
            samples_per_frame=4_194_304,
            kernel_buffers=16,
            radio_factory=lambda _uri, _serial, _decoder: radio,
        )
    assert not radio.opened
